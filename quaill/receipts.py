"""RFC 3161 timestamp receipts on witness heads: request them, and check them.

A witness entry says "at this time the chain head was this link". Written by the recorder itself, that is a
note, not evidence. An RFC 3161 receipt from a timestamp authority (TSA) the robot maker does not control turns
it into one: the TSA signs (hash of the link, its own clock time), so the chain through that link existed by then.

What verify() checks:
  1. the response status is granted;
  2. the receipt's messageImprint equals the digest of the 32 link bytes (sha256 unless the receipt says otherwise);
  3. the signed messageDigest attribute equals the digest of the TSTInfo the receipt carries;
  4. the CMS signature over the signed attributes verifies with the TSA certificate: the one embedded in the
     receipt, or one supplied with --tsa-cert (which then wins).
What it does NOT check: the TSA certificate's chain to a trust root, revocation, or the TSA's policy. The report
names the TSA so a reader can decide whether to trust it. No chain-to-root validation in this version.

Only the standard library, asn1crypto (parsing) and cryptography (signatures).
"""
from __future__ import annotations

import hashlib
import os
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

HASHES = {"sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
WEAK_HASHES = {"sha1"}  # parsed so the report can name it, never accepted


@dataclass
class ReceiptResult:
    status: str  # "valid" | "invalid" | "unverified"
    reason: str
    gen_time: datetime | None = None
    tsa: str = ""
    serial: int | None = None
    hash_algo: str = ""
    cert_source: str = ""  # "embedded" | "supplied" | ""

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, "gen_time": self.gen_time.isoformat() if self.gen_time else None, "tsa": self.tsa, "serial": self.serial, "hash_algo": self.hash_algo, "cert_source": self.cert_source}


def _der_set(contents: bytes) -> bytes:
    """Re-wrap the signed attributes as a universal SET OF (tag 0x31) for signature verification (RFC 5652 5.4)."""
    n = len(contents)
    if n < 0x80:
        length = bytes([n])
    else:
        nb = (n.bit_length() + 7) // 8
        length = bytes([0x80 | nb]) + n.to_bytes(nb, "big")
    return b"\x31" + length + contents


def _crypto_hash(name: str):
    from cryptography.hazmat.primitives import hashes

    return {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[name]()


def load_tsa_cert(path: str):
    """A TSA certificate as PEM or DER. Returns a cryptography Certificate."""
    from cryptography import x509

    data = open(path, "rb").read()
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _cert_name(cert) -> str:
    from cryptography.x509.oid import NameOID

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        parts = [a.value for a in cn] + [a.value for a in org if a.value not in [c.value for c in cn]]
        return ", ".join(parts) or cert.subject.rfc4514_string()
    except Exception:
        return "unknown"


def _pick_cert(signed_data, signer_info):
    """The certificate the SignerInfo points at, as a cryptography Certificate, or None."""
    from cryptography import x509

    certs = signed_data["certificates"]
    if certs is None or len(certs) == 0:
        return None
    sid = signer_info["sid"]
    chosen = []
    for c in certs:
        if c.name != "certificate":
            continue
        cert = c.chosen
        try:
            if sid.name == "issuer_and_serial_number":
                if cert.serial_number == sid.chosen["serial_number"].native and cert.issuer == sid.chosen["issuer"]:
                    chosen.append(cert)
            elif sid.name == "subject_key_identifier":
                if cert.key_identifier == sid.chosen.native:
                    chosen.append(cert)
        except Exception:
            pass
    if not chosen:
        chosen = [c.chosen for c in certs if c.name == "certificate"]
    return x509.load_der_x509_certificate(chosen[0].dump()) if chosen else None


def _verify_signature(cert, signer_info, signed_attrs_der: bytes) -> str | None:
    """None when the signature verifies, else the reason it does not."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    sig_alg = signer_info["signature_algorithm"]
    algo = sig_alg.signature_algo  # rsassa_pkcs1v15 | rsassa_pss | ecdsa | dsa
    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    try:
        hash_name = sig_alg.hash_algo
    except Exception:
        hash_name = digest_name
    hash_name = HASHES.get(hash_name or digest_name)
    if hash_name is None:
        return f"unsupported digest {digest_name}"
    sig = signer_info["signature"].native
    pub = cert.public_key()
    try:
        if algo == "rsassa_pkcs1v15":
            if not isinstance(pub, rsa.RSAPublicKey):
                return "certificate key is not RSA"
            pub.verify(sig, signed_attrs_der, padding.PKCS1v15(), _crypto_hash(hash_name))
        elif algo == "rsassa_pss":
            if not isinstance(pub, rsa.RSAPublicKey):
                return "certificate key is not RSA"
            params = sig_alg["parameters"]
            h = HASHES.get(params["hash_algorithm"]["algorithm"].native, hash_name)
            mgf_h = HASHES.get(params["mask_gen_algorithm"]["parameters"]["algorithm"].native, h)
            salt = int(params["salt_length"].native)
            pub.verify(sig, signed_attrs_der, padding.PSS(mgf=padding.MGF1(_crypto_hash(mgf_h)), salt_length=salt), _crypto_hash(h))
        elif algo == "ecdsa":
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return "certificate key is not EC"
            pub.verify(sig, signed_attrs_der, ec.ECDSA(_crypto_hash(hash_name)))
        else:
            return f"unsupported signature algorithm {algo}"
    except InvalidSignature:
        return "signature does not verify against the TSA certificate"
    except Exception as e:
        return f"signature check failed: {e}"
    return None


def verify(tsr_der: bytes, link_hex: str, tsa_cert=None) -> ReceiptResult:
    """Check one RFC 3161 TimeStampResp against the chain link it is supposed to cover.

    tsa_cert: a cryptography Certificate (from --tsa-cert). When given it is used instead of the one in the receipt.
    """
    try:
        from asn1crypto import cms, tsp
    except Exception as e:  # pragma: no cover
        return ReceiptResult("unverified", f"asn1crypto not available ({e})")
    try:
        try:
            resp = tsp.TimeStampResp.load(tsr_der)
            status = resp["status"]["status"].native
        except Exception:
            resp = None
            token = cms.ContentInfo.load(tsr_der)  # a bare TimeStampToken (.tst), as many clients store it
            token["content_type"].native
        if resp is not None:
            if status not in ("granted", "granted_with_mods"):
                texts = resp["status"]["status_string"].native if resp["status"]["status_string"] is not None else None
                return ReceiptResult("invalid", f"TSA status {status}" + (f": {' '.join(texts)}" if texts else ""))
            token = resp["time_stamp_token"]
        if token is None or token["content_type"].native != "signed_data":
            return ReceiptResult("invalid", "response carries no signed timestamp token")
        sd = token["content"]
        eci = sd["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            return ReceiptResult("invalid", f"token content is {eci['content_type'].native}, not tst_info")
        tst_der = eci["content"].contents  # the TSTInfo DER (the OCTET STRING's octets)
        tst = eci["content"].parsed
        gen_time = tst["gen_time"].native
        if gen_time is not None and gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)
        serial = tst["serial_number"].native
        imprint_algo = tst["message_imprint"]["hash_algorithm"]["algorithm"].native
        imprint = tst["message_imprint"]["hashed_message"].native
        tsa_name = ""
        try:
            if tst["tsa"] is not None and tst["tsa"].name == "directory_name":
                tsa_name = tst["tsa"].chosen.human_friendly
        except Exception:
            tsa_name = ""
    except Exception as e:
        return ReceiptResult("invalid", f"receipt does not parse as an RFC 3161 response: {e}")

    out = ReceiptResult("invalid", "", gen_time=gen_time, tsa=tsa_name, serial=serial, hash_algo=imprint_algo)
    h = HASHES.get(imprint_algo)
    if h is None:
        out.reason = f"unsupported imprint hash {imprint_algo}"
        return out
    if h in WEAK_HASHES:
        out.reason = f"imprint uses {h}, which is too weak to identify a link (the recorder asks for sha256)"
        return out
    try:
        link_bytes = bytes.fromhex(link_hex)
    except ValueError:
        out.reason = "link is not hex"
        return out
    if hashlib.new(h, link_bytes).digest() != imprint:
        out.reason = f"receipt covers a different value: its {h} imprint does not match this link"
        return out

    # 3. the signed attributes must commit to the TSTInfo
    try:
        si = sd["signer_infos"][0]
        digest_name = HASHES.get(si["digest_algorithm"]["algorithm"].native)
        if digest_name is None:
            out.reason = f"unsupported signer digest {si['digest_algorithm']['algorithm'].native}"
            return out
        if digest_name in WEAK_HASHES:
            out.reason = f"the authority signed with {digest_name}, which is too weak to trust"
            return out
        attrs = si["signed_attrs"]
        if attrs is None:
            out.reason = "signer has no signed attributes"
            return out
        md = None
        for a in attrs:
            if a["type"].native == "message_digest":
                md = a["values"][0].native
        if md is None:
            out.reason = "signed attributes carry no messageDigest"
            return out
        if hashlib.new(digest_name, tst_der).digest() != md:
            out.reason = "signed messageDigest does not match the TSTInfo in the receipt (token altered)"
            return out
        signed_attrs_der = _der_set(attrs.contents)
    except Exception as e:
        out.reason = f"token structure: {e}"
        return out

    # 4. the signature, with a certificate we can lay hands on
    cert = tsa_cert
    out.cert_source = "supplied" if cert is not None else ""
    if cert is None:
        try:
            cert = _pick_cert(sd, si)
        except Exception as e:
            out.reason = f"embedded certificate does not load: {e}"
            return out
        if cert is not None:
            out.cert_source = "embedded"
    if cert is None:
        out.status = "unverified"
        out.reason = "imprint and digest match, but the receipt carries no TSA certificate and none was supplied (--tsa-cert); signature not checked"
        return out
    out.tsa = _cert_name(cert) or tsa_name
    err = _verify_signature(cert, si, signed_attrs_der)
    if err:
        out.reason = err + (" (supplied certificate)" if out.cert_source == "supplied" else "")
        return out
    out.status = "valid"
    out.reason = f"signed by {out.tsa} at {gen_time.isoformat() if gen_time else '?'}"
    return out


def request_receipt(link_hex: str, tsa_url: str, timeout: float = 20.0) -> dict:
    """Ask a TSA for a receipt on sha256(link bytes). Returns the witness entry's rfc3161 dict."""
    from asn1crypto import tsp

    link_bytes = bytes.fromhex(link_hex)
    nonce = int.from_bytes(os.urandom(8), "big")
    req = tsp.TimeStampReq({"version": "v1", "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": hashlib.sha256(link_bytes).digest()}, "nonce": nonce, "cert_req": True})
    http = urllib.request.Request(tsa_url, data=req.dump(), method="POST", headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply", "User-Agent": "quaill-records"})
    with urllib.request.urlopen(http, timeout=timeout) as r:
        der = r.read()
    resp = tsp.TimeStampResp.load(der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        texts = resp["status"]["status_string"].native if resp["status"]["status_string"] is not None else None
        raise ValueError(f"TSA {tsa_url} answered {status}" + (f": {' '.join(texts)}" if texts else ""))
    tst = resp["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
    if tst["nonce"].native != nonce:
        raise ValueError("TSA response nonce does not match the request")
    res = verify(der, link_hex)
    if res.status == "invalid":
        raise ValueError(f"TSA response does not verify: {res.reason}")
    return {"tsa": tsa_url, "tsr_der_hex": der.hex(), "requested_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
