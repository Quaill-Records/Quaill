"""RFC 3161 receipts: the shipped test, then receipts moved, re-hashed, stripped of their certificate, and one forged outright.

Run from the repository root:  python tests/attacks/receipts_attack.py
No network: everything is built from tests/fixtures/freetsa-3786.tsr or signed with a throwaway key.
"""
import datetime as dt
import hashlib
import json
import subprocess
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A

from asn1crypto import algos, cms, core, tsp, x509 as ax509  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

T = A.Table()
OUT = A.OUT / "receipts"
OUT.mkdir(exist_ok=True)
FIX = A.ROOT / "tests" / "fixtures"
meta = json.loads((FIX / "freetsa-receipt.json").read_text(encoding="utf-8"))
TSR = (FIX / meta["tsr"]).read_bytes()
LINK = meta["link"]

# 1. the shipped test
r = subprocess.run([str(A.PY), str(A.ROOT / "tests" / "check_receipts.py")], cwd=str(A.ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
T.add("tests/check_receipts.py", "all ok, exit 0", {"exit": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "traceback": "Traceback" in r.stderr, "seconds": 0, "peak_mb": None}, "OK" if r.returncode == 0 else "BUG", r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:])

# a clean cdr log whose witness contains the fixture's head (seed 1, cdr: the fixture's link)
info = A.gen("receipts-base.mcap", encoding="cdr")
BASE = info["path"]
KEY = info["pubkey"]
W = json.loads(open(info["witness"], encoding="utf-8").read())
hit = [e for e in W["entries"] if e["seq"] == meta["seq"]]
assert hit and hit[0]["link"] == LINK, "generator no longer produces the fixture's head"


def witness_with(tsr_hex_by_seq: dict, path_name: str, link_override: dict | None = None) -> str:
    w = json.loads(json.dumps(W))
    for e in w["entries"]:
        if e["seq"] in tsr_hex_by_seq:
            e["rfc3161"] = {"tsa": meta["tsa"], "tsr_der_hex": tsr_hex_by_seq[e["seq"]]}
        if link_override and e["seq"] in link_override:
            e["link"] = link_override[e["seq"]]
    p = OUT / path_name
    p.write_text(json.dumps(w), encoding="utf-8")
    return str(p)


def rcpt(r):
    return [(x["seq"], x["status"], x["reason"][:90], x.get("tsa")) for x in r.get("json", {}).get("chain", {}).get("receipts", [])] if "json" in r else []


# 2. the real receipt on its own head
r = A.verify(BASE, witness=witness_with({meta["seq"]: TSR.hex()}, "w-valid.json"), pubkey=KEY)
T.add("real freetsa receipt on its own head", "RECEIPT_VALID, exit 0", r, "OK" if "RECEIPT_VALID" in r["codes"] and r["exit"] == 0 else "BUG", str(rcpt(r)))

# 3. the same receipt moved to a different head (different link)
other = next(e["seq"] for e in W["entries"] if e["seq"] != meta["seq"])
r = A.verify(BASE, witness=witness_with({other: TSR.hex()}, "w-moved.json"), pubkey=KEY)
T.add("real receipt attached to a different head", "RECEIPT_INVALID (imprint), exit 1", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))

# 4. TSTInfo hash algorithm rewritten to sha1 (token altered)
resp = tsp.TimeStampResp.load(TSR)
tst = resp["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
tst2 = tsp.TSTInfo.load(tst.dump())
tst2["message_imprint"]["hash_algorithm"] = algos.DigestAlgorithm({"algorithm": "sha1"})
tst2["message_imprint"]["hashed_message"] = hashlib.sha1(bytes.fromhex(LINK)).digest()
resp2 = tsp.TimeStampResp.load(TSR)
resp2["time_stamp_token"]["content"]["encap_content_info"]["content"] = core.ParsableOctetString(tst2.dump())
r = A.verify(BASE, witness=witness_with({meta["seq"]: resp2.dump(force=True).hex()}, "w-sha1.json"), pubkey=KEY)
T.add("TSTInfo rewritten to say sha1 (imprint matches sha1 of the link, signature untouched)", "RECEIPT_INVALID (signed digest mismatch), exit 1", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))

# 5. certificate stripped from the receipt
resp3 = tsp.TimeStampResp.load(TSR)
sd = resp3["time_stamp_token"]["content"]
embedded_cert_der = sd["certificates"][0].chosen.dump()
sd["certificates"] = None
stripped = resp3.dump(force=True)
assert tsp.TimeStampResp.load(stripped)["time_stamp_token"]["content"]["certificates"].native is None
wp = witness_with({meta["seq"]: stripped.hex()}, "w-nocert.json")
r = A.verify(BASE, witness=wp, pubkey=KEY)
T.add("receipt with its certificate stripped, no --tsa-cert", "RECEIPT_UNVERIFIED warn, exit 0", r, "OK" if "RECEIPT_UNVERIFIED" in r["codes"] and r["exit"] == 0 else "BUG", str(rcpt(r)))
freetsa_pem = OUT / "freetsa-embedded.pem"
freetsa_pem.write_bytes(x509.load_der_x509_certificate(embedded_cert_der).public_bytes(serialization.Encoding.PEM))
r = A.verify(BASE, witness=wp, pubkey=KEY, tsa_cert=freetsa_pem)
T.add("stripped receipt + correct --tsa-cert (the cert that was embedded)", "RECEIPT_VALID (supplied), exit 0", r, "OK" if "RECEIPT_VALID" in r["codes"] else "BUG", str(rcpt(r)))


# a throwaway "TSA": self-signed RSA certificate that CLAIMS to be freetsa
def fake_tsa(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Free TSA"), x509.NameAttribute(NameOID.COUNTRY_NAME, "DE")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(3786).not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650)).sign(key, hashes.SHA256())
    return key, cert


FAKE_KEY, FAKE_CERT = fake_tsa("www.freetsa.org")
fake_pem = OUT / "fake-tsa.pem"
fake_pem.write_bytes(FAKE_CERT.public_bytes(serialization.Encoding.PEM))
r = A.verify(BASE, witness=wp, pubkey=KEY, tsa_cert=fake_pem)
T.add("stripped receipt + WRONG --tsa-cert", "RECEIPT_INVALID, exit 1", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))
r = A.verify(BASE, witness=witness_with({meta["seq"]: TSR.hex()}, "w-valid2.json"), pubkey=KEY, tsa_cert=fake_pem)
T.add("REAL receipt (cert embedded) + wrong --tsa-cert", "the supplied cert wins: RECEIPT_INVALID, exit 1 (a typo in --tsa-cert fails a good log)", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))


# 6. a receipt forged end to end: own key, own self-signed cert, gen_time of our choosing, imprint over the FORGED head
def forge_receipt(link_hex: str, gen_time: dt.datetime, key, cert, imprint_algo="sha256", embed_cert=True, serial=4242) -> bytes:
    h = hashlib.new(imprint_algo, bytes.fromhex(link_hex)).digest()
    tst = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.1",
            "message_imprint": {"hash_algorithm": {"algorithm": imprint_algo}, "hashed_message": h},
            "serial_number": serial,
            "gen_time": gen_time,
            "tsa": ax509.GeneralName({"directory_name": ax509.Name.load(cert.subject.public_bytes())}),
        }
    )
    tst_der = tst.dump()
    acert = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": [cms.ContentType("tst_info")]}),
            cms.CMSAttribute({"type": "message_digest", "values": [core.OctetString(hashlib.sha256(tst_der).digest())]}),
        ]
    )
    sig = key.sign(signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    si = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": {"issuer": acert.issuer, "serial_number": acert.serial_number}}),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": sig,
        }
    )
    sd = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "tst_info", "content": core.ParsableOctetString(tst_der)},
            "certificates": [cms.CertificateChoices({"certificate": acert})] if embed_cert else None,
            "signer_infos": [si],
        }
    )
    resp = tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": cms.ContentInfo({"content_type": "signed_data", "content": sd})})
    return resp.dump()


# sanity: our forged receipt verifies with the checker's own function
from quaill import receipts  # noqa: E402

forged = forge_receipt(LINK, dt.datetime(2026, 10, 23, 18, 2, 0, tzinfo=dt.timezone.utc), FAKE_KEY, FAKE_CERT)
res = receipts.verify(forged, LINK)
print("forged receipt through receipts.verify():", res.status, "|", res.reason)

r = A.verify(BASE, witness=witness_with({meta["seq"]: forged.hex()}, "w-forged.json"), pubkey=KEY)
T.add("FORGED receipt: self-signed cert with CN www.freetsa.org, no --tsa-cert", "documented gap (no chain-to-root); the report says 'valid RFC 3161 receipt from www.freetsa.org'", r, "DESIGN-GAP" if "RECEIPT_VALID" in r["codes"] else "OK", str(rcpt(r)))
forged_sha1 = forge_receipt(LINK, dt.datetime(2026, 10, 23, 18, 2, 0, tzinfo=dt.timezone.utc), FAKE_KEY, FAKE_CERT, imprint_algo="sha1")
r = A.verify(BASE, witness=witness_with({meta["seq"]: forged_sha1.hex()}, "w-forged-sha1.json"), pubkey=KEY)
T.add("forged receipt with a sha1 imprint", "RECEIPT_INVALID (sha1 imprint refused), exit 1", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))

# 7. insider truncation + witness rebuilt + forged receipts on the forged heads: the complete package
header, msgs = A.read_mcap(BASE)
import forgery_helpers as FH  # noqa: E402

kept = FH.truncate_insider(msgs, "cdr")
tpath = OUT / "truncated-insider.mcap"
A.write_mcap(tpath, header, kept)
by_seq = {d["seq"]: d for m in kept if m.topic == A.CHAIN_TOPIC for d in [m.body()]}
w = json.loads(json.dumps(W))
w["entries"] = [e for e in w["entries"] if e["seq"] in by_seq]
last = max(by_seq)
w["entries"].append({"session_id": "rec-0001", "seq": last, "link": by_seq[last]["link"], "recv_time": by_seq[last]["recv_time"], "key_id": by_seq[last]["key_id"], "witnessed_at": "2026-10-23T18:05:01Z"})
for e in w["entries"]:
    e["rfc3161"] = {"tsa": "https://freetsa.org/tsr", "tsr_der_hex": forge_receipt(e["link"], dt.datetime(2026, 10, 23, 18, 5, 1, tzinfo=dt.timezone.utc), FAKE_KEY, FAKE_CERT, serial=e["seq"]).hex()}
wp = OUT / "w-truncated-forged-receipts.json"
wp.write_text(json.dumps(w), encoding="utf-8")
r = A.verify(tpath, witness=wp, pubkey=KEY)
T.add("insider cut + forged shutdown + rebuilt witness + forged receipts on every head", "the only thing that could catch an insider is the receipt; forged ones pass", r, "DESIGN-GAP" if r["exit"] == 0 and "RECEIPT_VALID" in r["codes"] else "OK", str(rcpt(r)[-1:]))
r = A.verify(tpath, witness=wp, pubkey=KEY, tsa_cert=freetsa_pem)
T.add("same, with the real freetsa certificate supplied via --tsa-cert", "RECEIPT_INVALID, exit 1", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)[-1:]))

# 8. a receipt whose status is 'rejection'
status_der = tsp.PKIStatusInfo({"status": "rejection", "status_string": ["nope"]}).dump()
rej_der = b"0" + bytes([len(status_der)]) + status_der  # TimeStampResp with no token
r = A.verify(BASE, witness=witness_with({meta["seq"]: rej_der.hex()}, "w-rejected.json"), pubkey=KEY)
T.add("receipt with status=rejection", "RECEIPT_INVALID, exit 1", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))

# 9. receipt with two signer infos, the first bogus
resp4 = tsp.TimeStampResp.load(TSR)
sd4 = resp4["time_stamp_token"]["content"]
si_real = sd4["signer_infos"][0]
si_bogus = cms.SignerInfo.load(si_real.dump())
si_bogus["signature"] = b"\x00" * len(si_real["signature"].native)
sd4["signer_infos"] = cms.SignerInfos([si_bogus, si_real])
r = A.verify(BASE, witness=witness_with({meta["seq"]: resp4.dump(force=True).hex()}, "w-two-signers.json"), pubkey=KEY)
T.add("receipt with two SignerInfos, first one bogus", "RECEIPT_INVALID (checker only looks at [0])", r, "OK" if "RECEIPT_INVALID" in r["fails"] else "BUG", str(rcpt(r)))
T.dump("receipts")
