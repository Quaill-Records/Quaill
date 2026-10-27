r"""RFC 3161 receipts: a real one from freetsa.org, checked offline, then wired through a whole report.

Run from the repository root:  python tests/check_receipts.py
No network needed. The fixture in tests/fixtures/ is one receipt freetsa.org issued for a witness head of the
clean demo log (quaill gen, seed 1, cdr), so the generator must still produce that same link.
"""
import json
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quaill import receipts  # noqa: E402
from quaill.engine import run  # noqa: E402
from quaill.gen import generate  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
meta = json.loads((FIX / "freetsa-receipt.json").read_text(encoding="utf-8"))
tsr = (FIX / meta["tsr"]).read_bytes()
link = meta["link"]

# 1. the receipt itself
res = receipts.verify(tsr, link)
assert res.status == "valid", res
assert res.gen_time is not None and "freetsa" in res.tsa.lower(), res
assert res.cert_source == "embedded", res
print(f"ok: receipt valid, {res.reason}")

from asn1crypto import tsp  # noqa: E402

bare = tsp.TimeStampResp.load(tsr)["time_stamp_token"].dump()
res = receipts.verify(bare, link)
assert res.status == "valid", res
assert receipts.verify(bare, "00" * 32).status == "invalid"
print("ok: bare TimeStampToken (no response envelope) -> valid; wrong link -> invalid")

res = receipts.verify(tsr, "00" * 32)
assert res.status == "invalid" and "different value" in res.reason, res
print("ok: wrong link -> invalid (imprint)")

bad = bytearray(tsr)
bad[-10] ^= 0x01  # inside the signature
res = receipts.verify(bytes(bad), link)
assert res.status == "invalid" and "signature" in res.reason, res
print("ok: flipped signature byte -> invalid")

import hashlib  # noqa: E402

imprint = hashlib.sha256(bytes.fromhex(link)).digest()
i = tsr.find(imprint)
assert i > 0, "imprint not found in the receipt"
bad = bytearray(tsr)
bad[i] ^= 0x01  # the imprint inside the TSTInfo: now it neither matches the link nor the signed digest
res = receipts.verify(bytes(bad), link)
assert res.status == "invalid", res
print("ok: altered TSTInfo -> invalid")

# 2. through a whole report, on the clean demo log
tmp = pathlib.Path(tempfile.mkdtemp(prefix="quaill-receipts-"))
try:
    out = str(tmp / "clean.mcap")
    info = generate(out, "delivery", None, True, encoding="cdr")
    wpath = pathlib.Path(info["witness"])
    w = json.loads(wpath.read_text(encoding="utf-8"))
    hit = [e for e in w["entries"] if e["seq"] == meta["seq"]]
    assert hit and hit[0]["link"] == link, "the generator no longer produces the fixture's witness head; re-stamp the fixture"

    rep = run(info["path"], "quaill-control", str(wpath), 2.0, info["pubkey"])
    assert rep.has("RECEIPT_ABSENT") and rep.exit_code == 0, [f.code for f in rep.findings]
    print("ok: witness without receipts -> RECEIPT_ABSENT, exit 0")

    hit[0]["rfc3161"] = {"tsa": meta["tsa"], "tsr_der_hex": tsr.hex()}
    wpath.write_text(json.dumps(w), encoding="utf-8")
    rep = run(info["path"], "quaill-control", str(wpath), 2.0, info["pubkey"])
    assert rep.has("RECEIPT_VALID") and rep.exit_code == 0, [f.code for f in rep.findings]
    f = next(x for x in rep.findings if x.code == "RECEIPT_VALID")
    assert "that link is in this file" in f.message, f.message
    assert rep.chain.receipts and rep.chain.receipts[0]["status"] == "valid"
    print("ok: witness with one receipt -> RECEIPT_VALID, exit 0:", f.message)

    hit[0]["rfc3161"] = {"tsa": meta["tsa"], "tsr_der_hex": bytes(bad).hex()}
    wpath.write_text(json.dumps(w), encoding="utf-8")
    rep = run(info["path"], "quaill-control", str(wpath), 2.0, info["pubkey"])
    assert rep.has("RECEIPT_INVALID") and rep.exit_code == 1, [f.code for f in rep.findings]
    print("ok: altered receipt -> RECEIPT_INVALID, exit 1")

    hit[0]["rfc3161"] = {"tsa": meta["tsa"], "error": "connection refused"}
    wpath.write_text(json.dumps(w), encoding="utf-8")
    rep = run(info["path"], "quaill-control", str(wpath), 2.0, info["pubkey"])
    f = next(x for x in rep.findings if x.code == "RECEIPT_ABSENT")
    assert "failed receipt request" in f.message, f.message
    print("ok: failed request -> RECEIPT_ABSENT with the failure noted")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print("ok: receipts")
