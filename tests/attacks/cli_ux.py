"""CLI and UX edge cases. Any traceback is a bug.

Run from the repository root:  python tests/attacks/cli_ux.py
"""
import json
import shutil
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A

T = A.Table()
OUT = A.OUT / "cli"
OUT.mkdir(exist_ok=True)
BASE = A.OUT / "base-json"
WIT = str(BASE) + ".witness.json"
KEY = str(BASE) + ".pubkey.pem"


def no_tb(r, want=None):
    return "BUG" if r["traceback"] or (want is not None and r["exit"] != want) else "OK"


def who(at, log=BASE, **kw):
    r = A.quaill("who", str(log), "--at", at, "--witness", WIT)
    return r


for at in ["nonsense", "", "-5", "99:99", "1e9", "5:30:00:00", "5:", ":30", "5:30.5", "2026-10-23T18:05:00Z", "2026-10-23 18:05", "2026-10-23T18:05:00+02:00", "٣", "1:2:3:4", "9" * 40, "0x10", " 5:30 "]:
    r = who(at)
    first = (r["stdout"].strip() or r["stderr"].strip()).splitlines()[0][:100] if (r["stdout"].strip() or r["stderr"].strip()) else ""
    T.add(f"who --at {at!r}", "answer or exit 2 with a message", r, no_tb(r), first)

r = A.quaill("who", str(A.OUT / "robust" / "negative-timestamps.db3"), "--at", "1")
T.add("who on a bag without control reports", "says so, exit 0 or 1", r, no_tb(r), r["stdout"].strip()[:100])
r = A.quaill("who", str(BASE), "--at", "11:00", "--witness", WIT)
T.add("who --at past the end", "says outside the log", r, no_tb(r), r["stdout"].strip()[:100])

# directories with trailing slashes, in both slash styles
info = A.gen("cli-bag", encoding="cdr", container="rosbag2-mcap")
bag = pathlib.Path(info["path"])
for variant in [str(bag) + "\\", str(bag) + "/", str(bag).replace("\\", "/") + "/", str(bag) + "\\\\", str(bag) + "\\.", str(bag) + "\\..\\" + bag.name]:
    r = A.verify(variant)
    note = f"witness picked up: {bool(r.get('json', {}).get('witness'))}" if "json" in r else ""
    T.add(f"verify on rosbag2 dir written as {variant[len(str(A.OUT)) :]!r}", "same result as without the slash, default witness found", r, "OK" if r["exit"] == 0 and r.get("json", {}).get("witness") else ("BUG" if r["traceback"] else "DESIGN-GAP"), note)

# a witness copied INTO the bag directory (README says <bag_dir>/witness.json works)
shutil.copy(info["witness"], bag / "witness.json")
r = A.verify(bag, witness=None)
T.add("rosbag2 dir with witness.json inside it, sidecar removed", "found", r, "OK" if r.get("json", {}).get("witness") else "BUG")

# paths with spaces and unicode
sp = OUT / "my robot log.mcap"
shutil.copy(BASE, sp)
shutil.copy(WIT, str(sp) + ".witness.json")
shutil.copy(KEY, str(sp) + ".pubkey.pem")
r = A.verify(sp)
T.add("log path with spaces, sidecars auto-found", "PASS", r, no_tb(r, 0), f"witness={r.get('json', {}).get('witness')}")
r = A.quaill("verify", str(sp))
T.add("text report for a path with spaces", "fine", r, no_tb(r, 0))
up = OUT / "лог ünï 測試.mcap"
shutil.copy(BASE, up)
r = A.quaill("verify", str(up), "--witness", "", "--pubkey", "")
T.add("text report for a unicode file name (stdout is a pipe)", "no traceback", r, no_tb(r))
r = A.quaill("verify", str(up), "--witness", "", "--pubkey", "", "--json")
T.add("json report for a unicode file name", "no traceback", r, no_tb(r))
uni_bag = next(A.OUT.glob("robust/bag-unicode*.mcap"))
r = A.quaill("verify", str(uni_bag), "--witness", "", "--pubkey", "")
T.add("text report with unicode topic names (stdout is a pipe)", "no traceback", r, no_tb(r))
r = A.quaill("who", str(uni_bag), "--at", "1:05", "--witness", "")
T.add("who with unicode topic names", "no traceback", r, no_tb(r))

# degenerate paths
for p in [".", "..", "D:\\", "D:", "/", "nul", "con", "C:\\Windows", ""]:
    r = A.verify(p)
    T.add(f"verify {p!r}", "exit 2 with a message", r, no_tb(r, 2), (r["stderr"].strip().splitlines() or [""])[-1][:100])

# a mistyped sidecar path: the user asked for a witness / key and gets a PASS without it
r = A.verify(BASE, witness=str(OUT / "typo.witness.json"), pubkey=KEY)
T.add("--witness pointing at a nonexistent file", "should be exit 2 (the user asked for it); is a warn", r, "DESIGN-GAP" if r["exit"] == 0 else "OK", f"codes {sorted(set(r['codes']))}")
r = A.verify(BASE, witness=WIT, pubkey=str(OUT / "typo.pem"))
T.add("--pubkey pointing at a nonexistent file", "should be exit 2; is a warn and falls back to the announced key", r, "DESIGN-GAP" if r["exit"] == 0 else "OK", f"codes {sorted(set(r['codes']))}")
r = A.verify(BASE, witness=WIT, pubkey=KEY, tsa_cert=str(OUT / "typo-cert.pem"))
T.add("--tsa-cert pointing at a nonexistent file", "should be exit 2; is a warn", r, "DESIGN-GAP" if r["exit"] == 0 else "OK", f"codes {sorted(set(r['codes']))}")
r = A.verify(BASE, witness=WIT, pubkey=KEY, profile="typo-profile")
T.add("--profile nonexistent name", "exit 2 listing the profiles", r, no_tb(r, 2), (r["stderr"].strip().splitlines() or [""])[-1][:100])
r = A.verify(BASE, witness=WIT, pubkey=KEY, profile="NONE")
T.add("--profile NONE (uppercase)", "built-in only", r, no_tb(r, 0))

# gen edge cases
for args in [["--duration", "0"], ["--duration", "-5"], ["--duration", "0.3"], ["--seed", str(2**70)], ["--defect", "nope"], ["--encoding", "cdr", "--container", "rosbag2-sqlite", "--defect", "sidecar-restart"], ["--scenario", "remote-vehicle", "--encoding", "cdr"]]:
    r = A.quaill("gen", str(OUT / ("gen-" + "_".join(a.strip("-") for a in args))), "--scenario", "delivery", *args) if "--scenario" not in args else A.quaill("gen", str(OUT / "gen-rv-cdr"), *args)
    T.add(f"gen {' '.join(args)}", "exit 0 or 2 with a message", r, no_tb(r), (r["stderr"].strip().splitlines() or [r["stdout"][:80]])[-1][:100])
r = A.quaill("gen", str(OUT / "gen-container-json-sqlite"), "--container", "rosbag2-sqlite")
T.add("gen --container rosbag2-sqlite with json encoding", "exit 2 with a message", r, no_tb(r, 2), (r["stderr"].strip().splitlines() or [""])[-1][:100])
r = A.quaill("gen", str(OUT / "gen-dur0"), "--duration", "0")
if r["exit"] == 0:
    rr = A.verify(OUT / "gen-dur0")
    T.add("verify a --duration 0 log", "no traceback", rr, no_tb(rr))

# misc
r = A.quaill()
T.add("quaill with no arguments", "usage, exit 2", r, no_tb(r, 2))
r = A.quaill("verify")
T.add("quaill verify with no log", "usage, exit 2", r, no_tb(r, 2))
r = A.quaill("profiles")
T.add("quaill profiles", "list", r, no_tb(r, 0), r["stdout"].strip().splitlines()[0][:80])
r = A.quaill("defects")
T.add("quaill defects", "list", r, no_tb(r, 0))
r = A.quaill("--version")
T.add("quaill --version", "version", r, no_tb(r, 0), r["stdout"].strip()[:40])
r = A.quaill("stamp", str(OUT / "nope.json"))
T.add("stamp a nonexistent witness", "exit 2 with message", r, no_tb(r, 2), (r["stderr"].strip().splitlines() or [""])[-1][:100])
p = OUT / "stamp-list.json"
p.write_text("[1,2]", encoding="utf-8")
r = A.quaill("stamp", str(p))
T.add("stamp a witness that is a list", "exit 2 with message", r, no_tb(r, 2), (r["stderr"].strip().splitlines() or [""])[-1][:100])
p = OUT / "stamp-empty.json"
p.write_text(json.dumps({"entries": []}), encoding="utf-8")
r = A.quaill("stamp", str(p), "--tsa", "http://127.0.0.1:9/")
T.add("stamp an empty witness with an unreachable TSA", "0 receipts, exit 0", r, no_tb(r), r["stdout"].strip()[:60])
p = OUT / "stamp-one.json"
p.write_text(json.dumps({"entries": [{"seq": 1, "link": "00" * 32}]}), encoding="utf-8")
r = A.quaill("stamp", str(p), "--tsa", "http://127.0.0.1:9/")
T.add("stamp one head with an unreachable TSA (127.0.0.1:9)", "exit 2 with a message", r, no_tb(r), (r["stderr"].strip().splitlines() or [""])[-1][:100])
r = A.quaill("stamp", str(p), "--tsa", "not a url")
T.add("stamp with a non-URL --tsa", "exit 2 with a message", r, no_tb(r), (r["stderr"].strip().splitlines() or [""])[-1][:100])

# the demo itself, into a scratch dir (not demo-logs)
r = A.quaill("demo", str(OUT / "demo"), timeout=1800)
T.add("quaill demo into a scratch directory", "all as expected, exit 0", r, no_tb(r, 0), r["stdout"].strip().splitlines()[-1][:80] if r["stdout"].strip() else "")
T.dump("cli")
