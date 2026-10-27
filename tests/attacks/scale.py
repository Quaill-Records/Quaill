"""Scale: generate long logs and time `verify`; also the quadratic cases (many identical messages, many edits, big witness).

Run from the repository root:  python tests/attacks/scale.py [gen|verify|quadratic|all]
"""
import json
import sys
import time
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A
from attacklib import CHAIN_TOPIC, ChainBuilder, enc

T = A.Table()
NS = 1_000_000_000
what = sys.argv[1] if len(sys.argv) > 1 else "all"
DURATIONS = [600, 1800, 3600, 7200, 36000]


def gen_long():
    for d in DURATIONS:
        out = A.OUT / f"scale-{d}.mcap"
        if out.exists() and (A.OUT / f"scale-{d}.mcap.witness.json").exists():
            continue
        t0 = time.perf_counter()
        r = A.quaill("gen", str(out), "--scenario", "delivery", "--encoding", "json", "--duration", str(d), timeout=7200)
        print(f"gen {d}s: exit {r['exit']} in {time.perf_counter() - t0:.0f} s, peak {r['peak_mb']} MB, size {out.stat().st_size / 2**20:.0f} MB" if r["exit"] == 0 else f"gen {d}: FAILED {r['stderr'][-300:]}", flush=True)


def verify_long():
    for d in DURATIONS:
        out = A.OUT / f"scale-{d}.mcap"
        if not out.exists():
            continue
        r = A.verify(out, timeout=7200)
        n = r.get("json", {}).get("messages") or r.get("json", {}).get("message_count")
        size = out.stat().st_size / 2**20
        T.add(f"verify {d} s log ({size:.0f} MB, {r['json']['log']['messages'] if 'json' in r and 'log' in r['json'] and isinstance(r['json']['log'], dict) and 'messages' in r['json']['log'] else '?'} msgs)", "linear time", r, "OK" if r["exit"] == 0 and r["seconds"] < 120 else ("BUG" if r["exit"] != 0 else "DESIGN-GAP"), f"{r['seconds']} s, peak {r['peak_mb']} MB")
        # time without a witness too (the witness loop rebuilds a dict per entry)
        r2 = A.verify(out, witness="", timeout=7200)
        T.rows[-1]["observed"] += f"; without witness {r2['seconds']} s"
        print(f"   without witness: {r2['seconds']} s", flush=True)


def identical_messages(n: int, name: str):
    """A parked robot: n identical /cmd_vel messages (same bytes, same hash), each with its own link."""
    header, base = A.read_mcap(A.OUT / "base-json")
    tpl = next(m for m in base if m.topic == CHAIN_TOPIC)
    start = base[0].log_time
    sess = [m for m in base if m.topic == "/quaill/session"]
    data = enc({"linear": {"x": 0.0, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": 0.0}})
    cb = ChainBuilder("rec-0001", None)
    out = []
    s = sess[0].clone(log_time=start, publish_time=start)
    out += [s, tpl.clone(data=enc(cb.add(s.topic, s.data, start)), log_time=start, publish_time=start)]
    for k in range(n):
        t = start + NS + k * (NS // 10)
        m = base[2].clone(topic="/cmd_vel", data=data, log_time=t, publish_time=t)
        out += [m, tpl.clone(data=enc(cb.add("/cmd_vel", data, t)), log_time=t, publish_time=t)]
    t += NS
    e = sess[-1].clone(log_time=t, publish_time=t)
    out += [e, tpl.clone(data=enc(cb.add(e.topic, e.data, t)), log_time=t, publish_time=t)]
    p = A.OUT / f"{name}.mcap"
    A.write_mcap(p, header, out)
    return p


def all_edited(n_edit: int, name: str):
    """Every /odom and /cmd_vel message in the base log has one byte flipped (n_edit of them): edit detection is O(missing x uncovered)."""
    header, base = A.read_mcap(A.OUT / "base-json")
    out = []
    k = 0
    for m in base:
        if m.topic in ("/odom", "/cmd_vel") and k < n_edit:
            d = bytearray(m.data)
            d[-1] ^= 0x01
            m = m.clone(data=bytes(d))
            k += 1
        out.append(m)
    p = A.OUT / f"{name}.mcap"
    A.write_mcap(p, header, out)
    return p


def quadratic():
    for n in (5_000, 10_000, 20_000, 40_000):
        p = identical_messages(n, f"identical-{n}")
        r = A.verify(p, witness="", pubkey="", timeout=1800)
        T.add(f"{n:,} identical chained messages (parked robot)", "linear time", r, "OK" if r["seconds"] < 60 else "BUG", f"{r['seconds']} s, peak {r['peak_mb']} MB")
    for n in (1_000, 2_000, 4_000, 6_000):
        p = all_edited(n, f"edited-{n}")
        r = A.verify(p, witness="", pubkey="", timeout=1800)
        T.add(f"{n:,} edited messages in a 600 s log", "linear time, MESSAGE_EDITED", r, "OK" if r["seconds"] < 60 else "BUG", f"{r['seconds']} s, peak {r['peak_mb']} MB")
    # big witness against a long log
    long = next((A.OUT / f"scale-{d}.mcap" for d in reversed(DURATIONS) if (A.OUT / f"scale-{d}.mcap").exists()), None)
    if long:
        w = json.loads((str(long) + ".witness.json").__class__ and open(str(long) + ".witness.json", encoding="utf-8").read())
        n0 = len(w["entries"])
        big = {"entries": [dict(e) for e in w["entries"] for _ in range(max(1, 20_000 // n0))]}
        wp = A.OUT / "scale-witness-20k.json"
        wp.write_text(json.dumps(big), encoding="utf-8")
        r = A.verify(long, witness=wp, timeout=7200)
        T.add(f"{len(big['entries']):,}-entry witness against {long.name}", "linear time", r, "OK" if r["seconds"] < 120 else "BUG", f"{r['seconds']} s, peak {r['peak_mb']} MB")


if what in ("gen", "all"):
    gen_long()
if what in ("verify", "all"):
    verify_long()
if what in ("quadratic", "all"):
    quadratic()
T.dump(f"scale-{what}")
