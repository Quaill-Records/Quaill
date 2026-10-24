"""Command line. Exit codes: 0 meets checks, 1 does not, 2 unreadable or usage error."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks.profile import list_profiles
from .engine import run
from .gen import CONTAINERS, SCENARIOS, generate
from .report import render_json, render_text, render_who


def case(scenario, defect, note, exit_code, code=None, *, witness=True, pubkey=True, profile="quaill-control", encodings=("json", "cdr"), container="mcap", point_at=None):
    return dict(scenario=scenario, defect=defect, note=note, exit=exit_code, code=code, witness=witness, pubkey=pubkey, profile=profile, encodings=encodings, container=container, point_at=point_at)


DEMO_CASES = [
    # planted defects, single mcap, both encodings
    case("delivery", None, "clean log", 0),
    case("delivery", "clock-back", "recorder clock set back 40 s mid-run; chain intact", 0, "TIME_JUMP"),
    case("delivery", "sidecar-restart", "chain sidecar killed and restarted mid-bag; two chains, 10 s unchained", 0, "CHAIN_RESTART"),
    case("delivery", "edit", "human stretch rewritten as AUTONOMOUS", 1, "MESSAGE_EDITED"),
    case("delivery", "delete", "human stretch deleted", 1, "CHAIN_BROKEN"),
    case("delivery", "delete-rechain", "deleted and chain rebuilt; only the witness can tell", 1, "WITNESS_MISMATCH"),
    case("delivery", "truncate", "end cut off, forged shutdown appended; only the witness can tell", 1, "TRUNCATED"),
    case("delivery", "truncate", "same file, no witness: NOT detectable, by design", 0, "UNWITNESSED", witness=False),
    case("delivery", "gap", "2 min silence, no markers", 1, "GAP_UNEXPLAINED"),
    case("delivery", "crash", "2 min silence, crash note on restart", 0, "GAP_EXPLAINED"),
    case("delivery", "clean-restart", "clean shutdown, restart", 0, "GAP_EXPLAINED"),
    case("delivery", "cutoff", "recorder died; witness confirms nothing was cut", 0, "ENDING_UNMARKED"),
    case("delivery", "cutoff", "recorder died; no witness, so cut or crash is unknown", 1, "ENDING_UNEXPLAINED", witness=False),
    case("delivery", "no-operator", "human in control, nobody named", 1, "OPERATOR_MISSING"),
    case("delivery", "handover-back-missing", "control reports stop after takeover", 1, "CONTROL_UNKNOWN"),
    case("delivery", "hidden-teleop", "human drove via teleop while reports said AUTONOMOUS (mode source lied)", 1, "CONTROL_INCONSISTENT"),
    # signatures: what a device key buys without a witness
    case("delivery", None, "clean, no witness, device key supplied: signed and trusted, end unverified", 0, "SIGNED_TRUSTED", witness=False),
    case("delivery", "rechain-nokey", "thorough outsider forgery, own key; device key supplied, no witness", 1, "KEY_MISMATCH", witness=False),
    case("delivery", "rechain-nokey", "same forgery, no device key, no witness: self-consistent, NOT detectable", 0, "SIGNED_ANNOUNCED", witness=False, pubkey=False),
    case("delivery", "truncate-nokey", "outsider cut the end, forged shutdown with own key; no witness needed", 1, "KEY_CHANGED", witness=False),
    case("remote-vehicle", None, "clean StVFernLV log", 0, profile="stvfernlv-anlage3", encodings=("json",)),
    case("remote-vehicle", "unpaired", "remote driving never ended", 1, "PROFILE_EVENT_UNPAIRED", profile="stvfernlv-anlage3", encodings=("json",)),
    case("remote-vehicle", "window", "no telemetry in the 10 s before a fault", 1, "PROFILE_WINDOW_INCOMPLETE", profile="stvfernlv-anlage3", encodings=("json",)),
    # the same log in the containers real robots produce (cdr only)
    case("delivery", None, "rosbag2 directory, mcap storage", 0, encodings=("cdr",), container="rosbag2-mcap"),
    case("delivery", None, "rosbag2 directory split in 2 mcap files; chain spans both", 0, encodings=("cdr",), container="rosbag2-mcap-split"),
    case("delivery", "edit", "split bag, human stretch rewritten", 1, "MESSAGE_EDITED", encodings=("cdr",), container="rosbag2-mcap-split"),
    case("delivery", None, "rosbag2 directory, mcap storage, file-level zstd", 0, encodings=("cdr",), container="rosbag2-mcap-filezstd"),
    case("delivery", None, "rosbag2 directory, sqlite3 storage (Humble default)", 0, encodings=("cdr",), container="rosbag2-sqlite"),
    case("delivery", "truncate", "sqlite3 bag, end cut off", 1, "TRUNCATED", encodings=("cdr",), container="rosbag2-sqlite"),
    case("delivery", None, "sqlite3 storage with per-message zstd", 0, encodings=("cdr",), container="rosbag2-sqlite-zstd"),
    case("delivery", None, "single .db3 file without metadata.yaml", 0, encodings=("cdr",), container="rosbag2-sqlite", point_at="db3"),
    case("ros1-plain", None, "plain ROS 1 bag: nothing to grade above L0, says so", 0, "CHAIN_ABSENT", witness=False, profile="none", encodings=("ros1",)),
]


def cmd_verify(a) -> int:
    rep = run(a.log, a.profile, a.witness, a.gap_seconds, a.pubkey)
    if a.json:
        print(json.dumps(render_json(rep), indent=2))
    else:
        print(render_text(rep))
    if a.out:
        Path(a.out).write_text(json.dumps(render_json(rep), indent=2), encoding="utf-8")
    return rep.exit_code


def cmd_who(a) -> int:
    rep = run(a.log, "none", a.witness, a.gap_seconds)
    print(render_who(rep, a.at))
    return rep.exit_code


def cmd_gen(a) -> int:
    info = generate(a.out, a.scenario, a.defect, not a.no_witness, a.seed, a.duration, encoding=a.encoding, container=a.container, sign=not a.no_sign)
    print(json.dumps(info, indent=2))
    return 0


def cmd_profiles(a) -> int:
    for p in list_profiles():
        print(f"{p['name']:<22} {p['status']:<36} {p['title']}")
    return 0


def cmd_demo(a) -> int:
    outdir = Path(a.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    rows = []
    all_ok = True
    for c in DEMO_CASES:
        for encoding in c["encodings"]:
            if a.encoding != "both" and encoding not in (a.encoding, "ros1"):
                continue
            tag = f"{c['scenario']}-{c['defect'] or 'clean'}" + ("" if c["witness"] else "-nowitness") + ("" if c["pubkey"] else "-nopubkey") + (f"-{c['container']}" if c["container"] != "mcap" else "") + (f"-{encoding}" if encoding == "cdr" else "")
            if c["scenario"] == "ros1-plain":
                out = str(outdir / f"{tag}.bag")
            elif c["container"] == "mcap":
                out = str(outdir / f"{tag}.mcap")
            else:
                out = str(outdir / tag)
            info = generate(out, c["scenario"], c["defect"], c["witness"], encoding=encoding if encoding != "ros1" else "json", container=c["container"])
            target = info.get("path") or info.get("bag")
            witness = info.get("witness") if c["witness"] else ""
            pubkey = info.get("pubkey") if c["pubkey"] and info.get("pubkey") else ""
            if c["point_at"] == "db3":
                target = str(next(Path(out).glob("*.db3")))
            rep = run(target, c["profile"], witness, a.gap_seconds, pubkey)
            found = rep.has(c["code"]) if c["code"] else True
            ok = found and rep.exit_code == c["exit"]
            all_ok &= ok
            rows.append((Path(target).name if c["point_at"] != "db3" else f"{Path(out).name}/{Path(target).name}", encoding, c["note"], c["code"] or "-", "yes" if found else "NO", rep.exit_code, "ok" if ok else "MISMATCH"))
            if a.verbose or (not ok and rep.error):
                print(render_text(rep))
                print("=" * 100)
    w = max(len(r[0]) for r in rows)
    print(f"{'log':<{w}}  {'enc':<5} {'planted / format':<58} {'expected finding':<26} {'found':<6} {'exit':<5} check")
    for r in rows:
        print(f"{r[0]:<{w}}  {r[1]:<5} {r[2][:58]:<58} {r[3]:<26} {r[4]:<6} {r[5]:<5} {r[6]}")
    print()
    print(f"{len(rows)} cases, {'all as expected' if all_ok else 'MISMATCHES above'}. Logs and witness files are in {outdir}")
    return 0 if all_ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="quaill", description="Checks a robot's log (MCAP, rosbag2 directory, .db3, ROS 1 .bag): who was in control, was anything changed, is anything missing.")
    p.add_argument("--version", action="version", version=f"quaill-records {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="check one log and print a report")
    v.add_argument("log", help="robot.mcap | bag_dir/ | robot.db3 | robot.bag | *.zstd")
    v.add_argument("--profile", default="quaill-control", help="profile name or path; 'none' for built-in checks only")
    v.add_argument("--witness", default=None, help="witness file, or a directory of per-session witness files (default: <log>.witness.json, <bag_dir>/witness.json or <bag_dir>/witness/ if present; '' for none)")
    v.add_argument("--pubkey", default=None, help="the device's public key (PEM or hex) to verify link signatures against (default: <log>.pubkey.pem or <bag_dir>/device.pubkey.pem if present; '' for none)")
    v.add_argument("--json", action="store_true", help="print JSON instead of text")
    v.add_argument("--out", default=None, help="also write the JSON report here")
    v.add_argument("--gap-seconds", type=float, default=2.0, help="silence longer than this is a gap (default 2.0)")
    v.set_defaults(fn=cmd_verify)

    wq = sub.add_parser("who", help="who was in control at a given time")
    wq.add_argument("log")
    wq.add_argument("--at", required=True, help="time: '5:30' or '330' (from log start) or ISO-8601")
    wq.add_argument("--witness", default=None)
    wq.add_argument("--gap-seconds", type=float, default=2.0)
    wq.set_defaults(fn=cmd_who)

    g = sub.add_parser("gen", help="write a synthetic test log (reference/example recorder)")
    g.add_argument("out", help="file path for mcap/.bag, directory path for rosbag2 containers")
    g.add_argument("--scenario", default="delivery", choices=sorted(SCENARIOS) + ["ros1-plain"])
    g.add_argument("--defect", default=None, help="planted defect; see 'quaill defects'")
    g.add_argument("--no-witness", action="store_true")
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--duration", type=float, default=None)
    g.add_argument("--encoding", default="json", choices=["json", "cdr"], help="cdr writes real ros2msg schemas and CDR bytes like rosbag2 (delivery scenario only)")
    g.add_argument("--container", default="mcap", choices=sorted(CONTAINERS), help="see 'quaill defects' for descriptions")
    g.add_argument("--no-sign", action="store_true", help="do not sign links with the demo device key")
    g.set_defaults(fn=cmd_gen)

    d = sub.add_parser("demo", help="generate every test case and check each one")
    d.add_argument("outdir")
    d.add_argument("--verbose", action="store_true", help="print every full report")
    d.add_argument("--gap-seconds", type=float, default=2.0)
    d.add_argument("--encoding", default="both", choices=["json", "cdr", "both"])
    d.set_defaults(fn=cmd_demo)

    pr = sub.add_parser("profiles", help="list the rule sets this checker can load")
    pr.set_defaults(fn=cmd_profiles)

    dl = sub.add_parser("defects", help="list the defects and containers the generator can produce")
    dl.set_defaults(fn=lambda a: (print("\n".join(f"{s:<16} {k:<24} {v}" for s, ds in SCENARIOS.items() for k, v in ds.items())), print(), print("\n".join(f"{'container':<16} {k:<24} {v}" for k, v in CONTAINERS.items())), 0)[-1])

    a = p.parse_args(argv)
    try:
        return a.fn(a)  # --witness "" means: do not look for a default witness file
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
