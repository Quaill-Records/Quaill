"""Reads the reports record_runs.sh wrote and prints one table: what each run was, what the checker said,
and whether that is what was expected. Writes OUT_DIR/summary.md too (and appends it to the GitHub step
summary with --github).

Exit 1 when a required check fails: run1 (the clean run) must meet its checks, and run0 (no Quaill nodes) must be
readable and graded NOT ASSESSABLE above L0 rather than failed. Every other run is reported, not required;
the first real recordings are there to find out what happens, not to pass.

Standard library only.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# run, profile, expected exit (None: not required), codes expected in the findings, what the run was
EXPECT = [
    ("run1", "quaill-control", 0, [], "clean run: two scripted takeovers, clean shutdown"),
    ("run0", "none", 0, ["CHAIN_ABSENT", "CONTROL_ABSENT", "SESSION_ABSENT"], "no Quaill nodes: built-in checks only"),
    ("run0", "quaill-control", None, ["PROFILE_TOPIC_MISSING"], "no Quaill nodes, graded against the Quaill control profile"),
    ("run0", "stvfernlv-anlage3", None, ["PROFILE_TOPIC_MISSING"], "no Quaill nodes, graded against Germany's remote-driving record"),
    ("run2", "quaill-control", None, ["FILE_NOT_FINALIZED"], "bag recorder killed -9; the sidecar ran on and stopped cleanly"),
    ("run3", "quaill-control", None, ["CHAIN_RESTART"], "chain sidecar killed -9 and restarted 10 s later"),
    ("run4a", "quaill-control", None, ["FILE_NOT_FINALIZED"], "power cut: the bag that was being written"),
    ("run4b", "quaill-control", None, [], "after the power cut: should open with a CRASH_NOTE for the dead session"),
]
REQUIRED = {("run1", "quaill-control"), ("run0", "none")}


def load(out: Path, run: str, profile: str) -> dict | None:
    p = out / "reports" / f"{run}.{profile}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:  # the checker writes the JSON only when it could read the file
        return {"error": f"report unreadable: {e}", "exit_code": 2, "grades": {}, "findings": []}


def codes(rep: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in rep.get("findings", []):
        out[f["code"]] = out.get(f["code"], 0) + 1
    return out


def bytes_verdict(rep: dict | None) -> str:
    """The one question only a real recording settles: does rosbag2 store the bytes the sidecar hashed."""
    if rep is None or rep.get("error"):
        return "UNKNOWN: run1 has no report"
    c = rep.get("chain") or {}
    if not c.get("present"):
        return "UNKNOWN: run1 has no chain links in the bag"
    k = codes(rep)
    links = c.get("links", 0)
    missing = sum(1 for f in rep["findings"] if f["code"] in ("MESSAGE_MISSING", "MESSAGE_EDITED"))
    if missing == 0:
        return f"YES: every one of the {links} chain links in the bag matched a message by content hash (no MESSAGE_MISSING, no MESSAGE_EDITED)"
    return f"NO or PARTLY: {links} links, with MESSAGE_MISSING x{k.get('MESSAGE_MISSING', 0)} and MESSAGE_EDITED x{k.get('MESSAGE_EDITED', 0)}; rosbag2 stored something other than what the sidecar hashed (RMW matters here)"


def receipts_verdict(rep: dict | None) -> str:
    """Did the witness heads reach a public clock (RFC 3161 receipts), and do they check out."""
    if rep is None or rep.get("error"):
        return "UNKNOWN: run1 has no report"
    k = codes(rep)
    if k.get("RECEIPT_INVALID"):
        return f"NO: RECEIPT_INVALID x{k['RECEIPT_INVALID']} (see the run1 report for the reason)"
    if k.get("RECEIPT_VALID"):
        return "YES: RECEIPT_VALID (the run1 report names the authority and its time for the last head)"
    if k.get("RECEIPT_UNVERIFIED"):
        return "PARTLY: receipts present but no certificate to check their signatures"
    if k.get("RECEIPT_ABSENT"):
        return "NO: the witness heads carry no receipts (no timestamp authority set, or every request failed; the run1 report says which)"
    return "no receipt findings in the run1 report"


def main(argv: list[str]) -> int:
    out = Path(argv[1] if len(argv) > 1 else "ros2-runs")
    github = "--github" in argv
    rmw = (out / "rmw.txt").read_text().strip() if (out / "rmw.txt").is_file() else "unknown"
    ver = (out / "checker-version.txt").read_text().strip() if (out / "checker-version.txt").is_file() else "unknown"
    L: list[str] = []
    L.append("# ROS 2 run: results")
    L.append("")
    L.append(f"Real ROS 2 Jazzy, real `ros2 bag record`, real sidecars; fake robot, scripted operator. Not a physical robot. RMW: `{rmw}`. Checker: `{ver}`.")
    L.append("")
    run1 = load(out, "run1", "quaill-control")
    L.append(f"**Do bag bytes equal sidecar bytes?** {bytes_verdict(run1)}")
    L.append("")
    tsa = (out / "tsa.txt").read_text().strip() if (out / "tsa.txt").is_file() else "none"
    L.append(f"**Witness heads anchored to a public clock?** (authority: `{tsa}`) {receipts_verdict(run1)}")
    L.append("")
    L.append("| run | what | against | grades | exit | expected | found | as expected? |")
    L.append("|---|---|---|---|---|---|---|---|")
    failed_required: list[str] = []
    for run, profile, want_exit, want_codes, what in EXPECT:
        rep = load(out, run, profile)
        required = (run, profile) in REQUIRED
        if rep is None:
            L.append(f"| {run} | {what} | {profile} | no report | - | {want_exit if want_exit is not None else '-'} | - | NO REPORT |")
            if required:
                failed_required.append(f"{run} ({profile}): no report")
            continue
        g = rep.get("grades", {})
        short = {"L0 format": "L0", "L1 integrity": "L1", "L2 control": "control", "L2 completeness": "complete", "profile": "profile"}
        grades = ", ".join(f"{short.get(k, k)}={v}" for k, v in g.items())
        k = codes(rep)
        found = ", ".join(f"{c}" + (f" x{n}" if n > 1 else "") for c, n in sorted(k.items())) or "-"
        exit_code = rep.get("exit_code")
        ok_exit = want_exit is None or exit_code == want_exit
        ok_codes = all(c in k for c in want_codes)
        verdict = "yes" if (ok_exit and ok_codes) else "differs" + ("" if ok_exit else f" (exit {exit_code})")
        if rep.get("error"):
            verdict = f"UNREADABLE: {rep['error']}"
        L.append(f"| {run} | {what} | {profile} | {grades} | {exit_code} | {want_exit if want_exit is not None else '-'}{(' + ' + ' '.join(want_codes)) if want_codes else ''} | {found} | {verdict} |")
        if required and not (ok_exit and ok_codes and not rep.get("error")):
            failed_required.append(f"{run} ({profile}): exit {exit_code}, findings {found}")
    L.append("")
    if run1 and not run1.get("error"):
        ctl = run1.get("control", {})
        L.append(f"run1 timeline: {len(ctl.get('handovers', []))} handover(s); {run1.get('message_count', '?')} messages on {len(run1.get('channels', {}))} channels; chain of {run1.get('chain', {}).get('links', '?')} links; ending `{run1.get('ending')}`.")
        who = out / "reports" / "run1.who.txt"
        if who.is_file():
            L.append("")
            L.append("```")
            L.append(who.read_text(encoding="utf-8").strip())
            L.append("```")
    L.append("")
    L.append("Full reports: `reports/<run>.<profile>.txt`; bags with their witness files: `<run>/`; process logs: `logs/`.")
    if failed_required:
        L.append("")
        L.append("**Required checks not met:** " + "; ".join(failed_required))
    text = "\n".join(L) + "\n"
    print(text)
    (out / "summary.md").write_text(text, encoding="utf-8")
    if github and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    return 1 if failed_required else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
