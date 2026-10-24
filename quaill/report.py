"""Text and JSON rendering of a Report. Facts only; the wording never judges."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .engine import Report
from .findings import NS, fmt_abs, fmt_dur, fmt_rel
from .mcapio import CHAIN_TOPIC


def parse_time(s: str, start_ns: int) -> int:
    """'5:30', '0:05:30', '330', '330.5' are relative to the log start; ISO-8601 is absolute."""
    s = s.strip()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return start_ns + int(float(s) * NS)
    m = re.fullmatch(r"(?:(\d+):)?(\d{1,2}):(\d{1,2}(?:\.\d+)?)", s)
    if m:
        h = int(m.group(1) or 0)
        return start_ns + int((h * 3600 + int(m.group(2)) * 60 + float(m.group(3))) * NS)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * NS)


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def render_text(rep: Report) -> str:
    L: list[str] = []
    prof = rep.profile
    prof_label = f"{prof['name']} v{prof.get('version', '?')} ({prof.get('status', '')})" if prof else "built-in checks only"
    L.append(f"Quaill Records v{rep.tool_version}   checks against: {prof_label}")
    L.append(f"file     {rep.path}")
    if rep.error:
        L.append(f"result   UNREADABLE (exit 2): {rep.error}")
        return "\n".join(L)
    log = rep.log
    assert log is not None
    L.append(f"kind     {log.kind}")
    L.append(f"sha256   {log.sha256}" + (f"  (over {len(log.files)} files)" if len(log.files) > 1 else ""))
    L.append(f"witness  {rep.witness_path or 'none supplied'}")
    L.append(f"pubkey   {rep.pubkey_path or 'none supplied (signatures checked against the key announced in the bag, if any)'}")
    chans = len(log.topic_counts)
    L.append(f"span     {fmt_abs(log.start)} -> {fmt_abs(log.end)}  ({fmt_dur(log.end - log.start)}), {chans} channels, {len(log.messages):,} messages" + (f", recorder: {log.library}" if log.library else ""))
    L.append("")

    g = rep.grades()
    notes = {}
    c = rep.chain
    if c and c.present:
        if c.truncated:
            notes["L1 integrity"] = "end of log cut off (per witness)"
        elif c.witness_present:
            notes["L1 integrity"] = f"chain of {len(c.links):,} links, " + ("witnessed to the end" if c.complete_per_witness else f"witnessed through {fmt_rel(c.witnessed_through_time, log.start) if c.witnessed_through_time else '?'}")
        else:
            notes["L1 integrity"] = f"chain of {len(c.links):,} links, no outside witness"
    ct = rep.control
    if ct and ct.present:
        notes["L2 control"] = f"{len(ct.handovers)} handover(s)"
    cp = rep.completeness
    if cp:
        n_un = sum(1 for x in cp.gaps if not x.explained)
        notes["L2 completeness"] = f"{len(cp.gaps)} gap(s), {n_un} unexplained, ending {cp.ending}"
    pr = rep.profile_result
    if pr:
        present = sum(1 for i in pr.items if i["present"] and not i["missing_fields"])
        notes["profile"] = f"{pr.name}: {present}/{len(pr.items)} items present with all fields"
    for k, v in g.items():
        L.append(f"  {k:<17}{v:<16}{notes.get(k, '')}")
    L.append("")

    if ct and ct.present:
        L.append("WHO WAS IN CONTROL")
        if c and c.present and any(f.severity == "fail" for f in c.findings):
            L.append("  (integrity check FAILED: this timeline is what the file says now, not necessarily what was recorded)")
        for s in ct.segments:
            who = s.mode_name if s.mode is not None else "UNKNOWN"
            op = f"operator {s.operator_ref}" if s.operator_ref else ""
            reason = f"({s.reason})" if s.reason else ""
            L.append(f"  {fmt_rel(s.t_start, log.start)} - {fmt_rel(s.t_end, log.start)}   {who:<22} {op:<20} {reason}".rstrip())
        if ct.handovers:
            L.append("  handovers: " + "; ".join(f"{fmt_rel(h['t'], log.start)} {h['from']} -> {h['to']}" for h in ct.handovers))
        L.append("")

    if cp and cp.sessions:
        L.append("SESSIONS")
        for e in cp.sessions:
            extra = f"software {e['software_version']}" if e.get("software_version") else ""
            if e.get("note"):
                extra = (extra + "  " if extra else "") + f"note: {e['note']}"
            L.append(f"  {fmt_rel(e['t'], log.start)}  {e['event']:<15} {e.get('session_id') or '':<8} {extra}".rstrip())
        L.append("")

    if cp:
        L.append("GAPS")
        if not cp.gaps:
            L.append("  none")
        for x in cp.gaps:
            L.append(f"  {fmt_rel(x.t_start, log.start)} - {fmt_rel(x.t_end, log.start)}  ({fmt_dur(x.t_end - x.t_start)})  " + (f"explained: {x.explanation}" if x.explained else "UNEXPLAINED"))
        L.append("")

    if pr and pr.items:
        L.append(f"PROFILE ITEMS  ({pr.name})")
        for i in pr.items:
            if not i["present"]:
                status = "MISSING"
            elif i.get("undecodable"):
                status = f"present ({i['messages']:,} msgs) but not decodable; fields unchecked"
            elif i.get("not_applicable"):
                status = "not applicable in this log (no matching messages)"
            elif i["missing_fields"]:
                status = "fields missing: " + ", ".join(i["missing_fields"])
            else:
                status = f"present ({i['messages']:,} msgs)"
            L.append(f"  {i.get('id') or '':<4} {(i.get('name') or '')[:52]:<52} {status}")
        L.append("")

    fs = rep.findings
    L.append(f"FINDINGS  ({rep.count('fail')} fail, {rep.count('warn')} warn, {rep.count('info')} info)")
    order = {"fail": 0, "warn": 1, "info": 2}
    for f in sorted(fs, key=lambda f: (order[f.severity], f.t_start if f.t_start is not None else float("inf"))):
        when = ""
        if f.t_start is not None:
            when = fmt_rel(f.t_start, log.start)
            if f.t_end is not None and f.t_end != f.t_start:
                when += f"-{fmt_rel(f.t_end, log.start)}"
        L.append(f"  {f.severity:<5} {f.code:<24} {when:<16} {f.message}")
    if not fs:
        L.append("  none")
    L.append("")
    verdict = {0: "MEETS CHECKS", 1: "DOES NOT MEET CHECKS", 2: "UNREADABLE"}[rep.exit_code]
    L.append(f"result   {verdict} (exit {rep.exit_code})")
    return "\n".join(L)


def render_json(rep: Report) -> dict:
    d = {"tool": "quaill-records", "version": rep.tool_version, "file": rep.path, "exit_code": rep.exit_code, "grades": rep.grades(), "error": rep.error}
    if rep.error or rep.log is None:
        return d
    log = rep.log
    d.update(
        {
            "sha256": log.sha256,
            "size": log.size,
            "kind": log.kind,
            "files": [{"path": f, "sha256": s, "size": n} for f, s, n in log.files],
            "recorder": log.library,
            "witness": rep.witness_path,
            "pubkey": rep.pubkey_path,
            "profile": {"name": rep.profile["name"], "version": rep.profile.get("version")} if rep.profile else None,
            "start": fmt_abs(log.start),
            "end": fmt_abs(log.end),
            "start_ns": log.start,
            "end_ns": log.end,
            "channels": dict(sorted(log.topic_counts.items())),
            "message_count": len(log.messages),
            "control": {
                "present": bool(rep.control and rep.control.present),
                "segments": [s.to_dict() for s in rep.control.segments] if rep.control else [],
                "handovers": rep.control.handovers if rep.control else [],
            },
            "sessions": rep.completeness.sessions if rep.completeness else [],
            "gaps": [x.to_dict() for x in rep.completeness.gaps] if rep.completeness else [],
            "ending": rep.completeness.ending if rep.completeness else None,
            "chain": {
                "present": bool(rep.chain and rep.chain.present),
                "links": len(rep.chain.links) if rep.chain else 0,
                "last_seq": rep.chain.last_seq if rep.chain else None,
                "last_link": rep.chain.last_link if rep.chain else None,
                "witness_present": bool(rep.chain and rep.chain.witness_present),
                "witnessed_through_seq": rep.chain.witnessed_through_seq if rep.chain else None,
                "truncated": bool(rep.chain and rep.chain.truncated),
            },
            "profile_items": rep.profile_result.items if rep.profile_result else [],
            "findings": [f.to_dict() for f in rep.findings],
        }
    )
    return d


def render_who(rep: Report, at: str) -> str:
    if rep.error or rep.log is None:
        return f"UNREADABLE: {rep.error}"
    log = rep.log
    t = parse_time(at, log.start)
    ct = rep.control
    rel = fmt_rel(t, log.start)
    if not ct or not ct.present:
        return f"{rel}: no control reports in this log; who was in control cannot be determined"
    if t < log.start or t > log.end:
        return f"{rel} is outside the log ({fmt_rel(log.start, log.start)} - {fmt_rel(log.end, log.start)})"
    s = ct.who_at(t)
    if s is None:
        return f"{rel}: no control report covers this time"
    lines = []
    if s.mode is None:
        last_known = next((x for x in reversed(ct.segments) if x.t_end <= s.t_start and x.mode is not None), None)
        lines.append(f"{rel}: UNKNOWN. Control reports stopped at {fmt_rel(s.t_start, log.start)} while the robot kept logging.")
        if last_known:
            lines.append(f"  Last known: {last_known.mode_name}" + (f", operator {last_known.operator_ref}" if last_known.operator_ref else "") + f", reported {fmt_rel(last_known.t_start, log.start)} - {fmt_rel(last_known.t_end, log.start)}.")
    else:
        who = {"human": "a HUMAN", "autonomous": "the AUTONOMOUS system", "nobody": "NOBODY (" + s.mode_name + ")"}[s.who]
        lines.append(f"{rel}: {who} was in control" + (f" (operator {s.operator_ref})" if s.operator_ref else "") + f", mode {s.mode_name}, from {fmt_rel(s.t_start, log.start)} to {fmt_rel(s.t_end, log.start)}.")
        before = [h for h in ct.handovers if h["t"] <= t]
        after = [h for h in ct.handovers if h["t"] > t]
        if before:
            h = before[-1]
            lines.append(f"  Previous handover: {fmt_rel(h['t'], log.start)} {h['from']} -> {h['to']}" + (f" ({h['reason']})" if h.get("reason") else ""))
        if after:
            h = after[0]
            lines.append(f"  Next handover:     {fmt_rel(h['t'], log.start)} {h['from']} -> {h['to']}" + (f" ({h['reason']})" if h.get("reason") else ""))
    c = rep.chain
    if c and c.present:
        if any(f.severity == "fail" for f in c.findings):
            lines.append("  Integrity: the chain or witness check FAILED for this log; see the full report before relying on this answer.")
        elif c.witness_present and c.witnessed_through_time is not None and t <= c.witnessed_through_time:
            lines.append("  Integrity: chain intact and witnessed through this time.")
        elif c.witness_present:
            lines.append("  Integrity: chain intact, but no outside witness has seen this part of the log yet.")
        else:
            lines.append("  Integrity: chain intact; no outside witness supplied.")
    else:
        lines.append("  Integrity: no chain in this log; edits cannot be ruled out.")
    return "\n".join(lines)
