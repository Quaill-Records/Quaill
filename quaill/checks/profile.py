"""Profile checks: does the log carry the fields a given rule set asks for?

A profile is a JSON file. It lists items (topic + fields), events (with pairing and a
before/after window), and which built-in checks to run. Profiles ship for our own layout
and for field lists regulators already wrote. The checker is the test suite; the profile
is the rule set. Whichever rule set wins, it loads here.
"""
from __future__ import annotations

import bisect
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..findings import NS, Finding, fmt_rel
from ..mcapio import LogFile

PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


def list_profiles() -> list[dict]:
    out = []
    for p in sorted(PROFILE_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({"name": d.get("name", p.stem), "title": d.get("title", ""), "status": d.get("status", ""), "path": str(p)})
        except Exception as e:
            out.append({"name": p.stem, "title": f"(unreadable: {e})", "status": "", "path": str(p)})
    return out


def load_profile(name_or_path: str) -> dict:
    p = Path(name_or_path)
    if not p.is_file():
        p = PROFILE_DIR / f"{name_or_path}.json"
    if not p.is_file():
        raise FileNotFoundError(f"profile not found: {name_or_path} (have: {', '.join(x['name'] for x in list_profiles())})")
    d = json.loads(p.read_text(encoding="utf-8"))
    d.setdefault("name", p.stem)
    return d


def _get(d, path: str):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _present(v) -> bool:
    """A field counts as present when it is not null and not an empty string (CDR has no null)."""
    return v is not None and v != ""


@dataclass
class ProfileResult:
    name: str = ""
    items: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def check_profile(log: LogFile, profile: dict, sample: int = 500) -> ProfileResult:
    r = ProfileResult(name=profile.get("name", "?"))
    F = r.findings
    start = log.start
    parsed_cache: dict[str, list] = {}

    def parsed(topic: str) -> list:
        if topic not in parsed_cache:
            out = []
            for m in log.by_topic(topic)[:sample]:
                d = m.body()
                if isinstance(d, dict):
                    out.append((m.log_time, d))
            parsed_cache[topic] = out
        return parsed_cache[topic]

    for item in profile.get("items", []):
        topic = item["topic"]
        required = item.get("required", True)
        label = f"{item.get('id', '')} {item.get('name', '')}".strip()
        n = log.topic_counts.get(topic, 0)
        row = {"id": item.get("id"), "name": item.get("name"), "topic": topic, "present": n > 0, "messages": n, "missing_fields": []}
        if n == 0:
            F.append(Finding("PROFILE_TOPIC_MISSING", "P", "fail" if required else "info", f"{label}: no messages on {topic}" + ("" if required else " (optional)")))
            r.items.append(row)
            continue
        rows = parsed(topic)
        if not rows:
            row["undecodable"] = True
            F.append(Finding("PROFILE_UNDECODABLE", "P", "warn", f"{label}: {n} message(s) on {topic} but none could be decoded (no schema text in this bag format, or unknown encoding); fields not checked"))
            r.items.append(row)
            continue
        when = item.get("when")  # e.g. {"field": "mode", "equals": 4}: only messages matching are checked
        if when:
            rows = [(t, d) for t, d in rows if _get(d, when["field"]) == when.get("equals")]
            row["applies_to"] = len(rows)
            if not rows:
                row["not_applicable"] = True
                r.items.append(row)
                continue
        for fld in item.get("fields", []):
            if not any(_present(_get(d, fld)) for _, d in rows):
                row["missing_fields"].append(fld)
        if row["missing_fields"]:
            F.append(Finding("PROFILE_FIELD_MISSING", "P", "fail", f"{label}: field(s) {', '.join(row['missing_fields'])} never present on {topic}"))
        r.items.append(row)

    ev = profile.get("events")
    if ev:
        topic, fld = ev["topic"], ev.get("field", "event")
        rows = parsed(topic)
        if not rows:
            F.append(Finding("PROFILE_EVENTS_MISSING", "P", "fail" if ev.get("required", True) else "info", f"event list: no messages on {topic}"))
        else:
            seen = [(t, _get(d, fld)) for t, d in rows]
            for a, b in ev.get("pairs", []):
                open_t = None
                for t, v in seen:
                    if v == a:
                        if open_t is not None:
                            F.append(Finding("PROFILE_EVENT_UNPAIRED", "P", "fail", f"{a} at {fmt_rel(open_t, start)} was not closed by {b} before the next {a} at {fmt_rel(t, start)}", open_t, t))
                        open_t = t
                    elif v == b:
                        if open_t is None:
                            F.append(Finding("PROFILE_EVENT_UNPAIRED", "P", "fail", f"{b} at {fmt_rel(t, start)} without a preceding {a}", t, t))
                        open_t = None
                if open_t is not None:
                    F.append(Finding("PROFILE_EVENT_UNPAIRED", "P", "fail", f"{a} at {fmt_rel(open_t, start)} has no matching {b} before the log ends", open_t, log.end))
            w = ev.get("window_s")
            if w:
                wns = int(w * NS)
                wvals = set(ev.get("window_values", []))
                wtopics = ev.get("window_topics", [])
                times = {wt: sorted(m.log_time for m in log.by_topic(wt)) for wt in wtopics}
                for t, v in seen:
                    if v not in wvals:
                        continue
                    for wt in wtopics:
                        ts = times[wt]
                        before = bisect.bisect_left(ts, t) - bisect.bisect_left(ts, t - wns)
                        after = bisect.bisect_right(ts, t + wns) - bisect.bisect_right(ts, t)
                        if before == 0 or after == 0:
                            side = "before" if before == 0 else "after"
                            if before == 0 and after == 0:
                                side = "before or after"
                            F.append(Finding("PROFILE_WINDOW_INCOMPLETE", "P", "fail", f"{v} at {fmt_rel(t, start)}: no {wt} messages in the {w} s {side} the event", t - wns, t + wns))
    return r
