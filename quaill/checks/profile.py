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
    validate_profile(d, str(p))
    d.setdefault("name", p.stem)
    return d


def validate_profile(d, source: str) -> None:
    """Shape check with a plain message. A malformed profile is a usage error (exit 2), never a traceback."""

    def bad(msg: str):
        raise ValueError(f"profile {source}: {msg}")

    def strings(v) -> bool:
        return isinstance(v, list) and all(isinstance(x, str) for x in v)

    if not isinstance(d, dict):
        bad("must be a JSON object")
    items = d.get("items", [])
    if not isinstance(items, list):
        bad("'items' must be a list")
    for n, item in enumerate(items, 1):
        if not isinstance(item, dict):
            bad(f"item {n} must be an object with a 'topic'")
        label = item.get("id") or f"#{n}"
        if not isinstance(item.get("topic"), str) or not item["topic"]:
            bad(f"item {label} needs a 'topic' string")
        if not strings(item.get("fields", [])):
            bad(f"item {label}: 'fields' must be a list of field names")
        when = item.get("when")
        if when is not None and (not isinstance(when, dict) or not isinstance(when.get("field"), str)):
            bad(f"item {label}: 'when' must be an object with a 'field' name")
    ev = d.get("events")
    if ev is not None:
        if not isinstance(ev, dict):
            bad("'events' must be an object")
        if not isinstance(ev.get("topic"), str) or not ev["topic"]:
            bad("'events' needs a 'topic' string")
        if "field" in ev and not isinstance(ev["field"], str):
            bad("'events.field' must be a field name")
        pairs = ev.get("pairs", [])
        if not isinstance(pairs, list) or not all(isinstance(pr, list) and len(pr) == 2 for pr in pairs):
            bad("'events.pairs' must be a list of [open, close] pairs")
        for key in ("values", "window_values", "window_topics"):
            if not strings(ev.get(key, [])):
                bad(f"'events.{key}' must be a list of strings")
        w = ev.get("window_s")
        if w is not None and (isinstance(w, bool) or not isinstance(w, (int, float)) or w < 0):
            bad("'events.window_s' must be a number of seconds")
    ops = d.get("operator_command_topics")
    if ops is not None and not strings(ops):
        bad("'operator_command_topics' must be a list of topic patterns")


def apply_mapping(profile: dict, mapping: dict) -> dict:
    """Point a profile's items and events at a fleet's own topics and field names (see profiles/MAPPING.md).
    Returns a new profile dict; the shipped file is not touched."""
    if not isinstance(mapping, dict):
        raise ValueError("mapping file must contain a JSON object")
    want = mapping.get("profile")
    if want and want != profile.get("name"):
        raise ValueError(f"mapping is for profile {want!r}, but the profile being checked is {profile.get('name')!r}")
    out = json.loads(json.dumps(profile))  # deep copy
    items_map = mapping.get("items", {})
    if not isinstance(items_map, dict):
        raise ValueError("mapping 'items' must be an object keyed by item id")
    by_id = {str(i.get("id")): i for i in out.get("items", [])}
    for iid, m in items_map.items():
        item = by_id.get(str(iid))
        if item is None:
            raise ValueError(f"mapping names item {iid!r}, which profile {out.get('name')!r} does not have")
        if not isinstance(m, dict):
            raise ValueError(f"mapping for item {iid!r} must be an object")
        if "topic" in m:
            item["topic"] = str(m["topic"])
        if "required" in m:
            item["required"] = bool(m["required"])
        renames = m.get("fields", {})
        if renames:
            if not isinstance(renames, dict):
                raise ValueError(f"mapping for item {iid!r}: 'fields' must be an object {{profile_field: your_field}}")
            known = set(item.get("fields", [])) | ({item["when"]["field"]} if item.get("when") else set())
            unknown = [f for f in renames if f not in known]
            if unknown:
                raise ValueError(f"mapping for item {iid!r} renames field(s) {', '.join(unknown)}, which the item does not have (it has: {', '.join(sorted(known)) or 'none'})")
            item["fields"] = [str(renames.get(f, f)) for f in item.get("fields", [])]
            if item.get("when") and item["when"].get("field") in renames:
                item["when"] = dict(item["when"], field=str(renames[item["when"]["field"]]))
        item["mapped"] = True
    ev_map = mapping.get("events")
    if ev_map:
        ev = out.get("events")
        if not ev:
            raise ValueError(f"mapping has 'events' but profile {out.get('name')!r} defines no event list")
        if "topic" in ev_map:
            ev["topic"] = str(ev_map["topic"])
        if "field" in ev_map:
            ev["field"] = str(ev_map["field"])
        if "window_topics" in ev_map:
            ev["window_topics"] = [str(t) for t in ev_map["window_topics"]]
        values = ev_map.get("values", {})
        if values:
            if not isinstance(values, dict):
                raise ValueError("mapping 'events.values' must be an object {profile_name: your_name}")
            ren = lambda v: str(values.get(v, v))
            ev["values"] = [ren(v) for v in ev.get("values", [])]
            ev["pairs"] = [[ren(a), ren(b)] for a, b in ev.get("pairs", [])]
            ev["window_values"] = [ren(v) for v in ev.get("window_values", [])]
    out["mapping_applied"] = True
    validate_profile(out, f"{out.get('name')!r} with mapping applied")
    return out


def load_mapping(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"mapping file not found: {path}")
    return json.loads(p.read_text(encoding="utf-8"))


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
