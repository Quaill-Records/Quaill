"""L2 completeness: is anything missing? Gaps, crashes, cut-off endings, each explained or flagged.

A recording gap is a stretch with no messages at all. The chain cannot see it (nothing was
written), so this check looks for the markers an honest recorder leaves:
  CLEAN_SHUTDOWN or POWER_LOST right before the gap, or CRASH_NOTE right after it.
Neither marker -> unexplained gap. The checker states the gap; it does not guess why.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..chain import ChainResult
from ..findings import NS, Finding, fmt_dur, fmt_rel
from ..mcapio import CHAIN_TOPIC, END_MARKERS, SESSION_TOPIC, LogFile

MARKER_TOLERANCE = 1 * NS


@dataclass
class Gap:
    t_start: int
    t_end: int
    explanation: str | None

    @property
    def explained(self) -> bool:
        return self.explanation is not None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["explained"] = self.explained
        return d


@dataclass
class CompletenessResult:
    gaps: list[Gap] = field(default_factory=list)
    sessions: list[dict] = field(default_factory=list)
    ending: str = "unknown"
    findings: list[Finding] = field(default_factory=list)


def check_completeness(log: LogFile, chain: ChainResult, gap_threshold_ns: int = 2 * NS) -> CompletenessResult:
    r = CompletenessResult()
    F = r.findings
    msgs = log.payload()
    if not msgs:
        return r
    start, end = log.start, log.end
    st = chain.signed_time  # messages the chain places by their signed recv_time (chain.py); the rest keep the bag's log_time
    T = lambda m: st.get(id(m), m.log_time)

    events = []
    malformed = 0
    for m in log.by_topic(SESSION_TOPIC):
        d = m.body()
        if not isinstance(d, dict) or not d.get("event"):
            malformed += 1
            continue
        ev = {"t": T(m), "event": d["event"], "session_id": d.get("session_id") or None, "prev_session_id": d.get("prev_session_id") or None, "software_version": d.get("software_version") or None, "note": d.get("note") or None}
        events.append(ev)
        r.sessions.append(ev)
    if malformed:
        F.append(Finding("SESSION_MALFORMED", "L2", "warn", f"{malformed} session event(s) could not be parsed"))
    markers = bool(events)
    if not markers:
        F.append(Finding("SESSION_ABSENT", "L2", "info", f"no {SESSION_TOPIC} markers: a crash, a clean stop and a cut-off end cannot be told apart in this log"))
    elif not any(e["event"] == "START" and abs(e["t"] - start) <= MARKER_TOLERANCE for e in events):
        F.append(Finding("SESSION_NO_START", "L2", "warn", "log does not begin with a START marker"))

    def marker_near(kinds, t: int) -> dict | None:
        for e in events:
            if e["event"] in kinds and abs(e["t"] - t) <= MARKER_TOLERANCE:
                return e
        return None

    times = sorted(T(m) for m in msgs)
    for a, b in zip(times, times[1:]):
        if b - a <= gap_threshold_ns:
            continue
        before = marker_near(END_MARKERS, a)
        after = marker_near(("CRASH_NOTE",), b)
        if before:
            expl = f"{before['event'].lower().replace('_', ' ')} marker at {fmt_rel(a, start)}" + (f", recording resumed at {fmt_rel(b, start)}" if marker_near(("START",), b) else "")
        elif after:
            expl = f"crash: recorder restarted at {fmt_rel(b, start)} and noted that session {after.get('prev_session_id') or '?'} ended unexpectedly"
        else:
            expl = None
        g = Gap(a, b, expl)
        r.gaps.append(g)
        if expl:
            F.append(Finding("GAP_EXPLAINED", "L2", "info", f"no messages from {fmt_rel(a, start)} to {fmt_rel(b, start)} ({fmt_dur(b - a)}); explained: {expl}", a, b))
        elif not markers:
            F.append(Finding("GAP_UNEXPLAINED", "L2", "warn", f"no messages from {fmt_rel(a, start)} to {fmt_rel(b, start)} ({fmt_dur(b - a)}); this log has no session markers that could explain it", a, b))
        else:
            F.append(Finding("GAP_UNEXPLAINED", "L2", "fail", f"no messages from {fmt_rel(a, start)} to {fmt_rel(b, start)} ({fmt_dur(b - a)}); no shutdown marker before it and no crash note after it", a, b))

    # How does the log end?
    if not markers:
        r.ending = "unknown (no session markers)"
    elif marker_near(END_MARKERS, end):
        r.ending = "marked"
    elif chain.truncated:
        r.ending = "cut"  # the chain finding already states it
    elif chain.complete_per_witness:
        r.ending = "unmarked, complete per witness"
        F.append(Finding("ENDING_UNMARKED", "L2", "warn", f"log ends at {fmt_rel(end, start)} without a shutdown marker; the outside witness confirms this is where the recording stopped (recorder died or was killed)", end, end))
    else:
        r.ending = "unexplained"
        F.append(Finding("ENDING_UNEXPLAINED", "L2", "fail", f"log ends at {fmt_rel(end, start)} without a shutdown marker or crash note; either the recorder died or the end was cut, and there is no outside witness to tell which", end, end))
    return r
