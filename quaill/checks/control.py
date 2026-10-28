"""L2 attribution: who was in control, and exactly when it changed.

Reads /quaill/control_mode reports. Each report says what the control mode was from its
timestamp until the next report. If the robot kept logging but the control reports stopped,
the control state is UNKNOWN for that stretch, and the checker says so.
"""
from __future__ import annotations

import bisect
import fnmatch
import statistics
from dataclasses import asdict, dataclass, field

from ..findings import NS, Finding, fmt_rel
from ..mcapio import CONTROL_TOPIC, HUMAN_MODES, MODE_NAMES, QUAILL_TOPICS, LogFile

# Topics that carry a human's commands. A profile can override; these are the usual ROS names.
DEFAULT_OPERATOR_PATTERNS = ["*teleop*", "*joy*", "*remote*", "*manual*", "*operator*"]
MIN_DISTINCT_OPERATOR_MSGS = 5  # a parked joystick repeats one message; a human produces many different ones


@dataclass
class Segment:
    t_start: int
    t_end: int
    mode: int | None  # None = unknown
    mode_name: str
    operator_ref: str | None
    reason: str | None

    @property
    def who(self) -> str:
        if self.mode is None:
            return "unknown"
        if self.mode in HUMAN_MODES:
            return "human"
        if self.mode in (1, 2, 3):
            return "autonomous"
        return "nobody"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["who"] = self.who
        return d


@dataclass
class ControlResult:
    present: bool = False
    heartbeat_ns: int | None = None
    segments: list[Segment] = field(default_factory=list)
    handovers: list[dict] = field(default_factory=list)
    operator_topics: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def who_at(self, t: int) -> Segment | None:
        for s in self.segments:
            if s.t_start <= t < s.t_end or (s is self.segments[-1] and t == s.t_end):
                return s
        return None


def check_control(log: LogFile, operator_patterns: list[str] | None = None, signed_time: dict[int, int] | None = None) -> ControlResult:
    """signed_time: id(message) -> the time the chain's signed recv_time gives it (chain.py). A message in it is
    placed by that time, not by the bag's log_time, so moving messages in bag time changes nothing here."""
    r = ControlResult()
    F = r.findings
    start, end = log.start, log.end
    st = signed_time or {}
    T = lambda m: st.get(id(m), m.log_time)
    pats = [p.lower() for p in (operator_patterns or DEFAULT_OPERATOR_PATTERNS)]
    r.operator_topics = sorted(t for t in log.topic_counts if t not in QUAILL_TOPICS and any(fnmatch.fnmatch(t.lower(), p) for p in pats))
    reports = []
    malformed = 0
    for m in log.by_topic(CONTROL_TOPIC):
        d = m.body()
        if not isinstance(d, dict) or not isinstance(d.get("mode"), int):
            malformed += 1
            continue
        # CDR has no null: an empty string means "no operator" / "no reason"
        reports.append((T(m), d["mode"], d.get("operator_ref") or None, d.get("reason") or None))
    if malformed:
        F.append(Finding("CONTROL_MALFORMED", "L2", "warn", f"{malformed} control report(s) could not be parsed"))
    if not reports:
        F.append(Finding("CONTROL_ABSENT", "L2", "info", f"no {CONTROL_TOPIC} channel: who was in control cannot be determined from this log"))
        return r
    r.present = True
    reports.sort(key=lambda x: x[0])

    # What counts as "the robot was still running"? Any non-Quaill message.
    activity = sorted(T(m) for m in log.messages if m.topic not in QUAILL_TOPICS)

    # Heartbeat: how often does this recorder repeat the control state?
    if len(reports) >= 3:
        gaps = [b[0] - a[0] for a, b in zip(reports, reports[1:]) if b[0] > a[0]]
        r.heartbeat_ns = int(statistics.median(gaps)) if gaps else None
    threshold = max(3 * r.heartbeat_ns, 5 * NS) if r.heartbeat_ns else None

    def active_between(a: int, b: int) -> tuple[int, int] | None:
        """First and last activity timestamps inside (a, b), or None."""
        import bisect

        i = bisect.bisect_right(activity, a)
        j = bisect.bisect_left(activity, b)
        if i < j:
            return activity[i], activity[j - 1]
        return None

    # Operator must be named (pseudonymously) whenever a human is in control.
    for t, mode, op, _ in reports:
        if mode in HUMAN_MODES and not op:
            F.append(Finding("OPERATOR_MISSING", "L2", "fail", f"control was MANUAL at {fmt_rel(t, start)} but no operator reference was recorded", t, t))
            break  # one finding per log is enough; the timeline shows the rest

    # Build the timeline.
    segs: list[Segment] = []
    if activity and threshold and activity[0] < reports[0][0] - threshold:
        segs.append(Segment(activity[0], reports[0][0], None, "UNKNOWN", None, "robot was logging before the first control report"))
        F.append(Finding("CONTROL_UNKNOWN", "L2", "fail", f"robot was logging from {fmt_rel(activity[0], start)} but the first control report is at {fmt_rel(reports[0][0], start)}", activity[0], reports[0][0]))
    for i, (t, mode, op, reason) in enumerate(reports):
        t_next = reports[i + 1][0] if i + 1 < len(reports) else max(end, t)
        seg_end = t_next
        unknown = None
        if threshold and t_next - t > threshold:
            act = active_between(t + threshold, t_next)
            if act:
                seg_end = t + threshold
                unknown = Segment(seg_end, t_next, None, "UNKNOWN", None, "control reports stopped while the robot kept logging")
        if segs and segs[-1].mode == mode and segs[-1].operator_ref == op and segs[-1].t_end == t:
            segs[-1].t_end = seg_end
        else:
            segs.append(Segment(t, seg_end, mode, MODE_NAMES.get(mode, f"MODE_{mode}"), op, reason))
        if unknown:
            segs.append(unknown)
            F.append(
                Finding(
                    "CONTROL_UNKNOWN",
                    "L2",
                    "fail",
                    f"control reports stopped after {fmt_rel(t, start)} ({MODE_NAMES.get(mode, mode)}"
                    + (f", operator {op}" if op else "")
                    + f") while the robot kept logging until {fmt_rel(t_next, start)}: who was in control is unknown for that stretch",
                    seg_end,
                    t_next,
                )
            )
    r.segments = segs

    # The recorder can lie by omission: a human drives through a channel the mode flag does not watch.
    # Human command traffic during a stretch reported as not-human is the visible trace of that.
    if r.operator_topics:
        op = sorted((T(m), m.hash) for m in log.messages if m.topic in r.operator_topics)
        op_times = [t for t, _ in op]
        for s in segs:
            if s.who in ("human", "unknown"):
                continue
            i, j = bisect.bisect_left(op_times, s.t_start), bisect.bisect_left(op_times, s.t_end)
            if j - i == 0:
                continue
            distinct = len({h for _, h in op[i:j]})
            if distinct >= MIN_DISTINCT_OPERATOR_MSGS:
                F.append(
                    Finding(
                        "CONTROL_INCONSISTENT",
                        "L2",
                        "fail",
                        f"{j - i} operator command message(s) ({distinct} distinct) on {', '.join(r.operator_topics)} between {fmt_rel(op_times[i], start)} and {fmt_rel(op_times[j - 1], start)} "
                        f"while control was reported {s.mode_name}: the control report does not match the robot's own command traffic",
                        op_times[i],
                        op_times[j - 1],
                    )
                )

    # Handovers: every change of who (human / autonomous / nobody / unknown).
    for a, b in zip(segs, segs[1:]):
        if a.who != b.who or a.operator_ref != b.operator_ref:
            r.handovers.append(
                {
                    "t": b.t_start,
                    "from": a.mode_name + (f" ({a.operator_ref})" if a.operator_ref else ""),
                    "to": b.mode_name + (f" ({b.operator_ref})" if b.operator_ref else ""),
                    "reason": b.reason,
                }
            )
    return r
