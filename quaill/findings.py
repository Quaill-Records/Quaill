"""Finding records and time formatting shared by every check."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

NS = 1_000_000_000


@dataclass
class Finding:
    code: str
    level: str  # "L0" format, "L1" integrity, "L2" control/completeness, "P" profile
    severity: str  # "fail" | "warn" | "info"
    message: str
    t_start: int | None = None  # absolute log time, ns
    t_end: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def fmt_rel(t_ns: int | None, start_ns: int) -> str:
    """mm:ss (or h:mm:ss) relative to the start of the log."""
    if t_ns is None:
        return "-"
    s = (t_ns - start_ns) / NS
    sign = "-" if s < 0 else ""
    s = abs(s)
    h, rem = divmod(int(s), 3600)
    m, sec = divmod(rem, 60)
    frac = s - int(s)
    secs = f"{sec:02d}" if frac < 0.05 else f"{sec + frac:05.2f}"
    return f"{sign}{h}:{m:02d}:{secs}" if h else f"{sign}{m:02d}:{secs}"


def fmt_abs(t_ns: int | None) -> str:
    if t_ns is None:
        return "-"
    dt = datetime.fromtimestamp(t_ns / NS, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{(t_ns % NS) // 1_000_000:03d}Z"


def fmt_dur(ns: int) -> str:
    s = ns / NS
    if s < 60:
        return f"{s:.1f} s"
    m, sec = divmod(int(round(s)), 60)
    return f"{m} min {sec:02d} s"
