"""L0: is this a readable MCAP file at all? Facts about the container, nothing about content."""
from __future__ import annotations

from ..findings import NS, Finding
from ..mcapio import CHAIN_TOPIC, ROS2_SUPPORT, LogFile


def check_format(log: LogFile) -> list[Finding]:
    F: list[Finding] = []
    if not log.magic_ok:
        F.append(Finding("FILE_BAD_MAGIC", "L0", "fail", "file does not start with the MCAP magic bytes"))
    if not log.finalized:
        F.append(Finding("FILE_NOT_FINALIZED", "L0", "warn", "file does not end with the MCAP magic: the recorder stopped mid-write, or the file was cut"))
    if not log.has_summary and log.finalized and log.kind.startswith("mcap"):
        F.append(Finding("FILE_NO_SUMMARY", "L0", "warn", "file has no summary section (readable, but slower to index)"))
    if log.read_error:
        F.append(Finding("FILE_PARTIAL_READ", "L0", "warn", f"reader error: {log.read_error}"))
    if not log.messages:
        F.append(Finding("FILE_EMPTY", "L0", "fail", "file contains no messages"))
        return F
    odd = 0
    unparsed: dict[str, int] = {}
    for m in log.messages:
        if m.publish_time and m.publish_time > m.log_time + NS:
            odd += 1
        if m.data is not None and m.encoding in ("json", "cdr") and m.body() is None:
            unparsed[m.topic] = unparsed.get(m.topic, 0) + 1
    if odd:
        F.append(Finding("TIME_ODD", "L0", "warn", f"{odd} message(s) claim a publish time more than 1 s after they were logged"))
    for topic, n in unparsed.items():
        hint = "" if ROS2_SUPPORT else " (install mcap-ros2-support to decode CDR)"
        F.append(Finding("MESSAGE_UNPARSEABLE", "L0", "warn", f"{n} message(s) on {topic} could not be decoded{hint}"))
    return F
