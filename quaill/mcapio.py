"""The Quaill MCAP layout (spec v0.0.2) and a tolerant MCAP reader that decodes JSON and ROS 2 CDR.

Layout: three channels added next to whatever the robot already records.
  /quaill/control_mode  who is in control right now (Autoware ControlModeReport numbering + operator_ref)
  /quaill/session       START / CLEAN_SHUTDOWN / CRASH_NOTE / POWER_LOST markers, with software version
  /quaill/chain         one hash-chain link per message on every other channel, paired by content hash

Message definitions live in ../quaill_msgs/msg/*.msg; the same text is embedded here (without comments)
so the generator can write real ros2msg schemas and the checker can decode them without ROS installed.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

CONTROL_TOPIC = "/quaill/control_mode"
SESSION_TOPIC = "/quaill/session"
CHAIN_TOPIC = "/quaill/chain"
QUAILL_TOPICS = (CONTROL_TOPIC, SESSION_TOPIC, CHAIN_TOPIC)

# Mirrors autoware_vehicle_msgs/ControlModeReport constants. We add nothing to the numbering.
MODE_NO_COMMAND = 0
MODE_AUTONOMOUS = 1
MODE_AUTONOMOUS_STEER_ONLY = 2
MODE_AUTONOMOUS_VELOCITY_ONLY = 3
MODE_MANUAL = 4
MODE_DISENGAGED = 5
MODE_NOT_READY = 6
MODE_NAMES = {
    0: "NO_COMMAND",
    1: "AUTONOMOUS",
    2: "AUTONOMOUS_STEER_ONLY",
    3: "AUTONOMOUS_VELOCITY_ONLY",
    4: "MANUAL",
    5: "DISENGAGED",
    6: "NOT_READY",
}
HUMAN_MODES = {MODE_MANUAL}
AUTONOMOUS_MODES = {MODE_AUTONOMOUS, MODE_AUTONOMOUS_STEER_ONLY, MODE_AUTONOMOUS_VELOCITY_ONLY}

SESSION_EVENTS = ("START", "CLEAN_SHUTDOWN", "CRASH_NOTE", "POWER_LOST")
END_MARKERS = ("CLEAN_SHUTDOWN", "POWER_LOST")

GENESIS = "0" * 64
MAGIC = b"\x89MCAP0\r\n"

# ---- ROS 2 message definitions (ros2msg schema text, concatenated format rosbag2 uses) ----
TIME_DEF = "================================================================================\nMSG: builtin_interfaces/Time\nint32 sec\nuint32 nanosec\n"
MSG_DEFS: dict[str, tuple[str, str]] = {
    CONTROL_TOPIC: (
        "quaill_msgs/msg/ControlModeReport",
        "builtin_interfaces/Time stamp\nuint8 mode\nstring mode_name\nstring operator_ref\nstring reason\n" + TIME_DEF,
    ),
    SESSION_TOPIC: (
        "quaill_msgs/msg/SessionEvent",
        "builtin_interfaces/Time stamp\nstring event\nstring session_id\nstring prev_session_id\nstring software_version\nstring note\nstring device_pubkey\n" + TIME_DEF,
    ),
    CHAIN_TOPIC: (
        "quaill_msgs/msg/ChainLink",
        "string session_id\nuint64 seq\nstring topic\nstring msg_sha256\nstring prev\nstring link\nint64 recv_time\nstring key_id\nstring sig\n",
    ),
}

# ---- JSON schemas for the same three channels (used when a recorder writes JSON) ----
STAMP_SCHEMA = {"type": "object", "properties": {"sec": {"type": "integer"}, "nanosec": {"type": "integer"}}, "required": ["sec", "nanosec"]}
SCHEMAS: dict[str, tuple[str, dict]] = {
    CONTROL_TOPIC: (
        "quaill_msgs/ControlModeReport",
        {
            "type": "object",
            "properties": {
                "stamp": STAMP_SCHEMA,
                "mode": {"type": "integer"},
                "mode_name": {"type": "string"},
                "operator_ref": {"type": ["string", "null"]},
                "reason": {"type": ["string", "null"]},
            },
            "required": ["stamp", "mode"],
        },
    ),
    SESSION_TOPIC: (
        "quaill_msgs/SessionEvent",
        {
            "type": "object",
            "properties": {
                "stamp": STAMP_SCHEMA,
                "event": {"type": "string", "enum": list(SESSION_EVENTS)},
                "session_id": {"type": "string"},
                "prev_session_id": {"type": ["string", "null"]},
                "software_version": {"type": ["string", "null"]},
                "note": {"type": ["string", "null"]},
                "device_pubkey": {"type": ["string", "null"]},
            },
            "required": ["stamp", "event", "session_id"],
        },
    ),
    CHAIN_TOPIC: (
        "quaill_msgs/ChainLink",
        {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "seq": {"type": "integer"},
                "topic": {"type": "string"},
                "msg_sha256": {"type": "string"},
                "prev": {"type": "string"},
                "link": {"type": "string"},
                "recv_time": {"type": "integer"},
                "key_id": {"type": ["string", "null"]},
                "sig": {"type": ["string", "null"]},
            },
            "required": ["seq", "topic", "msg_sha256", "prev", "link", "recv_time"],
        },
    ),
}

try:  # optional: ROS 2 CDR decoding without a ROS installation
    from mcap_ros2._dynamic import generate_dynamic as _generate_dynamic, serialize_dynamic as _serialize_dynamic

    ROS2_SUPPORT = True
except Exception:  # pragma: no cover
    ROS2_SUPPORT = False
    _generate_dynamic = _serialize_dynamic = None


def enc(obj) -> bytes:
    """Canonical JSON bytes (sorted keys, no spaces)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def message_hash(topic: str, data: bytes) -> str:
    """Content hash of one recorded message: topic and exact serialized bytes. No timestamps."""
    h = hashlib.sha256()
    h.update(topic.encode())
    h.update(b"\0")
    h.update(data)
    return h.hexdigest()


def link_hash(prev: str, msg_hash: str, seq: int, recv_time: int, topic: str) -> str:
    h = hashlib.sha256()
    h.update(bytes.fromhex(prev))
    h.update(bytes.fromhex(msg_hash))
    h.update(int(seq).to_bytes(8, "big"))
    h.update(int(recv_time).to_bytes(8, "big", signed=True))
    h.update(topic.encode())
    return h.hexdigest()


_DECODERS: dict[tuple[str, bytes], object] = {}
_ENCODERS: dict[tuple[str, str], object] = {}


def cdr_decoder(schema_name: str, schema_data: bytes):
    if not ROS2_SUPPORT:
        raise RuntimeError("mcap-ros2-support is not installed; cannot decode CDR messages")
    key = (schema_name, schema_data)
    d = _DECODERS.get(key)
    if d is None:
        d = _generate_dynamic(schema_name, schema_data.decode())[schema_name]
        _DECODERS[key] = d
    return d


def cdr_encoder(schema_name: str, schema_text: str):
    if not ROS2_SUPPORT:
        raise RuntimeError("mcap-ros2-support is not installed; cannot encode CDR messages")
    key = (schema_name, schema_text)
    e = _ENCODERS.get(key)
    if e is None:
        e = _serialize_dynamic(schema_name, schema_text)[schema_name]
        _ENCODERS[key] = e
    return e


def to_plain(obj):
    """Decoded ROS message object (slots) -> plain dicts/lists, so every check can use one shape."""
    if isinstance(obj, (str, bytes, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (list, tuple)):
        return [to_plain(x) for x in obj]
    slots = getattr(type(obj), "__slots__", None)
    if slots:
        return {name: to_plain(getattr(obj, name, None)) for name in slots}
    if hasattr(obj, "__dict__"):
        return {k: to_plain(v) for k, v in vars(obj).items()}
    return obj


@dataclass(slots=True)
class Msg:
    topic: str
    log_time: int
    publish_time: int
    sequence: int
    hash: str  # sha256(topic || 0 || bytes), computed while reading
    data: bytes | None  # kept only for Quaill channels and topics a profile looks into
    encoding: str
    schema_name: str | None
    schema_encoding: str | None = None
    schema_data: bytes | None = None
    _body: object = field(default=None, repr=False)
    _body_tried: bool = field(default=False, repr=False)

    def body(self):
        """Message content as plain Python (dict), or None if it cannot be decoded (or bytes were not kept)."""
        if not self._body_tried:
            self._body_tried = True
            try:
                if self.data is None:
                    self._body = None
                elif self.encoding == "json":
                    self._body = json.loads(self.data)
                elif self.encoding == "cdr" and self.schema_encoding == "ros2msg" and self.schema_data is not None and self.schema_name:
                    self._body = to_plain(cdr_decoder(self.schema_name, self.schema_data)(self.data))
                else:
                    self._body = None
            except Exception:
                self._body = None
        return self._body

    json = body  # older name

    @property
    def content_hash(self) -> str:
        return self.hash


@dataclass
class LogFile:
    path: str
    size: int
    sha256: str
    magic_ok: bool
    finalized: bool
    has_summary: bool
    library: str
    profile: str
    messages: list[Msg]
    topic_counts: Counter
    read_error: str | None = None
    kind: str = "mcap file"
    files: list[tuple[str, str, int]] = field(default_factory=list)  # (path, sha256, size)

    @property
    def start(self) -> int:
        return self.messages[0].log_time if self.messages else 0

    @property
    def end(self) -> int:
        return self.messages[-1].log_time if self.messages else 0

    def by_topic(self, topic: str) -> list[Msg]:
        return [m for m in self.messages if m.topic == topic]

    def payload(self) -> list[Msg]:
        """Everything except the chain itself."""
        return [m for m in self.messages if m.topic != CHAIN_TOPIC]


class UnreadableLog(Exception):
    pass


def read_log(path: str, keep_data_topics=None) -> LogFile:
    """Open any supported input (MCAP, rosbag2 directory, .db3, ROS 1 .bag). See inputs.py."""
    from .inputs import open_log

    return open_log(path, keep_data_topics)
