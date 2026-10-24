"""Synthetic log generator: a labeled reference/example recorder that makes test logs.

Not a product and not a recommendation for how to record. It exists so the checker has logs
with known, planted defects to be tested against. Two scenarios and two encodings:
  delivery        sidewalk delivery robot, autonomous, remote operator takes over for 30 s   (json or cdr)
  remote-vehicle  remote-driven car under Germany's StVFernLV, radio link lost, in-vehicle takeover (json)
"cdr" writes real ros2msg schemas and CDR bytes, the way rosbag2 does, so the checker is tested
on the encoding a real robot produces.
"""
from __future__ import annotations

import json
import math
import random
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .chain import ChainBuilder
from .findings import NS, fmt_abs
from .keys import CRYPTO, Signer
from .mcapio import (
    CHAIN_TOPIC,
    CONTROL_TOPIC,
    MODE_AUTONOMOUS,
    MODE_DISENGAGED,
    MODE_MANUAL,
    MODE_NAMES,
    MODE_NOT_READY,
    MSG_DEFS,
    SCHEMAS,
    SESSION_TOPIC,
    TIME_DEF,
    cdr_encoder,
    enc,
)

DEFAULT_START = int(datetime(2026, 10, 23, 18, 0, 0, tzinfo=timezone.utc).timestamp()) * NS
LIBRARY = "quaill-gen 0.0.2 (synthetic reference recorder)"

# ros2msg definitions for the delivery scenario's payload topics (cdr mode)
VECTOR3_DEF = "================================================================================\nMSG: geometry_msgs/Vector3\nfloat64 x\nfloat64 y\nfloat64 z\n"
GEN_MSG_DEFS: dict[str, tuple[str, str]] = {
    "/odom": ("quaill_gen/msg/Odom", "builtin_interfaces/Time stamp\nfloat64 x\nfloat64 y\nfloat64 yaw\nfloat64 v\n" + TIME_DEF),
    "/cmd_vel": ("geometry_msgs/msg/Twist", "geometry_msgs/Vector3 linear\ngeometry_msgs/Vector3 angular\n" + VECTOR3_DEF),
    "/teleop/cmd_vel": ("geometry_msgs/msg/Twist", "geometry_msgs/Vector3 linear\ngeometry_msgs/Vector3 angular\n" + VECTOR3_DEF),
    "/events": ("quaill_gen/msg/Event", "builtin_interfaces/Time stamp\nstring type\nstring detail\n" + TIME_DEF),
}

# delivery timeline, seconds from start
T_STUCK, T_TAKE, T_RELEASE = 52.0, 60.0, 90.0
T_GAP_A, T_GAP_B = 200.0, 320.0
T_BUMP = 330.0
T_TRUNC = 300.0
T_CUTOFF = 450.0

DELIVERY_DEFECTS = {
    "edit": "control reports during the human stretch (01:00-01:30) rewritten to AUTONOMOUS; chain links left as they were",
    "delete": "all MANUAL control reports and their chain links removed",
    "delete-rechain": "same as delete, then the whole chain recomputed so it looks intact; the witness still holds the original heads",
    "truncate": "everything after 05:00 removed (including the bumper contact at 05:30) and a forged CLEAN_SHUTDOWN appended with a valid chain link; only a witness can tell",
    "gap": "recorder silent 03:20-05:20 with no markers",
    "crash": "recorder silent 03:20-05:20; on restart it writes a CRASH_NOTE",
    "clean-restart": "CLEAN_SHUTDOWN at 03:20, START at 05:20",
    "cutoff": "recorder dies at 07:30; no shutdown marker",
    "no-operator": "human takes over but no operator reference is recorded",
    "handover-back-missing": "control reports stop right after the human takes over; the robot keeps logging",
    "clock-back": "recorder clock set back 40 s at 03:00 and forward again at 04:00 (timestamps lie; chain intact)",
    "sidecar-restart": "the chain sidecar is killed at 03:20 and restarted at 03:30 while the robot keeps logging: 10 s unchained, then a second chain under a new session id",
    "hidden-teleop": "a human drives via /teleop/cmd_vel from 06:00 to 06:20 but the control reports keep saying AUTONOMOUS (the mode source lied by omission); chain intact",
    "rechain-nokey": "a thorough outsider without the device key rewrites the human stretch to AUTONOMOUS, deletes the teleop traffic, rebuilds the chain with their own key and swaps the announced key; caught only if the real device key is known (--pubkey) or a witness exists",
    "truncate-nokey": "an outsider without the device key cuts the end and appends a forged shutdown signed with their own key; caught by the signature check alone",
}
DEMO_SIGNER = Signer.from_seed(b"quaill demo device key 0001") if CRYPTO else None
ATTACKER_SIGNER = Signer.from_seed(b"someone without the device key") if CRYPTO else None
T_SIDECAR_DOWN, T_SIDECAR_UP = 200.0, 210.0
T_HIDDEN_A, T_HIDDEN_B = 360.0, 380.0
VEHICLE_DEFECTS = {
    "unpaired": "REMOTE_DRIVING_END never written after REMOTE_DRIVING_START",
    "window": "telemetry missing for the 10 s before the radio-link FAULT at 02:30",
}
SCENARIOS = {"delivery": DELIVERY_DEFECTS, "remote-vehicle": VEHICLE_DEFECTS}
ENCODINGS = ("json", "cdr")
CONTAINERS = {
    "mcap": "single .mcap file (rosbag2 Iron+, Foxglove, mcap CLI)",
    "rosbag2-mcap": "rosbag2 directory with metadata.yaml, mcap storage, one file",
    "rosbag2-mcap-split": "rosbag2 directory, mcap storage, split into two files (the chain spans both)",
    "rosbag2-mcap-filezstd": "rosbag2 directory, mcap storage, file-level zstd compression (*.mcap.zstd)",
    "rosbag2-sqlite": "rosbag2 directory, sqlite3 storage (Foxy/Galactic/Humble default)",
    "rosbag2-sqlite-zstd": "rosbag2 directory, sqlite3 storage, per-message zstd compression",
}


@dataclass
class Rec:
    t: int
    order: int
    topic: str
    payload: dict


@dataclass
class Entry:
    t: int  # the bag's log_time (and the recorder's recv_time unless a clock defect says otherwise)
    order: int
    topic: str
    payload: dict
    data: bytes
    link: dict | None  # None: recorded while no chain sidecar was running


def stamp(t_ns: int) -> dict:
    return {"sec": t_ns // NS, "nanosec": t_ns % NS}


def _session(event: str, sid: str, sw: str, **extra) -> dict:
    d = {"event": event, "session_id": sid, "prev_session_id": None, "software_version": sw, "note": None, "device_pubkey": None}
    d.update(extra)
    return d


def _control(mode: int, op: str | None, reason: str | None) -> dict:
    return {"mode": mode, "mode_name": MODE_NAMES[mode], "operator_ref": op, "reason": reason}


def delivery_records(defect: str | None, duration: float, seed: int, start: int, pubkey_hex: str | None = None) -> list[Rec]:
    rng = random.Random(seed)
    S = lambda s: start + int(round(s * NS))
    R: list[Rec] = []

    def add(t: float, topic: str, payload: dict, order: int = 2):
        R.append(Rec(S(t), order, topic, payload))

    end = float(duration)
    windows = [(0.0, end)]
    if defect in ("gap", "crash", "clean-restart"):
        windows = [(0.0, T_GAP_A), (T_GAP_B, end)]
    elif defect == "cutoff":
        windows = [(0.0, T_CUTOFF)]

    def rec(t: float) -> bool:
        return any(a - 1e-9 <= t <= b + 1e-9 for a, b in windows)

    sw = "1.4.2"
    sid = "s-001"
    add(0, SESSION_TOPIC, _session("START", sid, sw, note=LIBRARY, device_pubkey=pubkey_hex), 0)
    if defect == "clean-restart":
        add(T_GAP_A, SESSION_TOPIC, _session("CLEAN_SHUTDOWN", sid, sw), 0)
        sid = "s-002"
        add(T_GAP_B, SESSION_TOPIC, _session("START", sid, sw, device_pubkey=pubkey_hex), 0)
    if defect == "crash":
        add(T_GAP_B, SESSION_TOPIC, _session("CRASH_NOTE", "s-002", sw, prev_session_id=sid, note="previous session s-001 ended unexpectedly (no shutdown marker found on restart)"), 0)
        sid = "s-002"
        add(T_GAP_B, SESSION_TOPIC, _session("START", sid, sw, device_pubkey=pubkey_hex), 1)
    if defect == "sidecar-restart":  # the restarted sidecar announces what happened to it
        add(T_SIDECAR_UP, SESSION_TOPIC, _session("CRASH_NOTE", "rec-0002", sw, prev_session_id="rec-0001", note="previous session rec-0001 ended unexpectedly; last chain seq unknown"), 0)
        add(T_SIDECAR_UP, SESSION_TOPIC, _session("START", "rec-0002", sw, note="quaill_recorder restarted", device_pubkey=pubkey_hex), 1)
    if defect != "cutoff":
        add(end, SESSION_TOPIC, _session("CLEAN_SHUTDOWN", sid, sw), 0)

    op = None if defect == "no-operator" else "op-7f3a"
    for k in range(0, int(end) + 1):
        t = float(k)
        if not rec(t):
            continue
        if defect == "handover-back-missing" and t > T_TAKE:
            continue
        manual = T_TAKE <= t < T_RELEASE
        reason = None
        if t == T_TAKE:
            reason = "no progress for 8 s; remote operator took control"
        elif t == T_RELEASE:
            reason = "operator released control"
        add(t, CONTROL_TOPIC, _control(MODE_MANUAL if manual else MODE_AUTONOMOUS, op if manual else None, reason), 1)

    def human_driving(t: float) -> bool:
        return T_TAKE <= t < T_RELEASE or (defect == "hidden-teleop" and T_HIDDEN_A <= t < T_HIDDEN_B)

    x = y = yaw = 0.0
    for k in range(0, int(end * 5) + 1):
        t = k / 5
        if not rec(t):
            continue
        if T_STUCK <= t < T_TAKE or T_BUMP <= t < T_BUMP + 3:
            v = 0.0
        elif human_driving(t):
            v = 0.3
        else:
            v = 0.8
        wz = round(rng.uniform(-0.05, 0.05), 4)
        if human_driving(t):  # the human's own commands, on the teleop topic, before the arbiter forwards them
            wz = round(rng.uniform(-0.4, 0.4), 3)
            add(t, "/teleop/cmd_vel", {"linear": {"x": v, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": wz}}, 1)
        x += v * 0.2 * math.cos(yaw)
        y += v * 0.2 * math.sin(yaw)
        yaw += wz * 0.2
        add(t, "/odom", {"x": round(x, 3), "y": round(y, 3), "yaw": round(yaw, 4), "v": v})
        add(t, "/cmd_vel", {"linear": {"x": v, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": wz}})
    if rec(T_STUCK):
        add(T_STUCK, "/events", {"type": "stuck_detected", "detail": "no progress for 8 s"})
    if rec(T_BUMP):
        add(T_BUMP, "/events", {"type": "bumper_contact", "detail": "front bumper"})
    R.sort(key=lambda r: (r.t, r.order))
    return R


# remote-vehicle timeline
V_REMOTE_START, V_FAULT, V_MRC, V_TAKEOVER = 10.0, 150.0, 152.0, 170.0


def vehicle_records(defect: str | None, duration: float, seed: int, start: int, pubkey_hex: str | None = None) -> list[Rec]:
    rng = random.Random(seed)
    S = lambda s: start + int(round(s * NS))
    R: list[Rec] = []

    def add(t: float, topic: str, payload: dict, order: int = 2):
        R.append(Rec(S(t), order, topic, payload))

    end = float(duration)
    sw = "rv-2.3.0"
    vin = "WVWZZZ1KZXW000001"
    add(0, SESSION_TOPIC, _session("START", "v-001", sw, note=LIBRARY, device_pubkey=pubkey_hex), 0)
    add(end, SESSION_TOPIC, _session("CLEAN_SHUTDOWN", "v-001", sw), 0)

    def mode_at(t):
        if t < V_REMOTE_START:
            return MODE_NOT_READY, None, "standing by" if t == 0 else None
        if t < V_MRC:
            return MODE_MANUAL, "remote-cert-2025-0142", "remote driving started" if t == V_REMOTE_START else None
        if t < V_TAKEOVER:
            return MODE_DISENGAGED, None, "radio link lost; minimal-risk condition initiated" if t == V_MRC else None
        return MODE_MANUAL, "in-vehicle-driver", "in-vehicle driver took over" if t == V_TAKEOVER else None

    for k in range(0, int(end) + 1):
        t = float(k)
        m, op, reason = mode_at(t)
        add(t, CONTROL_TOPIC, _control(m, op, reason), 1)

    for k in range(0, int(end) + 1, 5):
        add(float(k), "/stvfernlv/vehicle", {"vin": vin, "trip_number": 1})

    add(V_REMOTE_START, "/stvfernlv/remote_driver", {"certificate_name": "M. Mustermann (Fernlenker-Zertifikat 2025-0142)", "certificate_valid_until": "2027-06-30"}, 1)
    add(V_REMOTE_START, "/stvfernlv/event", {"event": "REMOTE_DRIVING_START", "trip_number": 1}, 1)
    add(V_FAULT, "/stvfernlv/event", {"event": "FAULT", "fault": "RADIO_LINK_LOSS", "trip_number": 1}, 1)
    add(V_MRC, "/stvfernlv/event", {"event": "MRC_INITIATED", "trip_number": 1}, 1)
    add(V_TAKEOVER, "/stvfernlv/event", {"event": "TAKEOVER_IN_VEHICLE", "trip_number": 1}, 1)
    if defect != "unpaired":
        add(V_TAKEOVER, "/stvfernlv/event", {"event": "REMOTE_DRIVING_END", "trip_number": 1}, 1)

    lat, lon, heading, speed = 52.52000, 13.40500, 90.0, 0.0
    for k in range(0, int(end * 5) + 1):
        t = k / 5
        if defect == "window" and V_FAULT - 10 <= t < V_FAULT:
            continue
        target = 0.0 if t < V_REMOTE_START or V_MRC <= t < V_TAKEOVER else (8.0 if t < V_MRC else 6.0)
        if V_FAULT <= t < V_MRC:
            target = 2.0
        accel = max(-3.0, min(1.5, (target - speed) * 0.8))
        speed = max(0.0, speed + accel * 0.2)
        lat += speed * 0.2 * math.cos(math.radians(heading)) / 111_320
        lon += speed * 0.2 * math.sin(math.radians(heading)) / 69_000
        link_ok = not (V_FAULT <= t < V_FAULT + 2)
        add(
            t,
            "/stvfernlv/telemetry",
            {
                "position": {"lat": round(lat, 5), "lon": round(lon, 5), "alt": 34.0, "heading": heading},
                "motion": {"speed_mps": round(speed, 2), "accel_long": round(accel, 2), "accel_lat": round(rng.uniform(-0.1, 0.1), 2)},
                "power": {"voltage": 398.0, "soc": round(0.82 - t / 20000, 4)},
                "lighting": {"low_beam": True, "indicator": "none"},
                "connectivity": {"latency_ms": (None if not link_ok else round(rng.uniform(35, 60), 1)), "bandwidth_kbps": (0 if not link_ok else 4800), "link": "ok" if link_ok else "lost"},
                "environment": {"weather": "overcast", "temp_c": 11.0, "visibility_m": 4000},
                "safety_systems": {"abs_active": False, "aeb_triggered": False},
                "system": {"software_version": sw, "faults": ([] if link_ok else ["RADIO_LINK_LOSS"])},
            },
        )
        if V_REMOTE_START <= t < V_FAULT:
            steer = round(rng.uniform(-2, 2), 1)
            cmd = {"steering_deg": steer, "throttle": 0.2 if speed < 8 else 0.1, "brake": 0.0}
            cmd["as_sent"] = json.dumps(cmd, separators=(",", ":"))
            add(t, "/stvfernlv/command", cmd)
    R.sort(key=lambda r: (r.t, r.order))
    return R


class Encoder:
    """Turns a payload dict into bytes for one topic, in the chosen encoding."""

    def __init__(self, encoding: str):
        if encoding not in ENCODINGS:
            raise ValueError(f"encoding must be one of {ENCODINGS}")
        self.encoding = encoding
        self.defs = {**GEN_MSG_DEFS, **MSG_DEFS}

    def schema(self, topic: str) -> tuple[str, str, bytes]:
        """(schema name, schema encoding, schema data) for the MCAP schema record."""
        if self.encoding == "cdr":
            if topic not in self.defs:
                raise ValueError(f"no ros2msg definition for {topic}; cdr mode supports the delivery scenario only")
            name, text = self.defs[topic]
            return name, "ros2msg", text.encode()
        name, js = SCHEMAS.get(topic, (f"quaill_gen/{topic.strip('/').replace('/', '_')}", {"type": "object"}))
        return name, "jsonschema", enc(js)

    def message_encoding(self) -> str:
        return "cdr" if self.encoding == "cdr" else "json"

    def encode(self, topic: str, payload: dict, t: int) -> bytes:
        p = dict(payload)
        p["stamp"] = stamp(t)
        if self.encoding == "cdr":
            name, text = self.defs[topic]
            return cdr_encoder(name, text)(p)
        return enc(p)


GEN_SESSION = "rec-0001"  # the generator's recorder keeps one chain across robot sessions


def chain_entries(records: list[Rec], encoder: Encoder, clock_shift=None, sidecar_restart: bool = False, start: int = DEFAULT_START, signer=None) -> list[Entry]:
    """clock_shift(t) -> recv_time lets a defect make the recorder's clock lie.
    sidecar_restart: no links between T_SIDECAR_DOWN and T_SIDECAR_UP, then a fresh chain under a new session id."""
    cb = ChainBuilder(GEN_SESSION, signer)
    cb2 = ChainBuilder("rec-0002", signer)
    out = []
    for r in records:
        data = encoder.encode(r.topic, r.payload, r.t)
        recv = clock_shift(r.t) if clock_shift else r.t
        rel = (r.t - start) / NS
        if sidecar_restart and T_SIDECAR_DOWN <= rel < T_SIDECAR_UP:
            link = None
        elif sidecar_restart and rel >= T_SIDECAR_UP:
            link = cb2.add(r.topic, data, recv)
        else:
            link = cb.add(r.topic, data, recv)
        out.append(Entry(r.t, r.order, r.topic, r.payload, data, link))
    return out


def rechain(entries: list[Entry], signer=None) -> list[Entry]:
    cb = ChainBuilder(GEN_SESSION, signer)
    return [Entry(e.t, e.order, e.topic, e.payload, e.data, cb.add(e.topic, e.data, e.link["recv_time"])) for e in entries]


def make_witness(all_entries: list[Entry], start: int, log_name: str, every_s: int = 30) -> dict:
    entries = [e for e in all_entries if e.link is not None]
    out, seen = [], set()
    if not entries:
        return {"type": "quaill-demo-witness", "entries": []}

    def key(e: Entry):
        return (e.link["session_id"], e.link["seq"])

    def ent(e: Entry, wt: int) -> dict:
        seen.add(key(e))
        return {"session_id": e.link["session_id"], "seq": e.link["seq"], "link": e.link["link"], "recv_time": e.link["recv_time"], "key_id": e.link.get("key_id", ""), "witnessed_at": fmt_abs(wt)}

    last = entries[-1]
    idx, k = 0, 1
    while True:
        cutoff = start + k * every_s * NS
        if cutoff >= last.t:
            break
        while idx + 1 < len(entries) and entries[idx + 1].t <= cutoff:
            idx += 1
        if entries[idx].t <= cutoff and key(entries[idx]) not in seen:
            out.append(ent(entries[idx], cutoff + NS // 2))
        k += 1
    if key(last) not in seen:
        out.append(ent(last, last.t + NS // 2))
    return {
        "type": "quaill-demo-witness",
        "version": "0.0.2",
        "note": "Stands in for a third-party receipt of the chain head (for example an RFC 3161 timestamp). "
        "Here the generator writes it; in real use a party the robot maker does not control holds it. "
        "Each entry says: at this wall-clock time, the chain head was this link.",
        "log": log_name,
        "session_id": GEN_SESSION,
        "every_s": every_s,
        "entries": out,
    }


def apply_defect(entries: list[Entry], defect: str | None, start: int, encoder: Encoder, signer=None, sw: str = "1.4.2") -> list[Entry]:
    """signer = the real device key (an insider has it); ATTACKER_SIGNER = someone who does not."""
    rel = lambda e: (e.t - start) / NS
    if defect == "edit":
        for e in entries:
            if e.topic == CONTROL_TOPIC and T_TAKE <= rel(e) < T_RELEASE:
                e.payload = dict(e.payload, mode=MODE_AUTONOMOUS, mode_name="AUTONOMOUS", operator_ref=None, reason=None)
                e.data = encoder.encode(e.topic, e.payload, e.t)
        return entries
    if defect in ("delete", "delete-rechain"):
        kept = [e for e in entries if not (e.topic == CONTROL_TOPIC and T_TAKE <= rel(e) < T_RELEASE)]
        return rechain(kept, signer) if defect == "delete-rechain" else kept  # the insider has the device key
    if defect == "rechain-nokey":
        # a thorough outsider: make the human disappear completely, then rebuild everything with their own key
        attacker = ATTACKER_SIGNER
        kept = [e for e in entries if not (e.topic == "/teleop/cmd_vel" and T_TAKE <= rel(e) < T_RELEASE)]
        for e in kept:
            if e.topic == CONTROL_TOPIC and T_TAKE <= rel(e) < T_RELEASE:
                e.payload = dict(e.payload, mode=MODE_AUTONOMOUS, mode_name="AUTONOMOUS", operator_ref=None, reason=None)
                e.data = encoder.encode(e.topic, e.payload, e.t)
            if e.topic == SESSION_TOPIC and e.payload.get("event") == "START":
                e.payload = dict(e.payload, device_pubkey=attacker.pub_hex() if attacker else None)
                e.data = encoder.encode(e.topic, e.payload, e.t)
        return rechain(kept, attacker)
    if defect in ("truncate", "truncate-nokey"):
        kept = [e for e in entries if rel(e) <= T_TRUNC]
        forger = signer if defect == "truncate" else ATTACKER_SIGNER  # insider keeps the real key; outsider signs with their own
        cb = ChainBuilder(GEN_SESSION, forger)
        cb.prev, cb.seq = kept[-1].link["link"], kept[-1].link["seq"]
        t = kept[-1].t + NS // 5
        payload = _session("CLEAN_SHUTDOWN", "s-001", sw)
        data = encoder.encode(SESSION_TOPIC, payload, t)
        kept.append(Entry(t, 0, SESSION_TOPIC, payload, data, cb.add(SESSION_TOPIC, data, t)))
        return kept
    return entries


def clock_back_shift(start: int):
    """Recorder clock 40 s behind between 03:00 and 04:00."""
    a, b = start + 180 * NS, start + 240 * NS
    return lambda t: t - 40 * NS if a <= t < b else t


def write_mcap(path: str, entries: list[Entry], encoder: Encoder, library: str = LIBRARY) -> None:
    from mcap.writer import Writer

    with open(path, "wb") as f:
        w = Writer(f)
        w.start(profile="ros2" if encoder.encoding == "cdr" else "", library=library)
        chan: dict[str, int] = {}
        seqs: Counter = Counter()

        def ch(topic: str) -> int:
            if topic not in chan:
                name, s_enc, s_data = encoder.schema(topic)
                sid = w.register_schema(name=name, encoding=s_enc, data=s_data)
                chan[topic] = w.register_channel(topic=topic, message_encoding=encoder.message_encoding(), schema_id=sid)
            return chan[topic]

        link_bytes = _link_bytes_fn(encoder)
        for e in entries:
            seqs[e.topic] += 1
            w.add_message(channel_id=ch(e.topic), log_time=e.t, publish_time=e.t, sequence=seqs[e.topic], data=e.data)
            if e.link is not None:
                seqs[CHAIN_TOPIC] += 1
                w.add_message(channel_id=ch(CHAIN_TOPIC), log_time=e.t, publish_time=e.t, sequence=seqs[CHAIN_TOPIC], data=link_bytes(e.link))
        w.finish()


def _link_bytes_fn(encoder: Encoder):
    return (lambda d: cdr_encoder(*MSG_DEFS[CHAIN_TOPIC])(d)) if encoder.encoding == "cdr" else enc


def _metadata_yaml(storage: str, parts: list[tuple[str, list[Entry]]], encoder: Encoder, cmode: str = "", cfmt: str = "") -> str:
    """metadata.yaml in the shape rosbag2 (version 9) writes it. Message counts include the chain links."""
    all_entries = [e for _, part in parts for e in part]
    start, end = min(e.t for e in all_entries), max(e.t for e in all_entries)
    topics = Counter(e.topic for e in all_entries)
    topics[CHAIN_TOPIC] = sum(1 for e in all_entries if e.link is not None)
    total = len(all_entries) + topics[CHAIN_TOPIC]
    L = [
        "rosbag2_bagfile_information:",
        f"  compression_format: '{cfmt}'",
        f"  compression_mode: '{cmode}'",
        "  custom_data: null",
        "  duration:",
        f"    nanoseconds: {end - start}",
        "  files:",
    ]
    for path, part in parts:
        ps, pe = min(e.t for e in part), max(e.t for e in part)
        n = len(part) + sum(1 for e in part if e.link is not None)
        L += ["  - duration:", f"      nanoseconds: {pe - ps}", f"    message_count: {n}", f"    path: {path}", "    starting_time:", f"      nanoseconds_since_epoch: {ps}"]
    L += [f"  message_count: {total}", "  relative_file_paths:"]
    L += [f"  - {path}" for path, _ in parts]
    L += ["  ros_distro: quaill-gen", "  starting_time:", f"    nanoseconds_since_epoch: {start}", f"  storage_identifier: {storage}", "  topics_with_message_count:"]
    for topic, n in sorted(topics.items()):
        name, _, _ = encoder.schema(topic)
        L += [f"  - message_count: {n}", "    topic_metadata:", f"      name: {topic}", "      offered_qos_profiles: []", f"      serialization_format: {encoder.message_encoding()}", f"      type: {name}", "      type_description_hash: ''"]
    L += ["  version: 9", ""]
    return "\n".join(L)


def write_container(out: str, entries: list[Entry], encoder: Encoder, container: str) -> str:
    """Write entries in the chosen container. Returns the path the checker should be pointed at."""
    import shutil

    if container not in CONTAINERS:
        raise ValueError(f"unknown container {container}; have {', '.join(CONTAINERS)}")
    p = Path(out)
    if container == "mcap":
        p.parent.mkdir(parents=True, exist_ok=True)
        write_mcap(str(p), entries, encoder)
        return str(p)

    if container.startswith("rosbag2-sqlite") and encoder.encoding != "cdr":
        raise ValueError("rosbag2 sqlite3 containers need --encoding cdr (rosbag2 never writes JSON into sqlite bags)")
    if p.exists():
        shutil.rmtree(p)
    p.mkdir(parents=True)
    name = p.name

    if container.startswith("rosbag2-mcap"):
        if container == "rosbag2-mcap-split":
            mid = (entries[0].t + entries[-1].t) // 2
            cut = next((i for i, e in enumerate(entries) if e.t > mid), len(entries))
            chunks = [entries[:cut], entries[cut:]]
        else:
            chunks = [entries]
        parts = []
        for i, chunk in enumerate(chunks):
            fname = f"{name}_{i}.mcap"
            write_mcap(str(p / fname), chunk, encoder)
            if container == "rosbag2-mcap-filezstd":
                import zstandard

                with (p / fname).open("rb") as fi, (p / (fname + ".zstd")).open("wb") as fo:
                    zstandard.ZstdCompressor(level=3).copy_stream(fi, fo)
                (p / fname).unlink()
                fname += ".zstd"
            parts.append((fname, chunk))
        cmode, cfmt = ("file", "zstd") if container == "rosbag2-mcap-filezstd" else ("", "")
        (p / "metadata.yaml").write_text(_metadata_yaml("mcap", parts, encoder, cmode, cfmt), encoding="utf-8")
        return str(p)

    # rosbag2 sqlite3 via the rosbags library (writes the real rosbag2 schema and metadata.yaml)
    from rosbags.rosbag2 import Writer
    from rosbags.rosbag2.writer import CompressionFormat, CompressionMode, StoragePlugin

    shutil.rmtree(p)  # rosbags wants to create the directory itself
    w = Writer(p, version=9, storage_plugin=StoragePlugin.SQLITE3)
    if container == "rosbag2-sqlite-zstd":
        w.set_compression(CompressionMode.MESSAGE, CompressionFormat.ZSTD)
    w.open()
    conns: dict[str, object] = {}

    def conn(topic: str):
        if topic not in conns:
            tname, _, sdata = encoder.schema(topic)
            conns[topic] = w.add_connection(topic, tname, msgdef=sdata.decode(), rihs01="RIHS01_" + "0" * 64, serialization_format="cdr")
        return conns[topic]

    link_bytes = _link_bytes_fn(encoder)
    for e in entries:
        w.write(conn(e.topic), e.t, e.data)
        if e.link is not None:
            w.write(conn(CHAIN_TOPIC), e.t, link_bytes(e.link))
    w.close()
    return str(p)


def generate_ros1(out: str, duration: float = 60.0, start: int = DEFAULT_START) -> dict:
    """A plain ROS 1 bag with no Quaill channels: /chatter (std_msgs/String) and /cmd_vel (Twist) at 10 Hz."""
    from rosbags.rosbag1 import Writer
    from rosbags.typesys import Stores, get_typestore

    ts = get_typestore(Stores.ROS1_NOETIC)
    String = ts.types["std_msgs/msg/String"]
    Twist = ts.types["geometry_msgs/msg/Twist"]
    Vector3 = ts.types["geometry_msgs/msg/Vector3"]
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        p.unlink()
    w = Writer(p)
    w.open()
    c1 = w.add_connection("/chatter", String.__msgtype__, typestore=ts)
    c2 = w.add_connection("/cmd_vel", Twist.__msgtype__, typestore=ts)
    n = int(duration * 10)
    for k in range(n):
        t = start + k * (NS // 10)
        w.write(c1, t, ts.serialize_ros1(String(data=f"tick {k}"), String.__msgtype__))
        w.write(c2, t, ts.serialize_ros1(Twist(linear=Vector3(x=0.5, y=0.0, z=0.0), angular=Vector3(x=0.0, y=0.0, z=0.1)), Twist.__msgtype__))
    w.close()
    return {"bag": str(p), "scenario": "ros1-plain", "messages": 2 * n, "description": "plain ROS 1 bag, no Quaill channels"}


def generate(out: str, scenario: str = "delivery", defect: str | None = None, witness: bool = True, seed: int = 1, duration: float | None = None, start: int = DEFAULT_START, encoding: str = "json", container: str = "mcap", sign: bool = True) -> dict:
    if scenario == "ros1-plain":
        return generate_ros1(out, duration or 60.0, start)
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario}; have {', '.join(SCENARIOS)}, ros1-plain")
    if defect and defect not in SCENARIOS[scenario]:
        raise ValueError(f"unknown defect {defect} for {scenario}; have {', '.join(SCENARIOS[scenario])}")
    if scenario == "remote-vehicle" and encoding == "cdr":
        raise ValueError("remote-vehicle scenario is json-only in this version")
    if duration is None:
        duration = 600.0 if scenario == "delivery" else 300.0
    signer = DEMO_SIGNER if (sign and CRYPTO) else None
    pub_hex = signer.pub_hex() if signer else None
    encoder = Encoder(encoding)
    records = delivery_records(defect, duration, seed, start, pub_hex) if scenario == "delivery" else vehicle_records(defect, duration, seed, start, pub_hex)
    entries = chain_entries(records, encoder, clock_back_shift(start) if defect == "clock-back" else None, sidecar_restart=(defect == "sidecar-restart"), start=start, signer=signer)
    wit = make_witness(entries, start, Path(out).name)  # the witness saw the honest chain
    entries = apply_defect(entries, defect, start, encoder, signer)
    written = write_container(out, entries, encoder, container)
    wpath = kpath = None
    if witness:
        wpath = out + ".witness.json"
        Path(wpath).write_text(json.dumps(wit, indent=1), encoding="utf-8")
    if signer:
        kpath = out + ".pubkey.pem"
        signer.save_public(kpath)
    return {
        "path": written,
        "witness": wpath,
        "pubkey": kpath,
        "scenario": scenario,
        "encoding": encoding,
        "container": container,
        "defect": defect,
        "description": SCENARIOS[scenario].get(defect, "clean log, no planted defects") if defect else "clean log, no planted defects",
        "messages": len(entries) + sum(1 for e in entries if e.link is not None),
        "chain_links": sum(1 for e in entries if e.link is not None),
    }
