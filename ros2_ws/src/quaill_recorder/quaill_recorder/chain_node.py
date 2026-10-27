"""quaill_chain: subscribes RAW to the configured topics, publishes one ChainLink per message,
writes session markers (START / CLEAN_SHUTDOWN / CRASH_NOTE) and periodic witness heads.

Run it next to `ros2 bag record`. The bag then contains the robot's own topics plus
/quaill/chain and /quaill/session, which is what the checker grades.

Design notes
- Raw subscriptions give the exact serialized bytes the publisher sent. rosbag2 stores those same
  bytes, so the checker can recompute every hash from the bag.
- The link carries the node's own receive time (recv_time), not the bag's log_time, which this
  node cannot know. The checker pairs by content hash and compares the two clocks.
- Session markers are published with TRANSIENT_LOCAL durability so a bag recorder that starts a
  moment later still receives START.
- The state file tells the next run whether this one ended cleanly. kill -9 leaves it dirty, and
  the next start publishes CRASH_NOTE before START. That is how the checker tells a crash from a cut.
- The witness file is written by this node, so on its own it is NOT an outside witness. It becomes
  one when its heads reach a party the robot maker does not control (optional RFC 3161 below).

Testing on real hardware soon.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from rosidl_runtime_py.utilities import get_message

from quaill_msgs.msg import ChainLink, SessionEvent

from .hashing import GENESIS, link_hash, message_hash

CHAIN_TOPIC = "/quaill/chain"
SESSION_TOPIC = "/quaill/session"
CONTROL_TOPIC = "/quaill/control_mode"
NEVER_CHAIN = {CHAIN_TOPIC, "/rosout", "/parameter_events"}


def _iso(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ChainNode(Node):
    def __init__(self) -> None:
        super().__init__("quaill_chain")
        self.declare_parameter("topics", ["/cmd_vel", "/odom"])
        self.declare_parameter("chain_quaill_topics", True)
        self.declare_parameter("discover", False)
        self.declare_parameter("state_dir", str(Path.home() / ".quaill"))
        self.declare_parameter("witness_every_s", 10.0)
        self.declare_parameter("software_version", "unknown")
        self.declare_parameter("session_id", "")
        self.declare_parameter("tsa_url", "")  # optional RFC 3161 timestamp authority, e.g. https://freetsa.org/tsr
        self.declare_parameter("sign", True)  # sign each link with an Ed25519 device key (needs python3-cryptography)
        self.declare_parameter("key_path", "")  # PEM private key; default <state_dir>/device.key.pem, generated on first run

        self.topics = list(self.get_parameter("topics").value)
        if self.get_parameter("chain_quaill_topics").value:
            for t in (CONTROL_TOPIC, SESSION_TOPIC):
                if t not in self.topics:
                    self.topics.append(t)
        self.discover = bool(self.get_parameter("discover").value)
        self.state_dir = Path(self.get_parameter("state_dir").value).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.state_dir / "session.json"
        self.software_version = str(self.get_parameter("software_version").value)
        self.session_id = str(self.get_parameter("session_id").value) or f"s-{uuid.uuid4().hex[:8]}"
        self.witness_path = self.state_dir / f"witness-{self.session_id}.json"  # one file per session; point the checker at the directory
        self.tsa_url = str(self.get_parameter("tsa_url").value)

        self.prev = GENESIS
        self.seq = 0
        self.head_recv = 0
        self.witness_entries: list[dict] = []
        self.subscribed: dict[str, object] = {}
        self.key = None
        self.key_id = ""
        self.pub_hex = ""
        if bool(self.get_parameter("sign").value):
            self._load_or_create_key(str(self.get_parameter("key_path").value) or str(self.state_dir / "device.key.pem"))

        reliable = QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=1000, reliability=ReliabilityPolicy.RELIABLE, durability=DurabilityPolicy.VOLATILE)
        latched = QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=10, reliability=ReliabilityPolicy.RELIABLE, durability=DurabilityPolicy.TRANSIENT_LOCAL)
        self.pub_chain = self.create_publisher(ChainLink, CHAIN_TOPIC, reliable)
        self.pub_session = self.create_publisher(SessionEvent, SESSION_TOPIC, latched)

        self._start_session()
        self.create_timer(2.0, self._discover_and_subscribe)
        self.create_timer(float(self.get_parameter("witness_every_s").value), self._witness_tick)
        self._discover_and_subscribe()
        self.get_logger().info(f"quaill_chain session {self.session_id}; chaining {self.topics}{' + discovered topics' if self.discover else ''}")

    # ---- device key ----
    def _load_or_create_key(self, path: str) -> None:
        """Ed25519 device key. The private key should live where the log does NOT (TPM, secure element, or at
        least a different host); a key file next to the bag only proves self-consistency."""
        try:
            import hashlib

            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except Exception as e:
            self.get_logger().warning(f"signing disabled: python3-cryptography not available ({e})")
            return
        p = Path(path).expanduser()
        if p.is_file():
            key = serialization.load_pem_private_key(p.read_bytes(), password=None)
        else:
            key = Ed25519PrivateKey.generate()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            self.get_logger().warning(f"generated a new device key at {p}; back it up and keep it off the log host")
        pub_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (p.parent / "device.pubkey.pem").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.key = key
        self.pub_hex = pub_raw.hex()
        self.key_id = hashlib.sha256(pub_raw).hexdigest()[:16]
        self.get_logger().info(f"signing links with device key {self.key_id}; public key at {p.parent / 'device.pubkey.pem'}")

    # ---- session markers ----
    def _publish_session(self, event: str, prev_session_id: str = "", note: str = "") -> None:
        m = SessionEvent()
        m.stamp = self.get_clock().now().to_msg()
        m.event = event
        m.session_id = self.session_id
        m.prev_session_id = prev_session_id
        m.software_version = self.software_version
        m.note = note
        m.device_pubkey = self.pub_hex if event == "START" else ""
        self.pub_session.publish(m)

    def _start_session(self) -> None:
        prev = None
        if self.state_path.is_file():
            try:
                prev = json.loads(self.state_path.read_text())
            except Exception:
                prev = None
        if prev and not prev.get("clean_end"):
            self._publish_session("CRASH_NOTE", prev_session_id=prev.get("session_id", ""), note=f"previous session ended unexpectedly; last chain seq {prev.get('seq', '?')} at {prev.get('updated', '?')}")
            self.get_logger().warning(f"previous session {prev.get('session_id')} did not end cleanly; CRASH_NOTE published")
        self._publish_session("START", note="quaill_recorder 0.0.2")
        self._write_state(clean_end=False)

    def _write_state(self, clean_end: bool) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"session_id": self.session_id, "seq": self.seq, "head": self.prev, "updated": _iso(time.time_ns()), "clean_end": clean_end}))
        os.replace(tmp, self.state_path)

    def shutdown_clean(self) -> None:
        self._publish_session("CLEAN_SHUTDOWN")
        self._witness_tick(final=True)
        self._write_state(clean_end=True)
        time.sleep(0.3)  # let the publisher flush before the process exits

    # ---- subscriptions ----
    def _qos_for(self, topic: str) -> QoSProfile:
        infos = self.get_publishers_info_by_topic(topic)
        reliability = ReliabilityPolicy.RELIABLE
        durability = DurabilityPolicy.VOLATILE
        if infos:
            if any(i.qos_profile.reliability == ReliabilityPolicy.BEST_EFFORT for i in infos):
                reliability = ReliabilityPolicy.BEST_EFFORT
            if all(i.qos_profile.durability == DurabilityPolicy.TRANSIENT_LOCAL for i in infos):
                durability = DurabilityPolicy.TRANSIENT_LOCAL
        return QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=100, reliability=reliability, durability=durability)

    def _discover_and_subscribe(self) -> None:
        available = dict(self.get_topic_names_and_types())
        wanted = set(self.topics)
        if self.discover:
            wanted |= set(available) - NEVER_CHAIN
        for topic in sorted(wanted):
            if topic in self.subscribed or topic in NEVER_CHAIN or topic not in available:
                continue
            types = available[topic]
            if not types:
                continue
            try:
                msg_type = get_message(types[0])
            except Exception as e:  # type not installed locally; cannot subscribe raw without it
                self.get_logger().warning(f"cannot subscribe to {topic} ({types[0]}): {e}")
                self.subscribed[topic] = None
                continue
            self.subscribed[topic] = self.create_subscription(msg_type, topic, lambda data, t=topic: self._on_raw(t, data), self._qos_for(topic), raw=True)
            self.get_logger().info(f"chaining {topic} ({types[0]})")

    def _on_raw(self, topic: str, data: bytes) -> None:
        recv = self.get_clock().now().nanoseconds
        mh = message_hash(topic, bytes(data))
        self.seq += 1
        link = link_hash(self.prev, mh, self.seq, recv, topic)
        m = ChainLink()
        m.session_id = self.session_id
        m.seq = self.seq
        m.topic = topic
        m.msg_sha256 = mh
        m.prev = self.prev
        m.link = link
        m.recv_time = recv
        if self.key is not None:
            m.key_id = self.key_id
            m.sig = self.key.sign(bytes.fromhex(link)).hex()
        self.pub_chain.publish(m)
        self.prev = link
        self.head_recv = recv

    # ---- witness ----
    def _witness_tick(self, final: bool = False) -> None:
        if self.seq == 0:
            return
        if self.witness_entries and self.witness_entries[-1]["seq"] == self.seq and not final:
            return
        entry = {"session_id": self.session_id, "seq": self.seq, "link": self.prev, "recv_time": self.head_recv, "key_id": self.key_id, "witnessed_at": _iso(time.time_ns())}
        if self.tsa_url:
            entry["rfc3161"] = self._timestamp(self.prev)
        self.witness_entries.append(entry)
        tmp = self.witness_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "type": "quaill-recorder-witness",
                    "version": "0.0.2",
                    "note": "Written by the recorder itself. It is an OUTSIDE witness only once these heads reach a party the robot maker does not control "
                    "(an RFC 3161 receipt per entry when tsa_url is set, or a copy pushed to a third party as it is written).",
                    "session_id": self.session_id,
                    "entries": self.witness_entries,
                },
                indent=1,
            )
        )
        os.replace(tmp, self.witness_path)
        self._write_state(clean_end=False)

    def _timestamp(self, link_hex: str) -> dict:
        """Optional RFC 3161 receipt for the chain head. Needs `pip install rfc3161ng`."""
        try:
            import rfc3161ng  # type: ignore

            rt = rfc3161ng.RemoteTimestamper(self.tsa_url, hashname="sha256", include_tsa_certificate=True)  # the checker needs the TSA certificate to check the signature
            tsr = rt.timestamp(data=bytes.fromhex(link_hex))
            return {"tsa": self.tsa_url, "tsr_der_hex": bytes(tsr).hex()}
        except Exception as e:
            return {"tsa": self.tsa_url, "error": str(e)}


def main(args=None) -> None:
    rclpy.init(args=args)
    node = ChainNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            node.shutdown_clean()
        finally:
            node.destroy_node()
            if rclpy.ok():
                rclpy.shutdown()


if __name__ == "__main__":
    main()
