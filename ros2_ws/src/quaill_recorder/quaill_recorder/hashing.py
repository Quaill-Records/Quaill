"""Hash functions for the chain. MUST stay byte-for-byte identical to quaill/mcapio.py in the checker.

The checker repo has a test that imports both and compares them on fixed inputs.
"""
import hashlib

GENESIS = "0" * 64


def as_stored(data: bytes) -> bytes:
    """The bytes rosbag2 will store for a CDR message. The DDS wire format pads a payload to a multiple of 4; a
    message a process delivers to itself skips the wire and arrives without that padding (seen in CI: 85 bytes
    received, 88 stored). Without this, anything published in the sidecar's own process fails to pair."""
    return data + b"\0" * (-len(data) % 4)


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
