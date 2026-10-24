r"""The connector (ROS 2 sidecar) and the checker must hash identically, or nothing pairs.

Run from the repository root:  python tests/check_hashes.py
The connector's hashing.py has no ROS imports on purpose, so it can be loaded here without ROS.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quaill import mcapio  # noqa: E402

spec = importlib.util.spec_from_file_location("connector_hashing", ROOT / "ros2_ws" / "src" / "quaill_recorder" / "quaill_recorder" / "hashing.py")
connector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(connector)

CASES = [
    ("/cmd_vel", b"", 1, 0),
    ("/odom", bytes(range(256)), 2, 1792778400000000000),
    ("/quaill/control_mode", b"\x00\x01\x00\x00\x05\x00\x00\x00", 2**40, -5),
    ("/stvfernlv/telemetry", "ünïcödé".encode(), 7, 2**62),
]

prev = mcapio.GENESIS
assert prev == connector.GENESIS
for topic, data, seq, recv in CASES:
    a = mcapio.message_hash(topic, data)
    b = connector.message_hash(topic, data)
    assert a == b, (topic, a, b)
    la = mcapio.link_hash(prev, a, seq, recv, topic)
    lb = connector.link_hash(prev, b, seq, recv, topic)
    assert la == lb, (topic, la, lb)
    prev = la
print(f"ok: connector and checker agree on {len(CASES)} message hashes and {len(CASES)} chained links")
