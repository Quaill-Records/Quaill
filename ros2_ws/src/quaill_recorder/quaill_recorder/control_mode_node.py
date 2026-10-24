"""quaill_control_mode: turns a robot's own idea of "who is driving" into standard ControlModeReports.

Sources (parameter `source`):
  topic     a std_msgs/String on `mode_topic` (default /quaill/mode_source). Accepts either a plain name
            ("AUTONOMOUS", "MANUAL", "DISENGAGED", "NOT_READY") optionally followed by ":operator_ref",
            or JSON {"mode": 4, "operator_ref": "op-7f3a", "reason": "teleop input"}.
  autoware  an autoware_vehicle_msgs/ControlModeReport on `mode_topic`; mode numbers are copied 1:1,
            operator_ref comes from the `operator_ref` parameter when mode is MANUAL.

Publishes /quaill/control_mode immediately on every change and as a heartbeat at `heartbeat_hz`.
The profile rule: whatever publishes the source should be the arbiter that decides whose commands
reach the motors, not a flag next to it.

Testing on real hardware soon.
"""
from __future__ import annotations

import json

import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

from quaill_msgs.msg import ControlModeReport

MODE_NAMES = {0: "NO_COMMAND", 1: "AUTONOMOUS", 2: "AUTONOMOUS_STEER_ONLY", 3: "AUTONOMOUS_VELOCITY_ONLY", 4: "MANUAL", 5: "DISENGAGED", 6: "NOT_READY"}
NAME_TO_MODE = {v: k for k, v in MODE_NAMES.items()}


class ControlModeNode(Node):
    def __init__(self) -> None:
        super().__init__("quaill_control_mode")
        self.declare_parameter("source", "topic")
        self.declare_parameter("mode_topic", "/quaill/mode_source")
        self.declare_parameter("heartbeat_hz", 1.0)
        self.declare_parameter("initial_mode", "NOT_READY")
        self.declare_parameter("operator_ref", "")

        self.mode = NAME_TO_MODE.get(str(self.get_parameter("initial_mode").value), 6)
        self.operator_ref = ""
        self.default_operator = str(self.get_parameter("operator_ref").value)

        qos = QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=100, reliability=ReliabilityPolicy.RELIABLE, durability=DurabilityPolicy.VOLATILE)
        self.pub = self.create_publisher(ControlModeReport, "/quaill/control_mode", qos)

        source = str(self.get_parameter("source").value)
        topic = str(self.get_parameter("mode_topic").value)
        if source == "autoware":
            from autoware_vehicle_msgs.msg import ControlModeReport as AwReport  # type: ignore

            self.create_subscription(AwReport, topic, self._on_autoware, qos)
        else:
            self.create_subscription(String, topic, self._on_string, qos)
        hz = float(self.get_parameter("heartbeat_hz").value)
        self.create_timer(1.0 / hz if hz > 0 else 1.0, lambda: self._publish(None))
        self._publish("initial")
        self.get_logger().info(f"quaill_control_mode source={source} topic={topic} heartbeat={hz} Hz")

    def _set(self, mode: int, operator_ref: str, reason: str) -> None:
        if mode in (4,) and not operator_ref:
            operator_ref = self.default_operator
        changed = mode != self.mode or operator_ref != self.operator_ref
        self.mode, self.operator_ref = mode, operator_ref
        if changed:
            self._publish(reason or "mode changed")

    def _on_string(self, msg: String) -> None:
        text = msg.data.strip()
        try:
            d = json.loads(text)
            if isinstance(d, dict):
                mode = int(d.get("mode", self.mode)) if "mode" in d else NAME_TO_MODE.get(str(d.get("mode_name", "")).upper(), self.mode)
                self._set(mode, str(d.get("operator_ref") or ""), str(d.get("reason") or ""))
                return
        except Exception:
            pass
        name, _, op = text.partition(":")
        mode = NAME_TO_MODE.get(name.upper())
        if mode is None:
            self.get_logger().warning(f"unknown mode '{text}'")
            return
        self._set(mode, op.strip(), "")

    def _on_autoware(self, msg) -> None:
        self._set(int(msg.mode), self.default_operator if int(msg.mode) == 4 else "", "")

    def _publish(self, reason: str | None) -> None:
        m = ControlModeReport()
        m.stamp = self.get_clock().now().to_msg()
        m.mode = self.mode
        m.mode_name = MODE_NAMES.get(self.mode, f"MODE_{self.mode}")
        m.operator_ref = self.operator_ref if self.mode == 4 else ""
        m.reason = reason or ""
        self.pub.publish(m)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = ControlModeNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()
