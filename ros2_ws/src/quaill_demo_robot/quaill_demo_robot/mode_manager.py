"""mode_manager: the arbiter. Decides whose commands reach /cmd_vel and announces who is driving.

  /auto/cmd_vel    from auto_driver (the "autonomy")
  /teleop/cmd_vel  from teleop_twist_keyboard (remapped; the human)
  /cmd_vel         what the robot actually does
  /quaill/mode_source   std_msgs/String JSON for quaill_control_mode

Any teleop message switches to MANUAL and stays there until `teleop_timeout_s` passes with no
teleop input, then control returns to AUTONOMOUS. This is the point of the design: the node that
gates the actuator path is the one that reports the mode, so the report cannot drift from reality.
"""
from __future__ import annotations

import json

import rclpy
from geometry_msgs.msg import Twist
from rclpy.node import Node
from std_msgs.msg import String


class ModeManager(Node):
    def __init__(self) -> None:
        super().__init__("mode_manager")
        self.declare_parameter("operator_ref", "op-7f3a")
        self.declare_parameter("teleop_timeout_s", 5.0)
        self.operator_ref = str(self.get_parameter("operator_ref").value)
        self.timeout = float(self.get_parameter("teleop_timeout_s").value)

        self.pub_cmd = self.create_publisher(Twist, "/cmd_vel", 10)
        self.pub_mode = self.create_publisher(String, "/quaill/mode_source", 10)
        self.create_subscription(Twist, "/auto/cmd_vel", self._on_auto, 10)
        self.create_subscription(Twist, "/teleop/cmd_vel", self._on_teleop, 10)
        self.create_timer(0.5, self._tick)

        self.manual = False
        self.last_teleop_ns = 0
        self._announce("AUTONOMOUS", "", "startup: autonomy active")

    def _announce(self, mode_name: str, operator_ref: str, reason: str) -> None:
        self.pub_mode.publish(String(data=json.dumps({"mode_name": mode_name, "operator_ref": operator_ref, "reason": reason})))
        self.get_logger().info(f"control -> {mode_name}{' (' + operator_ref + ')' if operator_ref else ''}: {reason}")

    def _on_auto(self, msg: Twist) -> None:
        if not self.manual:
            self.pub_cmd.publish(msg)

    def _on_teleop(self, msg: Twist) -> None:
        self.last_teleop_ns = self.get_clock().now().nanoseconds
        if not self.manual:
            self.manual = True
            self._announce("MANUAL", self.operator_ref, "teleop input received; remote operator took control")
        self.pub_cmd.publish(msg)

    def _tick(self) -> None:
        if self.manual and (self.get_clock().now().nanoseconds - self.last_teleop_ns) > self.timeout * 1e9:
            self.manual = False
            self._announce("AUTONOMOUS", "", f"no teleop input for {self.timeout:g} s; autonomy resumed")


def main(args=None) -> None:
    rclpy.init(args=args)
    node = ModeManager()
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
