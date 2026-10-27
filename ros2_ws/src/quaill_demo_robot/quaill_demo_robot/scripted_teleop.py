"""scripted_teleop: a stand-in for a human at teleop_twist_keyboard, for runs with nobody at a keyboard.

Publishes geometry_msgs/Twist on /teleop/cmd_vel following a pattern of drive/idle stretches, in seconds:
  pattern [15.0, 10.0, 15.0, 20.0]  ->  drive 15 s, idle 10 s, drive 15 s, idle 20 s, then exit.
  ros2 run quaill_demo_robot scripted_teleop --ros-args -p "pattern:=[15.0,10.0,15.0,20.0]"
Every drive stretch makes mode_manager hand control to the operator; every idle stretch longer than its
teleop_timeout_s hands it back. The topic is created at startup and left silent for `warmup_s` so the
chain sidecar can discover and subscribe to it before the first message.
"""
from __future__ import annotations

import rclpy
from geometry_msgs.msg import Twist
from rclpy.node import Node


class ScriptedTeleop(Node):
    def __init__(self) -> None:
        super().__init__("scripted_teleop")
        self.declare_parameter("pattern", [15.0, 10.0, 15.0, 20.0])
        self.declare_parameter("rate_hz", 10.0)
        self.declare_parameter("warmup_s", 4.0)
        self.declare_parameter("speed", 0.3)
        self.pub = self.create_publisher(Twist, "/teleop/cmd_vel", 10)
        self.stretches = [float(x) for x in self.get_parameter("pattern").value]
        self.speed = float(self.get_parameter("speed").value)
        self.t0 = self.get_clock().now().nanoseconds + int(float(self.get_parameter("warmup_s").value) * 1e9)
        self.done = False
        self.last_idx = -1
        self.create_timer(1.0 / float(self.get_parameter("rate_hz").value), self._tick)
        self.get_logger().info(f"scripted teleop: drive/idle pattern {self.stretches} s after {self.get_parameter('warmup_s').value} s warmup")

    def _tick(self) -> None:
        t = (self.get_clock().now().nanoseconds - self.t0) / 1e9
        if t < 0 or self.done:
            return
        idx, elapsed = 0, 0.0
        for idx, length in enumerate(self.stretches):
            if t < elapsed + length:
                break
            elapsed += length
        else:
            self.done = True
            self.get_logger().info("scripted teleop: pattern finished")
            return
        if idx != self.last_idx:
            self.last_idx = idx
            self.get_logger().info(f"scripted teleop: {'driving' if idx % 2 == 0 else 'idle'} for {self.stretches[idx]:g} s")
        if idx % 2 == 0:  # even stretches drive, odd stretches stay silent
            m = Twist()
            m.linear.x = self.speed
            m.angular.z = 0.5 if int(t) % 2 == 0 else -0.5
            self.pub.publish(m)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = ScriptedTeleop()
    try:
        while rclpy.ok() and not node.done:
            rclpy.spin_once(node, timeout_sec=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()
