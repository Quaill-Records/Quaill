"""fake_odom: integrates /cmd_vel into a pose and publishes nav_msgs/Odometry on /odom at 10 Hz."""
from __future__ import annotations

import math

import rclpy
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from rclpy.node import Node


class FakeOdom(Node):
    def __init__(self) -> None:
        super().__init__("fake_odom")
        self.pub = self.create_publisher(Odometry, "/odom", 10)
        self.create_subscription(Twist, "/cmd_vel", self._on_cmd, 10)
        self.v = 0.0
        self.w = 0.0
        self.x = self.y = self.yaw = 0.0
        self.last = self.get_clock().now().nanoseconds
        self.create_timer(0.1, self._tick)

    def _on_cmd(self, msg: Twist) -> None:
        self.v, self.w = msg.linear.x, msg.angular.z

    def _tick(self) -> None:
        now = self.get_clock().now().nanoseconds
        dt = (now - self.last) / 1e9
        self.last = now
        self.x += self.v * dt * math.cos(self.yaw)
        self.y += self.v * dt * math.sin(self.yaw)
        self.yaw += self.w * dt
        m = Odometry()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = "odom"
        m.child_frame_id = "base_link"
        m.pose.pose.position.x = self.x
        m.pose.pose.position.y = self.y
        m.pose.pose.orientation.z = math.sin(self.yaw / 2)
        m.pose.pose.orientation.w = math.cos(self.yaw / 2)
        m.twist.twist.linear.x = self.v
        m.twist.twist.angular.z = self.w
        self.pub.publish(m)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = FakeOdom()
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
