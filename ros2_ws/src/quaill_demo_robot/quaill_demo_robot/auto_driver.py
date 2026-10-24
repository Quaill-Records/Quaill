"""auto_driver: the stand-in autonomy. Publishes /auto/cmd_vel at 5 Hz: slow forward with a gentle weave."""
from __future__ import annotations

import math

import rclpy
from geometry_msgs.msg import Twist
from rclpy.node import Node


class AutoDriver(Node):
    def __init__(self) -> None:
        super().__init__("auto_driver")
        self.declare_parameter("speed", 0.5)
        self.pub = self.create_publisher(Twist, "/auto/cmd_vel", 10)
        self.t0 = self.get_clock().now().nanoseconds
        self.create_timer(0.2, self._tick)

    def _tick(self) -> None:
        t = (self.get_clock().now().nanoseconds - self.t0) / 1e9
        m = Twist()
        m.linear.x = float(self.get_parameter("speed").value)
        m.angular.z = 0.2 * math.sin(t / 4.0)
        self.pub.publish(m)


def main(args=None) -> None:
    rclpy.init(args=args)
    node = AutoDriver()
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
