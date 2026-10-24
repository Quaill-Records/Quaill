"""Fake robot + Quaill sidecars. Drive with teleop_twist_keyboard in another terminal."""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import IncludeLaunchDescription
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch_ros.actions import Node


def generate_launch_description():
    recorder_launch = os.path.join(get_package_share_directory("quaill_recorder"), "launch", "recorder.launch.py")
    return LaunchDescription(
        [
            Node(package="quaill_demo_robot", executable="auto_driver", name="auto_driver", output="screen"),
            Node(package="quaill_demo_robot", executable="fake_odom", name="fake_odom", output="screen"),
            Node(package="quaill_demo_robot", executable="mode_manager", name="mode_manager", output="screen", parameters=[{"operator_ref": "op-7f3a", "teleop_timeout_s": 5.0}]),
            IncludeLaunchDescription(PythonLaunchDescriptionSource(recorder_launch)),
        ]
    )
