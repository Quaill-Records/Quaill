"""Launch the two Quaill sidecar nodes with config/default.yaml (override with config:=/path/to.yaml)."""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    default = os.path.join(get_package_share_directory("quaill_recorder"), "config", "default.yaml")
    config = LaunchConfiguration("config")
    return LaunchDescription(
        [
            DeclareLaunchArgument("config", default_value=default),
            Node(package="quaill_recorder", executable="control_mode", name="quaill_control_mode", parameters=[config], output="screen"),
            Node(package="quaill_recorder", executable="chain", name="quaill_chain", parameters=[config], output="screen"),
        ]
    )
