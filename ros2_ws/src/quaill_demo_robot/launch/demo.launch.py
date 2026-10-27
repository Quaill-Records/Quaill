"""Fake robot + Quaill sidecars. Drive with teleop_twist_keyboard (or scripted_teleop) in another terminal.
`config:=/path/to.yaml` overrides the sidecars' config (default: quaill_recorder/config/default.yaml)."""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, IncludeLaunchDescription
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    share = get_package_share_directory("quaill_recorder")
    recorder_launch = os.path.join(share, "launch", "recorder.launch.py")
    default_config = os.path.join(share, "config", "default.yaml")
    return LaunchDescription(
        [
            DeclareLaunchArgument("config", default_value=default_config),
            Node(package="quaill_demo_robot", executable="auto_driver", name="auto_driver", output="screen"),
            Node(package="quaill_demo_robot", executable="fake_odom", name="fake_odom", output="screen"),
            Node(package="quaill_demo_robot", executable="mode_manager", name="mode_manager", output="screen", parameters=[{"operator_ref": "op-7f3a", "teleop_timeout_s": 5.0}]),
            IncludeLaunchDescription(PythonLaunchDescriptionSource(recorder_launch), launch_arguments={"config": LaunchConfiguration("config")}.items()),
        ]
    )
