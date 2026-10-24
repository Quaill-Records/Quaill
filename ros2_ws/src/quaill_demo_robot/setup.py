import os
from glob import glob

from setuptools import find_packages, setup

package_name = "quaill_demo_robot"

setup(
    name=package_name,
    version="0.0.2",
    packages=find_packages(exclude=["test"]),
    data_files=[
        ("share/ament_index/resource_index/packages", ["resource/" + package_name]),
        ("share/" + package_name, ["package.xml"]),
        (os.path.join("share", package_name, "launch"), glob("launch/*.launch.py")),
    ],
    install_requires=["setuptools"],
    zip_safe=True,
    maintainer="Quaill",
    maintainer_email="254507736+Deseace@users.noreply.github.com",
    description="Fake robot with real human/autonomous handovers for recording test bags.",
    license="Apache-2.0",
    entry_points={
        "console_scripts": [
            "mode_manager = quaill_demo_robot.mode_manager:main",
            "auto_driver = quaill_demo_robot.auto_driver:main",
            "fake_odom = quaill_demo_robot.fake_odom:main",
        ],
    },
)
