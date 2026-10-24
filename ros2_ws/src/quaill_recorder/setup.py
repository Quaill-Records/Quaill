import os
from glob import glob

from setuptools import find_packages, setup

package_name = "quaill_recorder"

setup(
    name=package_name,
    version="0.0.2",
    packages=find_packages(exclude=["test"]),
    data_files=[
        ("share/ament_index/resource_index/packages", ["resource/" + package_name]),
        ("share/" + package_name, ["package.xml"]),
        (os.path.join("share", package_name, "launch"), glob("launch/*.launch.py")),
        (os.path.join("share", package_name, "config"), glob("config/*.yaml")),
    ],
    install_requires=["setuptools"],
    zip_safe=True,
    maintainer="Quaill",
    maintainer_email="254507736+Deseace@users.noreply.github.com",
    description="Sidecar nodes: hash-chain links, control-mode reports, session markers, witness heads.",
    license="Apache-2.0",
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "chain = quaill_recorder.chain_node:main",
            "control_mode = quaill_recorder.control_mode_node:main",
        ],
    },
)
