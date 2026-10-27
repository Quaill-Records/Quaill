#!/usr/bin/env bash
# Records the test bags on a real ROS 2 Jazzy system with nobody at a keyboard, then runs the checker on each.
#
# Real: ROS 2, the Quaill sidecars, `ros2 bag record`, the bag files. Fake: the robot (quaill_demo_robot,
# no motors, no simulator). The operator is `scripted_teleop`, a timed stand-in for teleop_twist_keyboard.
# Not a physical robot.
#
# Needs a sourced ROS 2 Jazzy environment with ros2_ws built, and the checker as `quaill` on PATH
# (or QUAILL_BIN=/path/to/quaill). The sidecar keeps its state in ~/.quaill (QUAILL_STATE_DIR to change);
# this script wipes it before each run.
#
#   bash ros2_ws/record_runs.sh [OUT_DIR]        default ./ros2-runs
#
# OUT_DIR/<run>/           the bag, plus witness/ and device.pubkey.pem copied in from the sidecar's state dir,
#                          which is where the checker looks for them by itself
# OUT_DIR/logs/            stdout+stderr of every process
# OUT_DIR/reports/         checker output, text and JSON, per run and profile
# OUT_DIR/rmw.txt          the RMW implementation that was in use
#
# Then: python3 ros2_ws/summarize_runs.py OUT_DIR
#
# The runs, in order:
#   run1   clean: robot + sidecars, bag recorded, two scripted takeovers, everything stopped in the right order
#   run0   the same robot with no Quaill nodes at all (what a deployer has today)
#   run2   the bag recorder is killed -9 mid-run; the sidecar runs on and stops cleanly
#   run3   the chain sidecar is killed -9 mid-run and restarted 10 s later
#   run4a  power cut: every process killed -9 at once
#   run4b  restart after the power cut, recorded into a second bag (should begin with a CRASH_NOTE)
set -uo pipefail

OUT="$(realpath -m "${1:-$PWD/ros2-runs}")"
STATE="${QUAILL_STATE_DIR:-$HOME/.quaill}"
QUAILL="${QUAILL_BIN:-quaill}"
ROBOT_TOPICS="/cmd_vel /odom /auto/cmd_vel /teleop/cmd_vel"
QUAILL_TOPICS="/quaill/control_mode /quaill/session /quaill/chain"
CONFIG="$(ros2 pkg prefix quaill_recorder)/share/quaill_recorder/config/default.yaml"
export PYTHONUNBUFFERED=1 RCUTILS_LOGGING_BUFFERED_STREAM=0 RCUTILS_COLORIZED_OUTPUT=0
mkdir -p "$OUT/logs" "$OUT/reports"
if [ -n "${QUAILL_TSA_URL:-}" ]; then  # real RFC 3161 receipts on every witness head; needs rfc3161ng on the ROS python3
  sed "s|tsa_url: \"\"|tsa_url: \"$QUAILL_TSA_URL\"|" "$CONFIG" >"$OUT/recorder.yaml"
  CONFIG="$OUT/recorder.yaml"
  python3 -c "import rfc3161ng" 2>/dev/null || echo "!! QUAILL_TSA_URL is set but the ROS python3 cannot import rfc3161ng; receipts will carry an error" >&2
fi

say() { printf '\n== %s  (%s)\n' "$1" "$(date -u +%H:%M:%S)"; }

# Every background process gets its own process group (setsid) so a "power cut" can take it and its children.
# A script's background jobs start with SIGINT ignored; env --default-signal=INT restores it so `stop` acts like Ctrl+C.
bg() { local name=$1; shift; setsid env --default-signal=INT "$@" >"$OUT/logs/$name.log" 2>&1 & echo $!; }
alive() { kill -0 "$1" 2>/dev/null; }
wait_log() { # file pattern seconds
  local i; for ((i = 0; i < $3 * 2; i++)); do grep -q -- "$2" "$1" 2>/dev/null && return 0; sleep 0.5; done
  echo "!! timed out after $3 s waiting for '$2' in $1" >&2; tail -n 20 "$1" >&2; return 1
}
wait_gone() { # pid seconds
  local i; for ((i = 0; i < $2 * 2; i++)); do alive "$1" || return 0; sleep 0.5; done
  echo "!! pid $1 still alive after $2 s; killing its process group" >&2; kill -9 -- "-$1" 2>/dev/null; return 0
}
stop() { kill -INT "$1" 2>/dev/null; wait_gone "$1" "${2:-30}"; }   # what Ctrl+C in a terminal would do
cut_power() { kill -9 -- "-$1" 2>/dev/null; }                      # no warning, no shutdown hooks

launch() { # name: the fake robot plus both sidecars, via demo.launch.py
  LAUNCH_PID=$(bg "$1-launch" ros2 launch quaill_demo_robot demo.launch.py "config:=$CONFIG")
  wait_log "$OUT/logs/$1-launch.log" "quaill_chain session" 90 || return 1
  wait_log "$OUT/logs/$1-launch.log" "chaining /cmd_vel" 30 || true
  sleep 1
}
record() { # name topics...: start `ros2 bag record` into OUT/name and wait until it is recording
  local name=$1; shift
  BAG_PID=$(bg "$name-bag" ros2 bag record -s mcap -o "$OUT/$name" "$@")
  wait_log "$OUT/logs/$name-bag.log" "Recording..." 60 || return 1
  sleep 2
}
drive() { # pattern name: the scripted operator, blocking until its pattern is done
  ros2 run quaill_demo_robot scripted_teleop --ros-args -p "pattern:=$1" >"$OUT/logs/$2.log" 2>&1
}
attach() { # name: copy the sidecar's witness file(s) and public key next to the bag; the checker finds them there
  mkdir -p "$OUT/$1/witness"
  cp "$STATE"/witness-*.json "$OUT/$1/witness/" 2>/dev/null
  cp "$STATE/device.pubkey.pem" "$OUT/$1/" 2>/dev/null
  true
}
target_of() { # name: the bag directory, or the single .mcap when the recorder died before writing metadata.yaml
  if [ -f "$OUT/$1/metadata.yaml" ]; then echo "$OUT/$1"; else ls "$OUT/$1"/*.mcap 2>/dev/null | head -n 1; fi
}
check() { # name profile: reports/<name>.<profile>.txt and .json
  local name=$1 profile=$2 target base w k
  target="$(target_of "$name")"
  base="$OUT/reports/$name.$profile"
  w="$OUT/$name/witness"; [ -d "$w" ] && ls "$w"/*.json >/dev/null 2>&1 || w=""
  k="$OUT/$name/device.pubkey.pem"; [ -f "$k" ] || k=""
  if [ -z "$target" ]; then echo "!! $name: no bag file to check" >&2; echo "exit 2" >"$base.txt"; return; fi
  "$QUAILL" verify "$target" --profile "$profile" --witness "$w" --pubkey "$k" --out "$base.json" >"$base.txt" 2>&1
  echo "exit $?" >>"$base.txt"
  echo "-- $name against $profile:"; sed -n '1,14p' "$base.txt"; tail -n 1 "$base.txt"
}
kill_strays() { pkill -9 -f "lib/quaill_demo_robot/|lib/quaill_recorder/|ros2 bag record" 2>/dev/null; true; }

say "environment"
python3 -c 'import rclpy; rclpy.init(); from rclpy.utilities import get_rmw_implementation_identifier as g; print(g())' | tee "$OUT/rmw.txt"
"$QUAILL" --version | tee "$OUT/checker-version.txt"
ros2 pkg list | grep -E "^quaill_" | tee "$OUT/packages.txt"
echo "state dir: $STATE"
echo "${QUAILL_TSA_URL:-none}" | tee "$OUT/tsa.txt" | sed 's/^/timestamp authority: /'
kill_strays

say "run1: clean run, two scripted takeovers"
rm -rf "$STATE"
launch run1 && record run1 $ROBOT_TOPICS $QUAILL_TOPICS && {
  drive "[15.0,10.0,15.0,15.0]" run1-teleop
  stop "$LAUNCH_PID"     # sidecar first, so CLEAN_SHUTDOWN and the last witness head reach the bag
  sleep 1
  stop "$BAG_PID"
  attach run1
  check run1 quaill-control
  "$QUAILL" who "$OUT/run1" --at 0:20 >"$OUT/reports/run1.who.txt" 2>&1; cat "$OUT/reports/run1.who.txt"
}
kill_strays

say "run0: the same robot with no Quaill nodes (what a deployer has today)"
rm -rf "$STATE"
P1=$(bg run0-mode_manager ros2 run quaill_demo_robot mode_manager)
P2=$(bg run0-auto_driver ros2 run quaill_demo_robot auto_driver)
P3=$(bg run0-fake_odom ros2 run quaill_demo_robot fake_odom)
sleep 3
record run0 $ROBOT_TOPICS && {
  drive "[10.0,8.0]" run0-teleop
  stop "$BAG_PID"; stop "$P1" 5; stop "$P2" 5; stop "$P3" 5
  check run0 none
  check run0 quaill-control
  check run0 stvfernlv-anlage3
}
kill_strays

say "run2: the bag recorder is killed -9 mid-run; the sidecar runs on and stops cleanly"
rm -rf "$STATE"
launch run2 && record run2 $ROBOT_TOPICS $QUAILL_TOPICS && {
  TELEOP_PID=$(bg run2-teleop ros2 run quaill_demo_robot scripted_teleop --ros-args -p "pattern:=[10.0,8.0,10.0,8.0]")
  sleep 16
  cut_power "$BAG_PID"
  wait_gone "$TELEOP_PID" 60
  stop "$LAUNCH_PID"
  attach run2
  check run2 quaill-control
}
kill_strays

say "run3: the chain sidecar is killed -9 mid-run and restarted 10 s later"
rm -rf "$STATE"
launch run3 && record run3 $ROBOT_TOPICS $QUAILL_TOPICS && {
  TELEOP_PID=$(bg run3-teleop ros2 run quaill_demo_robot scripted_teleop --ros-args -p "pattern:=[10.0,8.0,10.0,12.0]")
  sleep 12
  pkill -9 -f "lib/quaill_recorder/chain" || echo "!! chain node not found to kill" >&2
  sleep 10
  CHAIN2_PID=$(bg run3-chain2 ros2 run quaill_recorder chain --ros-args --params-file "$CONFIG")
  wait_log "$OUT/logs/run3-chain2.log" "quaill_chain session" 30
  wait_gone "$TELEOP_PID" 60
  stop "$CHAIN2_PID"; stop "$LAUNCH_PID"; sleep 1; stop "$BAG_PID"
  attach run3
  check run3 quaill-control
}
kill_strays

say "run4: power cut (everything killed -9 at once), then a restart recorded into a second bag"
rm -rf "$STATE"
launch run4a && record run4a $ROBOT_TOPICS $QUAILL_TOPICS && {
  TELEOP_PID=$(bg run4a-teleop ros2 run quaill_demo_robot scripted_teleop --ros-args -p "pattern:=[10.0,8.0,10.0,8.0]")
  sleep 14
  cut_power "$TELEOP_PID"; cut_power "$LAUNCH_PID"; cut_power "$BAG_PID"; kill_strays
  sleep 2
  attach run4a
  check run4a quaill-control
  launch run4b && record run4b $ROBOT_TOPICS $QUAILL_TOPICS && {   # the sidecar finds the dirty session file: CRASH_NOTE, then START
    drive "[10.0,8.0]" run4b-teleop
    stop "$LAUNCH_PID"; sleep 1; stop "$BAG_PID"
    attach run4b
    check run4b quaill-control
  }
}
kill_strays

say "done: bags, logs and reports are in $OUT"
ls -la "$OUT" "$OUT/reports"
