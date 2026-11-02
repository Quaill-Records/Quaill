"""A stop signal must never cut a chain link in half. Needs a sourced ROS 2 environment with ros2_ws built.

The dangerous moment is inside the sidecar's _chain(): the link has taken its seq but is not published yet. Waiting
for a real Ctrl+C to land there is luck, so this test sends the signal at exactly that moment, every time, by wrapping
the chain publisher. Each case runs the sidecar in its own process and logs every link that really went out.

  sigint, sigterm  the sidecar's own main(): the chain must have no gap, the shutdown marker must be chained last,
                   and the state file must say the session ended cleanly
  control          the old handling (KeyboardInterrupt out of spin): must show the gap. If it does not, this test
                   has stopped being able to see the bug, and it fails

    python3 ros2_ws/test_shutdown_signal.py
"""
import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

INJECT_AT_LINK = 5
RATE_HZ = "50"
CASE_TIMEOUT_S = 60
SESSION_TOPIC = "/quaill/session"


def run_child(case: str, workdir: str) -> None:
    import rclpy
    from rclpy.executors import SingleThreadedExecutor
    from rclpy.signals import SignalHandlerOptions

    from quaill_recorder import chain_node

    links = open(Path(workdir) / "links.jsonl", "w", encoding="utf-8")
    sig = signal.SIGTERM if case == "sigterm" else signal.SIGINT
    args = ["--ros-args", "-p", "topics:=['/cmd_vel']", "-p", f"state_dir:={workdir}", "-p", "witness_every_s:=600.0", "-p", "sign:=false"]

    class Instrumented(chain_node.ChainNode):
        def __init__(self):
            super().__init__()
            real_publish = self.pub_chain.publish
            published = [0]

            def publish(msg):
                published[0] += 1
                if published[0] == INJECT_AT_LINK:
                    signal.raise_signal(sig)  # the link has its seq and has not gone out yet
                real_publish(msg)
                links.write(json.dumps({"seq": msg.seq, "prev": msg.prev, "link": msg.link, "topic": msg.topic}) + "\n")
                links.flush()

            self.pub_chain.publish = publish

    if case == "control":
        rclpy.init(args=args, signal_handler_options=SignalHandlerOptions.NO)
        signal.signal(signal.SIGINT, signal.default_int_handler)
        node = Instrumented()
        executor = SingleThreadedExecutor()
        executor.add_node(node)
        try:
            executor.spin()
        except KeyboardInterrupt:
            pass
        finally:
            node.shutdown_clean()
            executor.shutdown()
            node.destroy_node()
            rclpy.shutdown()
    else:
        chain_node.ChainNode = Instrumented
        chain_node.main(args=args)


def read_case(workdir: str) -> tuple[list[dict], list[str]]:
    path = Path(workdir) / "links.jsonl"
    links = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []
    gaps = []
    for a, b in zip(links, links[1:]):
        if b["seq"] != a["seq"] + 1:
            gaps.append(f"seq {a['seq']} then {b['seq']}")
        elif b["prev"] != a["link"]:
            gaps.append(f"link {b['seq']} does not point at link {a['seq']}")
    return links, gaps


def run_case(case: str) -> str | None:
    """Returns what went wrong, or None."""
    with tempfile.TemporaryDirectory(prefix=f"quaill-signal-{case}-") as workdir:
        try:
            p = subprocess.run([sys.executable, __file__, "--child", case, workdir], timeout=CASE_TIMEOUT_S, capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return f"did not stop within {CASE_TIMEOUT_S} s"
        links, gaps = read_case(workdir)
        print(f"{case}: exit {p.returncode}, {len(links)} links, gaps: {gaps or 'none'}")
        if len(links) < INJECT_AT_LINK:
            return f"only {len(links)} links went out; the signal was never injected\n{p.stderr[-1500:]}"
        if case == "control":
            return None if gaps else "the old handling showed no gap, so this test can no longer see the bug"
        if p.returncode != 0:
            return f"exit {p.returncode}\n{p.stderr[-1500:]}"
        if gaps:
            return f"chain gap: {gaps}"
        if links[-1]["topic"] != SESSION_TOPIC:
            return f"last link is on {links[-1]['topic']}, not the chained shutdown marker"
        state = json.loads((Path(workdir) / "session.json").read_text(encoding="utf-8"))
        if not state.get("clean_end"):
            return "the state file does not say the session ended cleanly"
    return None


def main() -> int:
    publisher = subprocess.Popen(["ros2", "topic", "pub", "-r", RATE_HZ, "/cmd_vel", "geometry_msgs/msg/Twist", "{}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failed = 0
    try:
        time.sleep(3)
        for case in ("sigint", "sigterm", "control"):
            problem = run_case(case)
            if problem:
                failed += 1
                print(f"FAIL {case}: {problem}")
            else:
                print(f"ok: {case}")
    finally:
        publisher.terminate()
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        run_child(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit(main())
