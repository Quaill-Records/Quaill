"""Second forgery pass: attacks on the signed-time rule, on session relabeling, on unchained
markers used as explanations, and on unchained command traffic used as evidence. Expected results are the
contract AFTER the fixes this pass led to; a row that comes back BUG is a regression.

Run from the repository root:  python tests/attacks/forgery2.py
Writes results-forgery2.json next to this file; logs go to out/.
"""
import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A
from attacklib import CHAIN_TOPIC, CONTROL_TOPIC, SESSION_TOPIC, link_hash, message_hash
T = A.Table()
NS = 1_000_000_000
A.OUT.mkdir(parents=True, exist_ok=True)


def slug(s):
    import re

    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:60].strip("_")


def v_fail_with(*codes):
    return lambda r: "OK" if r["exit"] == 1 and any(c in r["fails"] for c in codes) else "BUG"


def run_both2(name, mutate, expected, verdict_fn, witness="base", pubkey="base", who_at=None, profile=None):
    for encoding in ("json", "cdr"):
        base = A.OUT / f"base-{encoding}"
        header, msgs = A.read_mcap(base)
        new = mutate(list(msgs), encoding)
        out = A.OUT / f"{slug(name)}-{encoding}.mcap"
        A.write_mcap(out, header, new)
        w = str(base) + ".witness.json" if witness == "base" else witness
        k = str(base) + ".pubkey.pem" if pubkey == "base" else pubkey
        r = A.verify(out, witness=w, pubkey=k, profile=profile)
        note = ""
        if who_at:
            rw = A.quaill("who", str(out), "--at", who_at, "--witness", w)
            note = f"who --at {who_at}: " + " | ".join(ln.strip() for ln in rw["stdout"].strip().splitlines()[:3])[:220]
        T.add(f"{name} [{encoding}]", expected, r, verdict_fn(r), note)


def session_msg(msgs, encoding, event, t, sid, prev_sid=None, note=None):
    tpl = next(m for m in msgs if m.topic == SESSION_TOPIC)
    none = None if encoding == "json" else ""
    b = tpl.body()
    b.update(event=event, session_id=sid, prev_session_id=prev_sid if prev_sid is not None else none, note=note if note is not None else none, device_pubkey=none, stamp={"sec": t // NS, "nanosec": t % NS})
    return tpl.with_body(b).clone(log_time=t, publish_time=t)


def relabel_after(msgs, t_cut, new_sid="rec-0002"):
    out = []
    for m in msgs:
        if m.topic == CHAIN_TOPIC and m.log_time > t_cut:
            b = m.body()
            b["session_id"] = new_sid
            m = m.with_body(b)
        out.append(m)
    return out


def t0(msgs):
    return msgs[0].log_time


# ---------------------------------------------------------------- 1. signed time: move the incident instead of the human ----------------------------------------------------------------
def move_bumper_into_human_stretch(msgs, encoding):
    """Only the bumper contact event (05:30, /events) moves to 01:15, inside the MANUAL stretch. Bytes and links untouched."""
    i = next(i for i, m in enumerate(msgs) if m.topic == "/events" and 329 <= A.rel(msgs, m) <= 331)
    t = t0(msgs) + 75 * NS
    msgs[i] = msgs[i].clone(log_time=t, publish_time=t)
    return msgs


run_both2("move-bumper-event-into-human-stretch (log_time only)", move_bumper_into_human_stretch, "one moved message is a moved message: TIME_MOVED fail, exit 1", v_fail_with("TIME_MOVED"), who_at="1:15")


def shift_all_uniform(msgs, encoding):
    """Every message +340 s in bag time: a bag clock that simply differs from the recorder clock. Must not be called tampering."""
    return [m.clone(log_time=m.log_time + 340 * NS, publish_time=m.publish_time + 340 * NS) for m in msgs]


run_both2("shift-ALL-messages-uniformly-340s (false-positive guard)", shift_all_uniform, "one offset absorbs it: no TIME_MOVED, exit 0", lambda r: "OK" if r["exit"] == 0 and "TIME_MOVED" not in r["codes"] and not r["traceback"] else "BUG")


def shift_all_but_human(msgs, encoding):
    """The majority moves, the human stretch stays: the median offset follows the majority and the human stretch is what disagrees."""
    out = []
    for m in msgs:
        r = A.rel(msgs, m)
        if 60 <= r < 90:
            out.append(m)
        else:
            out.append(m.clone(log_time=m.log_time - 340 * NS, publish_time=m.publish_time - 340 * NS))
    return out


run_both2("shift-everything-EXCEPT-human-stretch-340s", shift_all_but_human, "TIME_MOVED fail on the human stretch's control reports, exit 1", v_fail_with("TIME_MOVED"))


# ---------------------------------------------------------------- 2. unchained command traffic as evidence against the maker ----------------------------------------------------------------
def inject_fake_teleop(msgs, encoding):
    """Eight distinct /teleop/cmd_vel messages (no links) at 05:00-05:02 while control was AUTONOMOUS: a claimant 'proving' a hidden human."""
    tpl = next(m for m in msgs if m.topic == "/teleop/cmd_vel")
    for k in range(8):
        b = tpl.body()
        b["linear"] = {"x": 0.1 * (k + 1), "y": 0.0, "z": 0.0}
        b["angular"] = {"x": 0.0, "y": 0.0, "z": 0.05 * k}
        t = t0(msgs) + 300 * NS + k * NS // 4
        msgs.append(tpl.with_body(b).clone(log_time=t, publish_time=t))
    return msgs


run_both2(
    "inject-8-unchained-teleop-messages-while-AUTONOMOUS",
    inject_fake_teleop,
    "the chain node was subscribed to /teleop/cmd_vel and never saw these: MESSAGE_UNCHAINED warn, NO CONTROL_INCONSISTENT, L2 control PASS",
    lambda r: "OK" if "CONTROL_INCONSISTENT" not in r["codes"] and "MESSAGE_UNCHAINED" in r["codes"] and r["grades"].get("L2 control") == "PASS" else "BUG",
)


def hidden_teleop_constant(msgs, encoding):
    """Insider (device key): 20 IDENTICAL teleop messages chained at 05:00-05:04 while control says AUTONOMOUS. One distinct message."""
    tpl = next(m for m in msgs if m.topic == "/teleop/cmd_vel")
    b = tpl.body()
    b["linear"] = {"x": 0.4, "y": 0.0, "z": 0.0}
    b["angular"] = {"x": 0.0, "y": 0.0, "z": 0.0}
    for k in range(20):
        t = t0(msgs) + 300 * NS + k * NS // 5
        msgs.append(tpl.with_body(b).clone(log_time=t, publish_time=t))
    return A.rechain(msgs, signer=A.DEMO_SIGNER)


run_both2("hidden-teleop-CONSTANT-command (insider rechain, 1 distinct message)", hidden_teleop_constant, "below the 5-distinct-messages bar: not caught (design gap, parked-joystick trade-off)", lambda r: "OK" if "CONTROL_INCONSISTENT" in r["fails"] else "DESIGN-GAP", witness="")


# ---------------------------------------------------------------- 3. session relabeling: split one chain in two to hide a cut in the middle ----------------------------------------------------------------
def cut_around_bumper_relabel(msgs, encoding):
    """Remove 1.5 s around the bumper contact (05:29.5-05:31) with their links; relabel every later link as a new session. No witness."""
    a, b = t0(msgs) + int(329.5 * NS), t0(msgs) + 331 * NS
    kept = [m for m in msgs if not (a <= m.log_time <= b)]
    return relabel_after(kept, b)


run_both2("cut-1.5s-around-bumper + relabel session after it (no witness)", cut_around_bumper_relabel, "a later session that begins above link 1 inside a file that holds the earlier session: CHAIN_BROKEN fail, exit 1", v_fail_with("CHAIN_BROKEN"), witness="", who_at="5:30")
run_both2("cut-1.5s-around-bumper + relabel (witness supplied)", cut_around_bumper_relabel, "TRUNCATED or CHAIN_BROKEN, exit 1", v_fail_with("TRUNCATED", "CHAIN_BROKEN"))


def relabel_only(msgs, encoding):
    return relabel_after(msgs, t0(msgs) + 300 * NS)


run_both2("relabel-second-half-only (nothing removed, no witness)", relabel_only, "same rule: CHAIN_BROKEN fail, exit 1", v_fail_with("CHAIN_BROKEN"), witness="")


def erase_two_minutes_relabel_markers(msgs, encoding):
    """Erase 03:20-05:20 (messages and links), relabel later links as rec-0002, and plant an unchained CRASH_NOTE + START at 05:20 so the gap reads as a crash."""
    a, b = t0(msgs) + 200 * NS, t0(msgs) + 320 * NS
    kept = [m for m in msgs if not (a <= m.log_time < b)]
    kept = relabel_after(kept, b - NS)
    kept.append(session_msg(kept, encoding, "CRASH_NOTE", b, "rec-0002", prev_sid="rec-0001", note="previous session ended unexpectedly"))
    kept.append(session_msg(kept, encoding, "START", b + NS // 10, "rec-0002"))
    return kept


run_both2("erase-2min + relabel + forged CRASH_NOTE/START (no witness)", erase_two_minutes_relabel_markers, "CHAIN_BROKEN fail, exit 1 (the forged crash story does not rescue it)", v_fail_with("CHAIN_BROKEN"), witness="")


def erase_two_minutes_clean_story(msgs, encoding):
    """Same erase, but the story is a clean stop: unchained CLEAN_SHUTDOWN at 03:20 and START at 05:20 for the relabeled session."""
    a, b = t0(msgs) + 200 * NS, t0(msgs) + 320 * NS
    kept = [m for m in msgs if not (a <= m.log_time < b)]
    kept = relabel_after(kept, b - NS)
    kept.append(session_msg(kept, encoding, "CLEAN_SHUTDOWN", a, "rec-0001"))
    kept.append(session_msg(kept, encoding, "START", b, "rec-0002"))
    return kept


run_both2("erase-2min + relabel + forged CLEAN_SHUTDOWN/START (no witness)", erase_two_minutes_clean_story, "CHAIN_BROKEN fail, exit 1", v_fail_with("CHAIN_BROKEN"), witness="")


# ---------------------------------------------------------------- 4. an unchained shutdown marker turning a cut into a clean stop ----------------------------------------------------------------
def cut_end_unchained_shutdown(msgs, encoding):
    """Cut after 05:00 and append a CLEAN_SHUTDOWN with no link and no signature (no key needed)."""
    kept = [m for m in msgs if A.rel(msgs, m) <= 300]
    t = kept[-1].log_time + NS // 5
    kept.append(session_msg(kept, encoding, "CLEAN_SHUTDOWN", t, "rec-0001"))
    return kept


run_both2("cut-end + UNCHAINED unsigned CLEAN_SHUTDOWN (no witness)", cut_end_unchained_shutdown, "a shutdown marker the chain never saw proves nothing: ENDING_UNEXPLAINED fail, exit 1", v_fail_with("ENDING_UNEXPLAINED"), witness="")
run_both2("cut-end + UNCHAINED CLEAN_SHUTDOWN (witness supplied)", cut_end_unchained_shutdown, "TRUNCATED, exit 1", v_fail_with("TRUNCATED"))


# ---------------------------------------------------------------- 5. known gaps, re-measured ----------------------------------------------------------------
def delete_first_4s_teleop(msgs, encoding):
    return [m for m in msgs if not (m.topic == "/teleop/cmd_vel" and A.rel(msgs, m) < 64)]


run_both2("delete-first-4s-of-teleop, keep links", delete_first_4s_teleop, "inside the 5 s late-subscription allowance: MESSAGE_BEFORE_START warn only (design gap)", lambda r: "OK" if "MESSAGE_MISSING" in r["fails"] else "DESIGN-GAP")


def manual_report_in_sidecar_gap(encoding):
    """Generated sidecar-restart log (no links 03:20-03:30): plant a MANUAL report at 03:25 and an AUTONOMOUS one at 03:29."""
    info = A.gen(f"sidecar-restart-{encoding}", defect="sidecar-restart", encoding=encoding)
    header, msgs = A.read_mcap(info["path"])
    tpl = next(m for m in msgs if m.topic == CONTROL_TOPIC)
    none = None if encoding == "json" else ""
    for t, mode, op, reason in ((205.0, 4, "op-9999", "planted takeover"), (209.0, 1, none, "planted release")):
        b = tpl.body()
        b.update(mode=mode, mode_name="MANUAL" if mode == 4 else "AUTONOMOUS", operator_ref=op, reason=reason, stamp={"sec": msgs[0].log_time // NS + int(t), "nanosec": 0})
        lt = msgs[0].log_time + int(t * NS)
        msgs.append(tpl.with_body(b).clone(log_time=lt, publish_time=lt))
    out = A.OUT / f"manual-in-sidecar-gap-{encoding}.mcap"
    A.write_mcap(out, header, msgs)
    r = A.verify(out, witness=info["witness"], pubkey=info["pubkey"])
    rw = A.quaill("who", str(out), "--at", "3:25.5", "--witness", info["witness"])
    note = "who --at 3:25.5: " + " | ".join(ln.strip() for ln in rw["stdout"].strip().splitlines()[:4])[:300]
    T.add(f"plant-MANUAL-report-inside-sidecar-outage [{encoding}]", "nothing covers that window: warn only, exit 0 (design gap); `who` must at least say the report is unchained", r, "DESIGN-GAP" if r["exit"] == 0 else "OK", note)


for e in ("json", "cdr"):
    manual_report_in_sidecar_gap(e)

T.dump("forgery2")
