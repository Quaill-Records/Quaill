"""Forgeries against a clean generated log, in json and cdr. Expected results per THREAT-MODEL.md.

Run from the repository root:  python tests/attacks/forgery.py
Writes results-forgery.json next to this file; logs go to out/.
"""
import json
import shutil
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A
from attacklib import CHAIN_TOPIC, CONTROL_TOPIC, SESSION_TOPIC, M, enc, link_hash, message_hash

T = A.Table()
NS = 1_000_000_000


def slug(s):
    import re
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:60].strip("_")


def human_control(msgs):
    """Indices of MANUAL control reports (01:00-01:30 in the delivery scenario)."""
    return [i for i, m in enumerate(msgs) if m.topic == CONTROL_TOPIC and 60 <= A.rel(msgs, m) < 90]


def run_both(name, mutate, expected, verdict_fn, witness="base", pubkey="base", who_at=None):
    """mutate(msgs, enc) -> new list. Runs the mutated log through verify in json and cdr."""
    for encoding in ("json", "cdr"):
        base = A.OUT / f"base-{encoding}"
        header, msgs = A.read_mcap(base)
        new = mutate(list(msgs), encoding)
        out = A.OUT / f"{slug(name)}-{encoding}.mcap"
        A.write_mcap(out, header, new)
        w = str(base) + ".witness.json" if witness == "base" else witness
        k = str(base) + ".pubkey.pem" if pubkey == "base" else pubkey
        r = A.verify(out, witness=w, pubkey=k)
        note = ""
        if who_at:
            rw = A.quaill("who", str(out), "--at", who_at, "--witness", w)
            note = f"who --at {who_at}: " + rw["stdout"].strip().splitlines()[0][:110]
        T.add(f"{name} [{encoding}]", expected, r, verdict_fn(r), note)


def v_fail_with(*codes):
    """Caught: exit 1 AND one of these fail codes present."""
    return lambda r: "OK" if r["exit"] == 1 and any(c in r["fails"] for c in codes) else "BUG"


def v_exit0_gap(label="DESIGN-GAP"):
    """Not caught at L1: the integrity grade is not FAIL (exit may still be 1 through an unrelated L2 finding)."""
    return lambda r: label if r["grades"].get("L1 integrity") != "FAIL" else "OK"


def v_exit0_ok(r):  # the honest table says this is not catchable
    return "OK" if r["exit"] == 0 and not r["traceback"] else "BUG"


# ---------------------------------------------------------------- 1. forgeries that should be caught ----------------------------------------------------------------
def edit_one(msgs, encoding):
    i = human_control(msgs)[5]
    b = msgs[i].body()
    b.update(mode=1, mode_name="AUTONOMOUS", operator_ref=None if encoding == "json" else "", reason=None if encoding == "json" else "")
    msgs[i] = msgs[i].with_body(b)
    return msgs


run_both("edit-one-message", edit_one, "MESSAGE_EDITED, exit 1", v_fail_with("MESSAGE_EDITED"))


def edit_one_byte(msgs, encoding):
    i = next(i for i, m in enumerate(msgs) if m.topic == "/odom" and A.rel(msgs, m) > 100)
    d = bytearray(msgs[i].data)
    d[-1] ^= 0x01
    msgs[i] = msgs[i].clone(data=bytes(d))
    return msgs


run_both("flip-one-byte-odom", edit_one_byte, "MESSAGE_EDITED, exit 1", v_fail_with("MESSAGE_EDITED"))


def delete_one(msgs, encoding):
    del msgs[human_control(msgs)[5]]
    return msgs


run_both("delete-one-message-keep-link", delete_one, "MESSAGE_MISSING, exit 1", v_fail_with("MESSAGE_MISSING"))


def delete_with_link(msgs, encoding):
    i = human_control(msgs)[5]
    j = A.link_for(msgs, i)
    for k in sorted({i, j}, reverse=True):
        del msgs[k]
    return msgs


run_both("delete-message-and-its-link", delete_with_link, "CHAIN_BROKEN, exit 1", v_fail_with("CHAIN_BROKEN"))


def delete_human_stretch_and_links(msgs, encoding):
    hs = set(human_control(msgs))
    ls = {A.link_for(msgs, i) for i in hs}
    return [m for i, m in enumerate(msgs) if i not in hs and i not in ls]


run_both("delete-human-stretch-and-links", delete_human_stretch_and_links, "CHAIN_BROKEN, exit 1", v_fail_with("CHAIN_BROKEN"))


def reorder_swap_times(msgs, encoding):
    """Swap the log_time of a MANUAL report (01:05) with an AUTONOMOUS one (06:40); bytes unchanged, links unchanged."""
    i = human_control(msgs)[5]
    j = next(k for k, m in enumerate(msgs) if m.topic == CONTROL_TOPIC and A.rel(msgs, m) == 400)
    ti, tj = msgs[i].log_time, msgs[j].log_time
    msgs[i] = msgs[i].clone(log_time=tj, publish_time=tj)
    msgs[j] = msgs[j].clone(log_time=ti, publish_time=ti)
    return msgs


run_both("reorder-swap-log-times", reorder_swap_times, "THREAT-MODEL: 'set the clock back: partly' (TIME_ORDER/CLOCK_SKEW warn); a hard fail would be better", v_exit0_gap(), who_at="6:40")


def duplicate_message(msgs, encoding):
    i = human_control(msgs)[5]
    msgs.append(msgs[i].clone(log_time=msgs[i].log_time + 300 * NS, publish_time=msgs[i].log_time + 300 * NS))
    return msgs


run_both("duplicate-message-no-link", duplicate_message, "a control report duplicated inside the chain's coverage: MESSAGE_UNCHAINED fail, exit 1", v_fail_with("MESSAGE_UNCHAINED"), who_at="6:05")


def duplicate_with_link(msgs, encoding):
    i = human_control(msgs)[5]
    j = A.link_for(msgs, i)
    t = msgs[i].log_time + 300 * NS
    msgs.append(msgs[i].clone(log_time=t, publish_time=t))
    msgs.append(msgs[j].clone(log_time=t, publish_time=t))
    return msgs


run_both("duplicate-message-and-link", duplicate_with_link, "CHAIN_BROKEN (duplicate seq), exit 1", v_fail_with("CHAIN_BROKEN"))


def swap_announced_pubkey(msgs, encoding):
    i = next(i for i, m in enumerate(msgs) if m.topic == SESSION_TOPIC)
    b = msgs[i].body()
    b["device_pubkey"] = A.FRESH_SIGNER.pub_hex()
    msgs[i] = msgs[i].with_body(b)
    return msgs


run_both("swap-announced-pubkey-only", swap_announced_pubkey, "START is chained: MESSAGE_EDITED, exit 1", lambda r: "OK" if "MESSAGE_EDITED" in r["fails"] else ("BUG" if r["exit"] == 1 else "BUG"), pubkey="")


# ---- the late-start tolerance: the first message on each topic is not protected ----
def edit_first_on_topic(msgs, encoding):
    i = next(i for i, m in enumerate(msgs) if m.topic == "/odom")
    d = bytearray(msgs[i].data)
    d[-1] ^= 0x01
    msgs[i] = msgs[i].clone(data=bytes(d))
    return msgs


run_both("edit FIRST message on /odom (byte flip)", edit_first_on_topic, "MESSAGE_EDITED, exit 1", v_fail_with("MESSAGE_EDITED"))


def delete_first_on_topic(msgs, encoding):
    i = next(i for i, m in enumerate(msgs) if m.topic == "/events")  # the stuck_detected event at 00:52
    del msgs[i]
    return msgs


run_both("delete FIRST message on /events (stuck_detected), keep link", delete_first_on_topic, "MESSAGE_MISSING, exit 1", v_fail_with("MESSAGE_MISSING"))


def delete_all_teleop(msgs, encoding):
    return [m for m in msgs if m.topic != "/teleop/cmd_vel"]


run_both("delete ALL /teleop/cmd_vel messages, keep their 150 links", delete_all_teleop, "MESSAGE_MISSING, exit 1", v_fail_with("MESSAGE_MISSING"))


def delete_first_control_reports(msgs, encoding):
    """Remove the first 12 control reports (00:00-00:11) and leave their links."""
    idx = [i for i, m in enumerate(msgs) if m.topic == CONTROL_TOPIC][:12]
    return [m for i, m in enumerate(msgs) if i not in set(idx)]


run_both("delete first 12 control reports, keep links", delete_first_control_reports, "MESSAGE_MISSING, exit 1", v_fail_with("MESSAGE_MISSING"))


def edit_first_k_on_topic(msgs, encoding):
    """Edit the first 3 /events... only 2 exist; edit first 5 /odom messages instead."""
    idx = [i for i, m in enumerate(msgs) if m.topic == "/odom"][:5]
    for i in idx:
        d = bytearray(msgs[i].data)
        d[-1] ^= 0x01
        msgs[i] = msgs[i].clone(data=bytes(d))
    return msgs


run_both("edit first 5 /odom messages", edit_first_k_on_topic, "MESSAGE_EDITED, exit 1", v_fail_with("MESSAGE_EDITED"))


def append_after_shutdown(msgs, encoding):
    last = msgs[-1]
    t0 = last.log_time
    odom = next(m for m in msgs if m.topic == "/odom")
    for k in range(1, 6):
        msgs.append(odom.clone(log_time=t0 + k * NS // 5, publish_time=t0 + k * NS // 5))  # same bytes, inside the 1 s marker tolerance
    return msgs


run_both("append-after-shutdown-within-1s", append_after_shutdown, "unchained messages after the end marker; MESSAGE_UNCHAINED warn only -> exit 0", v_exit0_gap())


def append_after_shutdown_far(msgs, encoding):
    last = msgs[-1]
    odom = next(m for m in msgs if m.topic == "/odom")
    for k in range(1, 6):
        t = last.log_time + 3 * NS + k * NS // 5
        msgs.append(odom.clone(log_time=t, publish_time=t))
    return msgs


run_both("append-after-shutdown-3s-later", append_after_shutdown_far, "ENDING_UNMARKED is a warn when the witness covers the last link -> exit 0", v_exit0_gap())


def inject_manual_report(msgs, encoding):
    """Insert a fake MANUAL control report (operator named) at 05:29 and an AUTONOMOUS one at 05:33: the bumper contact at 05:30 now happens under a human."""
    tpl = next(m for m in msgs if m.topic == CONTROL_TOPIC)
    none = None if encoding == "json" else ""
    for t, mode, op, reason in ((329.5, 4, "op-9999", "injected takeover"), (333.0, 1, none, "injected release")):
        b = tpl.body()
        b.update(mode=mode, mode_name="MANUAL" if mode == 4 else "AUTONOMOUS", operator_ref=op, reason=reason, stamp={"sec": msgs[0].log_time // NS + int(t), "nanosec": int((t % 1) * NS)})
        lt = msgs[0].log_time + int(t * NS)
        msgs.append(tpl.with_body(b).clone(log_time=lt, publish_time=lt))
    return msgs


run_both("inject-fake-MANUAL-report-at-bumper", inject_manual_report, "an inserted control report inside the chain's coverage: MESSAGE_UNCHAINED fail, exit 1 (who still answers from the file as written)", v_fail_with("MESSAGE_UNCHAINED"), who_at="329.7")


def prepend_before_start(msgs, encoding):
    tpl = next(m for m in msgs if m.topic == CONTROL_TOPIC)
    t = msgs[0].log_time - 3 * NS // 2  # 1.5 s before START: outside the 1 s marker tolerance, inside the 2 s gap threshold
    b = tpl.body()
    b.update(mode=4, mode_name="MANUAL", operator_ref="op-0000", stamp={"sec": t // NS, "nanosec": t % NS})
    msgs.append(tpl.with_body(b).clone(log_time=t, publish_time=t))
    return msgs


run_both("prepend-MANUAL-report-1.5s-before-START", prepend_before_start, "inserted message before START: warn only -> exit 0", v_exit0_gap(), who_at="0")


def prepend_fake_crash_note(msgs, encoding):
    tpl = next(m for m in msgs if m.topic == SESSION_TOPIC)
    t = msgs[0].log_time - 3 * NS // 2
    b = tpl.body()
    b.update(event="CRASH_NOTE", note="forged: previous session ended unexpectedly", prev_session_id="s-000", stamp={"sec": t // NS, "nanosec": t % NS})
    msgs.append(tpl.with_body(b).clone(log_time=t, publish_time=t))
    return msgs


run_both("prepend-fake-CRASH_NOTE", prepend_fake_crash_note, "unchained session marker before the first matched message counts as 'latched' (info) -> exit 0", v_exit0_gap())


def move_human_stretch(msgs, encoding):
    """Rewrite log_time only: everything in 01:00-01:30 moves to 06:40-07:10 and vice versa. Bytes and links untouched."""
    out = []
    for m in msgs:
        r = A.rel(msgs, m)
        if 60 <= r < 90:
            t = m.log_time + 340 * NS
        elif 400 <= r < 430:
            t = m.log_time - 340 * NS
        else:
            t = m.log_time
        out.append(m.clone(log_time=t, publish_time=t))
    return out


run_both("move-human-stretch-log_time-only", move_human_stretch, "recv_time in the signed link disagrees with log_time by 340 s: CLOCK_SKEW/TIME_ORDER are warns -> exit 0, timeline follows the forged times", v_exit0_gap(), who_at="1:15")


def shift_human_stretch_4s(msgs, encoding):
    """Shift only the human stretch by 4 s (inside SKEW_TOLERANCE); keeps order among control reports but not among all messages."""
    out = []
    for m in msgs:
        r = A.rel(msgs, m)
        t = m.log_time + 4 * NS if (60 <= r < 90 and m.topic == CONTROL_TOPIC) else m.log_time
        out.append(m.clone(log_time=t, publish_time=t))
    return out


run_both("shift-MANUAL-reports-4s", shift_human_stretch_4s, "inside the 5 s skew tolerance and 1 s order tolerance: no finding at all", lambda r: "DESIGN-GAP" if r["exit"] == 0 and "CLOCK_SKEW" not in r["codes"] and "TIME_ORDER" not in r["codes"] else "OK")


def truncate_mid_message(encoding):
    base = A.OUT / f"base-{encoding}"
    data = base.read_bytes()
    cut = int(len(data) * 0.6)
    out = A.OUT / f"truncate-mid-message-{encoding}.mcap"
    out.write_bytes(data[:cut])
    return out, base


for encoding in ("json", "cdr"):
    out, base = truncate_mid_message(encoding)
    r = A.verify(out, witness=str(base) + ".witness.json", pubkey=str(base) + ".pubkey.pem")
    T.add(f"truncate-mid-message (byte cut at 60%) [{encoding}]", "FILE_NOT_FINALIZED + TRUNCATED (witness), exit 1", r, "OK" if r["exit"] == 1 and "TRUNCATED" in r["fails"] and "FILE_NOT_FINALIZED" in r["codes"] else "BUG")
    r = A.verify(out, witness="", pubkey=str(base) + ".pubkey.pem")
    T.add(f"truncate-mid-message, no witness [{encoding}]", "ENDING_UNEXPLAINED, exit 1", r, "OK" if r["exit"] == 1 and "ENDING_UNEXPLAINED" in r["fails"] else "BUG")


# ---------------------------------------------------------------- my own: chain / signature / session attacks ----------------------------------------------------------------
def strip_chain(msgs, encoding):
    return [m for m in msgs if m.topic != CHAIN_TOPIC]


run_both("strip-chain-entirely (witness + pubkey supplied)", strip_chain, "the witness proves a chain existed: WITNESS_WITHOUT_CHAIN, exit 1", v_fail_with("WITNESS_WITHOUT_CHAIN"))


def edit_strip_chain(msgs, encoding):
    return strip_chain(edit_one(delete_one(msgs, encoding), encoding), encoding)


run_both("edit+delete then strip chain (witness + pubkey supplied)", edit_strip_chain, "same: WITNESS_WITHOUT_CHAIN, exit 1", v_fail_with("WITNESS_WITHOUT_CHAIN"))


def rechain_unsigned(msgs, encoding):
    new = edit_one_byte(msgs, encoding)
    return A.rechain(new, signer=None)


run_both("edit, rebuild chain UNSIGNED, --pubkey supplied, no witness", rechain_unsigned, "README: 'fails KEY_MISMATCH the moment the real device key is supplied': KEY_MISMATCH, exit 1", v_fail_with("KEY_MISMATCH"), witness="")


def rechain_fresh_key_announce(msgs, encoding):
    new = swap_announced_pubkey(edit_one_byte(msgs, encoding), encoding)
    return A.rechain(new, signer=A.FRESH_SIGNER)


run_both("edit, rebuild chain with fresh key + swapped announcement, --pubkey, no witness", rechain_fresh_key_announce, "KEY_MISMATCH, exit 1", v_fail_with("KEY_MISMATCH"), witness="")
run_both("same, no pubkey, no witness (honest table: not catchable)", rechain_fresh_key_announce, "SIGNED_ANNOUNCED, exit 0 by design", v_exit0_ok, witness="", pubkey="")
run_both("same, with witness", rechain_fresh_key_announce, "WITNESS_MISMATCH, exit 1", v_fail_with("WITNESS_MISMATCH", "WITNESS_KEY_MISMATCH"), pubkey="")


def rename_session(msgs, encoding):
    out = []
    for m in msgs:
        if m.topic == CHAIN_TOPIC:
            b = m.body()
            b["session_id"] = "rec-9999"
            m = m.with_body(b)
        out.append(m)
    return out


run_both("rename session_id on every link (not signed, not in link hash)", rename_session, "the witness matches no session in the file: WITNESS_UNMATCHED, exit 1", v_fail_with("WITNESS_UNMATCHED"))


def rename_session_and_truncate(msgs, encoding):
    """Insider: cut after 05:00, append a CLEAN_SHUTDOWN signed with the device key, relabel the session so the witness cannot match."""
    kept = [m for m in msgs if A.rel(msgs, m) <= 300]
    last_link = max((m.body() for m in kept if m.topic == CHAIN_TOPIC), key=lambda d: d["seq"])
    tpl_s = next(m for m in msgs if m.topic == SESSION_TOPIC)
    tpl_c = next(m for m in msgs if m.topic == CHAIN_TOPIC)
    t = kept[-1].log_time + NS // 5
    b = tpl_s.body()
    b.update(event="CLEAN_SHUTDOWN", note=None if encoding == "json" else "", device_pubkey=None if encoding == "json" else "", stamp={"sec": t // NS, "nanosec": t % NS})
    sd = tpl_s.with_body(b).clone(log_time=t, publish_time=t)
    mh = message_hash(SESSION_TOPIC, sd.data)
    seq = last_link["seq"] + 1
    lh = link_hash(last_link["link"], mh, seq, t, SESSION_TOPIC)
    rec = {"session_id": last_link["session_id"], "seq": seq, "topic": SESSION_TOPIC, "msg_sha256": mh, "prev": last_link["link"], "link": lh, "recv_time": t, "key_id": A.DEMO_SIGNER.key_id, "sig": A.DEMO_SIGNER.sign_link(lh)}
    kept += [sd, tpl_c.with_body(rec).clone(log_time=t, publish_time=t)]
    return rename_session(kept, encoding)


run_both("insider truncation + forged shutdown + session relabel (witness supplied)", rename_session_and_truncate, "relabeling no longer hides the cut: WITNESS_UNMATCHED, exit 1", v_fail_with("WITNESS_UNMATCHED"))


def truncate_insider(msgs, encoding):
    return [m for m in rename_session_and_truncate(msgs, encoding)]


def truncate_insider_keep_session(msgs, encoding):
    kept = rename_session_and_truncate(msgs, encoding)
    out = []
    for m in kept:
        if m.topic == CHAIN_TOPIC:
            b = m.body()
            b["session_id"] = "rec-0001"
            m = m.with_body(b)
        out.append(m)
    return out


run_both("insider truncation + forged shutdown (control: session kept)", truncate_insider_keep_session, "TRUNCATED, exit 1", v_fail_with("TRUNCATED"))


def fix_link_after_edit(msgs, encoding):
    """Edit a message and recompute its own link's msg_sha256 + link hash (attacker without the key signs nothing)."""
    i = human_control(msgs)[5]
    j = A.link_for(msgs, i)
    new = edit_one(msgs, encoding)
    d = new[j].body()
    d["msg_sha256"] = message_hash(new[i].topic, new[i].data)
    d["link"] = link_hash(d["prev"], d["msg_sha256"], d["seq"], d["recv_time"], d["topic"])
    new[j] = new[j].with_body(d)
    return new


run_both("edit message and recompute its link (sig left stale)", fix_link_after_edit, "SIGNATURE_INVALID and CHAIN_BROKEN at the next link, exit 1", v_fail_with("SIGNATURE_INVALID", "CHAIN_BROKEN"))


# ---------------------------------------------------------------- 2. forgeries the honest table says are NOT catchable ----------------------------------------------------------------
def rechain_fresh_key_nowitness(msgs, encoding):
    return A.rechain(swap_announced_pubkey(edit_one_byte(msgs, encoding), encoding), signer=A.FRESH_SIGNER)


run_both("rebuild whole chain, fresh key, swapped announcement, no witness, no pubkey", rechain_fresh_key_nowitness, "not catchable (honest table): exit 0", v_exit0_ok, witness="", pubkey="")


def rechain_device_key_nowitness(msgs, encoding):
    return A.rechain(edit_one_byte(msgs, encoding), signer=A.DEMO_SIGNER)


run_both("insider rebuild with device key, no witness, --pubkey", rechain_device_key_nowitness, "not catchable (honest table): SIGNED_TRUSTED, exit 0", v_exit0_ok, witness="")


def cut_end_no_witness(msgs, encoding):
    return [m for m in msgs if A.rel(msgs, m) <= 300]


run_both("cut the end, no forged marker, no witness", cut_end_no_witness, "ENDING_UNEXPLAINED fail (honest: cannot tell crash from cut)", v_fail_with("ENDING_UNEXPLAINED"), witness="")
run_both("insider cut + forged shutdown signed with device key, no witness", truncate_insider_keep_session, "not catchable (honest table): exit 0", v_exit0_ok, witness="")


# ---------------------------------------------------------------- witness rebuilt by the forger ----------------------------------------------------------------
def rebuilt_witness(encoding):
    base = A.OUT / f"base-{encoding}"
    header, msgs = A.read_mcap(base)
    new = A.rechain(edit_one_byte(list(msgs), encoding), signer=A.DEMO_SIGNER)
    out = A.OUT / f"rechain-rebuilt-witness-{encoding}.mcap"
    A.write_mcap(out, header, new)
    orig = json.loads(open(str(base) + ".witness.json", encoding="utf-8").read())
    by_seq = {d["seq"]: d for m in new if m.topic == CHAIN_TOPIC for d in [m.body()]}
    for e in orig["entries"]:
        d = by_seq.get(e["seq"])
        if d:
            e["link"], e["recv_time"], e["key_id"] = d["link"], d["recv_time"], d["key_id"]
    wp = str(out) + ".witness.json"
    open(wp, "w", encoding="utf-8").write(json.dumps(orig, indent=1))
    r = A.verify(out, witness=wp, pubkey=str(base) + ".pubkey.pem")
    T.add(f"insider rebuild + witness file rebuilt to match [{encoding}]", "not catchable without receipts (honest table): exit 0, RECEIPT_ABSENT", r, "OK" if r["exit"] == 0 and "RECEIPT_ABSENT" in r["codes"] else "BUG")


for e in ("json", "cdr"):
    rebuilt_witness(e)



# ---------------------------------------------------------------- a chain that matches nothing ----------------------------------------------------------------
def chain_from_other_bag(encoding):
    """Payload from a seed-2 log, chain (+witness +key) from the seed-1 log: no link matches any message."""
    other = A.gen(f"base-seed2-{encoding}", "--seed", "2", encoding=encoding)
    header, mine = A.read_mcap(A.OUT / f"base-{encoding}")
    _, theirs = A.read_mcap(other["path"])
    mixed = [m for m in theirs if m.topic != CHAIN_TOPIC] + [m for m in mine if m.topic == CHAIN_TOPIC]
    out = A.OUT / f"chain-from-other-bag-{encoding}.mcap"
    A.write_mcap(out, header, mixed)
    r = A.verify(out, witness=str(A.OUT / f"base-{encoding}") + ".witness.json", pubkey=str(A.OUT / f"base-{encoding}") + ".pubkey.pem")
    T.add(f"payload of log B + chain/witness/key of log A (no link matches any message) [{encoding}]", "MESSAGE_MISSING x6757 + MESSAGE_UNCHAINED, L1 FAIL", r, "BUG" if r["grades"].get("L1 integrity") != "FAIL" else "OK")


for e in ("json", "cdr"):
    chain_from_other_bag(e)

T.dump("forgery")
