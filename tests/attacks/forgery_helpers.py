"""Mutations shared between forgery.py and receipts_attack.py."""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A
from attacklib import CHAIN_TOPIC, SESSION_TOPIC, link_hash, message_hash

NS = 1_000_000_000


def truncate_insider(msgs, encoding, cut_s: float = 300.0):
    """Insider with the device key: drop everything after cut_s and append a CLEAN_SHUTDOWN with a valid, signed link."""
    kept = [m for m in msgs if A.rel(msgs, m) <= cut_s]
    last_link = max((m.body() for m in kept if m.topic == CHAIN_TOPIC), key=lambda d: d["seq"])
    tpl_s = next(m for m in msgs if m.topic == SESSION_TOPIC)
    tpl_c = next(m for m in msgs if m.topic == CHAIN_TOPIC)
    t = kept[-1].log_time + NS // 5
    b = tpl_s.body()
    none = None if encoding == "json" else ""
    b.update(event="CLEAN_SHUTDOWN", note=none, device_pubkey=none, prev_session_id=none, stamp={"sec": t // NS, "nanosec": t % NS})
    sd = tpl_s.with_body(b).clone(log_time=t, publish_time=t)
    mh = message_hash(SESSION_TOPIC, sd.data)
    seq = last_link["seq"] + 1
    lh = link_hash(last_link["link"], mh, seq, t, SESSION_TOPIC)
    rec = {"session_id": last_link["session_id"], "seq": seq, "topic": SESSION_TOPIC, "msg_sha256": mh, "prev": last_link["link"], "link": lh, "recv_time": t, "key_id": A.DEMO_SIGNER.key_id, "sig": A.DEMO_SIGNER.sign_link(lh)}
    return kept + [sd, tpl_c.with_body(rec).clone(log_time=t, publish_time=t)]
