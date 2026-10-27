"""Malformed and hostile inputs. Any Python traceback is a bug; exit 2 with a message is fine.

Run from the repository root:  python tests/attacks/robustness.py
"""
import json
import shutil
import sqlite3
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import attacklib as A
from attacklib import CHAIN_TOPIC, CONTROL_TOPIC, SESSION_TOPIC, M, enc, link_hash, message_hash

T = A.Table()
NS = 1_000_000_000
OUT = A.OUT / "robust"
OUT.mkdir(exist_ok=True)
BASE = A.OUT / "base-json"
HEADER, MSGS = A.read_mcap(BASE)
WIT = str(BASE) + ".witness.json"
KEY = str(BASE) + ".pubkey.pem"


def no_tb(r, want_exit=None):
    if r["traceback"]:
        return "BUG"
    if want_exit is not None and r["exit"] != want_exit:
        return "BUG"
    return "OK"


# ---------------------------------------------------------------- files ----------------------------------------------------------------
p = OUT / "empty.mcap"
p.write_bytes(b"")
T.add("empty 0-byte .mcap", "exit 2, message", A.verify(p), no_tb(A.verify(p), 2))

p = OUT / "magic-only.mcap"
p.write_bytes(b"\x89MCAP0\r\n")
T.add("file that is only the MCAP magic", "exit 2, message", A.verify(p), no_tb(A.verify(p), 2))

p = OUT / "magic-twice.mcap"
p.write_bytes(b"\x89MCAP0\r\n" + b"\x89MCAP0\r\n")
r = A.verify(p)
T.add("MCAP magic at both ends, nothing between", "exit 2 or FILE_EMPTY fail", r, no_tb(r))

p = OUT / "empty.db3"
p.write_bytes(b"")
r = A.verify(p)
T.add("0-byte .db3", "exit 2, message", r, no_tb(r, 2))

p = OUT / "garbage.db3"
p.write_bytes(b"not a database at all" * 100)
r = A.verify(p)
T.add("garbage .db3", "exit 2, message", r, no_tb(r, 2))

d = OUT / "bag-missing-file"
d.mkdir(exist_ok=True)
(d / "metadata.yaml").write_text("rosbag2_bagfile_information:\n  storage_identifier: mcap\n  relative_file_paths:\n  - gone_0.mcap\n  version: 9\n", encoding="utf-8")
r = A.verify(d)
T.add("rosbag2 dir whose metadata.yaml lists a missing file", "exit 2, message", r, no_tb(r, 2))

d = OUT / "bag-bad-yaml"
d.mkdir(exist_ok=True)
(d / "metadata.yaml").write_text("rosbag2_bagfile_information: [unclosed\n", encoding="utf-8")
r = A.verify(d)
T.add("rosbag2 dir with unparsable metadata.yaml", "exit 2, message", r, no_tb(r, 2))

d = OUT / "bag-yaml-not-dict"
d.mkdir(exist_ok=True)
(d / "metadata.yaml").write_text("- just\n- a list\n", encoding="utf-8")
r = A.verify(d)
T.add("rosbag2 dir whose metadata.yaml is a list", "exit 2, message", r, no_tb(r, 2))

d = OUT / "bag-storage-unknown"
d.mkdir(exist_ok=True)
(d / "metadata.yaml").write_text("rosbag2_bagfile_information:\n  storage_identifier: parquet\n  relative_file_paths:\n  - x\n", encoding="utf-8")
(d / "x").write_bytes(b"")
r = A.verify(d)
T.add("rosbag2 dir with unknown storage plugin", "exit 2, message", r, no_tb(r, 2))

d = OUT / "two-mcaps-no-metadata"
d.mkdir(exist_ok=True)
shutil.copy(BASE, d / "a_0.mcap")
shutil.copy(BASE, d / "a_1.mcap")
r = A.verify(d)
T.add("directory with two mcaps and no metadata.yaml", "exit 2, message", r, no_tb(r, 2))

p = OUT / "not-zstd.mcap.zstd"
p.write_bytes(b"\x00\x01\x02 this is not zstd" * 50)
r = A.verify(p)
T.add(".zstd that is not zstd", "exit 2, message", r, no_tb(r, 2))

p = OUT / "plain.mcap.zst"
shutil.copy(BASE, p)
r = A.verify(p)
T.add(".zst extension on an uncompressed mcap", "exit 2, message", r, no_tb(r, 2))

p = OUT / "readme.txt"
p.write_text("hello", encoding="utf-8")
r = A.verify(p)
T.add("a .txt file", "exit 2, message", r, no_tb(r, 2))

r = A.verify(OUT / "does-not-exist.mcap")
T.add("nonexistent path", "exit 2, message", r, no_tb(r, 2))

p = OUT / "empty.bag"
p.write_bytes(b"")
r = A.verify(p)
T.add("0-byte ROS 1 .bag", "exit 2, message", r, no_tb(r, 2))


# ---------------------------------------------------------------- witness files ----------------------------------------------------------------
def witness_case(name, obj, expected="warn WITNESS_UNREADABLE or exit 2, no traceback", want=None):
    p = OUT / f"witness-{name}.json"
    if isinstance(obj, bytes):
        p.write_bytes(obj)
    else:
        p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")
    r = A.verify(BASE, witness=p, pubkey=KEY)
    T.add(f"witness: {name}", expected, r, no_tb(r, want))
    return r


orig = json.loads(open(WIT, encoding="utf-8").read())
witness_case("top-level-list", [1, 2, 3])
witness_case("no-entries-key", {"foo": 1})
witness_case("entries-not-list", {"entries": {"a": 1}})
witness_case("entries-strings", {"entries": ["x", "y"]})
witness_case("entries-missing-fields", {"entries": [{"seq": 5}, {"link": "ab"}, {}]})
witness_case("seq-string-5", {"entries": [{"seq": "5", "link": orig["entries"][0]["link"], "session_id": "rec-0001"}]})
witness_case("seq-string-abc", {"entries": [{"seq": "abc", "link": "00" * 32}]})
witness_case("seq-null", {"entries": [{"seq": None, "link": "00" * 32}]})
witness_case("seq-float-string", {"entries": [{"seq": "5.0", "link": "00" * 32}]})
witness_case("seq-list", {"entries": [{"seq": [1], "link": "00" * 32}]})
witness_case("seq-negative", {"entries": [{"seq": -3, "link": "00" * 32}]})
witness_case("seq-huge", {"entries": [{"seq": 10**30, "link": "00" * 32}]})
witness_case("link-null", {"entries": [{"seq": 1, "link": None}]})
witness_case("link-int", {"entries": [{"seq": 1, "link": 12345}]})
witness_case("recv_time-string", {"entries": [{"seq": 10**6, "link": "00" * 32, "recv_time": "soon", "session_id": "rec-0001"}]})
witness_case("session_id-dict", {"entries": [{"seq": 1, "link": "00" * 32, "session_id": {"a": 1}}]})
witness_case("rfc3161-not-dict", {"entries": [dict(orig["entries"][0], rfc3161="yes")]})
witness_case("rfc3161-tsr-not-hex", {"entries": [dict(orig["entries"][0], rfc3161={"tsr_der_hex": "zz"})]})
witness_case("rfc3161-tsr-garbage", {"entries": [dict(orig["entries"][0], rfc3161={"tsr_der_hex": "deadbeef" * 20})]})
witness_case("rfc3161-tsr-int", {"entries": [dict(orig["entries"][0], rfc3161={"tsr_der_hex": 12345})]})
witness_case("invalid-json", "{not json")
witness_case("utf16", "{}".encode("utf-16"))
e = OUT / "witness-empty-dir"
e.mkdir(exist_ok=True)
r = A.verify(BASE, witness=e, pubkey=KEY)
T.add("witness: empty directory", "warn, no traceback", r, no_tb(r))

# 100k entries, all valid copies of the heads (timing)
big = {"entries": []}
for k in range(100_000):
    big["entries"].append(dict(orig["entries"][k % len(orig["entries"])]))
r = witness_case("100k-entries", big, "finishes in a few seconds", None)
T.rows[-1]["observed"] += f"; {r['seconds']} s, peak {r['peak_mb']} MB"
if r["seconds"] > 30:
    T.rows[-1]["verdict"] = "BUG"
# 100k entries, every one unknown (seq past the end)
big = {"entries": [{"seq": 10**6 + k, "link": "00" * 32, "session_id": "rec-0001"} for k in range(100_000)]}
r = witness_case("100k-entries-past-end", big, "one TRUNCATED, finishes in a few seconds", None)
T.rows[-1]["observed"] += f"; {r['seconds']} s, peak {r['peak_mb']} MB"
if r["seconds"] > 30:
    T.rows[-1]["verdict"] = "BUG"


# ---------------------------------------------------------------- profiles ----------------------------------------------------------------
def profile_case(name, obj, expected="exit 2 with message, or report; no traceback"):
    p = OUT / f"profile-{name}.json"
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")
    r = A.verify(BASE, witness=WIT, pubkey=KEY, profile=p)
    T.add(f"profile: {name}", expected, r, no_tb(r))


profile_case("unknown-keys", {"name": "x", "weird": 1, "items": [{"topic": "/odom", "fields": ["x"], "banana": True}], "checks": ["nothing"]})
profile_case("item-missing-topic", {"name": "x", "items": [{"id": "A1", "fields": ["x"]}]})
profile_case("items-is-dict", {"name": "x", "items": {"topic": "/odom"}})
profile_case("items-strings", {"name": "x", "items": ["topic"]})
profile_case("item-fields-not-list", {"name": "x", "items": [{"topic": "/odom", "fields": "x"}]})
profile_case("item-when-no-field", {"name": "x", "items": [{"topic": "/quaill/control_mode", "fields": ["operator_ref"], "when": {"equals": 4}}]})
profile_case("events-no-topic", {"name": "x", "events": {"pairs": [["A", "B"]]}})
profile_case("events-pairs-malformed", {"name": "x", "events": {"topic": "/events", "pairs": [["A"], "AB", ["A", "B", "C"]]}})
profile_case("events-window-topics-missing", {"name": "x", "events": {"topic": "/events", "window_s": "ten", "window_values": ["stuck_detected"], "window_topics": ["/odom"]}})
profile_case("operator-topics-not-list", {"name": "x", "operator_command_topics": "*teleop*"})
profile_case("operator-topics-ints", {"name": "x", "operator_command_topics": [1, 2]})
profile_case("top-level-list", [1, 2])
profile_case("invalid-json", "{nope")
r = A.verify(BASE, witness=WIT, pubkey=KEY, profile=OUT)
T.add("profile: path is a directory", "exit 2, message", r, no_tb(r, 2))
r = A.verify(BASE, witness=WIT, pubkey=KEY, profile="../../../../pyproject.toml")
T.add("profile: path traversal to a non-JSON file", "exit 2, message", r, no_tb(r, 2))


# ---------------------------------------------------------------- keys / certs ----------------------------------------------------------------
def key_case(name, data: bytes, expected="PUBKEY_UNREADABLE warn, no traceback"):
    p = OUT / f"pubkey-{name}.pem"
    p.write_bytes(data)
    r = A.verify(BASE, witness=WIT, pubkey=p)
    T.add(f"pubkey: {name}", expected, r, no_tb(r))


key_case("garbage", b"\x00\xff" * 40)
key_case("hex-short", b"abcd")
key_case("hex-odd", b"a" * 63)
key_case("empty", b"")
key_case("rsa-pem", b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n")
r = A.verify(BASE, witness=WIT, pubkey=OUT)
T.add("pubkey: path is a directory", "warn or exit 2, no traceback", r, no_tb(r))
p = OUT / "tsa-garbage.pem"
p.write_bytes(b"garbage")
r = A.verify(BASE, witness=WIT, pubkey=KEY, tsa_cert=p)
T.add("tsa-cert: garbage file", "TSA_CERT_UNREADABLE warn", r, no_tb(r))
r = A.verify(BASE, witness=WIT, pubkey=KEY, tsa_cert=OUT / "nope.pem")
T.add("tsa-cert: missing file", "warn, no traceback", r, no_tb(r))


# ---------------------------------------------------------------- hostile content inside the bag ----------------------------------------------------------------
def with_links(mut):
    """mut(link dict) -> link dict (or None to drop), applied to every chain message."""
    out = []
    for m in MSGS:
        if m.topic == CHAIN_TOPIC:
            d = mut(dict(m.body()))
            if d is None:
                continue
            m = m.clone(data=enc(d))
        out.append(m)
    return out


def bag_case(name, msgs, expected, want_exit=None, witness=WIT, pubkey=KEY, header=None):
    p = OUT / f"bag-{name}.mcap"
    A.write_mcap(p, header or HEADER, msgs)
    r = A.verify(p, witness=witness, pubkey=pubkey)
    T.add(f"bag: {name}", expected, r, no_tb(r, want_exit))
    return r


def seq_mut(fn):
    def m(d):
        d["seq"] = fn(d["seq"])
        return d

    return m


bag_case("seq-zero-based", with_links(seq_mut(lambda s: s - 1)), "CHAIN_BROKEN (seq 0), exit 1", 1)
bag_case("seq-negative", with_links(seq_mut(lambda s: -s)), "CHAIN_BROKEN, exit 1", 1)
bag_case("seq-huge", with_links(seq_mut(lambda s: s + 2**64)), "CHAIN_BROKEN, exit 1", 1)
bag_case("seq-string", with_links(seq_mut(lambda s: str(s))), "accepted after int() or CHAIN_MALFORMED; no traceback")
bag_case("seq-float", with_links(seq_mut(lambda s: float(s))), "int() accepts floats; no traceback")
bag_case("seq-bool", with_links(seq_mut(lambda s: True)), "CHAIN_BROKEN; no traceback")
bag_case("seq-list", with_links(seq_mut(lambda s: [s])), "CHAIN_MALFORMED; no traceback")


def recv_mut(fn):
    def m(d):
        d["recv_time"] = fn(d["recv_time"])
        return d

    return m


bag_case("recv_time-far-future-2^62", with_links(recv_mut(lambda t: t + 2**62)), "CHAIN_BROKEN (hash covers recv_time), no traceback", 1)
bag_case("recv_time-past-year-1", with_links(recv_mut(lambda t: t - 2**61)), "CHAIN_BROKEN, no traceback", 1)
bag_case("recv_time-beyond-int64", with_links(recv_mut(lambda t: 2**70)), "CHAIN_BROKEN, no traceback", 1)
bag_case("recv_time-float", with_links(recv_mut(lambda t: t / 1e9)), "CHAIN_BROKEN, no traceback", 1)
bag_case("recv_time-string", with_links(recv_mut(lambda t: "yesterday")), "CHAIN_MALFORMED, no traceback", 1)
bag_case("recv_time-null", with_links(recv_mut(lambda t: None)), "CHAIN_MALFORMED, no traceback", 1)


def hash_upper(d):
    d["msg_sha256"] = d["msg_sha256"].upper()
    return d


bag_case("msg_sha256-uppercase-hex", with_links(hash_upper), "same value, different case: ideally accepted; if not, a clear fail", None)


def link_upper(d):
    d["link"] = d["link"].upper()
    d["prev"] = d["prev"].upper()
    return d


bag_case("link+prev-uppercase-hex", with_links(link_upper), "same value, different case: ideally accepted", None)


def hash_nonhex(d):
    d["msg_sha256"] = "zz" * 32
    d["prev"] = "zz" * 32
    return d


bag_case("hashes-non-hex", with_links(hash_nonhex), "CHAIN_BROKEN, no traceback", 1)


def sig_empty_some(d):
    if d["seq"] % 2 == 0:
        d["sig"] = ""
    return d


bag_case("sig-empty-on-half", with_links(sig_empty_some), "SIGNATURE_PARTIAL, exit 1", 1)


def sig_nonhex(d):
    d["sig"] = "not hex"
    return d


bag_case("sig-non-hex", with_links(sig_nonhex), "SIGNATURE_INVALID, exit 1", 1)


def sig_int(d):
    d["sig"] = 12345
    d["key_id"] = 99
    return d


bag_case("sig-and-key_id-ints", with_links(sig_int), "SIGNATURE_INVALID or malformed, no traceback", None)


def sig_zero_bytes(d):
    d["sig"] = "00" * 64
    return d


bag_case("sig-64-zero-bytes", with_links(sig_zero_bytes), "SIGNATURE_INVALID, exit 1", 1)


def link_is_list(d):
    return [d]


bag_case("chain-message-is-a-list", with_links(link_is_list), "CHAIN_MALFORMED, exit 1", 1)


def drop_key(d):
    d.pop("sig", None)
    d.pop("key_id", None)
    d.pop("session_id", None)
    return d


bag_case("links-without-sig/key_id/session_id keys", with_links(drop_key), "UNSIGNED, witness matched via the single-session rule; no traceback")


def topic_none(d):
    d["topic"] = None
    return d


bag_case("link-topic-null", with_links(topic_none), "CHAIN_BROKEN/MALFORMED, no traceback", 1)


def topic_int(d):
    d["topic"] = 7
    return d


bag_case("link-topic-int", with_links(topic_int), "CHAIN_BROKEN/MALFORMED, no traceback", 1)


def session_mut():
    out = []
    for m in MSGS:
        if m.topic == CHAIN_TOPIC:
            d = m.body()
            d["session_id"] = {"nested": [1, 2]}
            m = m.clone(data=enc(d))
        out.append(m)
    return out


bag_case("link-session_id-is-a-dict", session_mut(), "str() of it; no traceback")


# control reports with odd field types
def control_mut(fn):
    out = []
    for m in MSGS:
        if m.topic == CONTROL_TOPIC:
            d = m.body()
            d = fn(d)
            m = m.clone(data=enc(d))
        out.append(m)
    return out


def mode_bool(d):
    d["mode"] = True
    return d


r = bag_case("control-mode-bool", control_mut(mode_bool), "CONTROL_MALFORMED or AUTONOMOUS (bool is int); no traceback")


def mode_str(d):
    d["mode"] = "4"
    return d


bag_case("control-mode-string", control_mut(mode_str), "CONTROL_MALFORMED, no traceback")


def mode_huge(d):
    d["mode"] = 2**40
    return d


bag_case("control-mode-huge", control_mut(mode_huge), "MODE_xxx label, no traceback")


def op_dict(d):
    d["operator_ref"] = {"name": "x"}
    d["reason"] = ["a"]
    return d


bag_case("control-operator_ref-dict", control_mut(op_dict), "rendered somehow, no traceback")


def session_mut2(fn):
    out = []
    for m in MSGS:
        if m.topic == SESSION_TOPIC:
            d = m.body()
            d = fn(d)
            m = m.clone(data=enc(d))
        out.append(m)
    return out


def event_int(d):
    d["event"] = 42
    d["session_id"] = 7
    d["note"] = {"x": 1}
    return d


bag_case("session-event-int", session_mut2(event_int), "SESSION_MALFORMED or rendered; no traceback")


def pubkey_garbage(d):
    d["device_pubkey"] = "zz"
    return d


bag_case("session-announced-pubkey-garbage", session_mut2(pubkey_garbage), "PUBKEY_UNREADABLE warn", None, pubkey="")


def pubkey_int(d):
    d["device_pubkey"] = 12345
    return d


bag_case("session-announced-pubkey-int", session_mut2(pubkey_int), "PUBKEY_UNREADABLE warn", None, pubkey="")

# deeply nested JSON in a chain message
deep = "[" * 100000 + "]" * 100000
out = []
done = False
for m in MSGS:
    if m.topic == CHAIN_TOPIC and not done:
        out.append(m.clone(data=deep.encode()))
        done = True
    out.append(m)
bag_case("chain-message-100k-nested-json", out, "CHAIN_MALFORMED, no traceback (RecursionError caught)", 1)

# mcap encodings mismatched
out = [m.clone(msg_encoding="cdr") if m.topic == CHAIN_TOPIC else m for m in MSGS]
bag_case("chain-channel-says-cdr-but-bytes-are-json", out, "CHAIN_MALFORMED fail", 1)
out = [m.clone(schema_name=None, schema_encoding=None, schema_data=None) for m in MSGS]
bag_case("no-schemas-at-all (schema_id 0)", out, "json still decodes; no traceback")
out = [m.clone(msg_encoding="protobuf") for m in MSGS]
bag_case("message_encoding=protobuf everywhere", out, "CHAIN_MALFORMED / undecodable; no traceback")

# huge log_time (uint64 max) on one message
out = list(MSGS)
out[-1] = out[-1].clone(log_time=2**64 - 1, publish_time=2**64 - 1)
bag_case("log_time-uint64-max-on-last-message", out, "no traceback (fmt_abs of year 2554)")
out = list(MSGS)
out[0] = out[0].clone(log_time=0, publish_time=0)
bag_case("log_time-0-on-first-message", out, "no traceback (fmt_abs of 1970)")
out = list(MSGS)
for i in range(len(out)):
    out[i] = out[i].clone(publish_time=0)
bag_case("publish_time-0-everywhere", out, "no traceback")

# unicode / odd topic names, chained properly
def unicode_topics():
    names = {"/odom": "/ünïcödé/топик/測試", "/cmd_vel": "a//b///c", "/events": "/", "/teleop/cmd_vel": "/teleop/\u0000nul"}
    payload = [m for m in MSGS if m.topic != CHAIN_TOPIC]
    tpl = next(m for m in MSGS if m.topic == CHAIN_TOPIC)
    from attacklib import ChainBuilder

    cb = ChainBuilder("rec-0001", A.DEMO_SIGNER)
    out = []
    for m in payload:
        t = names.get(m.topic, m.topic)
        m = m.clone(topic=t)
        rec = cb.add(t, m.data, m.log_time)
        out += [m, tpl.clone(data=enc(rec), log_time=m.log_time, publish_time=m.log_time)]
    return out


r = bag_case("unicode-and-odd-topic-names (rechained)", unicode_topics(), "PASS apart from the rebuilt witness; no traceback", None, witness="")
# a topic that exists only in the chain, never in the bag
def phantom_topic():
    tpl = next(m for m in MSGS if m.topic == CHAIN_TOPIC)
    return MSGS + [tpl.clone(data=enc({"session_id": "rec-0001", "seq": 6758, "topic": "/phantom", "msg_sha256": "11" * 32, "prev": "22" * 32, "link": "33" * 32, "recv_time": MSGS[-1].log_time, "key_id": "", "sig": ""}), log_time=MSGS[-1].log_time)]


bag_case("link for a topic that is not in the bag at all", phantom_topic(), "CHAIN_BROKEN + MESSAGE_MISSING; it will say MESSAGE_BEFORE_START (warn)", 1)


# 50 sessions
def fifty_sessions():
    payload = sorted([m for m in MSGS if m.topic != CHAIN_TOPIC], key=lambda m: m.log_time)
    tpl = next(m for m in MSGS if m.topic == CHAIN_TOPIC)
    from attacklib import ChainBuilder

    out, wit = [], []
    n = len(payload)
    for s in range(50):
        chunk = payload[s * n // 50 : (s + 1) * n // 50]
        cb = ChainBuilder(f"sess-{s:03d}", A.DEMO_SIGNER)
        for m in chunk:
            rec = cb.add(m.topic, m.data, m.log_time)
            out += [m, tpl.clone(data=enc(rec), log_time=m.log_time, publish_time=m.log_time)]
        wit.append({"session_id": f"sess-{s:03d}", "seq": cb.seq, "link": cb.prev, "recv_time": chunk[-1].log_time, "witnessed_at": "x"})
    wp = OUT / "witness-50-sessions.json"
    wp.write_text(json.dumps({"entries": wit}), encoding="utf-8")
    return out, wp


msgs50, wp50 = fifty_sessions()
r = bag_case("50 recorder sessions in one bag, per-session witness heads", msgs50, "CHAIN_RESTART info, PASS, no traceback", 0, witness=wp50)
T.rows[-1]["observed"] += f"; {r['seconds']} s"
# a witness directory with one file per session
wd = OUT / "witness-50-dir"
if wd.exists():
    shutil.rmtree(wd)
wd.mkdir()
for e in json.loads(wp50.read_text(encoding="utf-8"))["entries"]:
    (wd / f"{e['session_id']}.json").write_text(json.dumps({"session_id": e["session_id"], "entries": [e]}), encoding="utf-8")
(wd / "unrelated.json").write_text("[1,2,3]", encoding="utf-8")
(wd / "broken.json").write_text("{nope", encoding="utf-8")
r = A.verify(OUT / "bag-50_recorder_sessions_in_one_bag_per-session_witness_heads.mcap" if False else OUT / [p for p in OUT.glob("bag-50*.mcap")][0].name, witness=wd, pubkey=KEY)
T.add("witness directory with 50 per-session files + an unrelated list json + a broken json", "warn for the broken file, else PASS", r, no_tb(r))

# --- db3 with negative timestamps and a far-future timestamp (fmt_abs on Windows) ---
def make_db3(name, rows):
    p = OUT / f"{name}.db3"
    if p.exists():
        p.unlink()
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE topics(id INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, serialization_format TEXT NOT NULL, offered_qos_profiles TEXT NOT NULL)")
    con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, topic_id INTEGER NOT NULL, timestamp INTEGER NOT NULL, data BLOB NOT NULL)")
    con.execute("INSERT INTO topics VALUES (1, '/odom', 'quaill_gen/msg/Odom', 'cdr', '')")
    for i, (ts, data) in enumerate(rows, 1):
        con.execute("INSERT INTO messages VALUES (?, 1, ?, ?)", (i, ts, data))
    con.commit()
    con.close()
    return p


r = A.verify(make_db3("negative-timestamps", [(-5 * NS, b"abc"), (-4 * NS, b"abd"), (-2 * NS, b"abe")]))
T.add(".db3 with negative timestamps", "report with 1969 dates or a clear error; no traceback", r, no_tb(r))
r = A.verify(make_db3("far-future-timestamps", [(2**62, b"abc"), (2**62 + NS, b"abd")]))
T.add(".db3 with timestamps in year 2116", "report; no traceback", r, no_tb(r))
r = A.verify(make_db3("timestamp-2^63-1", [(2**63 - 1, b"abc")]))
T.add(".db3 with timestamp 2^63-1", "report; no traceback", r, no_tb(r))
r = A.verify(make_db3("null-data", [(NS, b"")]))
T.add(".db3 with an empty message", "report; no traceback", r, no_tb(r))
p = make_db3("topic-missing-row", [(NS, b"abc")])
con = sqlite3.connect(p)
con.execute("DELETE FROM topics")
con.commit()
con.close()
r = A.verify(p)
T.add(".db3 whose messages reference a topic row that does not exist", "report (topic#1); no traceback", r, no_tb(r))
p = make_db3("zstd-magic-not-zstd", [(NS, b"\x28\xb5\x2f\xfd garbage")])
r = A.verify(p)
T.add(".db3 message starting with the zstd magic but not zstd", "exit 2 or warn; no traceback", r, no_tb(r))


# ---------------------------------------------------------------- CLI switches ----------------------------------------------------------------
r = A.verify(BASE, witness=WIT, pubkey=KEY, extra=["--gap-seconds", "-1"])
T.add("--gap-seconds -1", "usage error or every pair becomes a gap; no traceback", r, no_tb(r))
T.rows[-1]["observed"] += f"; {len(r['codes'])} findings, {r['seconds']} s"
r = A.verify(BASE, witness=WIT, pubkey=KEY, extra=["--gap-seconds", "0"])
T.add("--gap-seconds 0", "no traceback", r, no_tb(r))
T.rows[-1]["observed"] += f"; {len(r['codes'])} findings"
r = A.verify(BASE, witness=WIT, pubkey=KEY, extra=["--gap-seconds", "nan"])
T.add("--gap-seconds nan", "usage error; no traceback", r, no_tb(r))
r = A.verify(BASE, witness=WIT, pubkey=KEY, extra=["--out", str(OUT)])
T.add("--out pointing at a directory", "exit 2 with message; no traceback", r, no_tb(r))
r = A.verify(BASE, witness=WIT, pubkey=KEY, extra=["--out", str(OUT / "no" / "such" / "dir" / "r.json")])
T.add("--out in a nonexistent directory", "exit 2 with message; no traceback", r, no_tb(r))

T.dump("robustness")
