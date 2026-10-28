"""Hash chain: build (for recorders) and verify (for the checker), plus the outside witness.

One link per message on every non-chain channel, in the order the recorder saw them:
    msg_sha256 = sha256(topic || 0 || serialized bytes)
    link       = sha256(prev || msg_sha256 || seq || recv_time || topic)
The checker pairs links to messages BY CONTENT HASH, never by the bag's log_time: a sidecar
node that publishes links cannot know what time rosbag2 will stamp on the original message.
Editing or removing a message breaks the chain. Cutting the END of the log does not: only an
outside witness (a party the robot maker does not control) holding a later chain head shows that.

Sessions: a recorder that restarts mid-bag starts a NEW chain (seq 1, prev = zeros) under a new
session_id. Each session's chain is verified on its own; witness entries carry the session_id.
"""
from __future__ import annotations

import bisect
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .findings import NS, Finding, fmt_rel
from .mcapio import CHAIN_TOPIC, CONTROL_TOPIC, GENESIS, SESSION_TOPIC, LogFile, Msg, link_hash, message_hash
from .receipts import ReceiptResult
from .receipts import verify as verify_receipt

LINK_KEYS = ("seq", "topic", "msg_sha256", "prev", "link", "recv_time")
ORDER_TOLERANCE = 1 * NS  # bag log_time may differ a little from the sidecar's receive order
SKEW_TOLERANCE = 5 * NS  # sidecar clock vs bag clock on the same robot
ANCHOR_TOLERANCE = 2 * NS  # how far a duplicate may sit from where the recorder's own clock places it, relative to a paired neighbour
START_JITTER = NS // 4  # a restarted recorder chains nothing before its START; this only absorbs delivery jitter into the bag
DISCOVERY_TOLERANCE = 5 * NS  # rosbag2 subscribes to a topic a moment after it appears (longer on a loaded CI runner); the sidecar may chain a few messages first
NOT_EXPECTED_CHAINED = {"/rosout", "/parameter_events"}  # ROS plumbing that nobody chains


class ChainBuilder:
    def __init__(self, session_id: str = "", signer=None) -> None:
        self.session_id = session_id
        self.signer = signer  # quaill.keys.Signer or None
        self.prev = GENESIS
        self.seq = 0
        self.links: list[dict] = []

    def add(self, topic: str, data: bytes, recv_time: int) -> dict:
        mh = message_hash(topic, data)
        self.seq += 1
        link = link_hash(self.prev, mh, self.seq, recv_time, topic)
        rec = {"session_id": self.session_id, "seq": self.seq, "topic": topic, "msg_sha256": mh, "prev": self.prev, "link": link, "recv_time": int(recv_time), "key_id": "", "sig": ""}
        if self.signer is not None:
            rec["key_id"] = self.signer.key_id
            rec["sig"] = self.signer.sign_link(link)
        self.prev = link
        self.links.append(rec)
        return rec


@dataclass
class Segment:
    session_id: str
    links: list[dict]

    @property
    def last(self) -> dict:
        return self.links[-1]


@dataclass
class ChainResult:
    present: bool = False
    links: list[dict] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    last_seq: int | None = None
    last_link: str | None = None
    last_time: int | None = None  # recv_time of the last link of the last segment
    matched_time: dict[tuple[str, int], int] = field(default_factory=dict)  # (session, seq) -> log_time of the matched message
    witness_present: bool = False
    witnessed_through_seq: int | None = None  # in the last segment
    witnessed_through_time: int | None = None
    truncated: bool = False
    receipts: list[dict] = field(default_factory=list)  # one per witness head that carries an RFC 3161 receipt
    findings: list[Finding] = field(default_factory=list)

    @property
    def complete_per_witness(self) -> bool:
        return self.witness_present and not self.truncated and self.witnessed_through_seq == self.last_seq


def load_witness(path: str | None) -> dict | None:
    """One witness file, or a directory of them (one per recorder session). Entries get a session_id."""
    if not path:
        return None
    p = Path(path)
    files = sorted(p.glob("*.json")) if p.is_dir() else [p]
    entries: list[dict] = []
    for f in files:
        with f.open("r", encoding="utf-8") as fh:
            w = json.load(fh)
        if not isinstance(w, dict) or "entries" not in w:
            if p.is_dir():
                continue  # unrelated json in the directory
            raise ValueError(f"{f} has no 'entries' list")
        sid = str(w.get("session_id") or "")
        if not isinstance(w["entries"], list):
            raise ValueError(f"{f}: 'entries' must be a list")
        for e in w["entries"]:
            if not (isinstance(e, dict) and "seq" in e and "link" in e):
                continue
            e = dict(e)
            try:
                e["seq"] = int(e["seq"])
            except (TypeError, ValueError):
                raise ValueError(f"{f}: entry has a seq that is not a whole number: {e['seq']!r}") from None
            if not isinstance(e["link"], str):
                raise ValueError(f"{f}: entry seq {e['seq']} has a link that is not a string")
            if e.get("recv_time") is not None:
                try:
                    e["recv_time"] = int(e["recv_time"])
                except (TypeError, ValueError):
                    raise ValueError(f"{f}: entry seq {e['seq']} has a recv_time that is not a whole number: {e['recv_time']!r}") from None
            e.setdefault("session_id", sid)
            entries.append(e)
    if p.is_dir() and not entries:
        raise ValueError(f"no witness files with entries in {p}")
    return {"entries": entries, "files": [str(f) for f in files]}


def _span(times: list[int], start: int) -> str:
    t0, t1 = min(times), max(times)
    return fmt_rel(t0, start) if t0 == t1 else f"{fmt_rel(t0, start)} to {fmt_rel(t1, start)}"


def _announced_keys(log: LogFile) -> dict[str, str]:
    """session_id -> device_pubkey hex announced on START events inside the bag."""
    from .mcapio import SESSION_TOPIC

    out: dict[str, str] = {}
    for m in log.by_topic(SESSION_TOPIC):
        d = m.body()
        if isinstance(d, dict) and d.get("event") == "START" and d.get("device_pubkey"):
            out[str(d.get("session_id") or "")] = str(d["device_pubkey"])
    return out


def verify_signatures(log: LogFile, segs: list[Segment], trusted_pub: str | None, F: list[Finding], start: int) -> None:
    """Checks link signatures. trusted_pub: path to a public key the caller trusts (PEM or hex), or None."""
    from .keys import CRYPTO, Verifier, key_id

    signed = [d for s in segs for d in s.links if d.get("sig")]
    if not CRYPTO and (signed or trusted_pub):
        F.append(Finding("SIGNATURE_UNCHECKED", "L1", "warn", "the 'cryptography' package is not installed, so link signatures were not checked" + (" and the supplied public key was not used" if trusted_pub else "")))
        return
    trusted = None
    if trusted_pub:
        try:
            trusted = Verifier.load(trusted_pub)
        except Exception as e:
            F.append(Finding("PUBKEY_UNREADABLE", "L1", "fail", f"could not read the supplied public key {trusted_pub}: {e}; the chain was not checked against it"))
    if not signed:
        if trusted is not None:  # the caller expects this device's signatures; a chain without any was not made by that key
            F.append(Finding("KEY_MISMATCH", "L1", "fail", f"a device key ({trusted.key_id}) was supplied, but no link carries a signature: this chain was not produced by that key (rebuilt without signing, or the recorder never signed)"))
        else:
            F.append(Finding("UNSIGNED", "L1", "info", "chain links carry no device signature: anyone holding the file could extend or rebuild the chain; only the witness can tell"))
        return
    announced = _announced_keys(log)
    for s in segs:
        sig_links = [d for d in s.links if d.get("sig")]
        if not sig_links:
            if trusted is not None:
                F.append(Finding("KEY_MISMATCH", "L1", "fail", f"session {s.session_id or '?'}: no link carries a signature, although a device key ({trusted.key_id}) was supplied", s.links[0]["recv_time"], s.links[-1]["recv_time"]))
            else:
                F.append(Finding("UNSIGNED", "L1", "info", f"session {s.session_id or '?'}: links carry no device signature"))
            continue
        if len(sig_links) != len(s.links):
            F.append(Finding("SIGNATURE_PARTIAL", "L1", "fail", f"session {s.session_id or '?'}: {len(s.links) - len(sig_links)} of {len(s.links)} links are unsigned while the rest are signed"))
        kids = {d.get("key_id") for d in sig_links}
        if len(kids) > 1:
            F.append(Finding("KEY_CHANGED", "L1", "fail", f"session {s.session_id or '?'}: links are signed by {len(kids)} different keys ({', '.join(sorted(k for k in kids if k))})"))
        kid = sorted(kids)[0] or "?"
        ann_hex = announced.get(s.session_id)
        if ann_hex is None and len(set(announced.values())) == 1:  # one key announced for the whole bag
            ann_hex = next(iter(announced.values()))
        verifier = None
        source = None
        if trusted is not None:
            if trusted.key_id in kids:
                verifier, source = trusted, "the supplied public key"
            else:
                F.append(Finding("KEY_MISMATCH", "L1", "fail", f"session {s.session_id or '?'}: links are signed by key {kid} but the supplied device key is {trusted.key_id}: this chain was not produced by the expected device key", s.links[0]["recv_time"], s.links[-1]["recv_time"]))
                continue
        elif ann_hex:
            try:
                v = Verifier.from_hex(ann_hex)
                if v.key_id in kids:
                    verifier, source = v, "the key announced in the bag's START marker"
                else:
                    F.append(Finding("KEY_MISMATCH", "L1", "fail", f"session {s.session_id or '?'}: links are signed by key {kid} but the START marker announces key {v.key_id}"))
                    continue
            except Exception as e:
                F.append(Finding("PUBKEY_UNREADABLE", "L1", "warn", f"session {s.session_id or '?'}: the announced device key does not parse: {e}"))
        if verifier is None:
            F.append(Finding("SIGNED_UNVERIFIED", "L1", "warn", f"session {s.session_id or '?'}: {len(sig_links)} links signed by key {kid}, but no public key is available (none announced in the bag, none supplied with --pubkey); signatures not checked"))
            continue
        bad = [d for d in sig_links if not verifier.verify_link(d["link"], d["sig"])]
        if bad:
            F.append(Finding("SIGNATURE_INVALID", "L1", "fail", f"session {s.session_id or '?'}: {len(bad)} of {len(sig_links)} link signatures do not verify against {source} (first at {fmt_rel(bad[0]['recv_time'], start)})", bad[0]["recv_time"], bad[-1]["recv_time"]))
        elif source.startswith("the supplied"):
            F.append(Finding("SIGNED_TRUSTED", "L1", "info", f"session {s.session_id or '?'}: all {len(sig_links)} links signed by device key {kid}, verified against the supplied public key"))
        else:
            F.append(Finding("SIGNED_ANNOUNCED", "L1", "info", f"session {s.session_id or '?'}: all {len(sig_links)} links verify against key {kid} announced inside the bag; a rebuilt chain could announce its own key, so supply the device's public key (--pubkey) or a witness to confirm it"))


def verify_chain(log: LogFile, witness: dict | None, trusted_pub: str | None = None, tsa_cert=None) -> ChainResult:
    r = ChainResult()
    F = r.findings
    start = log.start
    chain_msgs = log.by_topic(CHAIN_TOPIC)
    if not chain_msgs:
        F.append(Finding("CHAIN_ABSENT", "L1", "info", f"no {CHAIN_TOPIC} channel: edits and deletions cannot be checked from this file"))
        heads = [e for e in (witness or {}).get("entries", []) if "seq" in e and "link" in e]
        if heads:  # a witness is a claim that a chain existed; a file with none is not simply "not assessable"
            r.present = True
            F.append(Finding("WITNESS_WITHOUT_CHAIN", "L1", "fail", f"a witness holds {len(heads)} chain head(s) for this log, but the file has no {CHAIN_TOPIC} channel: the chain was removed from the file, or this witness belongs to another recording"))
        return r
    r.present = True

    links: list[dict] = []
    bad = 0
    for m in chain_msgs:
        d = m.body()
        if not isinstance(d, dict) or any(k not in d for k in LINK_KEYS):
            bad += 1
            continue
        try:
            d["seq"] = int(d["seq"])
            d["recv_time"] = int(d["recv_time"])
            d["session_id"] = str(d.get("session_id") or "")
        except Exception:
            bad += 1
            continue
        links.append(d)
    if bad:
        F.append(Finding("CHAIN_MALFORMED", "L1", "fail", f"{bad} chain message(s) could not be parsed as links"))
    if not links:
        return r

    # Split into sessions (segments), each ordered by seq, segments ordered by first recv_time.
    by_sid: dict[str, list[dict]] = defaultdict(list)
    for d in links:
        by_sid[d["session_id"]].append(d)
    segs = [Segment(sid, sorted(ls, key=lambda d: d["seq"])) for sid, ls in by_sid.items()]
    segs.sort(key=lambda s: min(d["recv_time"] for d in s.links))
    r.segments = segs
    r.links = [d for s in segs for d in s.links]
    if len(segs) > 1:
        F.append(Finding("CHAIN_RESTART", "L1", "info", f"{len(segs)} recorder sessions in this log (" + ", ".join(f"{s.session_id or '?'} from {fmt_rel(s.links[0]['recv_time'], start)}" for s in segs) + "); each chain is checked on its own"))

    # 1. Each chain must be continuous and self-consistent; the recorder's clock must not run backwards.
    breaks = jumps = 0
    for s in segs:
        prev_seq, prev_link, prev_recv = 0, GENESIS, None
        first = s.links[0]
        if first["seq"] > 1:  # a bag started after the sidecar (the usual case with `ros2 bag record`) begins mid-chain
            prev_seq, prev_link = first["seq"] - 1, first["prev"]
            F.append(
                Finding(
                    "CHAIN_STARTS_LATE",
                    "L1",
                    "warn",
                    f"session {s.session_id or '?'}: the file begins at link {first['seq']} ({fmt_rel(first['recv_time'], start)}); links 1-{first['seq'] - 1} are not in it. "
                    "A bag that started after the recorder looks the same as a file whose beginning was removed; the file alone cannot tell which",
                    first["recv_time"],
                    first["recv_time"],
                )
            )
        for d in s.links:
            problems = []
            if d["seq"] != prev_seq + 1:
                problems.append(f"link sequence jumps from {prev_seq} to {d['seq']} ({d['seq'] - prev_seq - 1} link(s) removed)")
            if d["prev"] != prev_link:
                problems.append(f"link {d['seq']} does not reference the previous link")
            try:
                expect = link_hash(d["prev"], d["msg_sha256"], d["seq"], d["recv_time"], d["topic"])
            except Exception:
                expect = None
            if expect != d["link"]:
                problems.append(f"link {d['seq']} hash does not match its contents")
            if problems:
                breaks += 1
                if breaks <= 5:
                    F.append(Finding("CHAIN_BROKEN", "L1", "fail", "; ".join(problems) + f" at {fmt_rel(d['recv_time'], start)}" + (f" (session {s.session_id})" if len(segs) > 1 else ""), d["recv_time"], d["recv_time"]))
            if prev_recv is not None and d["recv_time"] < prev_recv - ORDER_TOLERANCE:
                jumps += 1
                if jumps <= 3:
                    F.append(Finding("TIME_JUMP", "L1", "warn", f"recorder clock stepped back {(prev_recv - d['recv_time']) / NS:.1f} s at link {d['seq']} (recorder time {fmt_rel(d['recv_time'], start)}); timestamps after this point cannot be taken at face value", d["recv_time"], prev_recv))
            prev_seq, prev_link, prev_recv = d["seq"], d["link"], d["recv_time"]
    if breaks > 5:
        F.append(Finding("CHAIN_BROKEN", "L1", "fail", f"... and {breaks - 5} more chain break(s)"))
    if jumps > 3:
        F.append(Finding("TIME_JUMP", "L1", "warn", f"... and {jumps - 3} more backwards clock step(s)"))
    last = segs[-1].last
    r.last_seq, r.last_link, r.last_time = last["seq"], last["link"], last["recv_time"]

    # 1b. Device signatures on the links.
    verify_signatures(log, segs, trusted_pub, F, start)

    # 2. Every link must match a message in the file, byte for byte. Pairing is by content hash.
    #    Identical messages (a stopped robot publishes thousands of all-zero commands) share a hash, so:
    #    phase 1 pairs every hash that is unique on both sides; phase 2 places the duplicates inside the
    #    time window their already-paired neighbours in the chain define.
    pool: dict[str, list[Msg]] = defaultdict(list)
    for m in log.payload():  # already in log_time order
        pool[m.hash].append(m)
    link_count: Counter = Counter(d["msg_sha256"] for d in r.links)
    taken: set[int] = set()
    cursor: dict[str, int] = defaultdict(int)  # per hash: everything before this index in pool[hash] is already taken
    missing: list[dict] = []
    order_viol = 0
    max_skew = 0
    start_at: dict[str, int] = {}
    for m in log.by_topic(SESSION_TOPIC):
        d = m.body()
        if isinstance(d, dict) and d.get("event") == "START" and d.get("session_id"):
            start_at.setdefault(d["session_id"], m.log_time)
    for k, s in enumerate(segs):
        # a session that starts mid-file (a restarted recorder) holds nothing before its own START marker; the
        # first session's START may reach a bag late (it is latched), so it sets no floor
        floor = start_at.get(s.session_id) if k > 0 else None
        n = len(s.links)
        times: list[int | None] = [None] * n
        # phase 1: unambiguous
        for i, d in enumerate(s.links):
            cands = pool.get(d["msg_sha256"])
            if cands and len(cands) == 1 and link_count[d["msg_sha256"]] == 1:
                m = cands[0]
                if id(m) not in taken:
                    taken.add(id(m))
                    times[i] = m.log_time
        # phase 2: duplicates, bounded by the nearest anchored neighbours. Before the first anchor or after the
        # last one there is no neighbour on that side, so the bound comes from the recorder's own clock: a link
        # recorded k seconds before its anchor was received about k seconds before it, within ANCHOR_TOLERANCE.
        # Without that, a restarted sidecar's first links pair with identical messages from before it started.
        next_anchor: list[int | None] = [None] * n
        next_anchor_recv: list[int | None] = [None] * n
        nxt = nxt_recv = None
        for i in range(n - 1, -1, -1):
            if times[i] is not None:
                nxt, nxt_recv = times[i], s.links[i]["recv_time"]
            next_anchor[i], next_anchor_recv[i] = nxt, nxt_recv
        prev_anchor = prev_anchor_recv = None
        for i, d in enumerate(s.links):
            if times[i] is not None:
                prev_anchor, prev_anchor_recv = times[i], d["recv_time"]
                continue
            # pool[hash] is in log_time order and links come in seq order, so a cursor past the taken
            # prefix keeps a parked robot's 40,000 identical messages linear instead of quadratic
            h = d["msg_sha256"]
            lst = pool.get(h, [])
            c = cursor[h]
            while c < len(lst) and id(lst[c]) in taken:
                c += 1
            cursor[h] = c
            if c >= len(lst):
                missing.append(d)
                continue
            if prev_anchor is not None:
                lo = prev_anchor - ORDER_TOLERANCE
            elif next_anchor[i] is not None:
                lo = next_anchor[i] - (next_anchor_recv[i] - d["recv_time"]) - ANCHOR_TOLERANCE
            else:
                lo = start - ORDER_TOLERANCE
            if floor is not None:
                lo = max(lo, floor - START_JITTER)
            if next_anchor[i] is not None:
                hi = next_anchor[i] + ORDER_TOLERANCE
            elif prev_anchor is not None:
                hi = prev_anchor + (d["recv_time"] - prev_anchor_recv) + ANCHOR_TOLERANCE
            else:
                hi = log.end + ORDER_TOLERANCE
            m = None
            for j in range(c, len(lst)):  # first untaken candidate inside the window
                mj = lst[j]
                if id(mj) in taken:
                    continue
                if mj.log_time > hi:
                    break
                if mj.log_time >= lo:
                    m = mj
                    break
            if m is None:  # nothing in the window (bag and recorder order disagree): nearest by recorder time
                m = min((x for x in lst[c:] if id(x) not in taken), key=lambda x: abs(x.log_time - d["recv_time"]))
            taken.add(id(m))
            times[i] = m.log_time
            prev_anchor, prev_anchor_recv = m.log_time, d["recv_time"]
        prev_t = None
        for i, d in enumerate(s.links):
            t = times[i]
            if t is None:
                continue
            r.matched_time[(s.session_id, d["seq"])] = t
            if prev_t is not None and t < prev_t - ORDER_TOLERANCE:
                order_viol += 1
            prev_t = max(prev_t or t, t)
            max_skew = max(max_skew, abs(t - d["recv_time"]))
    uncovered = [m for ms in pool.values() for m in ms if id(m) not in taken]
    uncovered.sort(key=lambda m: m.log_time)
    if order_viol:
        F.append(Finding("TIME_ORDER", "L1", "warn", f"{order_viol} message(s) carry a log time earlier than messages chained before them (bag order and recorder order disagree by more than {ORDER_TOLERANCE / NS:.0f} s)"))
    if max_skew > SKEW_TOLERANCE:
        F.append(Finding("CLOCK_SKEW", "L1", "warn", f"recorder clock and bag clock differ by up to {max_skew / NS:.1f} s"))

    # 3. A link with no message. In order: chained before the bag held anything from this session (the bag
    #    started late: flagged, not decided); an unchained message on the same topic in the same window (an
    #    edit); chained just before the bag's first message on that topic (the bag subscribed a moment late:
    #    flagged); otherwise the message was deleted. The "late" cases are judged against the whole session,
    #    not per topic: deleting every message on one topic must not look like a late subscription.
    unc_by_topic: dict[str, list[Msg]] = defaultdict(list)
    for m in uncovered:
        unc_by_topic[m.topic].append(m)
    consumed: set[int] = set()
    edited: list[tuple[dict, Msg]] = []
    deleted: list[dict] = []
    before_start: list[dict] = []
    late_sub: list[dict] = []
    first_seq: dict[str, int] = {}  # session -> lowest seq whose message is in the file, any topic
    first_recv: dict[tuple[str, str], int] = {}  # (session, topic) -> recorder time of the first link on that topic whose message is in the file
    for s in segs:
        for d in s.links:  # in seq order
            if (s.session_id, d["seq"]) in r.matched_time:
                first_seq.setdefault(s.session_id, d["seq"])
                first_recv.setdefault((s.session_id, d["topic"]), d["recv_time"])
    for s in segs:
        matched_seqs = sorted(seq for (sid, seq) in r.matched_time if sid == s.session_id)
        for d in missing:
            if d["session_id"] != s.session_id:
                continue
            i = bisect.bisect_left(matched_seqs, d["seq"])
            t_lo = r.matched_time[(s.session_id, matched_seqs[i - 1])] if i > 0 else start
            t_hi = r.matched_time[(s.session_id, matched_seqs[i])] if i < len(matched_seqs) else log.end
            cand = None
            for m in unc_by_topic.get(d["topic"], []):
                if id(m) in consumed:
                    continue
                if t_lo - ORDER_TOLERANCE <= m.log_time <= t_hi + ORDER_TOLERANCE:
                    cand = m
                    break
            if cand is not None:
                consumed.add(id(cand))
                edited.append((d, cand))
                continue
            fs = first_seq.get(s.session_id)
            if fs is not None and d["seq"] < fs:
                before_start.append(d)
                continue
            fr = first_recv.get((s.session_id, d["topic"]))
            if fr is not None and d["recv_time"] < fr and fr - d["recv_time"] <= DISCOVERY_TOLERANCE:
                late_sub.append(d)
            else:
                deleted.append(d)
    unchained = [m for m in uncovered if id(m) not in consumed]

    by_topic: dict[str, list] = defaultdict(list)
    for d, m in edited:
        by_topic[d["topic"]].append(m.log_time)
    for topic, ts in by_topic.items():
        F.append(Finding("MESSAGE_EDITED", "L1", "fail", f"{len(ts)} message(s) on {topic} differ from what the chain recorded when they were logged (edited after the fact) ({_span(ts, start)})", min(ts), max(ts)))
    by_topic = defaultdict(list)
    for d in deleted:
        by_topic[d["topic"]].append(d["recv_time"])
    for topic, ts in by_topic.items():
        F.append(Finding("MESSAGE_MISSING", "L1", "fail", f"{len(ts)} message(s) on {topic} are recorded in the chain but are not in the file (deleted, or never recorded by the bag) ({_span(ts, start)})", min(ts), max(ts)))
    by_topic = defaultdict(list)
    for d in before_start:
        by_topic[d["topic"]].append(d["recv_time"])
    for topic, ts in by_topic.items():
        F.append(
            Finding(
                "MESSAGE_BEFORE_START",
                "L1",
                "warn",
                f"{len(ts)} message(s) on {topic} were chained before the first message the file holds from this session ({_span(ts, start)}): "
                "the bag had not started yet, or the beginning of the file was removed; the file alone cannot tell which",
                min(ts),
                max(ts),
            )
        )
    by_topic = defaultdict(list)
    for d in late_sub:
        by_topic[d["topic"]].append(d["recv_time"])
    for topic, ts in by_topic.items():
        F.append(
            Finding(
                "MESSAGE_BEFORE_START",
                "L1",
                "warn",
                f"{len(ts)} message(s) on {topic} were chained within {DISCOVERY_TOLERANCE / NS:.0f} s before the first message the file holds on that topic ({_span(ts, start)}): "
                "the bag subscribed to the topic a moment late (rosbag2 discovers topics after they appear), or the first message(s) on it were removed",
                min(ts),
                max(ts),
            )
        )

    # Unchained messages. Inside the stretch a chain covers a topic (bag time of its first to its last matched
    # message on that topic), the chain node was subscribed to it and saw every message, so a control report or
    # session marker without a link there was added afterwards, or the chain node never saw it: either way the
    # control timeline cannot be read as written. Outside that stretch (before the chain node had subscribed to
    # the topic, after it stopped, between two sessions) the file alone cannot say, so it is a warning.
    topic_of = {(d["session_id"], d["seq"]): d["topic"] for d in r.links}
    per_topic: dict[tuple[str, str], list[int]] = defaultdict(list)
    for key, t in r.matched_time.items():
        per_topic[(key[0], topic_of.get(key, ""))].append(t)
    covered: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for (sid, topic), ts in per_topic.items():
        covered[topic].append((min(ts), max(ts)))
    earliest_matched = min(r.matched_time.values()) if r.matched_time else log.end
    restart_starts = [start_at[s.session_id] for s in segs[1:] if s.session_id in start_at]
    counts: dict[str, int] = defaultdict(int)
    inserted: dict[str, list[int]] = defaultdict(list)
    latched = 0
    restart_markers = 0
    for m in unchained:
        if m.topic == SESSION_TOPIC and m.log_time <= earliest_matched + ORDER_TOLERANCE:
            latched += 1  # START / CRASH_NOTE are latched: a bag that starts late still receives them, without their links
            continue
        if m.topic == SESSION_TOPIC and any(f - ORDER_TOLERANCE <= m.log_time <= f + ORDER_TOLERANCE for f in restart_starts):
            restart_markers += 1  # a restarted recorder publishes CRASH_NOTE and START before it chains its own session topic
            continue
        if m.topic in (CONTROL_TOPIC, SESSION_TOPIC) and any(lo < m.log_time < hi for lo, hi in covered.get(m.topic, [])):
            inserted[m.topic].append(m.log_time)
            continue
        counts[m.topic] += 1
    if latched:
        F.append(Finding("MESSAGE_UNCHAINED", "L1", "info", f"{latched} session marker(s) at the start of the file have no chain link in it (latched markers reach a bag that started after the recorder; their links came earlier)"))
    if restart_markers:
        F.append(Finding("MESSAGE_UNCHAINED", "L1", "info", f"{restart_markers} session marker(s) where a recorder session restarts have no chain link (a restarted recorder publishes CRASH_NOTE and START before it chains its own session topic)"))
    for topic, ts in inserted.items():
        F.append(
            Finding(
                "MESSAGE_UNCHAINED",
                "L1",
                "fail",
                f"{len(ts)} message(s) on {topic} have no chain link although the chain was running then ({_span(ts, start)}): added after the fact, or never seen by the chain node; "
                "the control timeline cannot be read as written",
                min(ts),
                max(ts),
            )
        )
    for topic, n in counts.items():
        sev = "info" if topic in NOT_EXPECTED_CHAINED else "warn"
        F.append(Finding("MESSAGE_UNCHAINED", "L1", sev, f"{n} message(s) on {topic} are not covered by the chain (added later, recorded while the chain node was down, or never chained)"))

    # 4. Outside witness: the only way to see a cut-off end or a rebuilt chain.
    if witness is None:
        F.append(Finding("UNWITNESSED", "L1", "warn", "no outside witness: the chain is intact, but cutting off the end of the log would not be detectable from the file alone"))
        return r
    r.witness_present = True
    entries = sorted((e for e in witness.get("entries", []) if "seq" in e and "link" in e), key=lambda e: (str(e.get("session_id") or ""), int(e["seq"])))
    if not entries:
        F.append(Finding("WITNESS_EMPTY", "L1", "warn", "witness file has no entries"))
        return r
    seg_by_sid = {s.session_id: s for s in segs}
    reported_trunc: set[str] = set()
    unknown_sessions: set[str] = set()
    heads_before: dict[str, int] = defaultdict(int)  # session -> witness heads older than the file's first link
    matched_any = False  # at least one entry belongs to a session this file has
    seq_index: dict[str, dict[int, dict]] = {}  # session -> seq -> link, built once; a 20,000-entry witness must not rebuild it per entry
    for e in entries:
        sid = str(e.get("session_id") or "")
        seq = int(e["seq"])
        seg = seg_by_sid.get(sid) if sid else (segs[0] if len(segs) == 1 else None)
        if seg is None:
            if sid and sid not in seg_by_sid:
                unknown_sessions.add(sid)
            else:
                F.append(Finding("WITNESS_AMBIGUOUS", "L1", "warn", f"witness entry seq {seq} names no session and the log has {len(segs)} sessions; cannot be matched"))
            continue
        matched_any = True
        by_seq = seq_index.get(seg.session_id)
        if by_seq is None:
            by_seq = seq_index[seg.session_id] = {d["seq"]: d for d in seg.links}
        d = by_seq.get(seq)
        if d is None:
            if seq < seg.links[0]["seq"]:
                heads_before[seg.session_id] += 1
            elif seq > seg.last["seq"]:
                if seg.session_id not in reported_trunc:
                    reported_trunc.add(seg.session_id)
                    r.truncated = True
                    wt = e.get("recv_time")
                    where = "the end of the log was cut off" if seg is segs[-1] else f"messages at the end of session {seg.session_id or '?'} are missing"
                    F.append(
                        Finding(
                            "TRUNCATED",
                            "L1",
                            "fail",
                            f"the witness holds chain link {seq} (recorder time {fmt_rel(wt, start) if wt else '?'}, witnessed {e.get('witnessed_at', '?')}) "
                            f"but the file's chain ends at link {seg.last['seq']} ({fmt_rel(seg.last['recv_time'], start)}): {where}",
                            seg.last["recv_time"],
                            wt,
                        )
                    )
            else:
                F.append(Finding("WITNESS_MISMATCH", "L1", "fail", f"witness refers to link {seq}, which the file does not have"))
            continue
        if d["link"] != e["link"]:
            F.append(
                Finding(
                    "WITNESS_MISMATCH",
                    "L1",
                    "fail",
                    f"witness link {seq} ({fmt_rel(d['recv_time'], start)}) differs from the file's: the chain was rebuilt after it was witnessed (something before this point was changed or removed)",
                    d["recv_time"],
                    d["recv_time"],
                )
            )
            continue
        if e.get("key_id") and d.get("key_id") and e["key_id"] != d["key_id"]:
            F.append(Finding("WITNESS_KEY_MISMATCH", "L1", "fail", f"witness saw link {seq} signed by key {e['key_id']} but the file's link is signed by {d['key_id']}", d["recv_time"], d["recv_time"]))
            continue
        if seg is segs[-1] and (r.witnessed_through_seq is None or seq > r.witnessed_through_seq):
            r.witnessed_through_seq = seq
            r.witnessed_through_time = r.matched_time.get((seg.session_id, seq), d["recv_time"])
    for sid in sorted(unknown_sessions):
        F.append(Finding("WITNESS_OTHER_SESSION", "L1", "info", f"witness has entries for session {sid}, which is not in this log (another bag, or the recorder ran without the bag)"))
    for sid, n in sorted(heads_before.items()):
        F.append(Finding("WITNESS_BEFORE_START", "L1", "info", f"witness holds {n} head(s) from before the file begins (session {sid or '?'}); they cannot be checked against this file"))

    # 5. RFC 3161 receipts on the heads: the only part of a witness a third party vouches for.
    n_rcpt = valid = invalid = unverified = failed_requests = 0
    best: tuple[int, ReceiptResult, dict] | None = None  # the latest valid receipt in the last session
    for e in entries:
        rc = e.get("rfc3161")
        if not isinstance(rc, dict):
            continue
        if not rc.get("tsr_der_hex"):
            failed_requests += 1  # the recorder asked and got an error; it wrote that down
            continue
        n_rcpt += 1
        sid = str(e.get("session_id") or "")
        seq = int(e["seq"])
        try:
            res = verify_receipt(bytes.fromhex(str(rc["tsr_der_hex"])), str(e["link"]), tsa_cert)
        except Exception as ex:
            res = ReceiptResult("invalid", f"receipt unreadable: {ex}")
        r.receipts.append({"session_id": sid, "seq": seq, "tsa_url": rc.get("tsa", ""), **res.to_dict()})
        if res.status == "valid":
            valid += 1
            if (not sid or sid == segs[-1].session_id) and (best is None or seq > best[0]):
                best = (seq, res, e)
        elif res.status == "unverified":
            unverified += 1
        else:
            invalid += 1
            F.append(Finding("RECEIPT_INVALID", "L1", "fail", f"witness head link {seq} (session {sid or '?'}): its RFC 3161 receipt does not verify: {res.reason}", e.get("recv_time"), e.get("recv_time")))
    if n_rcpt == 0:
        F.append(
            Finding(
                "RECEIPT_ABSENT",
                "L1",
                "info",
                "witness heads carry no RFC 3161 receipt: this witness is the recorder's own file unless its heads left the robot some other way"
                + (f" ({failed_requests} head(s) record a failed receipt request)" if failed_requests else ""),
            )
        )
    else:
        if best is not None:
            seq, res, e = best
            seg = seg_by_sid.get(str(e.get("session_id") or "")) or segs[-1]
            seqs = [d["seq"] for d in seg.links]
            where = "that link is in this file" if seq in seqs else ("that link is past this file's end" if seq > seqs[-1] else "that link is from before this file begins")
            F.append(
                Finding(
                    "RECEIPT_VALID",
                    "L1",
                    "info",
                    f"{valid} of {n_rcpt} witness head(s) carry a valid RFC 3161 receipt from {res.tsa or 'an unnamed TSA'}; the chain through link {seq} "
                    f"(recorder time {fmt_rel(e.get('recv_time'), start) if e.get('recv_time') else '?'}) existed at {res.gen_time.strftime('%Y-%m-%dT%H:%M:%SZ') if res.gen_time else '?'} by that authority's clock; {where}"
                    + (" (checked against the supplied certificate)" if res.cert_source == "supplied" else ""),
                    e.get("recv_time"),
                    e.get("recv_time"),
                )
            )
        elif valid:
            F.append(Finding("RECEIPT_VALID", "L1", "info", f"{valid} of {n_rcpt} witness head(s) carry a valid RFC 3161 receipt, none of them for this file's last session"))
        if unverified:
            F.append(Finding("RECEIPT_UNVERIFIED", "L1", "warn", f"{unverified} of {n_rcpt} receipt(s) match their heads but carry no TSA certificate and none was supplied (--tsa-cert); their signatures were not checked"))
    if not matched_any:  # a witness that matches nothing: the wrong file, or the chain's session id was relabeled after it was witnessed
        F.append(
            Finding(
                "WITNESS_UNMATCHED",
                "L1",
                "fail",
                f"witness supplied, but none of its {len(entries)} entries belong to a session in this log (witness: {', '.join(sorted(unknown_sessions)) or '?'}; log: {', '.join(s.session_id or '?' for s in segs)}): "
                "the wrong witness, or the chain's session id was changed after it was witnessed; nothing in this file is confirmed by it",
            )
        )
    elif r.witnessed_through_seq is None and not r.truncated:
        F.append(Finding("UNWITNESSED", "L1", "warn", "witness supplied, but none of its entries match the last session in this log; the end cannot be confirmed"))
    elif r.witnessed_through_seq is not None and not r.truncated and r.witnessed_through_seq < r.last_seq:
        F.append(
            Finding(
                "UNWITNESSED_TAIL",
                "L1",
                "info",
                f"messages after {fmt_rel(r.witnessed_through_time, start)} (links {r.witnessed_through_seq + 1}-{r.last_seq}) are chained but no witness has seen them",
                r.witnessed_through_time,
                r.last_time,
            )
        )
    return r
