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
from .mcapio import CHAIN_TOPIC, GENESIS, LogFile, Msg, link_hash, message_hash

LINK_KEYS = ("seq", "topic", "msg_sha256", "prev", "link", "recv_time")
ORDER_TOLERANCE = 1 * NS  # bag log_time may differ a little from the sidecar's receive order
SKEW_TOLERANCE = 5 * NS  # sidecar clock vs bag clock on the same robot
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
        for e in w["entries"]:
            if isinstance(e, dict) and "seq" in e and "link" in e:
                e = dict(e)
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
    if not signed:
        F.append(Finding("UNSIGNED", "L1", "info", "chain links carry no device signature: anyone holding the file could extend or rebuild the chain; only the witness can tell"))
        return
    if not CRYPTO:
        F.append(Finding("SIGNATURE_UNCHECKED", "L1", "warn", "links are signed but the 'cryptography' package is not installed, so signatures were not checked"))
        return
    trusted = None
    if trusted_pub:
        try:
            trusted = Verifier.load(trusted_pub)
        except Exception as e:
            F.append(Finding("PUBKEY_UNREADABLE", "L1", "warn", f"could not read the supplied public key: {e}"))
    announced = _announced_keys(log)
    for s in segs:
        sig_links = [d for d in s.links if d.get("sig")]
        if not sig_links:
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


def verify_chain(log: LogFile, witness: dict | None, trusted_pub: str | None = None) -> ChainResult:
    r = ChainResult()
    F = r.findings
    start = log.start
    chain_msgs = log.by_topic(CHAIN_TOPIC)
    if not chain_msgs:
        F.append(Finding("CHAIN_ABSENT", "L1", "info", f"no {CHAIN_TOPIC} channel: edits and deletions cannot be checked from this file"))
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
    missing: list[dict] = []
    order_viol = 0
    max_skew = 0
    for s in segs:
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
        # phase 2: duplicates, bounded by the nearest anchored neighbours
        next_anchor: list[int | None] = [None] * n
        nxt = None
        for i in range(n - 1, -1, -1):
            if times[i] is not None:
                nxt = times[i]
            next_anchor[i] = nxt
        prev_anchor = None
        for i, d in enumerate(s.links):
            if times[i] is not None:
                prev_anchor = times[i]
                continue
            cands = [m for m in pool.get(d["msg_sha256"], []) if id(m) not in taken]
            if not cands:
                missing.append(d)
                continue
            lo = (prev_anchor if prev_anchor is not None else start) - ORDER_TOLERANCE
            hi = (next_anchor[i] if next_anchor[i] is not None else log.end) + ORDER_TOLERANCE
            inside = [m for m in cands if lo <= m.log_time <= hi]
            m = inside[0] if inside else min(cands, key=lambda m: abs(m.log_time - d["recv_time"]))
            taken.add(id(m))
            times[i] = m.log_time
            prev_anchor = m.log_time
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

    # 3. A link with no message plus an unchained message on the same topic in the same window = an edit.
    unc_by_topic: dict[str, list[Msg]] = defaultdict(list)
    for m in uncovered:
        unc_by_topic[m.topic].append(m)
    consumed: set[int] = set()
    edited: list[tuple[dict, Msg]] = []
    deleted: list[dict] = []
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
        F.append(Finding("MESSAGE_MISSING", "L1", "fail", f"{len(ts)} message(s) on {topic} are recorded in the chain but are not in the file (deleted) ({_span(ts, start)})", min(ts), max(ts)))
    counts: dict[str, int] = defaultdict(int)
    for m in unchained:
        counts[m.topic] += 1
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
        by_seq = {d["seq"]: d for d in seg.links}
        d = by_seq.get(seq)
        if d is None:
            if seq > seg.last["seq"]:
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
    if r.witnessed_through_seq is None and not r.truncated:
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
