"""Shared helpers for the adversarial tests. Nothing here touches quaill/ or ros2_ws/.

Run every script from anywhere; paths are absolute. Generated logs go to tests/attacks/out/.
"""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUT = HERE / "out"
PY = Path(sys.executable)
BOOT = f"import sys; sys.path.insert(0, {str(ROOT)!r}); from quaill.cli import main; raise SystemExit(main())"
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))
try:  # our own output may carry unicode topic names; the checker under test gets a plain cp1252 pipe, as a real user would
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from quaill.chain import ChainBuilder  # noqa: E402
from quaill.keys import Signer  # noqa: E402
from quaill.mcapio import CHAIN_TOPIC, CONTROL_TOPIC, MSG_DEFS, SESSION_TOPIC, cdr_decoder, cdr_encoder, enc, link_hash, message_hash  # noqa: E402

DEMO_SIGNER = Signer.from_seed(b"quaill demo device key 0001")
FRESH_SIGNER = Signer.from_seed(b"attacker fresh key for tests/attacks")


# ------------------------------------------------------------------ running the checker ------------------------------------------------------------------
def _peak_rss_mb(handle: int) -> float | None:
    try:
        import ctypes.wintypes as W

        class _PMC(ctypes.Structure):
            _fields_ = [
                ("cb", W.DWORD),
                ("PageFaultCount", W.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        psapi = ctypes.windll.psapi
        psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, ctypes.POINTER(_PMC), W.DWORD]
        psapi.GetProcessMemoryInfo.restype = W.BOOL
        pmc = _PMC()
        pmc.cb = ctypes.sizeof(_PMC)
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            return pmc.PeakWorkingSetSize / 2**20
    except Exception:
        pass
    return None


def quaill(*args: str, timeout: float = 900, cwd: Path | None = None) -> dict:
    """Runs `quaill <args>` in a child process. Returns exit code, stdout, stderr, seconds, peak RSS MB, traceback flag."""
    t0 = time.perf_counter()
    p = subprocess.Popen([str(PY), "-c", BOOT, *map(str, args)], cwd=str(cwd or ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        out, err = p.communicate(timeout=timeout)
        code = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        code = -999
    secs = time.perf_counter() - t0
    peak = _peak_rss_mb(int(p._handle)) if hasattr(p, "_handle") else None  # the handle stays valid until Popen is collected
    return {"exit": code, "stdout": out, "stderr": err, "seconds": round(secs, 2), "peak_mb": round(peak, 1) if peak else None, "traceback": "Traceback (most recent call last)" in err}


def verify(log, witness=None, pubkey=None, profile=None, tsa_cert=None, extra=(), timeout=900) -> dict:
    """`quaill verify --json`; adds parsed codes / grades. witness/pubkey: None = checker's default lookup, "" = none."""
    args = ["verify", str(log), "--json"]
    if witness is not None:
        args += ["--witness", str(witness)]
    if pubkey is not None:
        args += ["--pubkey", str(pubkey)]
    if profile is not None:
        args += ["--profile", str(profile)]
    if tsa_cert is not None:
        args += ["--tsa-cert", str(tsa_cert)]
    args += list(extra)
    r = quaill(*args, timeout=timeout)
    r["codes"] = []
    r["grades"] = {}
    r["fails"] = []
    r["error"] = None
    try:
        j = json.loads(r["stdout"])
        r["codes"] = [f["code"] for f in j.get("findings", [])]
        r["fails"] = [f["code"] for f in j.get("findings", []) if f["severity"] == "fail"]
        r["grades"] = j.get("grades", {})
        r["error"] = j.get("error")
        r["json"] = j
    except Exception:
        pass
    return r


def summary(r: dict) -> str:
    if r["traceback"]:
        last = [ln for ln in r["stderr"].strip().splitlines() if ln.strip()][-1:]
        return f"exit {r['exit']} TRACEBACK {last[0] if last else ''}"
    if r.get("error"):
        return f"exit {r['exit']} UNREADABLE: {r['error'][:120]}"
    if r.get("grades"):
        g = r["grades"]
        return f"exit {r['exit']} L1={g.get('L1 integrity')} L2c={g.get('L2 control')} L2m={g.get('L2 completeness')} codes={sorted(set(r['codes']))}"
    err = r["stderr"].strip().splitlines()
    return f"exit {r['exit']} {err[-1] if err else r['stdout'][:120]}"


# ------------------------------------------------------------------ MCAP in / out ------------------------------------------------------------------
class M:
    """One message plus everything needed to write it back."""

    __slots__ = ("topic", "log_time", "publish_time", "sequence", "data", "msg_encoding", "schema_name", "schema_encoding", "schema_data")

    def __init__(self, topic, log_time, publish_time, sequence, data, msg_encoding, schema_name, schema_encoding, schema_data):
        self.topic, self.log_time, self.publish_time, self.sequence, self.data = topic, log_time, publish_time, sequence, data
        self.msg_encoding, self.schema_name, self.schema_encoding, self.schema_data = msg_encoding, schema_name, schema_encoding, schema_data

    def clone(self, **kw) -> "M":
        m = M(*(getattr(self, s) for s in self.__slots__))
        for k, v in kw.items():
            setattr(m, k, v)
        return m

    # decoding / encoding of the content, by the file's own encoding
    def body(self):
        if self.msg_encoding == "json":
            return json.loads(self.data)
        return _to_plain(cdr_decoder(self.schema_name, self.schema_data)(self.data))

    def with_body(self, body: dict) -> "M":
        if self.msg_encoding == "json":
            return self.clone(data=enc(body))
        return self.clone(data=cdr_encoder(self.schema_name, self.schema_data.decode())(body))


def _to_plain(obj):
    if isinstance(obj, (str, bytes, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (list, tuple)):
        return [_to_plain(x) for x in obj]
    slots = getattr(type(obj), "__slots__", None)
    if slots:
        return {n: _to_plain(getattr(obj, n, None)) for n in slots}
    if hasattr(obj, "__dict__"):
        return {k: _to_plain(v) for k, v in vars(obj).items()}
    return obj


def read_mcap(path) -> tuple[dict, list[M]]:
    from mcap.reader import make_reader

    with open(path, "rb") as f:
        r = make_reader(f)
        h = r.get_header()
        header = {"profile": h.profile, "library": h.library}
        msgs = []
        for schema, channel, message in r.iter_messages(log_time_order=True):
            msgs.append(M(channel.topic, message.log_time, message.publish_time, message.sequence, bytes(message.data), channel.message_encoding, schema.name if schema else None, schema.encoding if schema else None, bytes(schema.data) if schema else None))
    return header, msgs


def write_mcap(path, header: dict, msgs: list[M], sort: bool = True) -> str:
    from mcap.writer import Writer

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if sort:
        msgs = sorted(msgs, key=lambda m: m.log_time)
    with open(path, "wb") as f:
        w = Writer(f)
        w.start(profile=header.get("profile", ""), library=header.get("library", "tests/attacks"))
        schemas, chans = {}, {}
        for m in msgs:
            sk = (m.schema_name, m.schema_encoding, m.schema_data)
            if sk not in schemas:
                schemas[sk] = w.register_schema(name=m.schema_name or "", encoding=m.schema_encoding or "", data=m.schema_data or b"") if m.schema_name else 0
            ck = (m.topic, m.msg_encoding, sk)
            if ck not in chans:
                chans[ck] = w.register_channel(topic=m.topic, message_encoding=m.msg_encoding, schema_id=schemas[sk])
            w.add_message(channel_id=chans[ck], log_time=m.log_time, publish_time=m.publish_time, sequence=m.sequence, data=m.data)
        w.finish()
    return str(path)


def links(msgs: list[M]) -> list[tuple[int, dict]]:
    """(index in msgs, decoded link) for every chain message."""
    return [(i, m.body()) for i, m in enumerate(msgs) if m.topic == CHAIN_TOPIC]


def link_for(msgs: list[M], i: int) -> int | None:
    """Index of the chain message whose msg_sha256 matches msgs[i] (first match)."""
    h = message_hash(msgs[i].topic, msgs[i].data)
    for j, m in enumerate(msgs):
        if m.topic == CHAIN_TOPIC and h in (m.body() or {}).get("msg_sha256", ""):
            return j
    return None


def rechain(msgs: list[M], signer=None, session_id: str | None = None) -> list[M]:
    """Drops every chain message and writes a fresh chain over the remaining messages (in log_time order), optionally signed."""
    payload = sorted([m for m in msgs if m.topic != CHAIN_TOPIC], key=lambda m: m.log_time)
    template = next(m for m in msgs if m.topic == CHAIN_TOPIC)
    sid = session_id if session_id is not None else (template.body() or {}).get("session_id", "")
    cb = ChainBuilder(sid, signer)
    out = []
    for m in payload:
        rec = cb.add(m.topic, m.data, m.log_time)
        out.append(m)
        out.append(template.with_body(rec).clone(log_time=m.log_time, publish_time=m.log_time))
    return out


def rel(msgs: list[M], m: M) -> float:
    return (m.log_time - msgs[0].log_time) / 1e9


def gen(name: str, *args: str, defect: str | None = None, encoding: str = "json", container: str = "mcap", duration: float | None = None, witness: bool = True, sign: bool = True) -> dict:
    """quaill gen into out/<name>; returns the generator's info dict (path, witness, pubkey)."""
    out = OUT / name
    a = ["gen", str(out), "--scenario", "delivery", "--encoding", encoding, "--container", container]
    if defect:
        a += ["--defect", defect]
    if duration:
        a += ["--duration", str(duration)]
    if not witness:
        a.append("--no-witness")
    if not sign:
        a.append("--no-sign")
    a += list(args)
    r = quaill(*a)
    if r["exit"] != 0:
        raise RuntimeError(f"gen failed: {r['stderr']}")
    return json.loads(r["stdout"])


def copy_sidecars(src_log: str, dst_log: str) -> tuple[str, str]:
    """Copies <src>.witness.json and <src>.pubkey.pem next to dst. Returns (witness, pubkey) paths."""
    w, k = Path(src_log + ".witness.json"), Path(src_log + ".pubkey.pem")
    dw, dk = Path(str(dst_log) + ".witness.json"), Path(str(dst_log) + ".pubkey.pem")
    if w.exists():
        shutil.copy(w, dw)
    if k.exists():
        shutil.copy(k, dk)
    return str(dw), str(dk)


class Table:
    """Collects rows for the README results table."""

    def __init__(self):
        self.rows: list[dict] = []

    def add(self, attack: str, expected: str, r: dict, verdict: str, note: str = ""):
        obs = summary(r)
        self.rows.append({"attack": attack, "expected": expected, "observed": obs + (f"; {note}" if note else ""), "exit": r["exit"], "verdict": verdict})
        print(f"[{verdict:<10}] {attack}: {obs}" + (f"  ({note})" if note else ""), flush=True)

    def dump(self, name: str):
        (HERE / f"results-{name}.json").write_text(json.dumps(self.rows, indent=1), encoding="utf-8")
        print(f"wrote results-{name}.json ({len(self.rows)} rows)")
