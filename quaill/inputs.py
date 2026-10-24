"""Every input the checker accepts, behind one function: open_log(path).

  robot.mcap                 single MCAP (rosbag2 Iron+, Foxglove SDK, mcap CLI, our generator)
  robot.mcap.zstd            a zstd-wrapped single file
  bag_dir/                   rosbag2 directory with metadata.yaml: storage mcap or sqlite3, split into
                             several files, file- or message-level zstd compression
  robot.db3                  a single rosbag2 SQLite file without its metadata.yaml
  robot.bag                  ROS 1 bag (read-only: hashed and timed, never decoded)

Memory: payload messages keep only their content hash and times. Message bytes are kept only for the
Quaill channels and for topics a profile needs to look inside. A multi-gigabyte bag still means a
multi-million-entry list, so this is "streams the bytes", not yet "constant memory".
"""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

from .mcapio import CHAIN_TOPIC, CONTROL_TOPIC, MAGIC, MSG_DEFS, SESSION_TOPIC, LogFile, Msg, UnreadableLog, message_hash

QUAILL_TOPICS_SET = {CHAIN_TOPIC, CONTROL_TOPIC, SESSION_TOPIC}
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
TYPE_DEFS = {name: text for (name, text) in MSG_DEFS.values()}  # ros2 type name -> ros2msg text (for bags without schema text)


def _keep(keep_data_topics) -> set[str]:
    return QUAILL_TOPICS_SET | set(keep_data_topics or ())


def _sha_file(p: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _zstd_bytes(data: bytes) -> bytes:
    import zstandard

    return zstandard.ZstdDecompressor().decompressobj().decompress(data)


def _zstd_file(src: Path, dst: Path) -> None:
    import zstandard

    with src.open("rb") as fi, dst.open("wb") as fo:
        zstandard.ZstdDecompressor().copy_stream(fi, fo)


def open_log(path: str, keep_data_topics=None) -> LogFile:
    p = Path(path)
    if not p.exists():
        raise UnreadableLog(f"no such file or directory: {path}")
    keep = _keep(keep_data_topics)
    if p.is_dir():
        return _read_rosbag2_dir(p, keep)
    name = p.name.lower()
    if name.endswith((".zstd", ".zst")):
        with tempfile.TemporaryDirectory() as td:
            inner = Path(td) / p.name[: p.name.rfind(".")]
            _zstd_file(p, inner)
            log = open_log(str(inner), keep_data_topics)
        sha, size = _sha_file(p)
        log.path, log.sha256, log.size, log.files = str(p), sha, size, [(str(p), sha, size)]
        log.kind += ", zstd-wrapped file"
        return log
    if name.endswith(".bag"):
        return _read_rosbag1(p, keep)
    if name.endswith(".db3"):
        return _read_sqlite_file(p, keep)
    return _read_mcap_file(p, keep)


# ---------------------------------------------------------------- MCAP ----------------------------------------------------------------
def _iter_mcap(p: Path, keep: set[str], message_zstd: bool = False):
    """Returns (msgs, library, profile, has_summary, magic_ok, finalized, read_error)."""
    from mcap.reader import make_reader

    size = p.stat().st_size
    with p.open("rb") as f:
        head = f.read(8)
        f.seek(max(0, size - 8))
        tail = f.read(8)
    magic_ok = head == MAGIC
    finalized = tail == MAGIC and size > 16

    msgs: list[Msg] = []
    library = profile = ""
    has_summary = False
    read_error = None

    def collect(reader, ordered: bool):
        for schema, channel, message in reader.iter_messages(log_time_order=ordered):
            data = bytes(message.data)
            if message_zstd:
                data = _zstd_bytes(data)
            topic = channel.topic
            msgs.append(
                Msg(
                    topic=topic,
                    log_time=message.log_time,
                    publish_time=message.publish_time,
                    sequence=message.sequence,
                    hash=message_hash(topic, data),
                    data=data if topic in keep else None,
                    encoding=channel.message_encoding,
                    schema_name=schema.name if schema else None,
                    schema_encoding=schema.encoding if schema else None,
                    schema_data=schema.data if schema else None,
                )
            )

    try:
        with p.open("rb") as f:
            reader = make_reader(f)
            header = reader.get_header()
            library, profile = header.library, header.profile
            has_summary = reader.get_summary() is not None
            collect(reader, True)
    except Exception as e:  # fall back to a straight stream read (cut-off files, no summary)
        msgs.clear()
        try:
            from mcap.reader import NonSeekingReader

            with p.open("rb") as f:
                collect(NonSeekingReader(f), False)
        except Exception as e2:
            if not msgs:
                raise UnreadableLog(f"{type(e).__name__}: {e}") from e
            read_error = f"{type(e2).__name__}: {e2} (kept {len(msgs)} messages read before the error)"
        else:
            read_error = f"{type(e).__name__}: {e} (read as a stream instead)"
        msgs.sort(key=lambda m: m.log_time)
    return msgs, library, profile, has_summary, magic_ok, finalized, read_error


def _read_mcap_file(p: Path, keep: set[str]) -> LogFile:
    msgs, library, profile, has_summary, magic_ok, finalized, err = _iter_mcap(p, keep)
    sha, size = _sha_file(p)
    return LogFile(
        path=str(p), size=size, sha256=sha, magic_ok=magic_ok, finalized=finalized, has_summary=has_summary, library=library, profile=profile,
        messages=msgs, topic_counts=Counter(m.topic for m in msgs), read_error=err, kind="mcap file", files=[(str(p), sha, size)],
    )


# ---------------------------------------------------------------- rosbag2 directory ----------------------------------------------------------------
def _load_metadata(p: Path) -> dict:
    yp = p / "metadata.yaml"
    if not yp.is_file():
        raise UnreadableLog(f"{p} is a directory without metadata.yaml (not a rosbag2 bag)")
    try:
        from ruamel.yaml import YAML

        d = YAML(typ="safe").load(yp.read_text(encoding="utf-8"))
    except Exception as e:
        raise UnreadableLog(f"cannot parse {yp}: {e}") from e
    info = d.get("rosbag2_bagfile_information") if isinstance(d, dict) else None
    if not isinstance(info, dict):
        raise UnreadableLog(f"{yp} has no rosbag2_bagfile_information section")
    return info


def _bag_files(p: Path, info: dict) -> list[Path]:
    rel = info.get("relative_file_paths") or [f["path"] for f in info.get("files", []) if isinstance(f, dict) and "path" in f]
    out = []
    for r in rel:
        cand = p / r
        if not cand.exists():
            cand = p / Path(r).name  # older bags stored "bagname/bagname_0.db3"
        if not cand.exists():
            raise UnreadableLog(f"bag file listed in metadata.yaml is missing: {r}")
        out.append(cand)
    if not out:
        raise UnreadableLog("metadata.yaml lists no bag files")
    return out


def _combined_sha(files: list[tuple[str, str, int]]) -> str:
    if len(files) == 1:
        return files[0][1]
    h = hashlib.sha256()
    for _, sha, _ in files:
        h.update(bytes.fromhex(sha))
    return h.hexdigest()


def _read_rosbag2_dir(p: Path, keep: set[str]) -> LogFile:
    info = _load_metadata(p)
    storage = str(info.get("storage_identifier") or "").lower()
    cmode = str(info.get("compression_mode") or "").lower()
    cfmt = str(info.get("compression_format") or "").lower()
    files = _bag_files(p, info)
    file_rows = [(str(f), *_sha_file(f)) for f in files]
    distro = info.get("ros_distro") or ""
    desc = f"rosbag2 directory, {storage}, {len(files)} file(s)" + (f", {cmode} compression ({cfmt})" if cmode and cmode != "none" else "") + (f", ros_distro {distro}" if distro else "")

    msgs: list[Msg] = []
    if storage == "mcap":
        libs, errors = set(), []
        finalized_all = magic_all = True
        for f in files:
            src = f
            td = None
            if cmode == "file":
                td = tempfile.TemporaryDirectory()
                src = Path(td.name) / f.name.replace(".zstd", "").replace(".zst", "")
                _zstd_file(f, src)
            try:
                part, library, _, _, magic_ok, finalized, err = _iter_mcap(src, keep, message_zstd=(cmode == "message"))
            finally:
                if td:
                    td.cleanup()
            msgs.extend(part)
            if library:
                libs.add(library)
            finalized_all &= finalized
            magic_all &= magic_ok
            if err:
                errors.append(f"{f.name}: {err}")
        msgs.sort(key=lambda m: m.log_time)
        return LogFile(
            path=str(p), size=sum(r[2] for r in file_rows), sha256=_combined_sha(file_rows), magic_ok=magic_all, finalized=finalized_all, has_summary=True,
            library="; ".join(sorted(libs)), profile="ros2", messages=msgs, topic_counts=Counter(m.topic for m in msgs),
            read_error="; ".join(errors) or None, kind=desc, files=file_rows,
        )
    if storage == "sqlite3":
        try:
            from rosbags.rosbag2 import Reader
        except Exception as e:  # pragma: no cover
            raise UnreadableLog(f"reading rosbag2 sqlite3 bags needs the 'rosbags' package: {e}") from e
        counts: Counter = Counter()
        try:
            with Reader(p) as r:
                for conn, ts, raw in r.messages():
                    topic = conn.topic
                    data = bytes(raw)
                    counts[topic] += 1
                    schema_text = TYPE_DEFS.get(conn.msgtype)
                    fmt = getattr(conn.ext, "serialization_format", "cdr") or "cdr"
                    msgs.append(
                        Msg(
                            topic=topic, log_time=ts, publish_time=ts, sequence=counts[topic], hash=message_hash(topic, data),
                            data=data if topic in keep else None, encoding=fmt, schema_name=conn.msgtype,
                            schema_encoding="ros2msg" if schema_text else None, schema_data=schema_text.encode() if schema_text else None,
                        )
                    )
        except UnreadableLog:
            raise
        except Exception as e:
            raise UnreadableLog(f"rosbags could not read {p}: {type(e).__name__}: {e}") from e
        msgs.sort(key=lambda m: m.log_time)
        return LogFile(
            path=str(p), size=sum(r[2] for r in file_rows), sha256=_combined_sha(file_rows), magic_ok=True, finalized=True, has_summary=True,
            library="rosbag2 sqlite3 storage" + (f" ({distro})" if distro else ""), profile="ros2", messages=msgs, topic_counts=Counter(m.topic for m in msgs),
            read_error=None, kind=desc + "; no schema text in sqlite bags: only Quaill's own types are decoded", files=file_rows,
        )
    raise UnreadableLog(f"unknown rosbag2 storage plugin '{storage}'")


# ---------------------------------------------------------------- single .db3 ----------------------------------------------------------------
def _read_sqlite_file(p: Path, keep: set[str]) -> LogFile:
    try:
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        topics = {row[0]: (row[1], row[2], row[3]) for row in con.execute("SELECT id, name, type, serialization_format FROM topics")}
        rows = con.execute("SELECT topic_id, timestamp, data FROM messages ORDER BY timestamp, id")
        msgs: list[Msg] = []
        counts: Counter = Counter()
        for topic_id, ts, data in rows:
            name, mtype, fmt = topics.get(topic_id, (f"topic#{topic_id}", "", "cdr"))
            data = bytes(data)
            if data[:4] == ZSTD_MAGIC:  # message-level compression; no metadata.yaml to tell us, so sniff
                data = _zstd_bytes(data)
            counts[name] += 1
            schema_text = TYPE_DEFS.get(mtype)
            msgs.append(
                Msg(
                    topic=name, log_time=int(ts), publish_time=int(ts), sequence=counts[name], hash=message_hash(name, data),
                    data=data if name in keep else None, encoding=fmt or "cdr", schema_name=mtype,
                    schema_encoding="ros2msg" if schema_text else None, schema_data=schema_text.encode() if schema_text else None,
                )
            )
        con.close()
    except UnreadableLog:
        raise
    except Exception as e:
        raise UnreadableLog(f"not a readable rosbag2 sqlite3 file: {type(e).__name__}: {e}") from e
    sha, size = _sha_file(p)
    return LogFile(
        path=str(p), size=size, sha256=sha, magic_ok=True, finalized=True, has_summary=True, library="rosbag2 sqlite3 storage (single file, no metadata.yaml)",
        profile="ros2", messages=msgs, topic_counts=Counter(m.topic for m in msgs), read_error=None,
        kind="rosbag2 sqlite3 file; no schema text: only Quaill's own types are decoded", files=[(str(p), sha, size)],
    )


# ---------------------------------------------------------------- ROS 1 ----------------------------------------------------------------
def _read_rosbag1(p: Path, keep: set[str]) -> LogFile:
    try:
        from rosbags.rosbag1 import Reader
    except Exception as e:  # pragma: no cover
        raise UnreadableLog(f"reading ROS 1 bags needs the 'rosbags' package: {e}") from e
    msgs: list[Msg] = []
    counts: Counter = Counter()
    try:
        with Reader(p) as r:
            for conn, ts, raw in r.messages():
                topic = conn.topic
                data = bytes(raw)
                counts[topic] += 1
                msgs.append(Msg(topic=topic, log_time=ts, publish_time=ts, sequence=counts[topic], hash=message_hash(topic, data), data=None, encoding="ros1", schema_name=conn.msgtype))
    except Exception as e:
        raise UnreadableLog(f"not a readable ROS 1 bag: {type(e).__name__}: {e}") from e
    msgs.sort(key=lambda m: m.log_time)
    sha, size = _sha_file(p)
    return LogFile(
        path=str(p), size=size, sha256=sha, magic_ok=True, finalized=True, has_summary=True, library="ROS 1 rosbag", profile="ros1",
        messages=msgs, topic_counts=Counter(m.topic for m in msgs), read_error=None,
        kind="ROS 1 bag (read-only: a ROS 1 robot carries no Quaill channels, so integrity and control are not assessable)", files=[(str(p), sha, size)],
    )
