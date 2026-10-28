# Quaill Records (v0.0.2)

Checks a robot's log and answers three questions:

1. **Who was in control**, the AI or a human, and exactly when it changed.
2. **Was anything changed** after it was logged (hash chain, plus an outside witness for the end of the file).
3. **Is anything missing** (gaps, crashes, cut-off endings), each one explained by a marker or flagged.

It is deterministic. No AI inside. Same file, same report. It states facts ("no messages 03:20 to 05:20, no shutdown marker before, no crash note after"), never guesses or accusations. It is a checker, not a recorder: it reads a finished log, anywhere, later.

## Start with a log you already have

Most robots today record nothing Quaill-specific. Run the checker on such a bag first, so you see exactly what can and cannot be established from it. This is the real output for a plain bag with no Quaill channels (here a ROS 1 bag from the demo set):

```
$ quaill verify robot.bag --profile none

  L0 format        PASS
  L1 integrity     NOT ASSESSABLE
  L2 control       NOT ASSESSABLE
  L2 completeness  PASS            0 gap(s), 0 unexplained, ending unknown (no session markers)
  profile          NOT RUN

FINDINGS  (0 fail, 0 warn, 3 info)
  info  CHAIN_ABSENT      no /quaill/chain channel: edits and deletions cannot be checked from this file
  info  CONTROL_ABSENT    no /quaill/control_mode channel: who was in control cannot be determined from this log
  info  SESSION_ABSENT    no /quaill/session markers: a crash, a clean stop and a cut-off end cannot be told apart in this log

result   MEETS CHECKS (exit 0)
```

That is the honest answer for a log that exists today: it is readable, nothing in it says who was in control, and nothing in it can show whether it was changed. "Meets checks" means the built-in checks found nothing wrong, not that the log proves anything.

Against a regulator's field list, the same bag gets an inventory of what is missing:

```
$ quaill verify robot.bag --profile stvfernlv-anlage3

  profile          FAIL            stvfernlv-anlage3: 0/15 items present with all fields

PROFILE ITEMS  (stvfernlv-anlage3)
  A1   Vehicle identification number                        MISSING
  A2   Position (lat/long 5 decimals, altitude, direction)  MISSING
  A3   Start/end of remote driving with trip number         MISSING
  ...
  A15  Takeover of the driving task by an in-vehicle driver MISSING

result   DOES NOT MEET CHECKS (exit 1)
```

A profile names the topics it expects (the shipped ones use placeholder names such as `/stvfernlv/telemetry`). A real fleet points the items at its own topics and field names with a small mapping file, `--map my-fleet.json` (format in [quaill/profiles/MAPPING.md](quaill/profiles/MAPPING.md)); the report then shows which topic each item was checked on. The checker does not guess topic names, and a mapping cannot invent data: an item the robot never records stays MISSING.

The three channels below (`/quaill/control_mode`, `/quaill/session`, `/quaill/chain`) are what turn NOT ASSESSABLE into an answer. They come from a sidecar that runs next to the robot's own recorder; nothing in the robot's own topics is touched.

## Run it

Python 3.12 or newer. No ROS install needed.

```bash
pip install quaill
quaill demo demo-logs
```

That generates 54 test logs, plants defects, writes them in every container real robots produce, and checks each one. The table at the end must say `all as expected`.

From a clone of this repository, `pip install -r requirements.txt` and `python -m quaill` work the same way, and

```bash
python tests/check_hashes.py
```

confirms the ROS 2 sidecar and the checker hash identically.

| Command | What it does |
|---|---|
| `quaill verify LOG` | Full report. `LOG` is a `.mcap`, a rosbag2 directory, a `.db3`, a ROS 1 `.bag`, or any of those zstd-wrapped. Exit 0 meets checks, 1 does not, 2 unreadable. |
| `quaill verify LOG --profile none` | Built-in checks only. Use this on a bag that has no Quaill channels yet to see what can and cannot be established. |
| `quaill verify LOG --profile stvfernlv-anlage3` | Check against another rule set. |
| `quaill verify LOG --json --out report.json` | Machine-readable report. |
| `quaill who LOG --at 5:30` | Who was in control at that moment, with the handovers around it. |
| `quaill gen OUT --defect truncate --encoding cdr --container rosbag2-sqlite` | Write a synthetic log with a planted defect, in a given container. `quaill defects` lists both. |
| `quaill profiles` | List the rule sets the checker can load. |

The witness is picked up automatically from `<log>.witness.json`, `<bag_dir>/witness.json`, or a `<bag_dir>/witness/` directory of per-session files. `--witness` can point at a file or a directory. `--witness ""` ignores it. The device's public key is picked up from `<log>.pubkey.pem` or `<bag_dir>/device.pubkey.pem`, or given with `--pubkey` (PEM or hex).

## Inputs the checker reads

| Input | Who produces it | Notes |
|---|---|---|
| `.mcap` | rosbag2 on Iron and newer (Jazzy, Kilted, Rolling), Foxglove SDK, mcap CLI | JSON or ROS 2 CDR messages; CDR decoded from the `ros2msg` schema text in the file, no ROS install needed |
| rosbag2 directory, mcap storage | same, as `ros2 bag record` lays it out | split into several files, file-level zstd, chain spans the files |
| rosbag2 directory, sqlite3 storage | Foxy, Galactic, **Humble** (the LTS most fleets run until 2027) | per-message zstd handled; sqlite bags carry no schema text, so only Quaill's own three types are decoded, everything else is hashed and timed |
| single `.db3` | a sqlite bag file without its `metadata.yaml` | per-message compression detected from the zstd magic |
| ROS 1 `.bag` | Noetic and older, still common in industry | read-only: hashed and timed; a ROS 1 robot has no Quaill channels, so integrity and control are NOT ASSESSABLE and the report says so |
| `*.zstd` | any of the above, compressed as a whole file | decompressed to a temp file |

Not read: PX4 ULog, proprietary formats, protobuf-encoded MCAP (planned: `mcap-protobuf-support`).

Memory: payload messages keep only a hash and times; bytes are kept for the Quaill channels and for topics a profile looks into. A multi-gigabyte bag still means a multi-million-entry list in memory, so this is "streams the bytes", not yet "constant memory". Measured on a laptop with synthetic logs: a 2-hour, 17 MB log verifies in 8 s using 290 MB; a 10-hour, 84 MB log in 85 s using 1.4 GB with a witness (29 s without). A fleet bag of several gigabytes will not fit yet.

## Levels

| Level | Question | Grade when it cannot be answered |
|---|---|---|
| L0 format | Is this a readable log? Can the messages be decoded? | FAIL / UNREADABLE |
| L1 integrity | Was anything edited or deleted? Was the end cut off? Did the recorder's clock behave? | NOT ASSESSABLE (no chain); PARTIAL (chain intact, no outside witness) |
| L2 control | Who was in control, when did it change, is any stretch unknown? | NOT ASSESSABLE (no control channel) |
| L2 completeness | Any gaps or an unexplained ending? | without session markers, gaps are warnings and the ending is "unknown" |
| profile | Does the log carry the fields a rule set asks for? | NOT RUN |

A log with no outside witness gets PARTIAL, not FAIL. Cutting the end of a log and appending a forged shutdown marker is **not detectable from the file alone**; the demo shows this honestly (`delivery-truncate-nowitness.mcap` passes). Only a witness the maker does not control (an RFC 3161 timestamp, a third party holding chain heads) catches it.

## The layout (spec v0.0.2, draft)

Three channels added next to whatever the robot already records. Nothing in the robot's own topics is touched. Message definitions are in `ros2_ws/src/quaill_msgs/msg/*.msg`; the checker decodes them from the schema text stored in the bag, or from its embedded copy for sqlite bags.

| Channel | Type | Contents | Shape borrowed from |
|---|---|---|---|
| `/quaill/control_mode` | `quaill_msgs/ControlModeReport` | `mode` (0..6), `operator_ref` (pseudonymous id, required when MANUAL), `reason`, `stamp`; one report on every change plus a heartbeat | Autoware `ControlModeReport` numbering |
| `/quaill/session` | `quaill_msgs/SessionEvent` | `START`, `CLEAN_SHUTDOWN`, `CRASH_NOTE`, `POWER_LOST`, with `session_id` and `software_version` | car EDRs, flight recorders |
| `/quaill/chain` | `quaill_msgs/ChainLink` | one link per message on every other channel: `session_id`, `seq`, `topic`, `msg_sha256 = sha256(topic ‖ 0 ‖ bytes)`, `prev`, `link = sha256(prev ‖ msg_sha256 ‖ seq ‖ recv_time ‖ topic)`, `recv_time`, plus `key_id` and `sig` (Ed25519 over the link, by the device key) | hash chain + per-link signature |

**Pairing is by content, not by time.** The sidecar that publishes links never sees the `log_time` rosbag2 stamps on the original message, so the link carries the content hash and the sidecar's own receive time. The checker pairs unique hashes first, then places duplicate messages (a stopped robot publishes thousands of identical commands) inside the time window their already-paired neighbours define. The two clocks become evidence: `TIME_JUMP` when the recorder clock steps back, `CLOCK_SKEW` when recorder and bag clocks disagree, `TIME_ORDER` when bag order and chain order disagree.

**Sessions.** A sidecar that dies and restarts mid-bag starts a new chain under a new `session_id`; the checker verifies each session's chain on its own (`CHAIN_RESTART`) and witness files are per session.

**Late start.** `ros2 bag record` usually starts after the sidecar, so a bag begins mid-chain: the first link in the file is above 1, the latched `START` marker arrives without its link, and the witness may hold heads from before the file begins. The checker verifies the chain from the first link it has and says so (`CHAIN_STARTS_LATE`, `WITNESS_BEFORE_START`, `MESSAGE_BEFORE_START`), because a bag that started late looks the same as a file whose beginning was removed; the file alone cannot tell which, and the report does not pretend to. The allowance is judged against the whole session, not per topic: links from before the first message the file holds at all, or within 5 s before the bag's first message on a topic (rosbag2 subscribes a moment after a topic appears), are flagged; every other link without its message is `MESSAGE_MISSING`, so deleting every message on one topic cannot pass as a late subscription. In the other direction, a control report or session marker that has no link while the chain was demonstrably running (between the chain's first and last matched message) is a failure (`MESSAGE_UNCHAINED`), because it was added afterwards or the chain node never saw it; unchained messages before the chain began or after it ended are only flagged.

**Signatures, and what they buy.** Every link is signed with an Ed25519 device key; the START marker announces the public key. Three levels of trust, in the report's words: `SIGNED_TRUSTED` (verified against a key you supplied, so nobody without that key produced this chain), `SIGNED_ANNOUNCED` (verifies against the key the bag itself announces, which a forger could swap, so it only proves self-consistency), `UNSIGNED`. The demo shows the boundary: a thorough outsider who rewrites the human stretch, deletes the teleop traffic, rebuilds the chain with their own key and swaps the announced key produces a file that passes with no key and no witness, and fails `KEY_MISMATCH` the moment the real device key is supplied. An outsider who only forges the ending fails `KEY_CHANGED` on their own. An insider with the device key is still caught only by the witness. Keep the private key off the log host; a key next to the bag is a formality.

**Receipts: what makes a witness an outside witness.** A witness file written by the recorder is a note, not evidence. An RFC 3161 receipt from a timestamp authority turns a head into one: the authority signs (hash of the link, its own clock time), so the chain through that link existed by then, whatever the robot's clock said. The sidecar requests one per head when `tsa_url` is set; `quaill stamp WITNESS` adds them to an existing witness file after the fact (default authority: freetsa.org, a public test service; use one you would defend in a dispute). The checker reports `RECEIPT_VALID` (imprint matches the link, the signed digest matches the token, the signature verifies with the authority's certificate embedded in the receipt or given with `--tsa-cert`), `RECEIPT_INVALID`, `RECEIPT_UNVERIFIED` (no certificate to check the signature against) or `RECEIPT_ABSENT`. It does not validate the authority's certificate chain to a root or check revocation; it names the authority so a reader can decide whether to trust it.

**The recorder can lie by omission.** If a human drives through a channel the mode source does not watch, the reports say AUTONOMOUS and no hash can tell. The visible trace is the human's own command traffic: `CONTROL_INCONSISTENT` fires when operator-command topics (by default anything matching `*teleop*`, `*joy*`, `*remote*`, `*manual*`, `*operator*`; a profile can list its own) carry many *distinct* messages during a stretch reported as not-human. A parked joystick repeating one message does not trigger it. Rule for recorders: the node that reports the mode must be the arbiter that decides whose commands reach the motors.

Profiles are JSON files in `quaill/profiles/`:

- `quaill-control`: our addition (who was in control, session markers, chain).
- `stvfernlv-anlage3`: Germany's remote-driving regulation, Anlage 3, 15 items + 6 event types + the 10 s window rule. **Draft mapping onto MCAP, not an official schema**; needs a German-reading reviewer.

Any future field list (UN R157 DSSAD, ISO/IEC 24970, EN 50742 tracing log) is another JSON file, not new code.

## The connector (ROS 2)

`ros2_ws/src/` holds three packages, written for ROS 2 Jazzy, **run on real ROS 2 Jazzy in CI** (see below); not on a physical robot yet:

- `quaill_msgs`: the three message types.
- `quaill_recorder`: the sidecar. `chain` subscribes raw to configured (or all discovered) topics, hashes the exact bytes the publisher sent, publishes one `ChainLink` per message, writes `START` / `CLEAN_SHUTDOWN` / `CRASH_NOTE` markers (a dirty state file after `kill -9` triggers the crash note on the next start), and writes witness heads every 10 s, with an optional RFC 3161 receipt per head. `control_mode` turns a mode source (a String topic or Autoware's `ControlModeReport`) into standard reports with a heartbeat.
- `quaill_demo_robot`: a fake robot with real handovers. `mode_manager` decides whose `/cmd_vel` reaches the robot (autonomy or `teleop_twist_keyboard`) and is therefore the node that reports who is driving. No simulator needed.

`ros2_ws/record_runs.sh` records the test bags on a real ROS 2 Jazzy system with nobody at a keyboard: the fake robot, both sidecars, `ros2 bag record`, a scripted operator (`scripted_teleop`) taking over twice, then a bag with no Quaill nodes at all, a killed recorder, a killed-and-restarted sidecar, and a power cut. `ros2_ws/summarize_runs.py` turns the checker's reports into one table. The workflow in `.github/workflows/ros2-run.yml` does all of that on a plain Ubuntu 24.04 runner and keeps the bags, witness files and reports as a downloadable artifact. Real ROS 2 and real bags; not a physical robot.

The one question only a real recording could settle was whether rosbag2 stores exactly the bytes the sidecar hashed. It does: in the first green run, every one of the clean run's 1,694 chain links matched a message in the bag by content hash (Fast DDS, `rmw_fastrtps_cpp`). The same run passed every level on the clean bag (four handovers, witnessed to the end, ending marked), and its witness heads carried valid RFC 3161 receipts from freetsa.org. The recorder-killed and power-cut bags fail, as they should. The workflow's summary repeats the check on every push.

## What the demo proves and what it does not

Proves: every planted defect is caught in both encodings and in every container; clean logs pass; the checker reads real `ros2msg`/CDR bags, rosbag2 directories (mcap and sqlite3, split, compressed), single `.db3` files and ROS 1 bags; the witness logic separates "recorder died" from "end was cut"; the sidecar and the checker hash identically.

Does not prove: anything about a real robot. All 54 logs come from the synthetic generator in `quaill/gen.py`, a labeled reference/example recorder, not a product. The CI recordings above come from real ROS 2 and real `ros2 bag record` with a fake robot; nothing has run on a physical robot yet.

## Other pages

- [THREAT-MODEL.md](THREAT-MODEL.md): who might fake a log, what each check catches against whom, what nothing can catch.
- [TRADEMARK.md](TRADEMARK.md): how the name may be used; never "certified", "verified", "compliant", "safe".
- [PRIVACY.md](PRIVACY.md): `operator_ref` is personal data; what a maker or operator should consider before switching the layout on.

## Not in v0.0.2 yet

- Key registration. The checker trusts a key you hand it; nothing yet ties a key to a robot in a registry or a witness record beyond the per-entry `key_id`.
- Validation of a timestamp authority's certificate chain. Receipts are checked against the certificate embedded in them or given with `--tsa-cert`; a forged receipt with a self-signed certificate that names a real authority passes unless the real certificate is supplied.
- `session_id` is not part of the link hash or signature, so the checker cannot tell a relabeled chain from a different session; a witness that matches no session in the file fails (`WITNESS_UNMATCHED`) rather than being ignored.
- `mcap doctor` delegation for L0. Protobuf MCAP. Constant-memory streaming.
- CDR generation for the remote-vehicle scenario (JSON-only; the checker is encoding-agnostic).
- A browser drop-in and a GitHub Action.

## Files

```
./
  requirements.txt      pinned Python dependencies
  LICENSE, NOTICE       Apache-2.0, Copyright Quaill LLC
  CLA.md, CONTRIBUTING.md
  THREAT-MODEL.md, TRADEMARK.md, PRIVACY.md
  tests\check_hashes.py connector and checker hash identically
  ros2_ws\src\
    quaill_msgs\        ControlModeReport.msg, SessionEvent.msg, ChainLink.msg (spec v0.0.2)
    quaill_recorder\    chain + control_mode sidecar nodes, config, launch
    quaill_demo_robot\  mode_manager, auto_driver, fake_odom, launch
  quaill\
    cli.py              commands: verify, who, gen, demo, profiles, defects
    engine.py           runs every check on one log
    inputs.py           every input format behind open_log()
    report.py           text / JSON / who-was-driving rendering
    mcapio.py           the layout, hashes, JSON + CDR decoding
    keys.py             Ed25519 device keys: sign links, verify, key ids
    chain.py            hash chain build + verify (content pairing, sessions, signatures) + witness + clock checks
    gen.py              synthetic generator (two scenarios, seventeen defects, json or cdr, six containers, plus a ROS 1 bag)
    checks\             format (L0), control (L2), completeness (L2), profile
    profiles\           quaill-control.json, stvfernlv-anlage3.json
  demo-logs\            output of `quaill demo`
```
