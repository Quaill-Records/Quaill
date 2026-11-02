# Adversarial tests

Scripts that attack the checker the way a maker, an operator, or an outsider holding the file would, plus broken inputs, forged receipts, CLI edge cases and a size ladder. They are the regression suite for the honest table in [THREAT-MODEL.md](../../THREAT-MODEL.md): every row records what the attack expects, what the checker said, and a verdict. `OK` means the checker did what the threat model promises. `DESIGN-GAP` means it did what the design says, and the design is the weak part; each one is listed below with the fix it would take. `BUG` means a wrong verdict or a traceback; there are none left in this run.

Numbers below are from the rerun after the fixes.

## Run

From anywhere, with the project's Python (needs `mcap`, `cryptography`, `asn1crypto`):

```
python tests/attacks/_baseline.py        # once: writes the two base logs into tests/attacks/out/
python tests/attacks/forgery.py          # ~2 min
python tests/attacks/forgery2.py         # ~1 min, the second pass (below)
python tests/attacks/robustness.py       # ~2 min
python tests/attacks/receipts_attack.py  # seconds
python tests/attacks/cli_ux.py           # ~4 min
python tests/attacks/scale.py            # ~5 min, peaks at 1.4 GB
```

Each script writes `results-<name>.json` (one row per attack: `attack`, `expected`, `observed`, `exit`, `verdict`) and prints the same lines; the `*.log` and `results-*.json` files are local output and are gitignored, like `out/`, which holds the generated logs (hundreds of MB). Run the scripts to reproduce them. The scripts never import from `ros2_ws/`; they read and rewrite MCAP files directly (`attacklib.py`) and run the checker in a child process, measuring time and peak memory.

## Results

| Suite | Rows | OK | DESIGN-GAP | BUG | What it does |
|---|---|---|---|---|---|
| `forgery.py` | 78 (39 attacks × JSON and CDR) | 70 | 8 | 0 | edits, deletions, insertions, reorders, truncations, chain rebuilds with and without the device key, session relabels, witness and key swaps, cross-file splices |
| `forgery2.py` | 28 (14 attacks × JSON and CDR) | 23 | 5 | 0 | the third pass: a moved incident instead of a moved human, planted command traffic, a chain split in two by relabeling to hide a cut in the middle, unchained shutdown markers as explanations, a planted report inside a sidecar outage, a constant hidden command |
| `robustness.py` | 117 | 117 | 0 | 0 | empty, truncated and garbage files in every container; malformed chain links, witness files, profiles and mappings; odd flags |
| `receipts_attack.py` | 14 | 12 | 2 | 0 | real freetsa.org receipt moved, altered, stripped; forged receipts with a self-signed certificate; wrong `--tsa-cert`; rejection status; bogus SignerInfo |
| `cli_ux.py` | 66 | 66 | 0 | 0 | `who --at` with every malformed time; `verify` on `.`, `D:`, `con`, `nul`, `C:\Windows`; unicode paths on a cp1252 pipe; `--profile`/`--witness`/`--pubkey`/`--tsa-cert` typos; `gen` edge cases; `stamp` against an unreachable authority |
| `scale.py` | 14 | 14 | 0 | 0 | 10 min to 10 h synthetic logs; 5,000 to 40,000 identical messages; thousands of edits; a huge witness; see the table below |

## What the first run found, and what was changed

| # | Attack | Before | After | Where |
|---|---|---|---|---|
| 1 | Delete the first message on a topic, keep its link | `MESSAGE_BEFORE_START` (warn), exit 0 | `MESSAGE_MISSING`, exit 1 | `chain.py`: the "bag started late" allowance is judged against the first message the file holds from the whole session, not per topic |
| 2 | Delete **every** message on `/teleop/cmd_vel` (the human's commands), keep the 150 links | warn, exit 0 | `MESSAGE_MISSING`, exit 1 | same |
| 3 | Delete the first 12 control reports | exit 1 only through `CONTROL_UNKNOWN` | `MESSAGE_MISSING` | same; the 5 s window before the bag's first message on a topic is the only late-subscription allowance left |
| 4 | Edit the first message on a topic (one byte, or the first five) | warn, exit 0 | `MESSAGE_EDITED` | `chain.py`: edit pairing runs before the late-start classification |
| 5 | Swap the announced public key in the START marker | `KEY_MISMATCH` but the edit itself was a warn | `KEY_MISMATCH` + `MESSAGE_EDITED` | same |
| 6 | Insert a MANUAL control report at the moment of the bumper hit (blame the human) | `MESSAGE_UNCHAINED` warn, exit 0; `who` named the forged operator | `MESSAGE_UNCHAINED` **fail** when the chain was running at that time | `chain.py`: unchained control reports and session markers inside the chain's coverage fail; outside it they still warn |
| 7 | Duplicate a control report 5 min later, no link | warn, exit 0 | fail | same |
| 8 | Strip the chain channel; the witness is still supplied | `CHAIN_ABSENT`, L1 NOT ASSESSABLE, exit 0 (witness ignored) | `WITNESS_WITHOUT_CHAIN`, exit 1 | `chain.py` |
| 9 | Rename `session_id` on every link so the witness matches nothing | `UNWITNESSED` warn, exit 0 | `WITNESS_UNMATCHED`, exit 1 | `chain.py` |
| 10 | Insider cuts the end, forges a shutdown, relabels the session, witness supplied | exit 0 (the witness was defeated) | `WITNESS_UNMATCHED`, exit 1 | same |
| 11 | Edit, rebuild the chain unsigned, supply the real device key | `UNSIGNED` info, exit 0 (README promised `KEY_MISMATCH`) | `KEY_MISMATCH`, exit 1 | `chain.py`: a supplied key with an unsigned chain is a mismatch |
| 12 | Forged receipt with a sha1 imprint | `RECEIPT_VALID` | `RECEIPT_INVALID` | `receipts.py`: sha1 refused for imprints and signer digests |
| 13 | Witness entry with `seq: null`, `seq: []`, `recv_time: "abc"` | traceback | `WITNESS_UNREADABLE` with the reason; a fail when the witness was named on the command line | `chain.py` `load_witness`, `engine.py` |
| 14 | Profile: items as a dict or strings, item without `topic`, `when` without `field`, events without `topic`, `operator_command_topics` as ints, top level a list, `window_s` a string | traceback (7 cases) | exit 2 with a plain message | `checks/profile.py` `validate_profile` |
| 15 | `--out` pointing at a directory | traceback | exit 2 with a message | `cli.py` |
| 16 | `quaill verify con` (a Windows console device name) | blocked on console input until killed | exit 2, "not a regular file or directory" | `inputs.py` |
| 17 | `quaill stamp` against an unreachable authority | traceback | exit 2 with the reason; receipts already written are kept | `cli.py` |
| 18 | `--tsa-cert` pointing at a nonexistent file | warn, exit 0 (a typo ended in "meets checks") | `TSA_CERT_UNREADABLE` fail, exit 1 (same rule as `--witness` and `--pubkey` typos) | `engine.py` |
| 20 | 20,000-entry witness against the 10-hour log | still running after 6 minutes: the seq-to-link table of all 396,157 links was rebuilt for every witness entry | 29 s; the table is built once per session | `chain.py` |
| 19 | 40,000 identical chained messages (a parked robot at 10 Hz for about an hour) | 88 s, quadratic: 5k 1.7 s, 10k 5.7 s, 20k 22 s, 40k 88 s | 1 s, linear: the duplicate pairing keeps a cursor per hash instead of rescanning the taken ones | `chain.py` |

The suites' `expected` strings and verdict functions were updated to the new contract (rows 6 to 12 now require the fail), so a regression shows up as `BUG`.

## What the third pass found (`forgery2.py`), and what was changed

Six attack families got through the checker as it stood after the second pass; each was confirmed against the threat model's promises before anything was changed, and the fix for each was checked against every suite above plus the 59-case demo.

| # | Attack | Before | After | Where |
|---|---|---|---|---|
| 21 | Move the **incident** (one `/events` message) into the human stretch in bag time, instead of moving the human | `TIME_MOVED` **warn**, exit 0: only control, session and operator topics counted as decisive | `TIME_MOVED` fail for any moved message | `chain.py`: a bag clock that steps on its own moves every topic at once; a lone moved message is a moved message |
| 22 | Plant eight distinct unchained `/teleop/cmd_vel` messages during an autonomous stretch ("prove" a hidden human) | `CONTROL_INCONSISTENT` fail against the maker, from messages the chain node never saw | no `CONTROL_INCONSISTENT`; `MESSAGE_UNCHAINED` warn names them | `checks/control.py`: command messages without a link on a topic the chain was covering are not evidence |
| 23 | Remove 1.5 s around the bumper contact (messages and links), relabel every later link as a new session; no witness | exit 0, L1 PARTIAL: each half checked on its own, the second one merely `CHAIN_STARTS_LATE` | `CHAIN_BROKEN`, exit 1 | `chain.py`: only the first session in a file may begin above link 1; a restarted recorder begins at link 1 |
| 24 | Same, with the whole second half relabeled and nothing removed; same with 2 min erased and forged `CRASH_NOTE`/`START` or `CLEAN_SHUTDOWN`/`START` markers telling a crash or clean-stop story | exit 0 | `CHAIN_BROKEN` (+ `GAP_UNEXPLAINED` for the clean-stop story) | same rule; the unchained shutdown marker no longer explains the gap |
| 25 | Cut the end and append an **unchained, unsigned** `CLEAN_SHUTDOWN` (no key needed); no witness | exit 0: "ending marked", the cut that fails as `ENDING_UNEXPLAINED` without the marker passed with it | `ENDING_UNEXPLAINED`, exit 1 | `checks/completeness.py`: where the log has a chain, `CLEAN_SHUTDOWN`/`POWER_LOST` count only if the chain saw them; `START`/`CRASH_NOTE` stay accepted unchained (latched, or published by a restarted recorder before it chains its own topic) |
| 26 | The real sidecar's own `CLEAN_SHUTDOWN` was unchained (published after `spin()` returned, so its own subscription never saw it): under row 25 every real recording would have failed | unchained marker | the sidecar chains the marker in-process from the same serialized bytes it publishes | `ros2_ws/.../chain_node.py`; the next CI run is the test |
| 27 | Plant a MANUAL report inside a sidecar outage; `who --at` named the planted operator with no hint | answer given as if chained | same answer, plus a "Caution: the control report behind this answer has no chain link" line | `report.py`, `checks/control.py` (`Segment.chained`) |

Guards added with them: shifting every message uniformly in bag time (a bag clock that simply differs from the recorder clock) stays exit 0, and shifting everything except the human stretch is still caught on the human stretch.

## What stays open (DESIGN-GAP), with the fix each would take

| Attack | What the checker says | Why it is allowed today | Fix |
|---|---|---|---|
| Append messages after the shutdown marker (within 1 s, or 3 s later) | `MESSAGE_UNCHAINED` warn (+ `ENDING_UNMARKED`/`GAP_EXPLAINED` warns), exit 0 | after the chain's last link the file alone cannot tell "added later" from "the chain node stopped first"; with a witness the end is confirmed up to the last head, not beyond | a rule that any message on a chained topic after `CLEAN_SHUTDOWN` is a fail; cheap, but a real robot can publish a few messages after the marker |
| Insert a MANUAL report 1.5 s before START, or inside a sidecar outage (`forgery2.py`) | `MESSAGE_UNCHAINED` warn, exit 0; `who` names the planted operator, now with a "no chain link" caution | before the chain began, or while it was down, nothing covers the file; a real sidecar outage produces exactly this shape (CI run3), so a failure here would fail honest logs | a recorder that never stops chaining (a second sidecar, or links written by the recorder itself); until then, read the caution |
| Prepend a fake `CRASH_NOTE` before the first matched message | counted as a latched marker (info), exit 0 | a bag that starts late legitimately receives latched markers without their links; a restarted recorder publishes `CRASH_NOTE` before it chains its own topic | the restarted recorder could chain its own `CRASH_NOTE`/`START` the way it now chains `CLEAN_SHUTDOWN`; then unchained ones could fail |
| A human holding one constant command (`forgery2.py`: 20 identical chained teleop messages while AUTONOMOUS) | not caught | below the 5-distinct-messages bar that keeps a parked joystick from firing `CONTROL_INCONSISTENT` | the mode source itself; or a per-robot threshold in the profile |
| Delete the first 4 s of a topic's messages, keep the links (`forgery2.py`) | `MESSAGE_BEFORE_START` warn (JSON); CDR fails anyway because its identical Twist messages re-pair and `MESSAGE_MISSING`/`TIME_MOVED` fire | the 5 s late-subscription allowance per topic (rosbag2 discovers topics after they appear) | shorten the allowance once real bags show how late rosbag2 subscribes |
| Forged receipt: self-signed certificate with CN `www.freetsa.org`, no `--tsa-cert` | `RECEIPT_VALID ... from www.freetsa.org, Free TSA` | the checker verifies the signature with the certificate embedded in the receipt and does not chain it to a root; the report names the authority so a reader can supply the real certificate | validate the embedded certificate against a supplied or bundled root (a few hours with `cryptography` + a pinned root list); until then, pass `--tsa-cert` in any dispute |
| Insider cut + rebuilt witness + forged receipts on every head | passes (same gap) | same | same; with the real freetsa certificate supplied via `--tsa-cert` it fails `RECEIPT_INVALID` (row 12 of the receipts suite) |

Closed on the second pass: swapping two messages' log times, moving the whole human stretch in bag time, and shifting the MANUAL reports by 4 s are all `TIME_MOVED` failures now, because the control and completeness timelines are built from the signed `recv_time` of each matched link (shifted by the session's one clock offset) instead of the bag's `log_time`; `who --at` answers from the signed times. The move tolerance is 2 s, the same bound the duplicate pairing uses. A session whose recorder clock stepped back keeps bag time, since that step is already reported and cannot be forged without the device key. Also on that pass: an MCAP that ends before its first complete record is reported as such, with the file size, instead of a bare `EndOfFile`.

Also known, not a suite row: `session_id` is not part of the link hash or signature, so a relabeled chain is caught only when a witness is supplied (`WITNESS_UNMATCHED`); putting it inside the hash is a spec change for v0.1 and a connector change.

## Scale (full rerun after both fixes, on a laptop)

| Synthetic log | Size | Verify with witness | Verify without | Peak memory (with witness) |
|---|---|---|---|---|
| 10 min | 1 MB | 4.8 s | 4.6 s | 54 MB |
| 30 min | 4 MB | 4.9 s | 3.5 s | 98 MB |
| 1 h | 8 MB | 5.6 s | 5.2 s | 165 MB |
| 2 h | 17 MB | 6.5 s | 6.6 s | 297 MB |
| 10 h | 84 MB | 31.8 s | 30.7 s | 1,388 MB |

Also in the suite: 5,000 to 40,000 identical chained messages (a parked robot publishing the same command), thousands of edited messages, and a witness with tens of thousands of entries. The identical-message case was quadratic before the fix (row 19 above) and is 1.0 s at 40,000 now (5k 0.5 s, 10k 0.5 s, 20k 0.7 s, 40k 1.0 s). The 19,200-entry witness against the 10-hour log takes 29.6 s (row 20); before the fix it did not finish in 6 minutes. The with-witness and without-witness times are now within a second of each other on every size.

Memory grows with message count (one entry per message plus the witness pairing), not with bytes. A real fleet bag of several gigabytes will not fit in RAM on a laptop; constant-memory streaming is the fix and is on the list for when someone sends a bag that big.
