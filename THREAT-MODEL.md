# Threat model (spec v0.0.2)

One page on who might fake a robot log, what each check catches against them, and what nothing in this design can catch. Read it before trusting any PASS.

## What is being protected

| Asset | Where it lives | Who controls it |
|---|---|---|
| The log (the bag) | the robot, then wherever the maker or operator copies it | maker or operator |
| The chain (`/quaill/chain`) | inside the bag | the sidecar on the robot, so: maker or operator |
| Witness heads | the sidecar's state directory, then a third party | should be a party the maker does not control; today it is the robot itself unless `tsa_url` is set |
| Control reports (`/quaill/control_mode`) | inside the bag | whoever wrote the mode source: maker |
| Device key | the robot; the checker only needs the public key | maker; should live in a TPM or secure element, never next to the log |

## Adversaries and what they can do

| Adversary | Motive | Capabilities |
|---|---|---|
| **Maker** | the robot gets blamed; make it look like the human or the environment | holds the file, the recorder, the clock, the mode source, and (today) the witness file |
| **Operator / deployer** | the operator gets blamed; make it look like the robot | holds the file after the fact; usually not the recorder |
| **Outside attacker** | discredit evidence, or extort | gets a copy of the file; maybe the witness heads |
| **Witness insider** | collude with the maker | can back-date or drop heads |

## What each check catches, against whom

| Attack | Catchable? | By what | Against whom |
|---|---|---|---|
| Edit a message after recording | Yes | chain: link hash ≠ message hash (`MESSAGE_EDITED`) | anyone who holds only the file |
| Delete a message and its link | Yes | chain: sequence gap, prev mismatch (`CHAIN_BROKEN`) | anyone who holds only the file |
| Delete and rebuild the whole chain | **Only with a witness** | witness head ≠ file head (`WITNESS_MISMATCH`) | anyone, including the maker, if the witness is outside |
| Cut the end and append a forged shutdown | **Only with a witness** | witness holds a later head (`TRUNCATED`) | same |
| Remove the beginning of the file | **Flagged, not decided** | a bag that started after the sidecar looks the same (`CHAIN_STARTS_LATE`, `MESSAGE_BEFORE_START`); a witness head from before the file's first link only confirms the chain existed earlier, not what it held | anyone who holds only the file |
| Remove the first messages on one topic, or every message on it | Yes, beyond 5 s | links from inside the stretch the file covers are `MESSAGE_MISSING`; only links within 5 s before the bag's first message on that topic are allowed as a late subscription (`MESSAGE_BEFORE_START`) | anyone who holds only the file |
| Insert a control report or session marker (no link) | Yes while the chain was running; **flagged** outside it | `MESSAGE_UNCHAINED` is a failure between the chain's first and last matched message, a warning before or after; `who` still answers from the file as written, so read the report first | anyone who holds only the file |
| Strip the chain channel from the file, keep the witness | Yes with a witness | `WITNESS_WITHOUT_CHAIN`: a witness is a claim that a chain existed | anyone who holds only the file |
| Relabel the chain's `session_id` so the witness matches nothing | Yes with a witness, as a failure to confirm | `WITNESS_UNMATCHED`; the session id is not inside the link hash or signature, so the checker cannot say which file the witness belongs to (spec change planned) | anyone who holds the file and the witness |
| Rebuild the chain without signing it | Yes if the real public key is supplied | `KEY_MISMATCH`: a chain with no signatures was not produced by that key | anyone without the device key |
| Stop recording for a while | Yes, as a gap | `GAP_UNEXPLAINED` unless a marker explains it | recorder operator |
| Kill the recorder | Told apart from a cut **only with a witness** | `ENDING_UNMARKED` vs `ENDING_UNEXPLAINED` | same |
| Set the clock back | Partly | `TIME_JUMP`, `CLOCK_SKEW`; witness gives an outer bound | maker |
| Re-stamp messages in bag time (move the human stretch to the moment of the incident; bytes and links untouched) | Yes, beyond 2 s | the link's `recv_time` is signed and the timelines are built from it; `TIME_MOVED` is a failure when a control report, session marker or operator command moved, so `who` answers from the signed times | anyone who holds the file |
| Report AUTONOMOUS while a human drives through an unwatched channel | **Partly** | `CONTROL_INCONSISTENT` if the human's commands are on a recorded topic; otherwise invisible | maker |
| Record honestly but lie in the recorder itself (fake sensor values) | **No** | nothing in a checker can; this is what signing keys and independent sensors are for | maker |
| Back-date witness entries | Yes for heads that carry an RFC 3161 receipt; otherwise **no** | the receipt's signed time comes from the timestamp authority's clock (`RECEIPT_VALID`); a head without one is the recorder's word (`RECEIPT_ABSENT`). The authority's certificate chain is not validated, so a forged receipt with a self-signed certificate that names a real authority passes unless the real certificate is given with `--tsa-cert`; the report names the authority. sha1 imprints are refused | witness insider, maker |
| Extend or rebuild the chain without the device key | Yes if the real public key is supplied or a witness exists, else **no** | signatures: the forger must sign with a different key (`KEY_MISMATCH` against the supplied key, `KEY_CHANGED` when the key switches mid-file) | anyone without the device key |

## Rules this implies for recorders

1. The node that publishes the control mode must be the one that decides whose commands reach the actuators. A flag next to the arbiter can lie; the arbiter cannot.
2. Chain every topic a human could command through, not just the actuator topic. Otherwise `CONTROL_INCONSISTENT` has nothing to see.
3. Witness heads must leave the robot while it runs, to a party the maker does not control. A witness file on the robot is a convenience, not evidence.
4. Sign links with a device key that is not stored next to the log.
5. Write the shutdown marker from a path that survives power loss if you can (capacitor, UPS); the checker rewards the marker but cannot require hardware.

## What the checker promises, in one sentence each

- PASS on L1 with a witness: nothing in this file was changed, removed or cut since the witnessed heads were taken.
- PASS on L1 without a witness: nothing in the middle was changed or removed; the end is unverified.
- PASS on L2 control: the control reports are present, continuous, name an operator whenever a human drove, and do not contradict the recorded command traffic.
- PASS on L2 completeness: every silence longer than the threshold has a marker that explains it, and the log ends with a marker or a witnessed head.
- Nothing here says the recorder told the truth when it wrote. That trust comes from outside the file: keys, witnesses, and pulling the log yourself.
