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
| Stop recording for a while | Yes, as a gap | `GAP_UNEXPLAINED` unless a marker explains it | recorder operator |
| Kill the recorder | Told apart from a cut **only with a witness** | `ENDING_UNMARKED` vs `ENDING_UNEXPLAINED` | same |
| Set the clock back | Partly | `TIME_JUMP`, `CLOCK_SKEW`; witness gives an outer bound | maker |
| Report AUTONOMOUS while a human drives through an unwatched channel | **Partly** | `CONTROL_INCONSISTENT` if the human's commands are on a recorded topic; otherwise invisible | maker |
| Record honestly but lie in the recorder itself (fake sensor values) | **No** | nothing in a checker can; this is what signing keys and independent sensors are for | maker |
| Back-date witness entries | No, unless the witness itself is anchored | planned: witness log anchored to public timestamp authorities | witness insider |
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
