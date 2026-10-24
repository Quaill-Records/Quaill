# Privacy note for the Quaill layout (not legal advice)

The layout exists to answer "who was in control, when". That is personal data the moment "who" can be traced to a person. This page says what the layout stores, what it does not, and what a maker or operator should think about before turning it on. It is general information, not legal advice; check your own situation with a lawyer.

## What the three channels store

| Channel | Contains | Personal data? |
|---|---|---|
| `/quaill/control_mode` | mode, a pseudonymous `operator_ref`, a reason string, timestamps | **Yes.** A pseudonymous ID that the operator's employer can resolve to a person is personal data under GDPR (Art. 4(1), (5)). Timestamps of when a named worker took control are performance data. |
| `/quaill/session` | start/stop/crash markers, software version | No, unless `note` carries names. Keep it free of them. |
| `/quaill/chain` | hashes of other messages, sequence numbers, times | Hashes of personal data are personal data if the input can be reproduced; treat the chain as part of the same record. |

The layout does **not** require recording camera images, audio, locations, or any sensor content. It needs control events, markers and hashes. A recorder may of course log sensors for its own reasons; that is the recorder's choice and the recorder's privacy obligation.

## What the law already says in the one place a who-was-driving record is mandatory

Germany's remote-driving regulation (StVFernLV, in force Dec 1, 2025) requires the remote driver's actual certificate name in the record, keeps it up to three years, hands it to authorities and to third parties with a legal claim, and handles privacy by **requiring a data protection impact assessment (DPIA)** and GDPR Articles 24, 25 and 32, not by leaving the field out. That is the model this layout follows: record who, protect how.

## What a maker or operator should consider before switching this on (EU)

1. **Lawful basis and purpose.** Incident reconstruction and legal defence are the purposes. Write them down. Do not reuse the record for performance reviews without a separate basis.
2. **DPIA.** Systematic monitoring of workers at scale is likely to need a data protection impact assessment (Art. 35).
3. **Works council (Germany).** A system that *can* monitor performance is likely subject to co-determination (BetrVG §87(1) No. 6) whether or not that is the intent. Involve them early.
4. **Minimise.** Use `operator_ref` as a per-session token that only the operator's employer can resolve, through a documented process. Never put a name in the record. Never put a name in `reason` or `note`.
5. **Retention.** Keep the record only as long as a legal duty or a real need requires (StVFernLV, for example, sets up to three years), then delete on schedule. The witness keeps only hashes and times.
6. **Access.** Decide in advance who can read the record and who can resolve a token: the operator, the deployer, an insurer, a court. Write it into contracts.

## US notes

Several states require notice before electronic monitoring of employees (for example New York and Connecticut). Illinois has strict rules on biometric data, which this layout does not collect. Workers' compensation and OSHA investigations can request records of what a machine did; a record that names a worker only through a token resolvable by the employer is easier to hand over.

## What the checker itself does

The checker reads a finished file and writes a report. It does not phone home, upload, or store anything. The report repeats the `operator_ref` values from the file; treat the report with the same care as the log. The optional witness holds hashes and times only, never content.
