# Contributing

Thanks for looking. Quaill Records is maintained by Quaill LLC; the maintainer has the final say on what merges.

1. **Sign the CLA.** On your first pull request the CLA Assistant bot asks you to sign [CLA.md](CLA.md). One click, once. Pull requests can't merge without it.
2. **Run the demo before you open a pull request.** `python -m quaill demo demo-logs` must end with `all as expected`.
3. **Keep the checker deterministic.** Same file, same report. No network calls, no AI, no guessing.
4. **Wording.** Reports and docs say "meets checks" or "checks against profile X". Never "certified", "safe", "accredited" or "compliant". See [TRADEMARK.md](TRADEMARK.md).
5. **No real personal data in test logs.** `operator_ref` is a token, never a name.

Bugs, real logs that break the checker, and new profiles (a regulator's or standard's field list) are the most useful contributions. Open an issue first for anything large.
