"""Runs every check on one log and holds the result. Formatting lives in report.py."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .chain import ChainResult, load_witness, verify_chain
from .checks.completeness import CompletenessResult, check_completeness
from .checks.control import ControlResult, check_control
from .checks.format import check_format
from .checks.profile import ProfileResult, apply_mapping, check_profile, load_mapping, load_profile
from .findings import NS, Finding
from .mcapio import LogFile, UnreadableLog, read_log


@dataclass
class Report:
    path: str
    tool_version: str = __version__
    log: LogFile | None = None
    error: str | None = None
    profile: dict | None = None
    witness_path: str | None = None
    pubkey_path: str | None = None
    tsa_cert_path: str | None = None
    format_findings: list[Finding] = field(default_factory=list)
    chain: ChainResult | None = None
    control: ControlResult | None = None
    completeness: CompletenessResult | None = None
    profile_result: ProfileResult | None = None

    @property
    def findings(self) -> list[Finding]:
        out = list(self.format_findings)
        for part in (self.chain, self.control, self.completeness, self.profile_result):
            if part is not None:
                out.extend(part.findings)
        return out

    def has(self, code: str) -> bool:
        return any(f.code == code for f in self.findings)

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def grades(self) -> dict[str, str]:
        g = {}
        if self.error:
            return {"L0 format": "UNREADABLE"}
        g["L0 format"] = "FAIL" if any(f.severity == "fail" for f in self.format_findings) else "PASS"
        c = self.chain
        if c is None or not c.present:
            g["L1 integrity"] = "NOT ASSESSABLE"
        elif any(f.severity == "fail" for f in c.findings):
            g["L1 integrity"] = "FAIL"
        elif not c.witness_present:
            g["L1 integrity"] = "PARTIAL"
        else:
            g["L1 integrity"] = "PASS"
        ct = self.control
        if ct is None or not ct.present:
            g["L2 control"] = "NOT ASSESSABLE"
        else:
            g["L2 control"] = "FAIL" if any(f.severity == "fail" for f in ct.findings) else "PASS"
        cp = self.completeness
        g["L2 completeness"] = "FAIL" if cp and any(f.severity == "fail" for f in cp.findings) else "PASS"
        pr = self.profile_result
        if pr is None:
            g["profile"] = "NOT RUN"
        else:
            g["profile"] = "FAIL" if any(f.severity == "fail" for f in pr.findings) else "PASS"
        return g

    @property
    def exit_code(self) -> int:
        if self.error:
            return 2
        return 1 if self.count("fail") else 0


def default_witness_path(log_path: str) -> str | None:
    p = Path(log_path)
    cands = [p.with_name(p.name + ".witness.json"), p.with_suffix(".witness.json")]
    if p.is_dir():
        cands += [p / "witness.json", p / "witness"]  # a recorder's witness file(s) copied into the bag directory
    for cand in cands:
        if cand.is_file() or (cand.is_dir() and any(cand.glob("*.json"))):
            return str(cand)
    return None


def default_pubkey_path(log_path: str) -> str | None:
    p = Path(log_path)
    for cand in (p.with_name(p.name + ".pubkey.pem"), p.with_suffix(".pubkey.pem"), p / "device.pubkey.pem" if p.is_dir() else None):
        if cand is not None and cand.is_file():
            return str(cand)
    return None


def run(path: str, profile_name: str | None = "quaill-control", witness_path: str | None = None, gap_seconds: float = 2.0, pubkey_path: str | None = None, tsa_cert_path: str | None = None, mapping_path: str | None = None) -> Report:
    rep = Report(path=path)
    tsa_cert = None
    if tsa_cert_path:
        try:
            from .receipts import load_tsa_cert

            tsa_cert = load_tsa_cert(tsa_cert_path)
            rep.tsa_cert_path = tsa_cert_path
        except Exception as e:
            rep.format_findings.append(Finding("TSA_CERT_UNREADABLE", "L1", "fail", f"TSA certificate {tsa_cert_path} could not be read: {e}; receipts were not checked against it (a typo here must not end in \"meets checks\")"))
    if profile_name and profile_name.lower() != "none":
        rep.profile = load_profile(profile_name)
        if mapping_path:  # the fleet's own topic and field names for this profile (profiles/MAPPING.md)
            rep.profile = apply_mapping(rep.profile, load_mapping(mapping_path))
    elif mapping_path:
        raise ValueError("--map needs a profile to map (--profile is 'none')")
    # keep message bytes only where a check will look inside them
    keep = set()
    if rep.profile:
        keep |= {i["topic"] for i in rep.profile.get("items", []) if "topic" in i}
        if rep.profile.get("events", {}).get("topic"):
            keep.add(rep.profile["events"]["topic"])
    try:
        rep.log = read_log(path, keep)
    except UnreadableLog as e:
        rep.error = str(e)
        return rep
    except Exception as e:  # anything else the reader throws is still "unreadable"
        rep.error = f"{type(e).__name__}: {e}"
        return rep
    log = rep.log

    asked_for_witness = bool(witness_path)
    if witness_path is None:
        witness_path = default_witness_path(path)
    witness = None
    if witness_path:
        try:
            witness = load_witness(witness_path)
            rep.witness_path = witness_path
        except Exception as e:  # a witness the caller named but the checker could not use must not end in "meets checks"
            rep.format_findings.append(Finding("WITNESS_UNREADABLE", "L1", "fail" if asked_for_witness else "warn", f"witness file {witness_path} could not be read: {e}" + ("; the end of the log was not checked against it" if asked_for_witness else "")))

    if pubkey_path is None:
        pubkey_path = default_pubkey_path(path)
    rep.pubkey_path = pubkey_path or None

    rep.format_findings.extend(check_format(log))
    op_topics = (rep.profile or {}).get("operator_command_topics")
    rep.chain = verify_chain(log, witness, rep.pubkey_path, tsa_cert, op_topics)
    rep.control = check_control(log, op_topics, rep.chain.signed_time)
    rep.completeness = check_completeness(log, rep.chain, int(gap_seconds * NS))
    if rep.profile is not None:
        rep.profile_result = check_profile(log, rep.profile)
    return rep
