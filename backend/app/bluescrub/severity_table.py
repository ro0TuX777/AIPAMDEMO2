"""Canonical severity by issue family — tier 1 of the precedence chain.

A generic SAST tool rates findings by how bad they are for a *service*. These
artifacts are offensive tooling, and the question is different: how badly does
this hurt the operator who deploys it? The two answers diverge sharply.

Measured on the sample corpus before this table existed, every severity came
from the scanner's own string. That produced ``hardcoded-c2`` at **low** — the
single finding the Co-Optability pillar exists to catch, because anyone who
seizes that address inherits the implants — and an operator's real email
address at **high** rather than disqualifying.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §2.3
"""

from __future__ import annotations

from backend.app.bluescrub.pillars import IssueFamily

#: Canonical severity per family. Rationale is per-entry because the reasoning
#: is the useful part — a future reviewer needs to know *why* a family outranks
#: its generic appsec severity, not just that it does.
SEVERITY_BY_FAMILY: dict[IssueFamily, str] = {
    # ── Attribution: identity exposure is the worst outcome in this domain ──
    # A name, handle, or classification marking is not "information
    # disclosure"; it is the end of deniability. Critical here triggers the
    # disqualification rule deliberately.
    IssueFamily.attribution_marking: "critical",
    IssueFamily.attribution_identity: "critical",
    IssueFamily.attribution_infrastructure: "high",
    IssueFamily.build_path_leak: "high",
    IssueFamily.hardcoded_secret: "high",
    IssueFamily.credential_exposure: "high",
    IssueFamily.metadata_leak: "medium",
    IssueFamily.forensic_artifact: "medium",

    # ── Co-Optability: could an adversary turn this against us ──
    # A hardcoded C2 address is not a "hardcoded configuration" smell. Whoever
    # takes that address inherits every implant pointing at it.
    IssueFamily.hardcoded_c2: "critical",
    IssueFamily.kill_switch: "critical",
    IssueFamily.unauth_control_channel: "critical",
    IssueFamily.dependency_vulnerable: "high",
    IssueFamily.typosquat: "high",
    IssueFamily.dependency_confusion: "medium",
    IssueFamily.iac_misconfig: "medium",
    IssueFamily.container_misconfig: "medium",

    # ── Vulnerability: counter-exploitation of the tool itself ──
    # Memory safety outranks the web-shaped families here: an on-target crash
    # is an OPSEC event, whereas SSRF in an implant rarely reaches anything.
    IssueFamily.memory_safety: "high",
    IssueFamily.command_injection: "high",
    IssueFamily.deserialization: "high",
    IssueFamily.authz_bypass: "high",
    IssueFamily.sql_injection: "medium",
    IssueFamily.path_traversal: "medium",
    IssueFamily.ssrf: "medium",
    IssueFamily.xxe: "medium",
    IssueFamily.weak_crypto: "medium",
    IssueFamily.insecure_random: "medium",

    # ── Detectability: what a defender's signatures will catch ──
    # A known framework signature is the worst case — it is a free attribution
    # to a tool family. Anti-analysis is itself a detection trigger, which is
    # why its presence counts against the artifact rather than for it.
    IssueFamily.signature_known: "high",
    IssueFamily.signature_trivial: "high",
    IssueFamily.shellcode_pattern: "high",
    IssueFamily.obfuscation_weak: "medium",
    IssueFamily.anti_analysis: "medium",
    IssueFamily.ci_misconfig: "low",

    # ── RE-Feasibility: severity is secondary to the signal score ──
    IssueFamily.packer_detected: "medium",
    IssueFamily.symbol_exposure: "medium",
    IssueFamily.string_exposure: "medium",
    IssueFamily.import_exposure: "medium",
    IssueFamily.decompile_easy: "medium",
}

#: Rule-level overrides, where one rule inside a family warrants a different
#: canonical severity than its siblings. Keyed on the full rule id.
SEVERITY_BY_RULE: dict[str, str] = {
    # Sleep-based evasion is the weakest possible anti-analysis technique and
    # is trivially defeated; flagging it at the family default overstates it.
    "AntiAnalysisValidator.sandbox_evasion.sleep_based_evasion": "low",
    "AntiAnalysisValidator.sandbox_evasion.timing_checks": "low",
    # A debugger check is a real EDR trigger, unlike a bare sleep.
    "AntiAnalysisValidator.debugger_detection.windows_debugger_detection": "medium",
}


def canonical_severity(rule_id: str, family: IssueFamily) -> str | None:
    """Tier-1 severity for a rule, or None to fall through to precedence."""
    override = SEVERITY_BY_RULE.get(rule_id)
    if override:
        return override
    return SEVERITY_BY_FAMILY.get(family)


def build_rule_mapping(findings) -> dict[str, str]:
    """Rule id → canonical severity for the rules present in one job.

    ``severity.resolve`` takes a rule-keyed mapping, while the table is family
    -keyed because that is the granularity the reasoning lives at. This bridges
    the two without making either side carry the other's shape.
    """
    mapping: dict[str, str] = {}
    for finding in findings:
        if finding.rule_id in mapping:
            continue
        severity = canonical_severity(finding.rule_id, finding.issue_family)
        if severity:
            mapping[finding.rule_id] = severity
    return mapping


def build_impact_modifiers(findings, *, analysis_kind: str) -> dict[str, str]:
    """Tier-2 contextual adjustments, bounded to one level of movement.

    Only one modifier is implemented, because only one is actually available
    offline and defensible: an artifact recovered from network traffic has
    already shipped, so an attribution leak inside it is not a risk any more —
    it is an exposure that has already occurred, and it escalates.

    Reachability, secret validity, and execution-path modifiers are deliberately
    absent rather than guessed: none can be established without analysis this
    pipeline does not perform.
    """
    if analysis_kind != "re_assessment":
        return {}

    from backend.app.bluescrub.pillars import FAMILY_PILLAR, Pillar

    modifiers: dict[str, str] = {}
    for finding in findings:
        if FAMILY_PILLAR.get(finding.issue_family) is not Pillar.attribution:
            continue
        base = canonical_severity(finding.rule_id, finding.issue_family)
        if base and base != "critical":
            # resolve() clamps to one level, so naming the ceiling is enough.
            modifiers[finding.rule_id] = "critical"
    return modifiers
