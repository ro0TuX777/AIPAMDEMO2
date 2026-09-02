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

from backend.app.bluescrub.pillars import DetectorClass, IssueFamily

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
    IssueFamily.metadata_leak: "medium",
    IssueFamily.forensic_artifact: "medium",

    # ── Co-Optability: could an adversary turn this against us ──
    # A hardcoded C2 address is not a "hardcoded configuration" smell. Whoever
    # takes that address inherits every implant pointing at it.
    IssueFamily.hardcoded_c2: "critical",
    # The same sentence with "credential" substituted, which is why these two
    # live here rather than under Attribution: a key does not say who wrote the
    # artifact, it says what someone else can do with it.
    IssueFamily.hardcoded_secret: "high",
    IssueFamily.credential_exposure: "high",
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

    # ── Reviewed promotions past the low-precision ceiling ──
    #
    # These three are regex detectors, so the ceiling in canonical_severity
    # would cap them at "high". They are promoted back because measurement
    # showed them to be precise, not because the concept sounds severe:
    # across 300 files of real code, email_address produced five hits and all
    # five were genuine addresses, linux_username produced one and it was a
    # real hardcoded home directory, windows_username produced none.
    #
    # Contrast the rules left capped — c2_reference matches the substring
    # "C2", attribution_comment matches the phrase "based on". Same detector
    # class, entirely different precision, which is why this is a per-rule
    # decision rather than a class-wide one.
    "MetadataLeakageScanner.contact_info.email_address": "critical",
    "MetadataLeakageScanner.embedded_paths.linux_username": "critical",
    "MetadataLeakageScanner.embedded_paths.windows_username": "critical",

    # ── Dirty-word: operator-declared terms ──
    #
    # Also regex detectors by class, and also promoted — but on different
    # grounds. The three above earned it by measuring low false positives; a
    # dirty-word hit is a literal match on a string the operator explicitly
    # declared sensitive. Nothing in this pipeline is more precise than being
    # told. The wordlist validator refuses terms under three characters, which
    # is what stops the "C2" failure recurring on the input side.
    "dirty_word.marking": "critical",
    "dirty_word.identity": "critical",
    "dirty_word.codename": "critical",
    # Below: real, but not disqualifying on their own.
    "dirty_word.org": "high",
    "dirty_word.hostname": "high",
    "dirty_word.path": "high",
    "dirty_word.mutex": "medium",
    "dirty_word.ticket": "medium",
    "dirty_word.tooling": "high",
    # The bottom of the ladder, and the reason it exists. `TODO` and `DEBUG`
    # ship in the builtin packs; categorised as identity they disqualified
    # every tree that contained a comment.
    "dirty_word.toolchain": "medium",
    "dirty_word.hygiene": "info",

    # ── Git history metadata ──
    #
    # Every entry here is explicit because the family defaults would be wrong
    # in both directions. `attribution-identity` defaults to critical, which
    # disqualifies outright — and a repository has authors by definition, so
    # that would fail any artifact that shipped its history, including a
    # vendored open-source tree whose contributors are not the operator.
    # gitmeta cannot tell whose identity it found, so it reports high and
    # leaves the judgement to the analyst.
    "gitmeta.author_identity": "high",
    # The exception, on the dirty-word argument: the identity carries a term
    # the operator declared sensitive. Being told is what makes it decisive.
    "gitmeta.declared_identity": "critical",
    # `metadata-leak` defaults to medium, which reads as a formatting nit. A
    # shipped `.git` carries every commit message, every branch name, and the
    # content of every file ever deleted from the tree.
    "gitmeta.history_present": "high",
    "gitmeta.deleted_sensitive_file": "high",
    # Timezone is left at the family default: it is a genuine signal and a
    # weak one, inferred from timestamps rather than read off a field.

    # ── Code-similarity fingerprints ──
    #
    # The family default is medium, which is right for a copyright notice and
    # wrong at both ends of the rest. A codebase of any size contains hundreds
    # of TODO comments; scoring each at medium would let a habit marker outweigh
    # a byline, which is the same shape as the failure that produced the
    # critical ceiling — volume standing in for significance.
    "CodeSimilarityDetector.fingerprint_patterns.code_quality_markers": "info",
    "CodeSimilarityDetector.fingerprint_patterns.developer_note_comments_developer_habit": "info",
    "CodeSimilarityDetector.fingerprint_patterns.unfinished_code": "info",
    # A debug artifact is weak evidence of habit and a little more than that:
    # it also means diagnostic output ships.
    "CodeSimilarityDetector.fingerprint_patterns.debug_print_statements": "low",
    "CodeSimilarityDetector.fingerprint_patterns.debugger_breakpoints": "low",
    # The one in this group that points at a person. Capped at high rather than
    # critical because the pattern finds the *tag*, not the name in it — the
    # name is what the dirty-word and gitmeta detectors are for.
    "CodeSimilarityDetector.fingerprint_patterns.author_attribution": "high",

    # ── Shipped Semgrep pack ──
    #
    # Same judgement as the vendored habit markers, reached the same way. This
    # rule fires on a bare "# TODO:", and while its family was
    # `attribution-identity` a two-line file containing one TODO comment scored
    # F with `disqualified: true`. It was invisible because semgrep was not
    # installed on the machine the calibration was done on.
    "bluescrub.attribution.operator-todo": "info",
}


#: Detector classes whose evidence is too weak to justify `critical` on its
#: own. Measured at scale: on a 300-file real codebase the table produced 344
#: criticals, and the top drivers were a regex matching the literal string
#: "C2", one matching "beacon", and one matching the English phrase "based on".
#: AIPAM contains all three because it *analyses* C2 traffic.
#:
#: The design already says a regex detector asserting CRITICAL must not
#: outrank a dataflow detector asserting medium. That principle was applied to
#: conflicts between detectors but not to canonical severity itself, which is
#: how a two-character substring match came to trigger disqualification.
LOW_PRECISION_DETECTORS = frozenset({
    DetectorClass.regex_pattern,
    DetectorClass.heuristic,
})

CRITICAL_CEILING_FOR_LOW_PRECISION = "high"


def canonical_severity(
    rule_id: str,
    family: IssueFamily,
    detector: DetectorClass | None = None,
) -> str | None:
    """Tier-1 severity for a rule, or None to fall through to precedence.

    An explicit rule-level entry is a reviewed decision and is honoured as
    written. A family default is a generalisation, so it is capped below
    `critical` when the only evidence is a low-precision detector — critical
    drives disqualification, and disqualification has to mean something.
    """
    override = SEVERITY_BY_RULE.get(rule_id)
    if override:
        return override

    severity = SEVERITY_BY_FAMILY.get(family)
    if (
        severity == "critical"
        and detector is not None
        and detector in LOW_PRECISION_DETECTORS
    ):
        return CRITICAL_CEILING_FOR_LOW_PRECISION
    return severity


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
        severity = canonical_severity(
            finding.rule_id, finding.issue_family, finding.detector_class
        )
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
        base = canonical_severity(
            finding.rule_id, finding.issue_family, finding.detector_class
        )
        if base and base != "critical":
            # resolve() clamps to one level, so naming the ceiling is enough.
            modifiers[finding.rule_id] = "critical"
    return modifiers
