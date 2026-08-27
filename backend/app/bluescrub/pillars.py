"""DACV+R pillar model — enums, weights, and calibration constants.

Data only. No scoring logic lives here; see ``scoring.py``.

Reference: docs/BLUESCRUB_SCORING_SPEC.md
"""

from __future__ import annotations

from enum import Enum


class Pillar(str, Enum):
    """The five OPSEC risk pillars. Stored in ``Finding.category``."""

    detectability = "Detectability"
    attribution = "Attribution"
    co_optability = "Co-Optability"
    vulnerability = "Vulnerability"
    re_feasibility = "RE-Feasibility"


#: Pillars scored by accumulating canonical findings (§1 of the scoring spec).
ACCUMULATION_PILLARS: frozenset[Pillar] = frozenset({
    Pillar.detectability,
    Pillar.attribution,
    Pillar.co_optability,
    Pillar.vulnerability,
})

#: RE-Feasibility uses the weighted-signal model instead (§4). It has no K_P.
SIGNAL_PILLARS: frozenset[Pillar] = frozenset({Pillar.re_feasibility})


class PillarStatus(str, Enum):
    """Coverage state. ``not_assessed`` scores ``None`` — never zero."""

    assessed = "assessed"
    degraded = "degraded"
    not_assessed = "not_assessed"


class DetectorClass(str, Enum):
    """Authority ranking for severity precedence (§2.3 of the data contracts).

    A regex detector claiming CRITICAL must not outrank a dataflow detector
    claiming medium, so class — not raw severity — decides conflicts.
    """

    semantic_dataflow = "semantic_dataflow"
    taint = "taint"
    ast_pattern = "ast_pattern"
    regex_pattern = "regex_pattern"
    heuristic = "heuristic"


#: Highest authority first. Index position is the precedence rank.
DETECTOR_PRECEDENCE: tuple[DetectorClass, ...] = (
    DetectorClass.semantic_dataflow,
    DetectorClass.taint,
    DetectorClass.ast_pattern,
    DetectorClass.regex_pattern,
    DetectorClass.heuristic,
)


def detector_rank(cls: DetectorClass | str | None) -> int:
    """Return the precedence rank of a detector class; unknown ranks last."""
    if cls is None:
        return len(DETECTOR_PRECEDENCE)
    try:
        return DETECTOR_PRECEDENCE.index(DetectorClass(cls))
    except ValueError:
        return len(DETECTOR_PRECEDENCE)


#: Severity contribution weights (§1 of the scoring spec).
SEV_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.25,
}

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


#: Saturation constants, per accumulation pillar.
#:
#: A single constant across pillars is wrong: Vulnerability runs an order of
#: magnitude higher in finding volume than Attribution, so a shared value makes
#: one saturate at trivial severity and leaves the other unmoved by a decisive
#: finding. PROVISIONAL until Sprint 9 calibrates against a labelled corpus.
K_P: dict[Pillar, float] = {
    Pillar.attribution: 15.0,     # low volume, high consequence
    Pillar.co_optability: 20.0,   # low volume, structural findings
    Pillar.detectability: 25.0,   # moderate volume
    Pillar.vulnerability: 40.0,   # highest volume by far
}

CALIBRATION_STATE = "provisional"

#: Weights for the overall grade. Sum to 1.0.
PILLAR_WEIGHT: dict[Pillar, float] = {
    Pillar.detectability: 0.25,
    Pillar.attribution: 0.25,
    Pillar.vulnerability: 0.20,
    Pillar.co_optability: 0.15,
    Pillar.re_feasibility: 0.15,
}

#: Grade bands as (inclusive_upper_bound, grade).
GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (19, "A"), (39, "B"), (59, "C"), (79, "D"), (100, "F"),
)

#: Contribution caps (§2 of the scoring spec).
RULE_CAP_FULL_WEIGHT = 5      # groups per rule_id contributing at full weight
FAMILY_CAP_FRACTION = 0.35    # max share of a pillar's raw total per issue_family
INFO_CAP_FRACTION = 0.10      # max aggregate share for info-severity findings

#: Overall grade requires every pillar assessed at or above this coverage.
COVERAGE_THRESHOLD = 0.9


class IssueFamily(str, Enum):
    """Closed vocabulary. Free text would make canonical grouping non-deterministic.

    Extending this is a versioned change to ``bluescrub.raw/N``, reviewed like a
    schema change.
    """

    memory_safety = "memory-safety"
    command_injection = "command-injection"
    path_traversal = "path-traversal"
    deserialization = "deserialization"
    ssrf = "ssrf"
    xxe = "xxe"
    sql_injection = "sql-injection"
    weak_crypto = "weak-crypto"
    insecure_random = "insecure-random"
    hardcoded_secret = "hardcoded-secret"
    credential_exposure = "credential-exposure"
    authz_bypass = "authz-bypass"
    unauth_control_channel = "unauth-control-channel"
    hardcoded_c2 = "hardcoded-c2"
    kill_switch = "kill-switch"
    dependency_vulnerable = "dependency-vulnerable"
    dependency_confusion = "dependency-confusion"
    typosquat = "typosquat"
    attribution_marking = "attribution-marking"
    attribution_identity = "attribution-identity"
    attribution_infrastructure = "attribution-infrastructure"
    build_path_leak = "build-path-leak"
    metadata_leak = "metadata-leak"
    forensic_artifact = "forensic-artifact"
    signature_trivial = "signature-trivial"
    signature_known = "signature-known"
    anti_analysis = "anti-analysis"
    obfuscation_weak = "obfuscation-weak"
    shellcode_pattern = "shellcode-pattern"
    packer_detected = "packer-detected"
    symbol_exposure = "symbol-exposure"
    string_exposure = "string-exposure"
    import_exposure = "import-exposure"
    decompile_easy = "decompile-easy"
    iac_misconfig = "iac-misconfig"
    ci_misconfig = "ci-misconfig"
    container_misconfig = "container-misconfig"
    #: Persisted and displayed, never scored. A non-zero count is a backlog signal.
    unmapped = "unmapped"


#: Default family → pillar mapping. The authoritative mapping is keyed on
#: ``(sensor, rule_namespace, rule_id)``; this is the fallback when a rule has no
#: explicit entry. ``unmapped`` deliberately has no pillar.
FAMILY_PILLAR: dict[IssueFamily, Pillar] = {
    IssueFamily.memory_safety: Pillar.vulnerability,
    IssueFamily.command_injection: Pillar.vulnerability,
    IssueFamily.path_traversal: Pillar.vulnerability,
    IssueFamily.deserialization: Pillar.vulnerability,
    IssueFamily.ssrf: Pillar.vulnerability,
    IssueFamily.xxe: Pillar.vulnerability,
    IssueFamily.sql_injection: Pillar.vulnerability,
    IssueFamily.weak_crypto: Pillar.vulnerability,
    IssueFamily.insecure_random: Pillar.vulnerability,
    IssueFamily.authz_bypass: Pillar.vulnerability,
    IssueFamily.hardcoded_secret: Pillar.attribution,
    IssueFamily.credential_exposure: Pillar.attribution,
    IssueFamily.attribution_marking: Pillar.attribution,
    IssueFamily.attribution_identity: Pillar.attribution,
    IssueFamily.attribution_infrastructure: Pillar.attribution,
    IssueFamily.build_path_leak: Pillar.attribution,
    IssueFamily.metadata_leak: Pillar.attribution,
    IssueFamily.forensic_artifact: Pillar.attribution,
    IssueFamily.unauth_control_channel: Pillar.co_optability,
    IssueFamily.hardcoded_c2: Pillar.co_optability,
    IssueFamily.kill_switch: Pillar.co_optability,
    IssueFamily.dependency_vulnerable: Pillar.co_optability,
    IssueFamily.dependency_confusion: Pillar.co_optability,
    IssueFamily.typosquat: Pillar.co_optability,
    IssueFamily.signature_trivial: Pillar.detectability,
    IssueFamily.signature_known: Pillar.detectability,
    IssueFamily.anti_analysis: Pillar.detectability,
    IssueFamily.obfuscation_weak: Pillar.detectability,
    IssueFamily.shellcode_pattern: Pillar.detectability,
    IssueFamily.symbol_exposure: Pillar.re_feasibility,
    IssueFamily.string_exposure: Pillar.re_feasibility,
    IssueFamily.import_exposure: Pillar.re_feasibility,
    IssueFamily.decompile_easy: Pillar.re_feasibility,
    IssueFamily.packer_detected: Pillar.re_feasibility,
    IssueFamily.iac_misconfig: Pillar.co_optability,
    IssueFamily.ci_misconfig: Pillar.attribution,
    IssueFamily.container_misconfig: Pillar.co_optability,
}


class RiskClass(str, Enum):
    """Scanner execution risk (isolation contract §3)."""

    parse_only = "parse_only"
    emulation = "emulation"
    repo_history = "repo_history"
    #: Executes attacker code by design. Disabled by default; not shipped in R1–R4.
    build_capable = "build_capable"
