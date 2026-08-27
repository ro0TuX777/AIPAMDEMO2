"""Rule → issue family and pillar mapping.

Keyed on ``(sensor, rule_id)`` with a CWE and keyword fallback. Pillar
assignment is rule-level, never tool-level: one scanner legitimately produces
findings across pillars — Semgrep serves both Vulnerability and Co-Optability
here — so a ``tool → pillar`` map is structurally wrong.

An unresolved rule maps to ``unmapped``: persisted and displayed, never scored.
Discarding it would hide scanner output; scoring it would put an unreviewed rule
into the grade.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §1.1–1.3
"""

from __future__ import annotations

import re

from backend.app.bluescrub.pillars import DetectorClass, IssueFamily

#: CWE → family. The most reliable signal when a scanner supplies it.
CWE_FAMILY: dict[str, IssueFamily] = {
    "CWE-77": IssueFamily.command_injection,
    "CWE-78": IssueFamily.command_injection,
    "CWE-88": IssueFamily.command_injection,
    "CWE-89": IssueFamily.sql_injection,
    "CWE-22": IssueFamily.path_traversal,
    "CWE-23": IssueFamily.path_traversal,
    "CWE-611": IssueFamily.xxe,
    "CWE-918": IssueFamily.ssrf,
    "CWE-502": IssueFamily.deserialization,
    "CWE-119": IssueFamily.memory_safety,
    "CWE-120": IssueFamily.memory_safety,
    "CWE-121": IssueFamily.memory_safety,
    "CWE-122": IssueFamily.memory_safety,
    "CWE-125": IssueFamily.memory_safety,
    "CWE-416": IssueFamily.memory_safety,
    "CWE-476": IssueFamily.memory_safety,
    "CWE-787": IssueFamily.memory_safety,
    "CWE-798": IssueFamily.hardcoded_secret,
    "CWE-259": IssueFamily.hardcoded_secret,
    "CWE-321": IssueFamily.hardcoded_secret,
    "CWE-327": IssueFamily.weak_crypto,
    "CWE-328": IssueFamily.weak_crypto,
    "CWE-330": IssueFamily.insecure_random,
    "CWE-338": IssueFamily.insecure_random,
    "CWE-200": IssueFamily.metadata_leak,
    "CWE-215": IssueFamily.metadata_leak,
    "CWE-532": IssueFamily.metadata_leak,
    "CWE-285": IssueFamily.authz_bypass,
    "CWE-862": IssueFamily.authz_bypass,
    "CWE-863": IssueFamily.authz_bypass,
    "CWE-1104": IssueFamily.dependency_vulnerable,
}

#: Ordered keyword fallbacks against the rule id. First match wins, so more
#: specific patterns must come first.
_KEYWORD_FAMILY: tuple[tuple[re.Pattern[str], IssueFamily], ...] = tuple(
    (re.compile(pattern, re.I), family)
    for pattern, family in (
        # Vendored-analyzer category labels. Their vocabulary differs from
        # Semgrep rule ids, so these patterns exist to map it onto the same
        # closed family set rather than letting a second taxonomy grow.
        (r"weak[-_.]?algorithm", IssueFamily.weak_crypto),
        (r"weak[-_.]?random|predictable[-_.]?seed", IssueFamily.insecure_random),
        (r"internal[-_.]?(ip|host|domain|network)", IssueFamily.attribution_infrastructure),
        (r"anti[-_.]?(debug|vm|analysis|sandbox|emulation)", IssueFamily.anti_analysis),
        (r"shellcode|egg[-_.]?hunter", IssueFamily.shellcode_pattern),
        (r"obfuscat|packer|encod(ed|ing)[-_.]?payload", IssueFamily.obfuscation_weak),
        (r"privilege[-_.]?escalation|privesc|token[-_.]?steal", IssueFamily.signature_known),
        (r"forensic|artefact|artifact|log[-_.]?tamper", IssueFamily.forensic_artifact),
        (r"exploit[-_.]?(tool|framework|signature)|metasploit|cobalt",
         IssueFamily.signature_known),
        (r"reliab|crash|stability", IssueFamily.memory_safety),
        (r"hardcoded[-_.]?c2|beacon[-_.]?config|c2[-_.]?address", IssueFamily.hardcoded_c2),
        (r"kill[-_.]?switch", IssueFamily.kill_switch),
        (r"unauth\w*[-_.]?(control|channel|listener)", IssueFamily.unauth_control_channel),
        (r"hardcoded[-_.]?(secret|password|credential|key|token)", IssueFamily.hardcoded_secret),
        (r"secret|credential|api[-_.]?key|private[-_.]?key", IssueFamily.hardcoded_secret),
        (r"command[-_.]?inject|os[-_.]?system|subprocess|shell", IssueFamily.command_injection),
        (r"sql[-_.]?inject", IssueFamily.sql_injection),
        (r"path[-_.]?travers|zip[-_.]?slip", IssueFamily.path_traversal),
        (r"deserial|pickle|yaml[-_.]?load", IssueFamily.deserialization),
        (r"ssrf", IssueFamily.ssrf),
        (r"xxe|xml[-_.]?external", IssueFamily.xxe),
        (r"buffer|overflow|use[-_.]?after[-_.]?free|memcpy|strcpy|format[-_.]?string",
         IssueFamily.memory_safety),
        (r"weak[-_.]?(crypto|cipher|hash)|md5|sha1|des\b|ecb", IssueFamily.weak_crypto),
        (r"insecure[-_.]?random|math[-_.]?random|rand\(", IssueFamily.insecure_random),
        (r"typosquat", IssueFamily.typosquat),
        (r"dependency[-_.]?confusion", IssueFamily.dependency_confusion),
        (r"vulnerable[-_.]?dependency|known[-_.]?vuln|cve-", IssueFamily.dependency_vulnerable),
        (r"dockerfile|container", IssueFamily.container_misconfig),
        (r"terraform|cloudformation|iac", IssueFamily.iac_misconfig),
        (r"github[-_.]?actions|workflow", IssueFamily.ci_misconfig),
        (r"debug|verbose[-_.]?log|stack[-_.]?trace", IssueFamily.metadata_leak),
        (r"authz|authorization|access[-_.]?control", IssueFamily.authz_bypass),
    )
)


def normalize_label(label: str) -> str:
    """Fold a human-written analyzer label into rule-id shape.

    The vendored analyzers report free text ("Hardcoded API key") where Semgrep
    reports dotted ids, and the keyword patterns are written for the latter.
    """
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")

#: Explicit per-rule overrides, highest priority. Populated as rules are
#: reviewed; an entry here is a reviewed decision, not a guess.
EXPLICIT: dict[tuple[str, str], IssueFamily] = {}

#: Detector class per sensor, used by severity precedence. A tool that owns
#: rules in several classes gets per-rule entries in EXPLICIT_DETECTOR.
SENSOR_DETECTOR: dict[str, DetectorClass] = {
    "semgrep": DetectorClass.ast_pattern,
    "codeql": DetectorClass.semantic_dataflow,
    "joern": DetectorClass.semantic_dataflow,
    "weggli": DetectorClass.ast_pattern,
    "bandit": DetectorClass.ast_pattern,
    "gosec": DetectorClass.ast_pattern,
    "flawfinder": DetectorClass.regex_pattern,
    "cppcheck": DetectorClass.ast_pattern,
    "gitleaks": DetectorClass.regex_pattern,
    "trufflehog": DetectorClass.regex_pattern,
    "dirty_word": DetectorClass.regex_pattern,
    "osv": DetectorClass.heuristic,
    "grype": DetectorClass.heuristic,
    "binary_analyzer": DetectorClass.heuristic,
}

_CWE_RE = re.compile(r"CWE-\d+")


def normalize_cwes(values: list[str] | None) -> list[str]:
    """Extract bare CWE ids from the decorated strings scanners emit."""
    out: list[str] = []
    for value in values or []:
        match = _CWE_RE.search(str(value))
        if match and match.group(0) not in out:
            out.append(match.group(0))
    return out


def resolve_family(sensor: str, rule_id: str, cwes: list[str] | None = None) -> IssueFamily:
    """Resolve a rule to its canonical issue family.

    Order: explicit review, then CWE, then keyword. Unresolved rules become
    ``unmapped`` rather than being guessed into a pillar.
    """
    explicit = EXPLICIT.get((sensor, rule_id))
    if explicit:
        return explicit

    for cwe in normalize_cwes(cwes):
        family = CWE_FAMILY.get(cwe)
        if family:
            return family

    for pattern, family in _KEYWORD_FAMILY:
        if pattern.search(rule_id):
            return family

    return IssueFamily.unmapped


def detector_for(sensor: str) -> DetectorClass:
    return SENSOR_DETECTOR.get(sensor, DetectorClass.heuristic)
