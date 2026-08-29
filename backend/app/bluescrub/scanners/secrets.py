"""Secret scanning over the repository — Gitleaks and TruffleHog.

The vendored `SecretsAnalyzer` reads the files that are in the working tree.
These two read the history, which is a different question: a key committed in
March and removed in April is absent from every file and present in every
clone. That is why both are `repo_history` class and why both are run against
the git history when there is one, and against the files only when there is
not.

**Both, not one.** They disagree constantly — Gitleaks is rule-and-entropy
driven with a large default pack, TruffleHog is detector-driven and finds
credential shapes Gitleaks has no rule for. Neither is authoritative, so both
are optional corroborators: canonicalization collapses the overlap, and
installing either one must not move a score. That is the same argument OSV and
Grype are wired on, and it is what keeps the grade machine-independent.

**Verification is hard-disabled, and that is a security property, not a
setting.** TruffleHog's verification mode proves a credential is live by
authenticating to the service it belongs to. In an air-gapped assessment of
somebody else's tooling that is an outbound connection carrying a secret the
operator has not authorised us to use, from a host that is not supposed to have
egress. The flag is passed explicitly *and* the isolation contract keeps the
class off the network; a test asserts the flag, because a defence that is only
enforced by configuration is enforced until someone edits the configuration.

**Their matches are the plaintext.** Everything else this pipeline writes to
disk is safe to keep for the job's 30 days; a credential is not. Both tools are
declared `secret_bearing`, which routes their artefacts to `quarantine/` — the
72-hour tier — and drops the evidence fields from them entirely. The plaintext
lives in memory only, from the parser to central redaction, which replaces it
with a mask and a keyed fingerprint.

Neither binary is installed here. The argv for each is therefore a documented
decision that a deployment must confirm; the parsers, which is where adapter
bugs actually live, are pure functions tested against recorded output.

Reference: docs/BLUESCRUB_DATA_HANDLING_POLICY.md §3 ·
docs/BLUESCRUB_ISOLATION_CONTRACT.md §3 (`repo_history`) ·
docs/BLUESCRUB_SUPPLY_CHAIN.md
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from backend.app.bluescrub.isolation import ResourceLimits
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.external import ExternalTool, run_external

logger = logging.getLogger(__name__)

#: Both are Go binaries, and a Go runtime reserves a large virtual arena at
#: startup — so RLIMIT_AS bounds something unrelated to what they use. See
#: ResourceLimits.for_external_tool.
LIMITS = ResourceLimits.for_external_tool()

#: Rule or detector names that describe a login rather than a machine key. The
#: distinction is not cosmetic: `credential-exposure` and `hardcoded-secret`
#: both sit under Attribution, but an analyst triaging a password reaches for a
#: different remedy than one triaging a rotated API token.
_CREDENTIAL_WORDS: tuple[str, ...] = (
    "password", "passwd", "credential", "basic-auth", "basicauth", "htpasswd",
    "login", "username",
)


def _family(name: str) -> IssueFamily:
    lowered = name.lower()
    if any(word in lowered for word in _CREDENTIAL_WORDS):
        return IssueFamily.credential_exposure
    return IssueFamily.hardcoded_secret


def _relative(path: str, source_root: Path) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).resolve().relative_to(source_root.resolve()))
    except (ValueError, OSError):
        return path


def _finding(
    *,
    sensor: str,
    rule_id: str,
    title: str,
    description: str,
    secret: str,
    file: str,
    line: int,
    column: int = 0,
    confidence: float,
) -> RawFinding:
    family = _family(rule_id + " " + title)
    return RawFinding(
        sensor=sensor, sensor_version="external", rule_namespace=sensor,
        rule_id=rule_id, issue_family=family, pillar_hint=FAMILY_PILLAR[family],
        # Rules plus entropy on both sides. High recall, and the reason the
        # canonical severity ceiling caps this class below `critical`.
        detector_class=DetectorClass.regex_pattern,
        raw_severity="HIGH", confidence=confidence, source_facet="source",
        title=title[:512], description=description[:4096],
        # The one place the plaintext appears. Central redaction masks it and
        # replaces it with a keyed fingerprint before anything is persisted.
        matched_tokens=secret[:4096],
        location=Location(
            kind="source", file=file or "unknown",
            start_line=max(1, line), start_column=max(0, column),
        ),
        recommendation=(
            "Rotate the credential first — it is in every clone of this "
            "history — then purge the blob and force-push."
        ),
    )


# ── Gitleaks ──────────────────────────────────────────────────────────────

def gitleaks_argv(root: Path) -> list[str]:
    """Scan the history when there is one, the files when there is not.

    `gitleaks detect` reads git history and fails outright on a directory that
    is not a repository, which would report the commonest case — an uploaded
    archive — as a crashed scanner rather than a scanned tree.
    """
    argv = [
        "detect",
        "--source", str(root),
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--no-banner",
        # Redaction is central, and the tool's own `--redact` would destroy the
        # value before the keyed fingerprint could be computed from it — so two
        # scans of the same secret would no longer deduplicate.
        "--redact=0",
    ]
    if not (root / ".git").exists():
        argv.append("--no-git")
    return argv


def parse_gitleaks(payload: Any, source_root: Path) -> list[RawFinding]:
    """Parse a Gitleaks JSON report.

    The report is a bare **array**, not an object with a findings key, and its
    fields are TitleCase. Both are easy to get wrong in a way that yields zero
    findings and no error.
    """
    records = payload if isinstance(payload, list) else (payload or {}).get("findings") or []
    findings: list[RawFinding] = []

    for record in records:
        if not isinstance(record, dict):
            continue
        secret = str(record.get("Secret") or record.get("Match") or "")
        rule = str(record.get("RuleID") or record.get("RuleId") or "unknown")
        if not secret:
            continue

        commit = str(record.get("Commit") or "")
        author = str(record.get("Email") or record.get("Author") or "")
        # A finding on a commit is not a finding in the working tree. Saying
        # which is the difference between "delete this line" and "rotate it".
        provenance = (
            f" Found in commit {commit[:12]}"
            + (f" by {author}" if author else "")
            + ", so it is in every clone of this history whether or not the "
              "file still contains it."
            if commit else ""
        )

        findings.append(_finding(
            sensor="gitleaks", rule_id=f"gitleaks.{rule}",
            title=str(record.get("Description") or f"Secret matched by {rule}"),
            description=(str(record.get("Description") or "") + provenance).strip()
                        or f"{rule} matched a value in this artifact.",
            secret=secret,
            file=_relative(str(record.get("File") or ""), source_root),
            line=int(record.get("StartLine") or 1),
            column=int(record.get("StartColumn") or 0),
            # Entropy-gated rules; precise on shaped tokens, looser on generics.
            confidence=0.8 if not rule.startswith("generic") else 0.6,
        ))

    return findings


GITLEAKS = ExternalTool(
    sensor="gitleaks",
    binary="gitleaks",
    argv=gitleaks_argv,
    parse=parse_gitleaks,
    # gitleaks exits 1 when it finds leaks.
    finding_exit_codes=(0, 1),
    version_argv=("version",),
    limits=LIMITS,
    secret_bearing=True,
)


# ── TruffleHog ────────────────────────────────────────────────────────────

VERIFICATION_FLAG = "--no-verification"


def trufflehog_argv(root: Path) -> list[str]:
    """History when there is one, filesystem when there is not.

    ``--no-verification`` is not optional and not configurable. Verification
    proves a credential is live by authenticating to the service it belongs to
    — an outbound connection, carrying somebody else's secret, from a host with
    no egress.
    """
    source = ["git", f"file://{root}"] if (root / ".git").exists() \
        else ["filesystem", str(root)]
    return [*source, "--json", VERIFICATION_FLAG, "--no-update"]


def verification_disabled(argv: list[str]) -> bool:
    return VERIFICATION_FLAG in argv


def _trufflehog_location(record: dict) -> tuple[str, int]:
    """Dig the path and line out of the source metadata.

    The shape is nested by source type — ``Filesystem``, ``Git``, ``Github`` —
    and reading only one of them silently drops every finding from the others.
    """
    data = ((record.get("SourceMetadata") or {}).get("Data") or {})
    for payload in data.values():
        if not isinstance(payload, dict):
            continue
        path = str(payload.get("file") or payload.get("path") or "")
        line = payload.get("line")
        if path:
            return path, int(line) if isinstance(line, int) else 1
    return "", 1


def parse_trufflehog(payload: Any, source_root: Path) -> list[RawFinding]:
    """Parse ``trufflehog --json``, one record per line.

    A record reporting ``Verified: true`` means verification ran despite the
    flag — the tool reached the network. It is logged at error level and the
    finding is kept: suppressing it would hide the evidence that the boundary
    failed.
    """
    records = payload.get("results") if isinstance(payload, dict) else payload
    findings: list[RawFinding] = []
    verified = 0

    for record in records or []:
        if not isinstance(record, dict):
            continue
        secret = str(record.get("Raw") or record.get("RawV2") or "")
        detector = str(record.get("DetectorName") or "unknown")
        if not secret:
            continue
        if record.get("Verified"):
            verified += 1

        path, line = _trufflehog_location(record)
        findings.append(_finding(
            sensor="trufflehog", rule_id=f"trufflehog.{detector}",
            title=f"{detector} credential",
            description=(
                f"TruffleHog's {detector} detector matched a credential shape. "
                "It was not verified against the issuing service, so whether "
                "it is still live is unknown and must be assumed."
            ),
            secret=secret,
            file=_relative(path, source_root),
            line=line,
            # A shaped detector match with no verification behind it.
            confidence=0.75,
        ))

    if verified:
        logger.error(
            "trufflehog returned %d verified finding(s) — verification was "
            "requested to be disabled and evidently ran; the analyzer reached "
            "the network", verified,
        )

    return findings


TRUFFLEHOG = ExternalTool(
    sensor="trufflehog",
    binary="trufflehog",
    argv=trufflehog_argv,
    parse=parse_trufflehog,
    finding_exit_codes=(0, 183),  # 183 is "found results" in recent builds
    version_argv=("--version",),
    limits=LIMITS,
    json_lines=True,
    secret_bearing=True,
)


def run_gitleaks(source_root: Path, output_dir: Path, **_kw):
    return run_external(GITLEAKS, source_root, output_dir)


def run_trufflehog(source_root: Path, output_dir: Path, **_kw):
    return run_external(TRUFFLEHOG, source_root, output_dir)
