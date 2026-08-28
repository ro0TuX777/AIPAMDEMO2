"""Hardcoded build and PDB paths in compiled artifacts.

`C:\\Users\\ada.chen\\source\\repos\\loader\\obj\\Release\\loader.pdb` is a
complete attribution package: the developer's account name, the project name,
the toolchain, and the build configuration, compiled into the artifact by
default and shipped to the target. Nothing in this pipeline was reading it,
because nothing was reading compiled artifacts' strings at all.

**Binaries only, deliberately.** The vendored `MetadataLeakageScanner` already
covers `/home/<user>/` and friends in *source*, and a second regex detector
over the same text would add noise rather than coverage — the measurement that
produced the false-positive filter is explicit that `/home/<username>/` in
source is the finding, and it is already found. The gap is the compiled side,
where a path survives compilation, survives stripping, and is invisible to
every source scanner.

**A toolchain path is not an operator path.** Every Rust binary ever built
contains `/rustc/<hash>/library/core/src/...`, and every Go binary contains
`/usr/local/go/src/...`. Those name the compiler, not a person, and reporting
them at Attribution severity would bury the one path that does name somebody
under a hundred that do not. They are reported at the metadata tier instead —
present, visible, and not disqualifying — and the split is decided by whether a
username can actually be read out of the path.

CI service accounts (`runner`, `jenkins`, `builder`) sit on the toolchain side
of that line for the same reason: `/home/runner/work/` is on every GitHub
Actions build in the world and identifies the build system, not its operator.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §7 (typed evidence) ·
§14 Sprint 5
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.isolation import (
    AnalyzerStatus,
    ResourceLimits,
    require_privilege_drop,
    run_analyzer,
)
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "build_paths"
RULE_NAMESPACE = "BuildPaths"

_SHA256 = re.compile(r"^[a-f0-9]{64}$")

DEFAULT_LIMITS = ResourceLimits(wall_clock_seconds=300, cpu_seconds=300)

#: One path repeated through a debug section is one path.
MAX_PATHS_PER_FILE = 100
#: A recovered "string" longer than this is a blob, not a path, and running
#: alternations over it buys nothing.
MAX_STRING_LENGTH = 4096

#: Every quantifier below is bounded. Unbounded nesting is what makes a path
#: regex catastrophic on a hostile string, and these run over attacker-authored
#: bytes by definition.
#:
#: Whitespace is excluded from a path component, which costs the tail of
#: `C:\\Users\\Ada Chen\\...` — it is reported as `C:\\Users\\Ada`, still naming the
#: account. The alternative is worse: a class that accepts spaces runs greedily
#: past the end of the path into whatever text follows it in the recovered
#: string, so the reported path and the typed evidence both contain the next
#: sentence. Under-reporting a component is recoverable; over-reporting one is
#: evidence that is simply wrong.
_PATH_SEGMENT = r"[^\s\\\"<>|*?]{1,64}"

#: A path must start at a boundary. Without this, `https://example.com/home/page`
#: reports `/home/page` and an operator called "page".
_LEFT_BOUNDARY = r"(?<![A-Za-z0-9._/~-])"

#: A PDB path is the canonical case: MSVC writes it into the PE debug directory
#: unless explicitly told not to.
_PDB = re.compile(
    rf"[A-Za-z]:\\(?:{_PATH_SEGMENT}\\){{0,12}}{_PATH_SEGMENT}\.pdb", re.IGNORECASE
)
#: A Windows profile path names the account directly.
_WINDOWS_USER = re.compile(
    rf"([A-Za-z]:\\Users\\({_PATH_SEGMENT})\\(?:{_PATH_SEGMENT}\\){{0,10}}"
    rf"{_PATH_SEGMENT}?)", re.IGNORECASE
)
#: The Unix equivalent. `/root/` has no name to extract but is still a
#: developer machine rather than a build farm.
_UNIX_HOME = re.compile(
    _LEFT_BOUNDARY
    + r"(/(?:home|Users)/([A-Za-z0-9._-]{1,32})(?:/[A-Za-z0-9._+-]{1,64}){0,12})"
)
_UNIX_ROOT = re.compile(_LEFT_BOUNDARY + r"(/root/(?:[A-Za-z0-9._+-]{1,64}/?){1,12})")
#: MSVC's build configuration, which names the project even without a username.
_WINDOWS_BUILD = re.compile(
    rf"([A-Za-z]:\\(?:{_PATH_SEGMENT}\\){{0,10}}(?:obj|bin)\\(?:Release|Debug)"
    rf"(?:\\{_PATH_SEGMENT}){{0,4}})", re.IGNORECASE
)

#: Paths that name a compiler or a distribution build root. Present in every
#: artifact built the same way, so they identify the toolchain and nobody else.
_TOOLCHAIN: tuple[re.Pattern[str], ...] = (
    re.compile(_LEFT_BOUNDARY + r"(/rustc/[0-9a-f]{7,40}(?:/[A-Za-z0-9._+-]{1,64}){0,10})"),
    re.compile(_LEFT_BOUNDARY + r"(/go/pkg/mod(?:/[A-Za-z0-9._+@!-]{1,80}){0,10})"),
    re.compile(_LEFT_BOUNDARY + r"(/usr/local/go/src(?:/[A-Za-z0-9._+-]{1,64}){0,10})"),
    re.compile(_LEFT_BOUNDARY + r"(/usr/lib/go-[0-9.]{1,8}/src(?:/[A-Za-z0-9._+-]{1,64}){0,10})"),
    re.compile(_LEFT_BOUNDARY + r"(/builddir/build/BUILD(?:/[A-Za-z0-9._+-]{1,64}){0,10})"),
    re.compile(_LEFT_BOUNDARY + r"(/build/[a-z0-9.+~-]{1,48}-[0-9][A-Za-z0-9.+~-]{0,32})"),
    re.compile(_LEFT_BOUNDARY + r"(/\.cargo/registry(?:/[A-Za-z0-9._+-]{1,64}){0,10})"),
)

#: Accounts that belong to a build system rather than a person. `/home/runner/`
#: is on every GitHub Actions build there has ever been.
_SERVICE_ACCOUNTS: frozenset[str] = frozenset({
    "runner", "builder", "build", "jenkins", "buildbot", "root", "user",
    "ubuntu", "debian", "vagrant", "docker", "circleci", "travis", "gitpod",
    "codespace", "azureuser", "ec2-user", "administrator", "defaultuser0",
    "containeradministrator", "runneradmin", "vsts", "vso", "ci",
})


@dataclass(frozen=True)
class PathHit:
    """One path found in one artifact."""

    path: str
    kind: str          # "pdb_path" | "build_path"
    rule: str          # the rule id suffix
    username: str | None
    offset: int | None


def _clean(path: str) -> str:
    return path.strip().strip("\"'").rstrip("\\/")


def classify(path: str) -> tuple[str, str, str | None] | None:
    """Return (rule, typed-evidence kind, username) for a path, or None.

    The order matters. A PDB path under `C:\\Users\\ada\\` is both a PDB path
    and a user path; it is reported once, as the PDB, because that is the
    stronger statement about how the artifact was built.
    """
    if _PDB.fullmatch(path) or path.lower().endswith(".pdb"):
        user = _WINDOWS_USER.search(path + "\\")
        return "pdb_path", "pdb_path", _named_user(user.group(2) if user else None)

    for pattern, group in ((_WINDOWS_USER, 2), (_UNIX_HOME, 2)):
        match = pattern.fullmatch(path)
        if match:
            user = _named_user(match.group(group))
            rule = "operator_path" if user else "build_environment"
            return rule, "build_path", user

    if _UNIX_ROOT.fullmatch(path) or _WINDOWS_BUILD.fullmatch(path):
        return "operator_path", "build_path", None

    if any(pattern.fullmatch(path) for pattern in _TOOLCHAIN):
        return "build_environment", "build_path", None

    return None


def _named_user(candidate: str | None) -> str | None:
    if not candidate:
        return None
    return None if candidate.lower() in _SERVICE_ACCOUNTS else candidate


def extract_paths(text: str, base_offset: int | None = None,
                  width: int = 1) -> list[PathHit]:
    """Pull build-relevant paths out of one recovered string.

    Offsets are carried through the same way the dirty-word binary pass carries
    them: a character index inside a UTF-16LE string is not a byte offset.
    """
    if len(text) > MAX_STRING_LENGTH:
        return []

    hits: list[PathHit] = []
    seen: set[str] = set()
    claimed: list[tuple[int, int]] = []

    # (start, priority, -length, text). A PDB path outranks the user path it
    # sits inside: both describe the same span, and the PDB is the stronger
    # statement about how the artifact was built.
    candidates: list[tuple[int, int, int, str]] = []
    for match in _PDB.finditer(text):
        candidates.append((match.start(), 0, -len(match.group(0)), match.group(0)))
    for pattern in (_WINDOWS_USER, _UNIX_HOME, _UNIX_ROOT, _WINDOWS_BUILD, *_TOOLCHAIN):
        for match in pattern.finditer(text):
            candidates.append((match.start(), 1, -len(match.group(1)), match.group(1)))

    for index, _priority, _neg_len, raw in sorted(candidates):
        span = (index, index + len(raw))
        # One region of one string is one path. Without this, a user path and
        # the PDB path inside it are reported as two findings of one fact.
        if any(index < high and span[1] > low for low, high in claimed):
            continue
        path = _clean(raw)
        if not path or path in seen:
            continue
        verdict = classify(path)
        if verdict is None:
            continue
        seen.add(path)
        claimed.append(span)
        rule, kind, user = verdict
        hits.append(PathHit(
            path=path, kind=kind, rule=rule, username=user,
            offset=base_offset + index * width if base_offset is not None else None,
        ))

    return hits


def _finding(hit: PathHit, rel: str, recovery: binstrings.Recovery) -> RawFinding:
    family = (
        IssueFamily.build_path_leak if hit.rule != "build_environment"
        else IssueFamily.metadata_leak
    )
    if hit.username:
        detail = (
            f"The path names the account {hit.username!r}. A username compiled "
            "into a shipped artifact is an identity, not a formatting slip."
        )
    elif hit.rule == "pdb_path":
        detail = (
            "MSVC writes the debug-symbol path into the PE debug directory "
            "unless told not to. It carries the project name and the build "
            "configuration even when it carries no username."
        )
    elif hit.rule == "build_environment":
        detail = (
            "The path names the toolchain or distribution build root. Every "
            "artifact built the same way carries it, so it describes the build "
            "environment rather than whoever ran it."
        )
    else:
        detail = "The path describes the developer machine the artifact was built on."

    return RawFinding(
        sensor=SENSOR, sensor_version="builtin", rule_namespace=RULE_NAMESPACE,
        rule_id=f"build_paths.{hit.rule}",
        issue_family=family, pillar_hint=FAMILY_PILLAR[family],
        detector_class=DetectorClass.regex_pattern,
        raw_severity="HIGH" if family is IssueFamily.build_path_leak else "MEDIUM",
        confidence=0.9 if hit.kind == "pdb_path" else 0.8,
        source_facet="binary",
        title=(
            "Debug-symbol path compiled into the artifact" if hit.kind == "pdb_path"
            else "Build path compiled into the artifact"
        ),
        description=f"{rel} contains the build path {hit.path!r}. {detail}"[:4096],
        matched_tokens=hit.path[:4096],
        # Typed evidence rather than an observable: a build path needs
        # partial-match and normalization semantics before two of them can be
        # said to be equal, which the IOC pipeline does not have (§7).
        typed_evidence=[{"kind": hit.kind, "value": hit.path[:4096]}],
        location=Location(
            kind="binary", file=rel, artifact_sha256=recovery.sha256,
            format=recovery.binary_format, offset=hit.offset,
        ),
        recommendation=(
            "Build with deterministic paths — `/PDBALTPATH`, `-fdebug-prefix-map`, "
            "or `-trimpath` — and strip the debug directory before shipping."
        ),
    )


def collect(source_root: Path, *, profile: str | None = None,
            run_floss=None) -> list[dict]:
    """Recover strings from every binary and read the build paths out of them.

    Runs inside the analyzer subprocess: it opens attacker-authored bytes and
    runs alternations over them, which the isolation contract admits no
    in-process exception for, however pure the Python is.
    """
    from backend.app.bluescrub.scanners.dirty_word import binary_paths

    records: list[dict] = []

    for rel in sorted(binary_paths(source_root)):
        recovery = binstrings.recover(
            source_root / rel, profile=profile, run_floss=run_floss
        )
        if not recovery.sha256:
            logger.warning("build_paths: could not read %s: %s", rel, recovery.reason)
            continue

        per_file = 0
        seen: set[str] = set()
        for entry in recovery.strings:
            width = 2 if entry.encoding == "utf-16le" else 1
            for hit in extract_paths(entry.value, entry.offset, width):
                if hit.path in seen:
                    continue
                if per_file >= MAX_PATHS_PER_FILE:
                    logger.warning(
                        "build_paths: %s hit the %d-path cap; the rest were not "
                        "reported", rel, MAX_PATHS_PER_FILE,
                    )
                    break
                seen.add(hit.path)
                per_file += 1
                records.append({
                    "file": rel, "path": hit.path, "kind": hit.kind,
                    "rule": hit.rule, "username": hit.username,
                    "offset": hit.offset, "sha256": recovery.sha256,
                    "format": recovery.binary_format,
                })

    return records


def to_findings(records: list[dict]) -> list[RawFinding]:
    """Turn collected records into raw findings. Pure, so it needs no subprocess."""
    findings: list[RawFinding] = []
    for record in records:
        if not isinstance(record, dict) or not record.get("path"):
            continue
        digest = str(record.get("sha256") or "")
        if not _SHA256.match(digest):
            # A binary location needs the artifact digest, and the contract
            # rejects one without it. Nothing at runtime validates raw
            # findings, so a forged location would reach the database.
            logger.warning("build_paths: dropping a record with no artifact digest")
            continue
        offset = record.get("offset")
        findings.append(_finding(
            PathHit(
                path=str(record["path"]), kind=str(record.get("kind") or "build_path"),
                rule=str(record.get("rule") or "build_environment"),
                username=record.get("username"),
                offset=offset if isinstance(offset, int) else None,
            ),
            str(record.get("file") or "unknown"),
            binstrings.Recovery(
                sha256=digest, binary_format=record.get("format"),
            ),
        ))
    return findings


def scan(source_root: Path, *, profile: str | None = None,
         run_floss=None) -> list[RawFinding]:
    """In-process convenience for tests; ``run`` goes through the boundary."""
    return to_findings(collect(source_root, profile=profile, run_floss=run_floss))


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    result = run_analyzer(
        [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
         "__build_paths__", str(source_root), "build_paths"],
        cwd=Path.cwd(),
        limits=limits or DEFAULT_LIMITS,
        require_privilege_drop=require_privilege_drop(),
        env_extra={
            "PYTHONPATH": os.getcwd(),
            binstrings.PROFILE_ENV: os.getenv(binstrings.PROFILE_ENV, ""),
        },
    )
    if not result.ok:
        return ScannerOutcome(sensor=SENSOR, status=result.status.value,
                              duration_ms=result.duration_ms, reason=result.reason)

    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError as exc:
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.unparseable.value,
                              duration_ms=result.duration_ms, reason=str(exc)[:256])
    if not payload.get("ok"):
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.crashed.value,
                              duration_ms=result.duration_ms,
                              reason=str(payload.get("error"))[:256])

    findings = to_findings(payload.get("findings") or [])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )
    return ScannerOutcome(
        sensor=SENSOR, status=AnalyzerStatus.completed.value, findings=findings,
        version="builtin", ruleset_version=f"{len(_TOOLCHAIN) + 5} patterns",
        duration_ms=result.duration_ms,
        # The deep profile's missing emulation tier applies here too: a build
        # path assembled at runtime is only recoverable by FLOSS.
        ruleset_state=binstrings.recovery_state(),
    )
