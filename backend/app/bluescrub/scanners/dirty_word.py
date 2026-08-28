"""Dirty-word scanning — the operator-declared side of Attribution.

Every other detector guesses what matters. This one is told: the operator names
the codenames, handles, markings, and internal hostnames that must not ship,
and a literal match on a declared term is about as precise as this pipeline
gets.

That precision is why these findings are promoted past the detector-precision
ceiling. The ceiling exists because a generic regex matching ``"C2"`` cannot
justify disqualifying an artifact; a term the operator explicitly declared
sensitive can.

**The wordlist is itself sensitive.** It contains the classification markings
and operation codenames being hunted, so it never travels as argv — ``ps``
output is world-readable — and never as an environment value. It is written to
the job's runtime directory at mode 0600, handed over by path, and deleted once
the scan finishes.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §Dirty Word search
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "dirty_word"
WORDLIST_ENV = "AIPAM_BLUESCRUB_WORDLIST_FILE"

#: Term category → issue family. The category is what lets a classification
#: marking outrank a build-path fragment; upstream's packs are flat word lists
#: with no such distinction.
CATEGORY_FAMILY: dict[str, IssueFamily] = {
    "marking": IssueFamily.attribution_marking,
    "identity": IssueFamily.attribution_identity,
    "org": IssueFamily.attribution_identity,
    "codename": IssueFamily.attribution_marking,
    "hostname": IssueFamily.attribution_infrastructure,
    "ticket": IssueFamily.metadata_leak,
    "path": IssueFamily.build_path_leak,
    "mutex": IssueFamily.forensic_artifact,
    # A framework signature in your own tool is a detection problem, not an
    # attribution one — defenders match it, they do not trace it to you.
    "tooling": IssueFamily.signature_known,
    # Compiler and build-system identifiers describe the environment rather
    # than whoever ran it, which is the split the build-path scanner draws too.
    "toolchain": IssueFamily.metadata_leak,
    # Developer-note markers, placeholder credentials, generic account names.
    # Real enough to show an operator, never enough to disqualify on.
    "hygiene": IssueFamily.metadata_leak,
}


def write_wordlist(job_dir: Path, terms: list[dict]) -> Path | None:
    """Persist terms for the sandboxed scanner. Owner-readable only."""
    if not terms:
        return None
    runtime = job_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    path = runtime / "wordlist.json"
    path.write_text(json.dumps(terms))
    path.chmod(0o600)
    return path


#: One term repeated through a data section is one finding's worth of signal.
#: The cap is reported rather than applied silently.
MAX_BINARY_HITS_PER_FILE = 200
#: Characters of surrounding string kept as evidence.
BINARY_CONTEXT = 24


def binary_paths(root: Path) -> set[str]:
    """Files this scanner recovers strings from, as paths relative to *root*.

    Content **or** extension. Content is what catches the stripped ELF called
    `loader`, which extension-based classification misses entirely; extension is
    kept because it is what the vendored matcher used, and dropping it would
    quietly lose the files it was already covering.
    """
    from backend.app.bluescrub.vendored.dirty_word_scanner import BINARY_EXTENSIONS

    found: set[str] = set()
    if not root.is_dir():
        return found
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix.lower() in BINARY_EXTENSIONS or binstrings.is_binary_file(path):
            found.add(str(path.relative_to(root)))
    return found


def _occurrences(value: str, term: str, case_sensitive: bool):
    haystack = value if case_sensitive else value.casefold()
    needle = term if case_sensitive else term.casefold()
    if not needle:
        return
    index = haystack.find(needle)
    while index != -1:
        yield index
        index = haystack.find(needle, index + 1)


def scan_binaries(root: Path, terms: list[dict], *,
                  profile: str | None = None, run_floss=None) -> list[dict]:
    """Match declared terms against strings recovered from binary artifacts.

    Returns match records in the vendored scanner's shape, plus the artifact
    identity and encoding the raw-finding contract needs for a binary location.
    """
    matches: list[dict] = []

    for rel in sorted(binary_paths(root)):
        recovery = binstrings.recover(root / rel, profile=profile, run_floss=run_floss)
        if not recovery.sha256:
            logger.warning("dirty_word: could not read %s: %s", rel, recovery.reason)
            continue

        per_file = 0
        for entry in recovery.strings:
            if per_file >= MAX_BINARY_HITS_PER_FILE:
                break
            # UTF-16LE is two bytes per character, so a character index inside
            # the recovered string is not a byte offset into the file.
            width = 2 if entry.encoding == "utf-16le" else 1
            for term in terms:
                word = str(term.get("term") or "")
                sensitive = bool(term.get("case_sensitive"))
                for index in _occurrences(entry.value, word, sensitive):
                    if per_file >= MAX_BINARY_HITS_PER_FILE:
                        break
                    per_file += 1
                    start = max(0, index - BINARY_CONTEXT)
                    end = index + len(word) + BINARY_CONTEXT
                    matches.append({
                        "file": rel,
                        "word": entry.value[index:index + len(word)],
                        "line": None,
                        "offset": (entry.offset + index * width
                                   if entry.offset is not None else None),
                        "context": entry.value[start:end],
                        "type": "binary",
                        "sha256": recovery.sha256,
                        "format": recovery.binary_format,
                        "encoding": entry.encoding,
                        "recovery": entry.method,
                    })

        if per_file >= MAX_BINARY_HITS_PER_FILE:
            logger.warning(
                "dirty_word: %s hit the %d-match cap; further matches not reported",
                rel, MAX_BINARY_HITS_PER_FILE,
            )

    return matches


_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _locate(hit: dict, rel: str, line, offset) -> tuple[Location, str, str]:
    """Build the location, facet, and evidence phrase for one hit.

    A binary hit used to be written into a ``source`` location carrying an
    offset and no line number — which the raw-finding contract rejects, since a
    source location must have one. The offset was computed and then discarded.
    A binary location needs the artifact digest, so a hit that cannot supply
    one is reported project-scoped rather than given a location it cannot
    support.
    """
    digest = str(hit.get("sha256") or "")
    if hit.get("type") == "binary" or hit.get("binary"):
        method = str(hit.get("recovery") or "static")
        encoding = str(hit.get("encoding") or "ascii")
        where = f", recovered as a {encoding} string"
        if method != "static":
            # A runtime-assembled string was never on disk, so there is no
            # offset to seek to and saying so is the useful part.
            where += f" that FLOSS reconstructed at runtime ({method})"
        elif isinstance(offset, int):
            where += f" at offset 0x{offset:x}"

        if _SHA256.match(digest):
            return (
                Location(
                    kind="binary", file=rel or None, artifact_sha256=digest,
                    format=str(hit.get("format") or "") or None,
                    offset=offset if isinstance(offset, int) else None,
                ),
                "binary", where,
            )
        return (
            Location(kind="project", file=rel or None,
                     subject=f"artifact:{rel or 'unknown'}"),
            "binary", where,
        )

    return (
        Location(
            kind="source", file=rel,
            start_line=int(line) if isinstance(line, int) else 1,
            start_column=0,
        ),
        "source", "",
    )


def parse_hits(payload: dict, terms: list[dict], source_root: Path) -> list[RawFinding]:
    """Turn scanner hits into findings, carrying each term's category through."""
    by_term = {t["term"]: t for t in terms}
    by_term_ci = {t["term"].casefold(): t for t in terms}
    findings: list[RawFinding] = []

    for hit in payload.get("matches") or payload.get("findings") or []:
        if not isinstance(hit, dict):
            continue
        term = str(hit.get("word") or hit.get("term") or hit.get("match") or "")
        if not term:
            continue

        meta = by_term.get(term) or by_term_ci.get(term.casefold()) or {}
        category = str(meta.get("category") or "codename")
        family = CATEGORY_FAMILY.get(category, IssueFamily.attribution_marking)

        raw_path = str(hit.get("file") or hit.get("path") or "")
        try:
            rel = str(Path(raw_path).resolve().relative_to(source_root.resolve()))
        except (ValueError, OSError):
            rel = raw_path

        line = hit.get("line") or hit.get("line_number")
        offset = hit.get("offset")
        location, facet, where = _locate(hit, rel, line, offset)

        findings.append(RawFinding(
            sensor=SENSOR, sensor_version="vendored",
            rule_namespace="DirtyWord",
            # Deliberately not per-term: the term can be a classification
            # marking, and rule_id reaches logs, metrics keys, and fingerprints.
            rule_id=f"dirty_word.{category}",
            issue_family=family, pillar_hint=FAMILY_PILLAR.get(family),
            detector_class=DetectorClass.regex_pattern,
            raw_severity="HIGH", confidence=0.9,
            source_facet=facet,
            title=f"Declared term found ({category})",
            description=(
                f"The term {term!r} from the {meta.get('list', 'operator')} list "
                f"appears in {rel or 'the artifact'}{where}. It was declared "
                "sensitive, so its presence in shipped material is a leak by "
                "definition."
            )[:4096],
            matched_tokens=str(hit.get("context") or term)[:4096],
            location=location,
        ))

    return findings


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    wordlist_path = os.getenv(WORDLIST_ENV)
    if not wordlist_path or not Path(wordlist_path).exists():
        # No list means nothing was declared sensitive. That is a real state,
        # not a clean result: the pillar has not been assessed against operator
        # knowledge, and reporting zero findings would imply it had.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason="no dirty-word list configured for this job",
        )

    try:
        terms = json.loads(Path(wordlist_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
                              reason=f"unreadable wordlist: {exc}")

    result = run_analyzer(
        [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
         "__dirty_word__", str(source_root), "dirty_word"],
        cwd=Path.cwd(),
        limits=limits or ResourceLimits(),
        require_privilege_drop=os.getenv(
            "AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true"
        ).lower() not in ("0", "false", "no"),
        # By path, never by value: the terms are the secrets.
        env_extra={
            "PYTHONPATH": os.getcwd(), WORDLIST_ENV: wordlist_path,
            # FLOSS is emulation-class, so the recovery pass needs to know
            # whether this is a deep scan before it may run it.
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
                              duration_ms=result.duration_ms, reason=str(exc))
    if not payload.get("ok"):
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.crashed.value,
                              duration_ms=result.duration_ms,
                              reason=str(payload.get("error"))[:256])

    findings = parse_hits(payload.get("findings") or {}, terms, source_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )
    return ScannerOutcome(
        sensor=SENSOR, status=AnalyzerStatus.completed.value, findings=findings,
        version="vendored", ruleset_version=f"{len(terms)} terms",
        # A deep scan without FLOSS recovered only what was already on disk.
        # That is partial coverage of the question the profile asked.
        ruleset_state=binstrings.recovery_state(),
        duration_ms=result.duration_ms,
    )
