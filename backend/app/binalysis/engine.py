"""
Arbitrary binary / file analysis engine.

Computes cryptographic hashes, file size, Shannon entropy, a coarse format
label, and (when ``yara-python`` is available) YARA rule matches. This makes
binary/YARA analysis a first-class analysis mode rather than something that
only runs on PCAP-extracted files.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.app.pipeline.artifact_classifier import classify_artifact

try:  # yara-python is optional; analysis degrades gracefully without it.
    import yara as _yara
except ImportError:  # pragma: no cover - exercised only when dependency absent
    _yara = None

_CHUNK = 262_144


@dataclass
class YaraMatch:
    """A single YARA rule match against a file."""

    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)


@dataclass
class BinaryAnalysis:
    """Full analysis result for one file."""

    filename: str
    size_bytes: int
    sha256: str
    md5: str
    sha1: str
    entropy: float
    format: str | None
    artifact_class: str
    yara_matches: list[YaraMatch] = field(default_factory=list)
    yara_available: bool = False


def yara_available() -> bool:
    """Return True if the yara-python binding is importable."""
    return _yara is not None


def _compute_hashes(path: Path) -> tuple[str, str, str]:
    """Return (sha256, md5, sha1) computed in a single streamed pass."""
    sha256, md5, sha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
    return sha256.hexdigest(), md5.hexdigest(), sha1.hexdigest()


def _compute_entropy(path: Path) -> float:
    """Compute Shannon entropy (bits/byte, 0.0–8.0) over the whole file."""
    counts: Counter[int] = Counter()
    total = 0
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            counts.update(chunk)
            total += len(chunk)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def compile_yara_rules(rules_dir: Path):
    """Compile every ``*.yar`` / ``*.yara`` file under ``rules_dir``.

    Returns a compiled rules object, or None if YARA is unavailable or no
    valid rule files are present.
    """
    if _yara is None or not rules_dir.exists():
        return None
    filepaths: dict[str, str] = {}
    for p in sorted(rules_dir.iterdir()):
        if p.suffix.lower() in (".yar", ".yara") and p.is_file():
            filepaths[p.stem] = str(p)
    if not filepaths:
        return None
    try:
        return _yara.compile(filepaths=filepaths)
    except _yara.Error:
        return None


def _run_yara(compiled, path: Path) -> list[YaraMatch]:
    """Run compiled YARA rules against a file; return structured matches."""
    if compiled is None:
        return []
    try:
        raw = compiled.match(str(path))
    except _yara.Error:
        return []
    matches: list[YaraMatch] = []
    for m in raw:
        strings = []
        for s in getattr(m, "strings", []):
            ident = getattr(s, "identifier", None)
            if ident is None and isinstance(s, tuple):  # older yara API
                ident = s[1] if len(s) > 1 else None
            if ident:
                strings.append(str(ident))
        matches.append(YaraMatch(
            rule=m.rule,
            tags=list(getattr(m, "tags", []) or []),
            meta=dict(getattr(m, "meta", {}) or {}),
            strings=sorted(set(strings)),
        ))
    return matches


def analyze_file(path: Path, compiled_rules=None, filename: str | None = None) -> BinaryAnalysis:
    """Analyze a single file: hashes, size, entropy, format, YARA matches."""
    name = filename or path.name
    sha256, md5, sha1 = _compute_hashes(path)
    classification = classify_artifact(path, name)
    return BinaryAnalysis(
        filename=name,
        size_bytes=path.stat().st_size,
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        entropy=_compute_entropy(path),
        format=classification.format,
        artifact_class=classification.artifact_class,
        yara_matches=_run_yara(compiled_rules, path),
        yara_available=yara_available(),
    )
