"""
Generic artifact classifier (SO-CRATES-style multi-format intake).

Classifies an uploaded file into a coarse ``artifact_class`` using magic
bytes first, then file extension, then a text/binary heuristic. The result
lets job creation route an artifact to the correct analysis pipeline
(pcap / log / binary / archive) instead of assuming every upload is a PCAP.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Artifact classes
PCAP = "pcap"
ARCHIVE = "archive"
BINARY = "binary"
LOG = "log"
UNKNOWN = "unknown"

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
}

_ARCHIVE_EXTENSIONS = {".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar", ".gz", ".bz2"}
_LOG_EXTENSIONS = {".json", ".jsonl", ".ndjson", ".evtx", ".log", ".csv", ".xml", ".txt"}
_BINARY_EXTENSIONS = {".exe", ".dll", ".sys", ".bin", ".so", ".elf", ".o", ".dylib", ".a"}
_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@dataclass
class ClassifyResult:
    """Outcome of classifying a single artifact."""

    artifact_class: str
    format: str | None
    detail: str


def _match_ext(filename: str, exts: set[str]) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in exts)


def _classify_by_magic(head: bytes, tar_block: bytes) -> ClassifyResult | None:
    """Return a classification from leading magic bytes, or None."""
    if head[:4] in _PCAP_MAGICS:
        fmt = "pcapng" if head[:4] == b"\x0a\x0d\x0d\x0a" else "pcap"
        return ClassifyResult(PCAP, fmt, "magic")
    if head[:4] == b"\x7fELF":
        return ClassifyResult(BINARY, "elf", "magic")
    if head[:2] == b"MZ":
        return ClassifyResult(BINARY, "pe", "magic")
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return ClassifyResult(BINARY, "macho", "magic")
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return ClassifyResult(ARCHIVE, "zip", "magic")
    if head[:2] == b"\x1f\x8b":
        return ClassifyResult(ARCHIVE, "gzip", "magic")
    if head[:3] == b"BZh":
        return ClassifyResult(ARCHIVE, "bzip2", "magic")
    if tar_block[257:262] == b"ustar":
        return ClassifyResult(ARCHIVE, "tar", "magic")
    if head[:8] == b"ElfFile\x00":
        return ClassifyResult(LOG, "evtx", "magic")
    return None


def _looks_textual(sample: bytes) -> bool:
    """Heuristic: treat a sample as text if it has no NULs and is mostly printable."""
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) >= 0.85


def classify_artifact(path: Path, filename: str | None = None) -> ClassifyResult:
    """Classify a file on disk into an artifact class.

    Order: magic bytes -> extension -> text/binary heuristic.
    """
    name = filename or path.name
    with open(path, "rb") as f:
        head = f.read(512)
        rest = f.read(max(0, 264 - len(head)))
    tar_block = head + rest

    magic = _classify_by_magic(head, tar_block)
    if magic is not None:
        return magic

    if _match_ext(name, _PCAP_EXTENSIONS):
        return ClassifyResult(PCAP, "pcap", "extension")
    if _match_ext(name, _ARCHIVE_EXTENSIONS):
        return ClassifyResult(ARCHIVE, None, "extension")
    if _match_ext(name, _BINARY_EXTENSIONS):
        return ClassifyResult(BINARY, None, "extension")
    if _match_ext(name, _LOG_EXTENSIONS):
        return ClassifyResult(LOG, "text", "extension")

    if _looks_textual(head):
        return ClassifyResult(LOG, "text", "heuristic")
    return ClassifyResult(UNKNOWN, None, "heuristic")
