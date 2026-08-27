"""Stable finding fingerprints — scheme ``fp/2``.

The scheme identifier travels with every finding. Two earlier attempts were
wrong (one keyed binary findings on the artifact SHA-256, so every rebuild
orphaned its triage), and a third revision is plausible; without a version
field that migration silently discards every triage decision in the system.

Normalization must be byte-deterministic across runs and hosts. A fingerprint
that shifts for reasons unrelated to the code is indistinguishable, at triage
time, from a correctness bug.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §3
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

SCHEME = "fp/2"

MAX_TOKEN_BYTES = 512
CONTEXT_LINES = 3

#: Line-comment markers by file extension. Unknown extensions are not stripped
#: — guessing wrong would corrupt the token stream and destabilise the key.
_LINE_COMMENTS: dict[str, tuple[str, ...]] = {
    ".py": ("#",), ".rb": ("#",), ".sh": ("#",), ".pl": ("#",), ".yaml": ("#",),
    ".yml": ("#",), ".toml": ("#",), ".r": ("#",),
    ".c": ("//",), ".h": ("//",), ".cc": ("//",), ".cpp": ("//",), ".hpp": ("//",),
    ".go": ("//",), ".rs": ("//",), ".java": ("//",), ".cs": ("//",),
    ".js": ("//",), ".ts": ("//",), ".tsx": ("//",), ".jsx": ("//",),
    ".php": ("//", "#"), ".swift": ("//",), ".kt": ("//",), ".scala": ("//",),
}

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL = re.compile(
    r"""("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')""", re.DOTALL
)
_NUMBER_LITERAL = re.compile(r"\b(?:0[xXbBoO][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)\b")
_WHITESPACE = re.compile(r"\s+")


def decode_bytes(raw: bytes) -> str:
    """Decode source bytes deterministically. UTF-8, falling back to latin-1."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _ascii_casefold(text: str) -> str:
    """Lowercase ASCII only.

    ``str.lower()`` is Unicode-aware and locale-sensitive at the edges (Turkish
    dotless i, final sigma), which would make the same file fingerprint
    differently on two hosts.
    """
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in text)


def strip_comments(text: str, suffix: str | None) -> str:
    """Remove comments for known languages; leave unknown languages untouched."""
    if not suffix:
        return text
    suffix = suffix.lower()
    if suffix not in _LINE_COMMENTS:
        return text

    text = _BLOCK_COMMENT.sub(" ", text)
    markers = _LINE_COMMENTS[suffix]
    out: list[str] = []
    for line in text.splitlines():
        cut = len(line)
        for marker in markers:
            idx = line.find(marker)
            if idx != -1:
                cut = min(cut, idx)
        out.append(line[:cut])
    return "\n".join(out)


def normalize_tokens(text: str, suffix: str | None = None) -> str:
    """Canonicalise matched source text for fingerprinting.

    Literals are masked so that changing a constant — a port number, a key
    string — does not orphan the triage decision attached to the construct.
    """
    text = unicodedata.normalize("NFC", text)
    text = strip_comments(text, suffix)
    text = _STRING_LITERAL.sub("<str>", text)
    text = _NUMBER_LITERAL.sub("<num>", text)
    text = _WHITESPACE.sub(" ", text).strip()
    text = _ascii_casefold(text)

    encoded = text.encode("utf-8", "surrogatepass")[:MAX_TOKEN_BYTES]
    return encoded.decode("utf-8", "ignore")


def context_hash(
    lines: list[str],
    match_line: int,
    suffix: str | None = None,
    window: int = CONTEXT_LINES,
) -> str:
    """Hash the lines surrounding a match. ``match_line`` is 1-indexed.

    File boundaries are not padded: a match at line 1 simply has less context.
    """
    idx = match_line - 1
    before = lines[max(0, idx - window):idx]
    after = lines[idx + 1:idx + 1 + window]

    prepared = []
    for line in (*before, *after):
        line = unicodedata.normalize("NFC", line)
        line = strip_comments(line, suffix)
        line = _WHITESPACE.sub(" ", line).strip()
        prepared.append(_ascii_casefold(line))

    return hashlib.sha1("\n".join(prepared).encode("utf-8", "surrogatepass")).hexdigest()


def _digest(*parts: str | int | None) -> str:
    joined = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(joined.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def source_fingerprint(
    *,
    project_id: str,
    rule_namespace: str | None,
    rule_id: str,
    relative_path: str,
    enclosing_symbol: str | None,
    node_kind: str | None,
    normalized_tokens: str,
    context_digest: str,
    occurrence_index: int = 0,
) -> str:
    """Fingerprint a source finding.

    Deliberately excludes the line number: inserting an unrelated line above a
    finding must not orphan its triage.
    """
    return _digest(
        project_id, rule_namespace, rule_id, relative_path,
        enclosing_symbol, node_kind, normalized_tokens, context_digest,
        occurrence_index,
    )


def binary_fingerprint(
    *,
    project_id: str,
    rule_id: str,
    binary_format: str | None,
    architecture: str | None,
    section: str | None,
    nearest_symbol: str | None,
    normalized_value: str,
    occurrence_index: int = 0,
) -> str:
    """Fingerprint a binary finding using semantic anchors only.

    The artifact SHA-256 is deliberately absent: it changes on every rebuild,
    so including it would guarantee that no binary finding ever retains its
    triage. The SHA lives in evidence instead.
    """
    return _digest(
        project_id, rule_id, binary_format, architecture, section,
        nearest_symbol, normalized_value, occurrence_index,
    )


_SLUG = re.compile(r"[^a-z0-9]+")


def pillar_slug(pillar: str) -> str:
    return _SLUG.sub("-", pillar.lower()).strip("-")


def canonical_id(pillar: str, tool: str, digest: str, dup: int = 0) -> str:
    """Compose the persisted ``Finding.finding_id``.

    ``dup`` is only ever non-zero when a defective fingerprint produced a
    collision inside one job; it keeps the job alive while making the defect
    countable.
    """
    tool_slug = re.sub(r"[^a-z0-9_]+", "_", tool.lower()).strip("_") or "unknown"
    base = f"bs-{pillar_slug(pillar)}-{tool_slug}-{digest}"
    return f"{base}-dup{dup}" if dup else base
