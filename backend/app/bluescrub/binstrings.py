"""Binary string recovery — the input the dirty-word scanner never had.

A codename planted in a compiled implant is the single finding Sprint 5's
acceptance criterion names, and until now it could not be reported correctly.
The vendored matcher decides a file is binary from its **extension**, which
misses every stripped ELF called `loader` or `agent`, and when it does take the
binary branch it hands back a byte offset that the adapter then wrote into a
`source` location — a location the raw-finding contract rejects, because a
source location must carry a line number. The offset was being computed and
then thrown away.

Recovery here is deliberately two-tiered, and the tiers are not
interchangeable:

- **Static extraction** runs everywhere. It is `strings -a` and `strings -el`
  in Python: printable ASCII and UTF-16LE runs, each with its true file offset.
  It is cheap enough for the Quick profile, which is where Attribution belongs.
- **FLOSS** recovers stack, tight, and decoded strings — the ones assembled at
  runtime and therefore invisible to any static pass. `recover()` takes it as
  an injected runner, and the invocation, the tiering and the parser are all
  tested here.

A string FLOSS decoded at runtime never existed on disk, so it has no file
offset. That is reported as `offset=None` rather than filled in with the
address it was assembled at: an offset an analyst cannot seek to is worse than
an absent one.

**The FLOSS runner is not wired to a scanner yet, and that is deliberate.**
FLOSS is `emulation` class: it executes the sample's decoding routines under an
emulator, and the isolation contract gives that class its own limits — 8 GiB,
900 seconds — and confines it to `deep`. The two scanners that consume this
module, dirty-word and build-paths, are `parse_only` and run in profiles where
`deep` is not selected. Invoking FLOSS from inside either of them would promote
a `parse_only` scanner to `emulation` in fact while leaving it `parse_only` in
the registry, and would run a 900-second tool inside a 120-second process
boundary that would kill it. The emulation-class invocation belongs to the
FLOSS scanner in Sprint 6, which is where the plan puts it.

What that costs is reported rather than hidden: on `deep`, `recovery_state()`
returns `strings_static_only`, which degrades Attribution coverage. A deep scan
asked for emulation-grade recovery and got the static pass, and a scorecard
that presented that as complete would be lying about what it looked at.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md §3 (`emulation`) ·
docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §14 Sprint 5
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

#: Four is what `strings` uses. Below it, every binary is mostly noise.
MIN_STRING_LENGTH = 4
#: Per-artifact read ceiling. Ingest permits a 256 MiB member.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
#: How much of the head decides text-versus-binary.
SNIFF_BYTES = 8192
#: Above this share of non-text bytes, treat the file as binary.
NON_TEXT_RATIO = 0.30

PROFILE_ENV = "AIPAM_BLUESCRUB_PROFILE"
FLOSS_BINARY = "floss"

#: Container formats worth naming in a finding's location. The value goes into
#: ``Location.format``, which the binary fingerprint keys on.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\x00asm", "wasm"),
    # 0xCAFEBABE is a Java class *and* a Mach-O universal binary. Java is the
    # commoner case in a source tree, and the distinction does not change how
    # strings are recovered, so it is not guessed at beyond the label.
    (b"\xca\xfe\xba\xbe", "class-or-macho-universal"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"!<arch>", "ar"),
)

#: Printable ASCII plus tab, the classic `strings` alphabet.
_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING_LENGTH)
#: The same alphabet in UTF-16LE, which is where Windows string literals live
#: and which a plain `strings` misses entirely.
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_STRING_LENGTH)

#: Bytes that occur freely in text. Everything else counts towards the ratio.
_TEXT_BYTES = frozenset(bytes(range(0x20, 0x7F)) + b"\t\n\r\f\b\x1b")


@dataclass(frozen=True)
class RecoveredString:
    """One string pulled out of an artifact.

    ``offset`` is a file offset an analyst can seek to, or ``None`` for a
    string that was assembled at runtime and never existed on disk.
    """

    value: str
    offset: int | None
    encoding: str          # "ascii" | "utf-16le" | "unknown"
    method: str            # "static" | "stack" | "tight" | "decoded"


@dataclass
class Recovery:
    """What was recovered from one artifact, and how completely."""

    sha256: str
    binary_format: str | None = None
    strings: list[RecoveredString] = field(default_factory=list)
    #: "static" when only the built-in pass ran, "floss" when FLOSS added to it.
    method: str = "static"
    truncated: bool = False
    reason: str | None = None


# ── classification ────────────────────────────────────────────────────────

def detect_format(head: bytes) -> str | None:
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    return None


def looks_binary(head: bytes) -> bool:
    """Decide by content, not by extension.

    Extension-based classification is why a stripped ELF named ``loader`` was
    read as text: the codename was still found, but at a line number and column
    that mean nothing in a file with no lines.
    """
    if not head:
        return False
    if detect_format(head):
        return True
    if b"\x00" in head:
        return True
    non_text = sum(1 for byte in head if byte not in _TEXT_BYTES)
    return non_text / len(head) > NON_TEXT_RATIO


def is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return looks_binary(handle.read(SNIFF_BYTES))
    except OSError:
        return False


# ── static extraction ─────────────────────────────────────────────────────

def extract_static(data: bytes) -> list[RecoveredString]:
    """Printable ASCII and UTF-16LE runs, each with its true file offset.

    UTF-16LE is extracted first and its byte ranges are withheld from the ASCII
    pass. Without that, ``N\\0I\\0G\\0H\\0T\\0`` is reported twice — once as the
    real wide string and once as a stream of one-character ASCII runs — and the
    duplicate is indistinguishable from two genuine occurrences.
    """
    found: list[RecoveredString] = []
    wide_ranges: list[tuple[int, int]] = []

    for match in _UTF16LE_RUN.finditer(data):
        wide_ranges.append((match.start(), match.end()))
        found.append(RecoveredString(
            value=match.group().decode("utf-16-le", "replace"),
            offset=match.start(), encoding="utf-16le", method="static",
        ))

    for match in _ASCII_RUN.finditer(data):
        start = match.start()
        if any(low <= start < high for low, high in wide_ranges):
            continue
        found.append(RecoveredString(
            value=match.group().decode("ascii", "replace"),
            offset=start, encoding="ascii", method="static",
        ))

    found.sort(key=lambda s: (s.offset if s.offset is not None else -1, s.value))
    return found


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── FLOSS ─────────────────────────────────────────────────────────────────

def floss_argv(path: Path) -> list[str]:
    """The invocation Sprint 6's emulation-class FLOSS scanner will use.

    FLOSS is asked for JSON on stdout and nothing else.

    ``--no static`` is deliberate: the static pass above already ran and
    already has the offsets. Asking FLOSS to repeat it doubles the work and
    produces two records per string that then have to be reconciled.
    """
    return [
        "--json",
        "--no", "static",
        "--quiet",
        str(path),
    ]


def parse_floss(payload: dict) -> list[RecoveredString]:
    """Parse ``floss --json``.

    Shape: ``strings`` -> {static_strings, stack_strings, tight_strings,
    decoded_strings}, each a list of records. Only ``static_strings`` carries a
    file ``offset``; the other three are runtime constructions, and their
    ``program_counter`` / ``decoding_routine`` fields are addresses in the
    emulated image, not positions in the file.
    """
    buckets = (payload.get("strings") or {}) if isinstance(payload, dict) else {}
    recovered: list[RecoveredString] = []

    for key, method in (
        ("static_strings", "static"),
        ("stack_strings", "stack"),
        ("tight_strings", "tight"),
        ("decoded_strings", "decoded"),
    ):
        for record in buckets.get(key) or []:
            if isinstance(record, str):
                value, offset, encoding = record, None, "unknown"
            elif isinstance(record, dict):
                value = str(record.get("string") or "")
                raw_offset = record.get("offset")
                offset = raw_offset if isinstance(raw_offset, int) else None
                encoding = str(record.get("encoding") or "unknown").lower()
            else:
                continue
            if not value:
                continue
            recovered.append(RecoveredString(
                value=value,
                # Only the static bucket's offset is a file position.
                offset=offset if method == "static" else None,
                encoding=encoding, method=method,
            ))

    return recovered


def floss_enabled(profile: str | None = None) -> bool:
    """FLOSS is emulation-class, so it is confined to the deep profile.

    Reading the profile from the environment matches how the dirty-word list
    reaches the sandbox. The alternative — a keyword through every adapter —
    was tried when the wordlist landed and reverted, because it broke every
    caller to carry a value only one adapter reads.
    """
    active = profile if profile is not None else os.getenv(PROFILE_ENV, "")
    return active == "deep" and shutil.which(FLOSS_BINARY) is not None


# ── the whole recovery ────────────────────────────────────────────────────

def recover(
    path: Path,
    *,
    max_bytes: int = MAX_ARTIFACT_BYTES,
    profile: str | None = None,
    run_floss=None,
) -> Recovery:
    """Recover strings from one artifact.

    ``run_floss`` is injected rather than resolved here: FLOSS is emulation
    class, and only a caller that is itself emulation class may supply it. See
    the module docstring. It takes a path and returns a parsed JSON payload, or
    None.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        return Recovery(sha256="", reason=f"unreadable: {exc}")

    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]

    recovery = Recovery(
        sha256=sha256_of(data),
        binary_format=detect_format(data[:16]),
        strings=extract_static(data),
        truncated=truncated,
        reason=f"read capped at {max_bytes} bytes" if truncated else None,
    )

    if run_floss is None:
        return recovery

    try:
        payload = run_floss(path)
    except Exception as exc:  # a recovery failure must not lose the static pass
        logger.warning("floss on %s raised: %s", path.name, exc)
        payload = None

    if payload:
        seen = {(s.value, s.offset) for s in recovery.strings}
        for entry in parse_floss(payload):
            if (entry.value, entry.offset) not in seen:
                recovery.strings.append(entry)
                seen.add((entry.value, entry.offset))
        recovery.method = "floss"

    return recovery


def recovery_state(profile: str | None = None) -> str | None:
    """Ruleset state for the deep profile's missing emulation tier.

    A deep scan is a request for emulation-grade recovery. Getting only the
    static pass is partial coverage, not a clean result, so it is reported as a
    state the scorer degrades on rather than left invisible.
    """
    active = profile if profile is not None else os.getenv(PROFILE_ENV, "")
    if active != "deep":
        return None
    return None if floss_enabled(active) else "strings_static_only"
