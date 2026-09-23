"""RE-Feasibility signals — how cheaply an artifact gives up its secrets.

The scoring side of this pillar has existed since Sprint 3: `score_re_pillar`,
`ReSignal`, the weights, and the invariant that an unmeasured signal's weight
is *reported and excluded* rather than redistributed across the others. What
never existed was anything to feed it. The service passed `re_signals=[]`, so
the pillar read `not_assessed` on every scan ever run, and an OPSEC review of a
compiled artifact found the second question anyone asks — how hard is this to
reverse — simply unanswered.

Seven of the eight signals turned out to be derivable from measurements the
pipeline already takes. Only decompilation needs a tool that is not here.

**The gauge runs the opposite way to the others.** 1.0 means *cheap to
reverse*, which is bad OPSEC. A debug build with full DWARF scores 1.0 on
symbols; a stripped binary scores near zero. The pillar label says so
explicitly because a reader who assumes "high is good" reads every number
backwards.

**Decompilation is reported unavailable, not guessed.** Ghidra is Sprint 9.
Its 0.15 is excluded from the denominator rather than spread over the rest,
which is why coverage reads 0.85 and the pillar is `degraded` rather than
`assessed` — and why `overall` stays `None`, since completeness needs every
pillar at 0.9. That is the design working, not a gap to paper over.

**Multiple artifacts take the most reversible, not the average.** An attacker
reverses the easiest one in the package and reads the rest from what it tells
them; averaging would let a pile of stripped binaries hide one debug build.

Reference: docs/BLUESCRUB_SCORING_SPEC.md §4 ·
docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §4.1
"""

from __future__ import annotations

from backend.app.pipeline.outcomes import PROPAGATE_ERRORS, public_failure

import logging
from pathlib import Path

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.models import CanonicalGroup
from backend.app.bluescrub.pillars import IssueFamily
from backend.app.bluescrub.scoring import ReSignal

logger = logging.getLogger(__name__)

#: Entropy anchors from the plan's signal table: below 6.5 is unpacked, above
#: 7.2 is packed or encrypted. Measured on ordinary binaries — ls 5.93, python
#: 5.62, a PE stub 6.13 — all comfortably under the lower anchor.
_ENTROPY_CLEAR = 6.5
_ENTROPY_PACKED = 7.2

#: Recoverable strings per KiB, counting only *substantial* ones.
#:
#: The length floor is the whole point. Random bytes throw off short accidental
#: ASCII runs at a great rate — a 60 KiB block of noise yielded 12.9 four-char
#: runs per KiB, more than any real binary here, so a packed artifact scored as
#: the most readable thing on the bench. At eight characters the same block
#: yields 0.32/KiB while ordinary binaries (ls, bash, curl, python, grep, tar,
#: sed, gzip) hold 2.5–5.1. Eight characters is where accidental runs die out
#: and deliberate text survives.
_MIN_SUBSTANTIAL = 8
_STRINGS_RICH = 4.0      # median of those eight binaries
_STRINGS_BARREN = 0.5    # below anything that carries real text

#: Named imports. A rich table names the API surface and does much of an
#: analyst's work; `ls` has 109, a PE stub 81, a stripped implant 5.
_IMPORTS_RICH = 50.0

#: Symbol count standing in for how much of the symbol table survived. Capped
#: below 1.0 because surviving symbols are never as generous as debug info.
_SYMBOLS_RICH = 200.0
_SYMBOLS_CEILING = 0.6

#: Markers of a managed or high-level runtime, which reverses far more cheaply
#: than hand-written native code: bytecode decompiles, native code does not.
_MANAGED_MARKERS: tuple[str, ...] = (
    "go build id", "go1.", "runtime.main",          # Go
    "mscoree.dll", ".net framework", "mscorlib",    # .NET
    "pyinstaller", "python3", "py_initialize",      # Python
    "java/lang", "jvm.dll",                         # Java/JVM
    "rustc/", "core::panicking",                    # Rust with symbols
)
_NATIVE_FLOOR = 0.15

#: Families that say the artifact resists analysis.
_ANTI_ANALYSIS: frozenset[IssueFamily] = frozenset({
    IssueFamily.anti_analysis,
    IssueFamily.packer_detected,
})

#: Families that say its configuration is sitting in plain sight.
_PLAINTEXT_CONFIG: frozenset[IssueFamily] = frozenset({
    IssueFamily.hardcoded_c2,
    IssueFamily.hardcoded_secret,
    IssueFamily.credential_exposure,
    IssueFamily.attribution_infrastructure,
})
#: Absence of plaintext config is weak evidence, not proof of encryption: the
#: artifact may simply have no configuration. Scored low rather than zero.
_NO_PLAINTEXT_CONFIG = 0.3


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _scale(value: float, cheap: float, hard: float) -> float:
    """Normalise so `cheap` maps to 1.0 and `hard` to 0.0."""
    if cheap == hard:
        return 0.0
    return _clamp((value - hard) / (cheap - hard))


def entropy_signal(entropy: float) -> float:
    """Low entropy reverses cheaply; high entropy means packed or encrypted."""
    return _scale(entropy, _ENTROPY_CLEAR, _ENTROPY_PACKED)


def string_yield_signal(strings: int, kib: float) -> float:
    """`strings` counts only those at or above the substantial-length floor."""
    return _scale(strings / max(kib, 1.0), _STRINGS_RICH, _STRINGS_BARREN)


def import_signal(imports: int) -> float:
    return _clamp(imports / _IMPORTS_RICH)


def symbol_signal(has_debug_info: bool, symbols: int) -> float:
    """Debug info is the cheapest case there is; surviving symbols are less."""
    if has_debug_info:
        return 1.0
    return _SYMBOLS_CEILING * _clamp(symbols / _SYMBOLS_RICH)


def runtime_signal(text: str) -> float:
    lowered = text.lower()
    return 1.0 if any(m in lowered for m in _MANAGED_MARKERS) else _NATIVE_FLOOR


def _artifact_facts(path: Path) -> dict | None:
    """Everything one artifact contributes, or None if it cannot be read."""
    from backend.app.binalysis.engine import _compute_entropy

    recovery = binstrings.recover(path)
    if not recovery.sha256:
        return None

    try:
        size_kib = max(1.0, path.stat().st_size / 1024)
    except OSError:
        return None

    facts = {
        "entropy": _compute_entropy(path),
        "strings": sum(1 for s in recovery.strings
                       if len(s.value) >= _MIN_SUBSTANTIAL),
        "kib": size_kib,
        "text": "\n".join(s.value for s in recovery.strings[:20000]),
        "symbols": 0,
        "imports": 0,
        "debug": False,
        "parsed": False,
    }

    try:
        import lief

        lief.logging.disable()
        binary = lief.parse(str(path))
    except PROPAGATE_ERRORS:
        raise
    except Exception as exc:  # pragma: no cover - lief is a declared dependency
        logger.info("lief could not parse %s: %s", path.name, public_failure(exc))
        return facts

    if binary is None:
        return facts

    facts["parsed"] = True
    facts["symbols"] = len(list(getattr(binary, "symbols", []) or []))
    facts["imports"] = len(list(getattr(binary, "imported_functions", []) or []))
    names = [getattr(s, "name", "") or "" for s in getattr(binary, "sections", [])]
    facts["debug"] = any(
        n.startswith(".debug") or n in (".symtab", ".stab", ".pdb") for n in names
    )
    return facts


def compute(source_root: Path, groups: list[CanonicalGroup]) -> list[ReSignal]:
    """Measure every signal this deployment can, and report the rest as absent."""
    from backend.app.bluescrub.scanners.dirty_word import binary_paths

    facts = [
        f for f in (_artifact_facts(source_root / rel)
                    for rel in sorted(binary_paths(source_root)))
        if f is not None
    ]

    if not facts:
        # No binary to assess. Not a zero — a zero would claim the artifact is
        # maximally hard to reverse, which is the opposite of unknown.
        absent = "no binary artifact to assess"
        return [
            ReSignal(signal=name, normalized=None, reason=absent)
            for name in ("symbols", "packing", "string_yield", "import_table",
                         "runtime_language", "anti_analysis", "config_exposure",
                         "decompilation")
        ]

    # The easiest artifact sets the effort: an attacker reverses that one and
    # reads the others from what it tells them.
    best = max
    families = {g.issue_family for g in groups}

    signals = [
        ReSignal("symbols", best(symbol_signal(f["debug"], f["symbols"]) for f in facts)),
        ReSignal("packing", best(entropy_signal(f["entropy"]) for f in facts)),
        ReSignal("string_yield",
                 best(string_yield_signal(f["strings"], f["kib"]) for f in facts)),
        ReSignal("runtime_language", best(runtime_signal(f["text"]) for f in facts)),
        ReSignal("anti_analysis", 0.0 if families & _ANTI_ANALYSIS else 1.0),
        ReSignal("config_exposure",
                 1.0 if families & _PLAINTEXT_CONFIG else _NO_PLAINTEXT_CONFIG),
        ReSignal(
            "decompilation", None,
            reason="Ghidra headless is not available; decompilation is Sprint 9",
        ),
    ]

    if any(f["parsed"] for f in facts):
        signals.append(
            ReSignal("import_table", best(import_signal(f["imports"]) for f in facts))
        )
    else:
        signals.append(ReSignal(
            "import_table", None,
            reason="no artifact could be parsed for its import table",
        ))

    return signals
