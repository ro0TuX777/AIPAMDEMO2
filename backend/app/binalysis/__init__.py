"""Arbitrary binary / file analysis: hashing, metadata, entropy, YARA."""

from backend.app.binalysis.engine import (
    BinaryAnalysis,
    YaraMatch,
    analyze_file,
    compile_yara_rules,
    yara_available,
)
from backend.app.binalysis.service import (
    BINARY_SENSOR,
    analyze_and_persist,
    default_rules_dir,
    persist_analysis,
)

__all__ = [
    "BinaryAnalysis",
    "YaraMatch",
    "analyze_file",
    "compile_yara_rules",
    "yara_available",
    "BINARY_SENSOR",
    "analyze_and_persist",
    "default_rules_dir",
    "persist_analysis",
]
