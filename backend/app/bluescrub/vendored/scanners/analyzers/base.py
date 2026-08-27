"""
BaseAnalyzer — abstract base class for all BlueScrub pattern-based analyzers.

Subclasses define *what* to look for (patterns, extensions, skip-dirs);
the base class handles *how* to walk the tree and collect findings.
"""

import os
import re
from abc import ABC, abstractmethod


import logging

logger = logging.getLogger(__name__)
# Directories skipped by every analyzer by default.
DEFAULT_SKIP_DIRS = frozenset({
    'analysis_results', 'dependency-check-report',
    '__pycache__', '.git', 'node_modules',
})


class BaseAnalyzer(ABC):
    """Walk a directory tree, read source files, and apply regex patterns.

    Subclasses must implement ``analyze_file(file_path, content)`` which
    returns a list of finding dicts (or an empty list).
    """

    #: File extensions this analyzer cares about.
    #: Override in subclasses.  ``None`` means "all text files".
    EXTENSIONS: tuple[str, ...] | None = (
        '.py', '.js', '.ts', '.rb', '.go',
        '.c', '.cpp', '.h', '.hpp', '.sh', '.bash',
    )

    #: Extra directories to skip (merged with DEFAULT_SKIP_DIRS).
    EXTRA_SKIP_DIRS: frozenset[str] = frozenset()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, directory: str) -> list[dict]:
        """Walk *directory* and return aggregated findings."""
        skip = DEFAULT_SKIP_DIRS | self.EXTRA_SKIP_DIRS
        findings: list[dict] = []

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                if self.EXTENSIONS and not fname.endswith(self.EXTENSIONS):
                    continue
                file_path = os.path.join(root, fname)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                except IOError:
                    continue
                findings.extend(self.analyze_file(file_path, content, directory))

        self._log_summary(findings)
        return findings

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def analyze_file(self, file_path: str, content: str, root_directory: str) -> list[dict]:
        """Return a list of finding dicts for a single file.

        Parameters
        ----------
        file_path : str
            Absolute path to the file being analyzed.
        content : str
            Full text content of the file.
        root_directory : str
            The top-level directory passed to ``run()``.
        """
        ...

    # ------------------------------------------------------------------
    # Helpers available to subclasses
    # ------------------------------------------------------------------

    #: Human-readable label used for summary logging.
    LABEL: str = "Analyzer"

    def _log_summary(self, findings: list[dict]) -> None:
        logger.info("%s: Found %d potential issues", self.LABEL, len(findings))

    @staticmethod
    def _line_number(content: str, offset: int) -> int:
        """Return the 1-based line number for a character *offset*."""
        return content[:offset].count('\n') + 1

    @staticmethod
    def _match_patterns(
        content: str,
        patterns: list[tuple[str, str]],
        flags: int = re.IGNORECASE | re.MULTILINE,
    ):
        """Yield ``(match, description)`` for every regex hit in *content*."""
        for pattern, description in patterns:
            for match in re.finditer(pattern, content, flags):
                yield match, description

    @staticmethod
    def _match_categorized_patterns(
        content: str,
        pattern_map: dict[str, list[str]],
        flags: int = re.MULTILINE,
    ):
        """Yield ``(match, category)`` for a ``{category: [patterns]}`` map."""
        for category, patterns in pattern_map.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, flags):
                    yield match, category

