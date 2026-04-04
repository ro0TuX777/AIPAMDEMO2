"""Parser registry — discovers and manages telemetry parsers.

The registry holds all registered parser instances and provides
lookup by source_system or file-level auto-detection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.app.parsers.base import BaseParser

logger = logging.getLogger("aipam.parsers.registry")


class ParserRegistry:
    """Central registry of all telemetry parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, "BaseParser"] = {}

    def register(self, parser: "BaseParser") -> None:
        """Register a parser instance."""
        if parser.name in self._parsers:
            logger.warning("Parser '%s' already registered, overwriting", parser.name)
        self._parsers[parser.name] = parser
        logger.info(
            "Registered parser: %s v%s (systems: %s)",
            parser.name,
            parser.version,
            ", ".join(parser.supported_source_systems),
        )

    def get(self, name: str) -> "BaseParser | None":
        """Get a parser by name."""
        return self._parsers.get(name)

    def find_by_source_system(self, source_system: str) -> list["BaseParser"]:
        """Find all parsers that support a given source system."""
        return [
            p for p in self._parsers.values()
            if source_system in p.supported_source_systems
        ]

    def find_for_file(self, path: Path, hint: str | None = None) -> "BaseParser | None":
        """Find the best parser for a given file.

        If a hint is provided, try that parser first.
        Otherwise, ask each registered parser if it can handle the file.
        """
        # Try hint first
        if hint and hint in self._parsers:
            parser = self._parsers[hint]
            if parser.can_parse(path, hint=hint):
                return parser

        # Auto-detect
        for parser in self._parsers.values():
            try:
                if parser.can_parse(path, hint=hint):
                    return parser
            except Exception:
                logger.debug("Parser '%s' raised during can_parse for %s", parser.name, path)
                continue

        return None

    @property
    def registered_parsers(self) -> list[str]:
        """Return names of all registered parsers."""
        return list(self._parsers.keys())

    def __len__(self) -> int:
        return len(self._parsers)

    def __contains__(self, name: str) -> bool:
        return name in self._parsers


# Module-level singleton
_default_registry = ParserRegistry()


def get_parser_registry() -> ParserRegistry:
    """Get the default parser registry singleton."""
    return _default_registry

