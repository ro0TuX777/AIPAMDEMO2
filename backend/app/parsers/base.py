"""Base parser contract for telemetry normalization.

Every parser must subclass ``BaseParser`` and implement:
  - ``name``          : unique parser identifier
  - ``version``       : semver string
  - ``supported_source_systems`` : list of source_system values it handles
  - ``can_parse(path, hint)``    : returns True if this parser can handle the file
  - ``parse(path, job_id, ...)`` : yields ``ParserResult`` objects

This contract ensures all parsers produce uniform output that the
correlator and evidence graph can consume.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from backend.app.schemas.common import EvidenceStatus, NormalizedEventType, SourceType


logger = logging.getLogger("aipam.parsers")


# ---------------------------------------------------------------------------
# Parser result — what a parser yields per record
# ---------------------------------------------------------------------------


@dataclass
class ParserResult:
    """A single normalized event produced by a parser."""

    event_type: NormalizedEventType
    timestamp: datetime
    data: dict[str, Any] = field(default_factory=dict)

    # Provenance (auto-filled by base class if not set)
    source_type: SourceType = SourceType.log_bundle
    source_system: str | None = None
    source_filename: str | None = None
    parser_name: str | None = None
    parser_version: str | None = None
    raw_ref: str | None = None

    # Evidence
    evidence_status: EvidenceStatus = EvidenceStatus.observed

    # Correlation keys (parsers should populate as many as possible)
    correlation_keys: dict[str, str] = field(default_factory=dict)

    # Optional fields
    hostname: str | None = None
    username: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    community_id: str | None = None
    session_id: str | None = None
    process_guid: str | None = None
    exercise_id: str | None = None
    tags: list[str] = field(default_factory=list)
    pcap_label: str | None = None  # phase label: "before", "during", "after", etc.


# ---------------------------------------------------------------------------
# Abstract base parser
# ---------------------------------------------------------------------------


class BaseParser(abc.ABC):
    """Abstract base class for all telemetry parsers.

    Subclass this and implement the abstract methods to create
    a parser for a specific log format.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique parser identifier, e.g. 'windows_evtx', 'linux_auth'."""
        ...

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Parser version string (semver)."""
        ...

    @property
    @abc.abstractmethod
    def supported_source_systems(self) -> list[str]:
        """Source systems this parser can handle, e.g. ['sysmon', 'windows_security']."""
        ...

    @abc.abstractmethod
    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        """Return True if this parser can handle the given file.

        Args:
            path: Path to the file to check.
            hint: Optional parser hint from the source manifest.
        """
        ...

    @abc.abstractmethod
    def parse(
        self,
        path: Path,
        job_id: str,
        source_type: SourceType = SourceType.log_bundle,
        exercise_id: str | None = None,
    ) -> Iterator[ParserResult]:
        """Parse the file and yield normalized events.

        Args:
            path: Path to the file to parse.
            job_id: The job this file belongs to.
            source_type: The source type of the bundle.
            exercise_id: Optional exercise/campaign identifier.

        Yields:
            ParserResult for each successfully parsed record.
            Invalid/malformed records should be logged and skipped.
        """
        ...

    def _fill_provenance(self, result: ParserResult, path: Path) -> ParserResult:
        """Fill in provenance fields if not already set by the parser."""
        if result.parser_name is None:
            result.parser_name = self.name
        if result.parser_version is None:
            result.parser_version = self.version
        if result.source_filename is None:
            result.source_filename = path.name
        return result

