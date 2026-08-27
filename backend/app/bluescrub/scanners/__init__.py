"""Scanner adapters. Each turns one tool's output into raw normalized findings."""

from __future__ import annotations

from backend.app.bluescrub.scanners.base import ScannerOutcome, ScannerSpec

__all__ = ["ScannerOutcome", "ScannerSpec"]
