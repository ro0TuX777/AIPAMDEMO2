"""Backward-compatibility shim — real implementation lives in ``scanners.binary``.

Existing callers (``bluescrub_scan_service.py``, CLI ``__main__`` block)
continue to work unchanged.
"""

from backend.app.bluescrub.vendored.scanners.binary import BinaryAnalyzer, analyze_binaries_in_directory  # noqa: F401
