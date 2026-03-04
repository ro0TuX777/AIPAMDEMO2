"""DAWN-inspired immutable ledger for AIPAM.

Provides an append-only JSONL audit trail for all pipeline events
(PCAP analysis jobs, training runs, model deployments).
Events are never mutated or deleted — only appended.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_LEDGER_DIR = Path(
    os.getenv("AIPAM_LEDGER_DIR", str(Path(__file__).resolve().parent.parent / "ledger"))
)

_write_lock = threading.Lock()


class Ledger:
    """Append-only JSONL ledger for pipeline audit trail."""

    def __init__(self, ledger_dir: Path | str | None = None) -> None:
        self._dir = Path(ledger_dir) if ledger_dir else _DEFAULT_LEDGER_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "events.jsonl"

    def log_event(
        self,
        job_id: str,
        step: str,
        status: str,
        *,
        error: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append a single event to the ledger."""
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": job_id,
            "step": step,
            "status": status,
        }
        if error:
            entry["error"] = error
        if extra:
            entry.update(extra)

        with _write_lock:
            try:
                with open(self._path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                logger.debug("Failed to write ledger event", exc_info=True)

    def get_events(
        self,
        job_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Read events from the ledger, optionally filtered by job_id."""
        events: List[Dict[str, Any]] = []
        if not self._path.exists():
            return events
        try:
            with open(self._path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                        if job_id is None or evt.get("job_id") == job_id:
                            events.append(evt)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            logger.debug("Failed to read ledger", exc_info=True)
        return events


_ledger: Optional[Ledger] = None


def get_ledger() -> Ledger:
    """Return the singleton Ledger instance."""
    global _ledger
    if _ledger is None:
        _ledger = Ledger()
    return _ledger

