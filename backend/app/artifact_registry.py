"""DAWN-inspired artifact registry for AIPAM.

Tracks SHA-256 digests and metadata for all pipeline artifacts
(PCAPs, model checkpoints, analysis results) to ensure provenance
and reproducibility.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_REGISTRY_DIR = Path(
    os.getenv("AIPAM_REGISTRY_DIR", str(Path(__file__).resolve().parent.parent / "artifact_registry"))
)

_index_lock = threading.Lock()


def sha256_file(path: str | Path, chunk_size: int = 8192) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


class ArtifactRegistry:
    """JSON-file-backed artifact registry."""

    def __init__(self, registry_dir: Path | str | None = None) -> None:
        self._dir = Path(registry_dir) if registry_dir else _DEFAULT_REGISTRY_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._dir / "index.json"

    def _load_index(self) -> Dict[str, Any]:
        if not self._index_path.exists():
            return {}
        try:
            with open(self._index_path) as f:
                return json.load(f)
        except Exception:
            logger.debug("Failed to load artifact index", exc_info=True)
            return {}

    def _save_index(self, index: Dict[str, Any]) -> None:
        try:
            with open(self._index_path, "w") as f:
                json.dump(index, f, indent=2)
        except Exception:
            logger.debug("Failed to save artifact index", exc_info=True)

    def register(self, key: str, **kwargs: Any) -> None:
        """Register an artifact with arbitrary metadata."""
        with _index_lock:
            index = self._load_index()
            index[key] = kwargs
            self._save_index(index)

    def lookup(self, key: str) -> Optional[Dict[str, Any]]:
        """Look up an artifact by key."""
        index = self._load_index()
        return index.get(key)

    def list_artifacts(self, artifact_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all artifacts, optionally filtered by type."""
        index = self._load_index()
        results = []
        for key, meta in index.items():
            if artifact_type is None or meta.get("artifact_type") == artifact_type:
                results.append({"key": key, **meta})
        return results


_registry: Optional[ArtifactRegistry] = None


def get_registry() -> ArtifactRegistry:
    """Return the singleton ArtifactRegistry instance."""
    global _registry
    if _registry is None:
        _registry = ArtifactRegistry()
    return _registry

