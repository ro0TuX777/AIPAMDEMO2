"""AIPAM's resilient HTTP boundary for its dedicated MNEMOS service."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import requests

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT_SECONDS = 5.0


class MnemosBoundaryError(RuntimeError):
    """MNEMOS failed to provide a valid search response."""


class MnemosBoundaryClient:
    """Call MNEMOS without letting a remote outage remove AIPAM's local memory."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        collection: str = "aipam_forensic_findings",
        request: Callable[..., Any] = requests.request,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._collection = collection
        self._request = request

    def index(self, documents: list[dict[str, Any]]) -> int | None:
        """Return the remote write count, or ``None`` when MNEMOS is unavailable."""
        response = self._call("POST", "/v1/mnemos/index", {"documents": documents})
        if response is None or response.get("status") != "healthy":
            return None
        result = response.get("result")
        if not isinstance(result, dict):
            return None
        indexed = result.get("indexed")
        return indexed if isinstance(indexed, int) else None

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Return normalized evidence hits or raise for any failed search contract."""
        payload: dict[str, Any] = {"query": query, "top_k": top_k}
        # MNEMOS flattens application metadata into Qdrant payload fields and
        # translates API filters of the form ``metadata.<key>`` to those fields.
        scoped_filters = {"metadata.collection": self._collection}
        if filters:
            scoped_filters.update(filters)
        payload["filters"] = scoped_filters
        response = self._call("POST", "/v1/mnemos/search", payload)
        if response.get("status") != "healthy":
            raise MnemosBoundaryError("MNEMOS search response was not healthy")

        raw_hits = response.get("results")
        if not isinstance(raw_hits, list):
            raise MnemosBoundaryError("MNEMOS search response did not contain results")

        hits: list[dict[str, Any]] = []
        for raw_hit in raw_hits:
            if not isinstance(raw_hit, dict):
                raise MnemosBoundaryError("MNEMOS search result was not an object")
            engram = raw_hit.get("engram")
            if not isinstance(engram, dict):
                raise MnemosBoundaryError("MNEMOS search result did not contain an engram")
            content = engram.get("content")
            metadata = engram.get("metadata")
            score = raw_hit.get("score")
            if not isinstance(content, str):
                raise MnemosBoundaryError("MNEMOS search result content was not text")
            if not isinstance(metadata, dict):
                raise MnemosBoundaryError("MNEMOS search result metadata was not an object")
            if not isinstance(score, (int, float)):
                raise MnemosBoundaryError("MNEMOS search result score was not numeric")
            relevance = float(score)
            hits.append(
                {
                    "document": content,
                    "metadata": metadata,
                    "relevance": relevance,
                    "distance": round(max(0.0, 1.0 - relevance), 6),
                    "evidence": raw_hit.get("evidence"),
                }
            )
        return hits

    def _call(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            response = self._request(
                method,
                f"{self._base_url}{path}",
                headers=headers,
                json=payload,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict):
                raise MnemosBoundaryError("MNEMOS response was not a JSON object")
            return body
        except MnemosBoundaryError:
            raise
        except Exception as exc:
            logger.warning("MNEMOS request %s %s failed", method, path)
            raise MnemosBoundaryError("MNEMOS request failed") from exc


def get_mnemos_client() -> MnemosBoundaryClient | None:
    """Create a configured client only when the AIPAM MNEMOS feature is enabled."""
    from backend.app.config_v2 import get_settings

    settings = get_settings()
    if not settings.mnemos_enabled:
        return None
    return MnemosBoundaryClient(settings.mnemos_base_url, token=settings.mnemos_token)
