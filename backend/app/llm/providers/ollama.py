"""Ollama LLM provider — pure HTTP transport.

Handles all communication with the Ollama (or OpenAI-compatible) API
without any prompt construction or response parsing logic.

Usage::

    provider = OllamaProvider(
        endpoint="http://ollama:11434/v1/chat/completions",
        model="aipam-cybersec-llm",
    )
    raw_text = await provider.send(messages=[
        {"role": "system", "content": "You are a forensic analyst."},
        {"role": "user",   "content": "Analyze this traffic..."},
    ])
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OllamaProvider:
    """Stateless HTTP transport for Ollama / OpenAI-compatible endpoints.

    Attributes:
        endpoint: Full URL to the chat completions endpoint.
        model: Model name to request (e.g. ``"aipam-cybersec-llm"``).
        temperature: Sampling temperature.
        max_tokens: Maximum tokens in response.
        timeout_seconds: HTTP timeout.
    """

    endpoint: str = "http://ollama:11434/v1/chat/completions"
    model: str = "aipam-cybersec-llm"
    temperature: float = 0.1
    max_tokens: int = 2000
    timeout_seconds: float = 600.0

    async def send(
        self,
        messages: List[Dict[str, str]],
        *,
        response_format: Optional[Dict[str, str]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Send a chat-completion request and return the raw content string.

        Args:
            messages: List of ``{"role": "...", "content": "..."}`` dicts.
            response_format: Optional ``{"type": "json_object"}`` etc.
            temperature: Override default temperature for this call.
            max_tokens: Override default max_tokens for this call.

        Returns:
            The ``choices[0].message.content`` string from the API.

        Raises:
            httpx.ConnectError: If the endpoint is unreachable.
            httpx.TimeoutException: If the request exceeds the timeout.
            httpx.HTTPStatusError: If the API returns an error status.
        """
        payload: Dict[str, Any] = {
            "model": self.model,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            "messages": messages,
        }
        if response_format:
            payload["response_format"] = response_format

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(self.endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()

        content = data["choices"][0]["message"]["content"]
        logger.debug("LLM response (first 200 chars): %s", content[:200])
        return content

    async def health_check(self) -> bool:
        """Check if the Ollama endpoint is reachable.

        Returns:
            True if the endpoint responds within 5 seconds.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Ollama exposes /api/tags for model listing
                # OpenAI-compatible endpoints usually accept /models
                for path in ["/api/tags", "/v1/models"]:
                    base = self.endpoint.rsplit("/v1/", 1)[0]
                    try:
                        resp = await client.get(f"{base}{path}")
                        if resp.status_code < 500:
                            return True
                    except httpx.ConnectError:
                        continue
            return False
        except Exception:
            return False
