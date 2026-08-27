from __future__ import annotations

from typing import Any


def build_prompt_messages(prompt: str, system_prompt: str | None = None) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    return messages


def render_simple_chat_prompt(messages: list[dict[str, str]], eos_token: str = "") -> str:
    rendered: list[str] = []
    for message in messages:
        role = message.get("role", "user")
        content = message.get("content", "")
        rendered.append(f"[{role}] {content}")
    return "\n".join(rendered).strip() + eos_token
