"""Prompt rendering — loads Jinja2 templates from the prompts/ directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader

_PROMPTS_DIR = Path(__file__).parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(str(_PROMPTS_DIR)),
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_prompt(template_name: str, **kwargs: Any) -> str:
    """Render a Jinja2 prompt template.

    Args:
        template_name: Filename in ``app/llm/prompts/`` (e.g. ``"triage.j2"``).
        **kwargs: Template variables.

    Returns:
        Rendered prompt string.
    """
    template = _env.get_template(template_name)
    return template.render(**kwargs)


def get_system_prompt() -> str:
    """Return the rendered system prompt."""
    return render_prompt("system.j2")
