"""AIPAM LLM subsystem — modular providers, prompts, and parsers.

Re-exports the public API so callers can do::

    from app.llm import OllamaProvider, render_prompt, parse_llm_response
"""

from .providers.ollama import OllamaProvider
from .parsers import parse_llm_response, repair_llm_output

__all__ = [
    "OllamaProvider",
    "parse_llm_response",
    "repair_llm_output",
]
