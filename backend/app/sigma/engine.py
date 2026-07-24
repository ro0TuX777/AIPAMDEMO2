"""
Lightweight Sigma rule engine.

Supports the common subset of the Sigma specification needed for log
detection over normalized telemetry events:

  * field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``all``
  * value lists (OR) and selection maps (AND)
  * keyword selections (list of strings searched across all values)
  * conditions: identifiers, ``and`` / ``or`` / ``not``, parentheses,
    ``1 of x*`` / ``all of x*`` / ``1 of them`` / ``all of them``

This is intentionally dependency-light (PyYAML only) so it can run in the
air-gapped pipeline without the full ``pysigma`` toolchain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    level: str
    detection: dict[str, Any]
    condition: str
    logsource: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    status: str = "experimental"
    tags: list[str] = field(default_factory=list)
    source_path: str | None = None


@dataclass
class SigmaMatch:
    rule_id: str
    title: str
    level: str
    tags: list[str]
    event: dict[str, Any]


def load_rule(yaml_text: str, source_path: str | None = None) -> SigmaRule:
    """Parse a single Sigma rule from YAML text."""
    doc = yaml.safe_load(yaml_text)
    if not isinstance(doc, dict):
        raise ValueError("Sigma rule must be a YAML mapping")
    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if not condition:
        raise ValueError("Sigma rule missing detection.condition")
    return SigmaRule(
        rule_id=str(doc.get("id") or doc.get("title") or "unnamed"),
        title=str(doc.get("title") or "Untitled Sigma rule"),
        level=str(doc.get("level") or "medium").lower(),
        detection=detection,
        condition=str(condition),
        logsource=doc.get("logsource") or {},
        description=str(doc.get("description") or ""),
        status=str(doc.get("status") or "experimental"),
        tags=[str(t) for t in (doc.get("tags") or [])],
        source_path=source_path,
    )


def load_rules_from_dir(directory: Path) -> list[SigmaRule]:
    """Load every ``*.yml`` / ``*.yaml`` Sigma rule under ``directory``."""
    rules: list[SigmaRule] = []
    if not directory.exists():
        return rules
    for p in sorted(directory.rglob("*")):
        if p.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            rules.append(load_rule(p.read_text(encoding="utf-8"), source_path=str(p)))
        except (ValueError, yaml.YAMLError):
            continue
    return rules


def _to_text(value: Any) -> str:
    return "" if value is None else str(value)


def _match_scalar(event_val: Any, expected: Any, modifier: str | None) -> bool:
    """Match a single event value against an expected value + modifier."""
    ev = _to_text(event_val).lower()
    exp = _to_text(expected).lower()
    if modifier == "contains":
        return exp in ev
    if modifier == "startswith":
        return ev.startswith(exp)
    if modifier == "endswith":
        return ev.endswith(exp)
    if modifier == "re":
        try:
            return re.search(_to_text(expected), _to_text(event_val)) is not None
        except re.error:
            return False
    # Plain equality, with Sigma '*' wildcard support
    if "*" in exp:
        pattern = "^" + re.escape(exp).replace("\\*", ".*") + "$"
        return re.match(pattern, ev) is not None
    return ev == exp


def _match_field(event: dict[str, Any], key: str, expected: Any) -> bool:
    """Match one ``field|modifier: value(s)`` entry against the event."""
    parts = key.split("|")
    field_name = parts[0]
    modifiers = parts[1:]
    require_all = "all" in modifiers
    scalar_mod = next((m for m in modifiers if m in ("contains", "startswith", "endswith", "re")), None)

    event_val = event.get(field_name)
    expected_list = expected if isinstance(expected, list) else [expected]

    results = [_match_scalar(event_val, exp, scalar_mod) for exp in expected_list]
    return all(results) if require_all else any(results)


def _match_keywords(event: dict[str, Any], keywords: list[Any]) -> bool:
    """Keyword selection: each keyword searched (substring) across all values."""
    haystack = " ".join(_to_text(v) for v in event.values()).lower()
    return any(_to_text(k).lower() in haystack for k in keywords)


def _match_selection(event: dict[str, Any], selection: Any) -> bool:
    """Evaluate one named selection block against an event."""
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        # List of maps -> OR; list of scalars -> keyword search.
        if all(isinstance(item, dict) for item in selection):
            return any(_match_selection(event, item) for item in selection)
        return _match_keywords(event, selection)
    return _match_keywords(event, [selection])


def _expand_quantifier(expr: str, names: list[str]) -> str:
    """Rewrite ``1 of x*`` / ``all of them`` into boolean sub-expressions."""
    def repl(match: re.Match) -> str:
        quant, pattern = match.group(1), match.group(2)
        if pattern == "them":
            matched = list(names)
        else:
            prefix = pattern.rstrip("*")
            matched = [n for n in names if n.startswith(prefix)]
        if not matched:
            return "False"
        joiner = " or " if quant == "1" else " and "
        return "(" + joiner.join(matched) + ")"

    return re.sub(r"\b(1|all)\s+of\s+([A-Za-z0-9_*]+|them)", repl, expr)


def _eval_condition(condition: str, sel_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string given per-selection match results."""
    names = [k for k in sel_results if k != "condition"]
    expr = _expand_quantifier(condition.strip(), names)
    # Build a safe boolean namespace: only selection names + and/or/not allowed.
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr)
    for tok in tokens:
        if tok in ("and", "or", "not", "True", "False"):
            continue
        if tok not in sel_results:
            # Unknown identifier -> treat as no-match to stay safe.
            expr = re.sub(rf"\b{re.escape(tok)}\b", "False", expr)
    namespace = {k: bool(v) for k, v in sel_results.items()}
    try:
        return bool(eval(expr, {"__builtins__": {}}, namespace))  # noqa: S307
    except Exception:
        return False


def match_event(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True if ``event`` satisfies ``rule``'s detection logic."""
    sel_results: dict[str, bool] = {}
    for name, block in rule.detection.items():
        if name == "condition":
            continue
        sel_results[name] = _match_selection(event, block)
    return _eval_condition(rule.condition, sel_results)


def run_rules(
    rules: list[SigmaRule], events: list[dict[str, Any]]
) -> list[SigmaMatch]:
    """Evaluate every rule against every event; return all matches."""
    matches: list[SigmaMatch] = []
    for event in events:
        for rule in rules:
            if match_event(rule, event):
                matches.append(
                    SigmaMatch(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        level=rule.level,
                        tags=rule.tags,
                        event=event,
                    )
                )
    return matches
