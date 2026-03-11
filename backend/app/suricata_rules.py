from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger("aipam.suricata_rules")

INSTALLED_SURICATA_RULES_CANDIDATES = (
    Path("/var/lib/suricata/rules/suricata.rules"),
    Path("/etc/suricata/rules/suricata.rules"),
)

_RUNTIME_DIR_NAME = ".runtime"
_RUNTIME_BUNDLE_NAME = "aipam-ui.rules"


def _find_installed_suricata_rules() -> Path | None:
    for candidate in INSTALLED_SURICATA_RULES_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def ensure_suricata_rules_seeded(rules_dir: Path) -> list[Path]:
    """Ensure the UI-managed rules directory exists and has at least one rules file."""
    rules_dir.mkdir(parents=True, exist_ok=True)
    existing_rules = sorted(path for path in rules_dir.glob("*.rules") if path.is_file())
    if existing_rules:
        return existing_rules

    installed_rules = _find_installed_suricata_rules()
    if not installed_rules:
        logger.warning("Suricata rules: no installed rules found to seed %s", rules_dir)
        return []

    seeded_path = rules_dir / installed_rules.name
    shutil.copyfile(installed_rules, seeded_path)
    logger.info("Suricata rules: seeded %s from %s", seeded_path, installed_rules)
    return [seeded_path]


def build_runtime_suricata_bundle(rules_dir: Path) -> Path | None:
    """Build a single runtime rules bundle from UI-managed Suricata rule files."""
    rule_files = ensure_suricata_rules_seeded(rules_dir)
    if not rule_files:
        return None

    runtime_dir = rules_dir / _RUNTIME_DIR_NAME
    runtime_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = runtime_dir / _RUNTIME_BUNDLE_NAME

    with bundle_path.open("w", encoding="utf-8") as bundle:
        for index, rule_file in enumerate(rule_files):
            if index:
                bundle.write("\n")
            bundle.write(f"# Source: {rule_file.name}\n")
            content = rule_file.read_text(encoding="utf-8", errors="replace")
            bundle.write(content)
            if content and not content.endswith("\n"):
                bundle.write("\n")

    logger.info(
        "Suricata rules: built runtime bundle %s from %d file(s)",
        bundle_path,
        len(rule_files),
    )
    return bundle_path