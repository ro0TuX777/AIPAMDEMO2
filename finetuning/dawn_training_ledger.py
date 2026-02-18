#!/usr/bin/env python3
"""
DAWN Training Audit Ledger — Immutable JSONL logging for AIPAM fine-tuning runs.

Every training event (start, complete, fail) is appended as a single JSON line to
`dawn_training_ledger.jsonl`. Each entry includes a SHA-256 config_hash that
uniquely fingerprints the training configuration for reproducibility audits.

This satisfies the DAWN V1 (Audit Integrity) constitutional requirement.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Ledger lives next to the training scripts
LEDGER_PATH = Path(__file__).parent / "dawn_training_ledger.jsonl"


def compute_config_hash(config: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hash of the training configuration.

    Keys are sorted, and the JSON is serialized with consistent formatting
    to ensure the same config always produces the same hash.

    Args:
        config: Dictionary of training parameters.

    Returns:
        Hex-encoded SHA-256 hash prefixed with 'sha256:'.
    """
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def log_training_event(
    event_type: str,
    config: Dict[str, Any],
    metrics: Optional[Dict[str, Any]] = None,
    ledger_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Append an immutable training event to the DAWN ledger.

    Args:
        event_type: One of 'orpo_training_start', 'orpo_training_complete',
                    'orpo_training_failed', 'sft_training_start', etc.
        config: Full training configuration dictionary.
        metrics: Optional training metrics (loss, accuracy, etc.).
        ledger_path: Override default ledger file path (for testing).

    Returns:
        The ledger entry that was written.
    """
    target = ledger_path or LEDGER_PATH
    config_hash = compute_config_hash(config)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "config_hash": config_hash,
        "random_seed": config.get("random_seed", config.get("seed")),
        "base_model": config.get("base_model"),
        "dataset_path": config.get("dataset_path"),
        "dataset_samples": config.get("dataset_samples"),
        "lora_r": config.get("lora_r"),
        "lora_alpha": config.get("lora_alpha"),
        "epochs": config.get("epochs"),
        "learning_rate": config.get("learning_rate"),
        "batch_size": config.get("batch_size"),
        "max_seq_length": config.get("max_seq_length"),
        "trainer_type": config.get("trainer_type", "ORPOTrainer"),
    }

    # Add ORPO-specific fields
    if "beta" in config:
        entry["beta"] = config["beta"]

    # Add completion metrics if provided
    if metrics:
        entry["metrics"] = metrics

    # Append-only write (immutable ledger)
    with open(target, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")

    return entry


def read_ledger(ledger_path: Optional[Path] = None):
    """Read all entries from the DAWN training ledger.

    Args:
        ledger_path: Override default ledger file path.

    Returns:
        List of ledger entry dictionaries.
    """
    target = ledger_path or LEDGER_PATH
    if not target.exists():
        return []

    entries = []
    with open(target) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


if __name__ == "__main__":
    # Quick self-test
    test_config = {
        "random_seed": 3407,
        "base_model": "unsloth/llama-3.1-8b-bnb-4bit",
        "dataset_path": "data/v6-orpo/train.jsonl",
        "dataset_samples": 0,
        "lora_r": 128,
        "lora_alpha": 128,
        "epochs": 3,
        "learning_rate": 2e-4,
        "batch_size": 1,
        "max_seq_length": 8192,
        "trainer_type": "ORPOTrainer",
        "beta": 0.1,
    }

    h = compute_config_hash(test_config)
    print(f"Config hash: {h}")

    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    entry = log_training_event("self_test", test_config, ledger_path=tmp_path)
    print(f"Ledger entry: {json.dumps(entry, indent=2)}")

    entries = read_ledger(tmp_path)
    assert len(entries) == 1
    assert entries[0]["config_hash"] == h
    assert entries[0]["random_seed"] == 3407
    print("✓ DAWN Training Ledger self-test passed")

    # Cleanup
    tmp_path.unlink()
