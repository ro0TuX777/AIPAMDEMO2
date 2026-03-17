"""
Frontier Knowledge Distillation v2 — structured task-oriented teacher distillation.

Training pipeline is on v8 GGUF (Unsloth → LoRA → GGUF → Ollama).
Distilled samples are merged into the training set at "Start Training" time.

Flow:
1. After AIPAM analyzes a PCAP, evidence bundles are built per-task
   (explain_finding, host_summary, job_summary, etc.).
2. Each bundle + task prompt is sent to a frontier teacher (GPT-5.4, etc.).
3. The teacher's response is validated against the task's Pydantic output schema.
4. Validated samples are saved as structured JSONL training data.
5. When "Start Training" is clicked, distilled data is merged into v8 GGUF training set.

Key v2 improvements:
- Task-specific prompts instead of generic chunk mirroring
- Structured evidence bundles instead of raw text
- JSON schema validation of teacher responses
- Per-task stats and rejection tracking
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ── Distilled data storage ──────────────────────────────────────────────────

DISTILL_DIR = Path(
    os.environ.get(
        "DISTILL_DATA_DIR",
        "/data/finetuning/data/distilled",
    )
)


@dataclass
class TeacherConfig:
    """Configuration for the frontier teacher model."""

    endpoint: str = ""  # e.g. https://api.openai.com/v1/chat/completions
    api_key: str = ""
    model: str = ""  # e.g. gpt-4o, claude-sonnet-4-20250514
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout_seconds: float = 120.0
    enabled: bool = False
    # Extra headers (e.g. for Anthropic: {"anthropic-version": "2023-06-01"})
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def is_configured(self) -> bool:
        return bool(self.endpoint and self.api_key and self.model)


# ── Persistent config (shared between backend + worker via JSON file) ──────

_CONFIG_FILE = DISTILL_DIR / "teacher_config.json"
_teacher_config: Optional[TeacherConfig] = None


def _load_config_from_file() -> TeacherConfig:
    """Load teacher config from the persistent JSON file, falling back to env vars."""
    if _CONFIG_FILE.exists():
        try:
            import json as _json
            data = _json.loads(_CONFIG_FILE.read_text())
            return TeacherConfig(
                endpoint=data.get("endpoint", ""),
                api_key=data.get("api_key", ""),
                model=data.get("model", ""),
                temperature=float(data.get("temperature", 0.1)),
                max_tokens=int(data.get("max_tokens", 4096)),
                timeout_seconds=float(data.get("timeout_seconds", 120)),
                enabled=bool(data.get("enabled", False)),
                extra_headers=data.get("extra_headers", {}),
            )
        except Exception as e:
            logger.warning("Failed to load teacher config from %s: %s", _CONFIG_FILE, e)
    # Fallback to env vars
    return TeacherConfig(
        endpoint=os.environ.get("TEACHER_LLM_ENDPOINT", ""),
        api_key=os.environ.get("TEACHER_LLM_API_KEY", ""),
        model=os.environ.get("TEACHER_LLM_MODEL", ""),
        temperature=float(os.environ.get("TEACHER_LLM_TEMPERATURE", "0.1")),
        max_tokens=int(os.environ.get("TEACHER_LLM_MAX_TOKENS", "4096")),
        timeout_seconds=float(os.environ.get("TEACHER_LLM_TIMEOUT", "120")),
        enabled=os.environ.get("TEACHER_LLM_ENABLED", "").lower() in ("1", "true", "yes"),
    )


def _save_config_to_file(tc: TeacherConfig) -> None:
    """Persist teacher config to JSON so the Celery worker can read it."""
    import json as _json
    DISTILL_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(_json.dumps({
        "endpoint": tc.endpoint,
        "api_key": tc.api_key,
        "model": tc.model,
        "temperature": tc.temperature,
        "max_tokens": tc.max_tokens,
        "timeout_seconds": tc.timeout_seconds,
        "enabled": tc.enabled,
        "extra_headers": tc.extra_headers,
    }, indent=2))


def get_teacher_config() -> TeacherConfig:
    """Return the current teacher config, loading from file/env on first call."""
    global _teacher_config
    if _teacher_config is None:
        _teacher_config = _load_config_from_file()
    return _teacher_config


def reload_teacher_config() -> TeacherConfig:
    """Force-reload config from disk (used by worker before each distillation)."""
    global _teacher_config
    _teacher_config = _load_config_from_file()
    return _teacher_config


def update_teacher_config(cfg: Dict[str, Any]) -> TeacherConfig:
    """Update the teacher config at runtime (from API call) and persist to disk."""
    global _teacher_config
    tc = get_teacher_config()
    for key in ("endpoint", "api_key", "model", "temperature", "max_tokens",
                "timeout_seconds", "enabled", "extra_headers"):
        if key in cfg:
            setattr(tc, key, cfg[key])
    _teacher_config = tc
    _save_config_to_file(tc)
    return tc


# ── Core distillation logic ─────────────────────────────────────────────────


async def distill_chunk(
    system_prompt: str,
    user_prompt: str,
    teacher: TeacherConfig,
) -> Optional[str]:
    """Send a single prompt to the frontier teacher and return its response."""
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {teacher.api_key}",
        **teacher.extra_headers,
    }
    # Newer models (gpt-4.1+, gpt-5+, o-series) require 'max_completion_tokens'
    # instead of the legacy 'max_tokens' parameter.
    _new_param_models = ("gpt-4.1", "gpt-5", "o1", "o3", "o4")
    use_new_param = any(teacher.model.startswith(p) for p in _new_param_models)
    token_key = "max_completion_tokens" if use_new_param else "max_tokens"

    payload = {
        "model": teacher.model,
        "temperature": teacher.temperature,
        token_key: teacher.max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        async with httpx.AsyncClient(timeout=teacher.timeout_seconds) as client:
            resp = await client.post(teacher.endpoint, json=payload, headers=headers)
            if resp.status_code != 200:
                # Log the full error body so we can diagnose
                try:
                    err_body = resp.json()
                except Exception:
                    err_body = resp.text
                logger.error(
                    "Frontier teacher HTTP %s: %s", resp.status_code, err_body
                )
                return None
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return content.strip()
    except Exception as e:
        logger.error("Frontier teacher call failed: %s", e)
        return None


def _save_training_pair(
    system_prompt: str,
    user_prompt: str,
    teacher_response: str,
    metadata: Dict[str, Any],
    validation: Optional[Dict[str, Any]] = None,
) -> Path:
    """Append a single distilled training pair to the JSONL file."""
    DISTILL_DIR.mkdir(parents=True, exist_ok=True)
    out_file = DISTILL_DIR / "distilled_train.jsonl"

    record = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": teacher_response},
        ],
        "metadata": {
            **metadata,
            "distilled_at": datetime.now(timezone.utc).isoformat(),
            "teacher_model": metadata.get("teacher_model", "unknown"),
        },
    }
    if validation:
        record["validation"] = validation
    with open(out_file, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return out_file


def _save_rejected(
    task_type: str,
    scope_id: str,
    job_id: str,
    reason: str,
    teacher_response: Optional[str] = None,
) -> None:
    """Log a rejected distillation sample for debugging."""
    rejected_dir = DISTILL_DIR / "rejected"
    rejected_dir.mkdir(parents=True, exist_ok=True)
    out_file = rejected_dir / "rejected.jsonl"
    record = {
        "task_type": task_type,
        "scope_id": scope_id,
        "job_id": job_id,
        "reason": reason,
        "teacher_response_preview": (teacher_response or "")[:500],
        "rejected_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(out_file, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _validate_teacher_response(
    raw_response: str,
    task_spec,
) -> Dict[str, Any]:
    """Validate the teacher response against the task's output schema.

    Returns:
        {"valid": True, "parsed": <model_instance>} on success
        {"valid": False, "reason": "..."} on failure
    """
    # 1. Must be valid JSON
    try:
        data = json.loads(raw_response)
    except json.JSONDecodeError as e:
        return {"valid": False, "reason": f"invalid_json: {e}"}

    # 2. Must match the Pydantic schema
    try:
        parsed = task_spec.output_schema.model_validate(data)
        return {"valid": True, "parsed": parsed}
    except Exception as e:
        return {"valid": False, "reason": f"schema_mismatch: {e}"}


async def distill_v2(
    db_session_factory,
    job_id: str,
    teacher: Optional[TeacherConfig] = None,
) -> Dict[str, Any]:
    """Run v2 structured distillation for all tasks in a job.

    This is the main entry point for post-analysis distillation.

    Args:
        db_session_factory: Callable that returns a DB session (e.g. SessionLocal).
        job_id: The job to distill.
        teacher: Teacher config (uses global if None).

    Returns:
        Stats dict with per-task counts.
    """
    from .distillation_bundles import collect_job_targets
    from .distillation_schemas import TASK_REGISTRY, TEACHER_SYSTEM_PROMPT

    if teacher is None:
        teacher = get_teacher_config()

    if not teacher.is_configured():
        return {"error": "Teacher model not configured", "distilled": 0}

    stats: Dict[str, Any] = {
        "total": 0, "distilled": 0, "failed": 0, "rejected": 0,
        "per_task": {},
    }
    t0 = time.monotonic()

    # Collect all targets from DB
    db = db_session_factory()
    try:
        targets = collect_job_targets(db, job_id)
    finally:
        db.close()

    stats["total"] = len(targets)

    for i, target in enumerate(targets):
        task_type = target["task_type"]
        scope_id = target["scope_id"]
        bundle = target["bundle"]

        spec = TASK_REGISTRY.get(task_type)
        if not spec:
            logger.warning("Unknown task type %s, skipping", task_type)
            continue

        # Initialize per-task counters
        if task_type not in stats["per_task"]:
            stats["per_task"][task_type] = {"distilled": 0, "failed": 0, "rejected": 0}

        # Build the user prompt from the template
        bundle_json = json.dumps(bundle, indent=2, default=str)
        user_prompt = spec.prompt_template.format(bundle_json=bundle_json)

        logger.info(
            "Distilling [%d/%d] task=%s scope=%s for job %s via %s",
            i + 1, len(targets), task_type, scope_id, job_id, teacher.model,
        )

        # Call the teacher
        response = await distill_chunk(TEACHER_SYSTEM_PROMPT, user_prompt, teacher)
        if not response:
            stats["failed"] += 1
            stats["per_task"][task_type]["failed"] += 1
            _save_rejected(task_type, scope_id, job_id, "teacher_no_response")
            continue

        # Validate against schema
        validation = _validate_teacher_response(response, spec)
        if not validation["valid"]:
            stats["rejected"] += 1
            stats["per_task"][task_type]["rejected"] += 1
            _save_rejected(
                task_type, scope_id, job_id,
                validation["reason"], response,
            )
            logger.warning(
                "Teacher response rejected for %s/%s: %s",
                task_type, scope_id, validation["reason"],
            )
            continue

        # Save validated training pair
        _save_training_pair(
            system_prompt=TEACHER_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            teacher_response=response,
            metadata={
                "job_id": job_id,
                "task_type": task_type,
                "scope_id": scope_id,
                "teacher_model": teacher.model,
                "schema": spec.output_schema_name,
            },
            validation={
                "schema": spec.output_schema_name,
                "valid": True,
            },
        )
        stats["distilled"] += 1
        stats["per_task"][task_type]["distilled"] += 1

    stats["elapsed_seconds"] = round(time.monotonic() - t0, 2)
    logger.info("Distillation v2 complete for job %s: %s", job_id, stats)
    return stats


def get_distill_stats() -> Dict[str, Any]:
    """Return statistics about accumulated distilled training data (v2)."""
    out_file = DISTILL_DIR / "distilled_train.jsonl"
    rejected_file = DISTILL_DIR / "rejected" / "rejected.jsonl"

    if not out_file.exists():
        return {
            "total_samples": 0,
            "file_size_mb": 0,
            "file_path": str(out_file),
            "exists": False,
            "teacher_models": [],
            "jobs_distilled": [],
            "per_task": {},
            "rejected_count": 0,
        }

    total = 0
    teacher_models: set = set()
    jobs: set = set()
    per_task: Dict[str, int] = {}

    with open(out_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                rec = json.loads(line)
                meta = rec.get("metadata", {})
                if meta.get("teacher_model"):
                    teacher_models.add(meta["teacher_model"])
                if meta.get("job_id"):
                    jobs.add(meta["job_id"])
                task_type = meta.get("task_type", "legacy")
                per_task[task_type] = per_task.get(task_type, 0) + 1
            except json.JSONDecodeError:
                continue

    # Count rejected samples
    rejected_count = 0
    if rejected_file.exists():
        with open(rejected_file) as f:
            for line in f:
                if line.strip():
                    rejected_count += 1

    size_mb = out_file.stat().st_size / (1024 * 1024)
    return {
        "total_samples": total,
        "file_size_mb": round(size_mb, 2),
        "file_path": str(out_file),
        "exists": True,
        "teacher_models": sorted(teacher_models),
        "jobs_distilled": sorted(jobs)[-20:],
        "per_task": per_task,
        "rejected_count": rejected_count,
    }


def merge_distilled_into_training(
    base_train_path: Path,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Merge distilled JSONL into the base training file for fine-tuning.

    Creates a new merged file (does not modify the original).

    Args:
        base_train_path: Existing train.jsonl file.
        output_path: Where to write merged output (defaults to merged_train.jsonl
                      next to the distilled dir).

    Returns:
        Stats about the merge.
    """
    distilled_file = DISTILL_DIR / "distilled_train.jsonl"
    if output_path is None:
        output_path = DISTILL_DIR / "merged_train.jsonl"

    base_count = 0
    distilled_count = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as out:
        # Copy base training data
        if base_train_path.exists():
            with open(base_train_path) as f:
                for line in f:
                    if line.strip():
                        out.write(line if line.endswith("\n") else line + "\n")
                        base_count += 1

        # Append distilled data (strip metadata for training)
        if distilled_file.exists():
            with open(distilled_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        # Keep only messages for training
                        train_rec = {"messages": rec["messages"]}
                        out.write(json.dumps(train_rec, ensure_ascii=False) + "\n")
                        distilled_count += 1
                    except (json.JSONDecodeError, KeyError):
                        continue

    return {
        "base_samples": base_count,
        "distilled_samples": distilled_count,
        "total_samples": base_count + distilled_count,
        "output_path": str(output_path),
    }
