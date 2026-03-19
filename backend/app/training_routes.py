"""
Training Intelligence API Routes — Phase 6 Training Dashboard

Provides endpoints to read the DAWN Training Ledger and return
aggregated training statistics for the web UI.
"""

import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v1/training", tags=["training"])

# Ledger path resolution — works in Docker (/data/finetuning/) and on host

_LEDGER_CANDIDATES = [
    Path("/data/dawn_training_ledger.jsonl"),                               # Docker writable volume
    Path("/data/finetuning/dawn_training_ledger.jsonl"),                    # Docker mount (legacy)
    Path(__file__).resolve().parents[2] / "finetuning" / "dawn_training_ledger.jsonl",  # host dev
    Path(__file__).resolve().parents[2] / "finetuning" / "dawn_training_ledger_host.jsonl",  # host trainer
]

# Add explicit override if set
_env_override = os.environ.get("DAWN_LEDGER_PATH", "").strip()
if _env_override:
    _LEDGER_CANDIDATES.insert(0, Path(_env_override))

def _find_ledger() -> Path:
    for p in _LEDGER_CANDIDATES:
        if p.is_file():
            return p
    # Default to writable Docker volume path
    return Path("/data/dawn_training_ledger.jsonl")

LEDGER_PATH = _find_ledger()


def _read_ledger() -> List[Dict[str, Any]]:
    """Read all entries from ALL DAWN training ledger paths and merge them."""
    entries = []
    seen_paths = set()
    for candidate in _LEDGER_CANDIDATES:
        if candidate.exists() and str(candidate) not in seen_paths:
            seen_paths.add(str(candidate))
            with open(candidate) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
    return entries


# Phase label mapping
PHASE_LABELS = {
    "orpo_training": "6.1 — ORPO Alignment",
    "sft_training": "6.0 — SFT Baseline",
    "session_training": "6.2 — Session-Level IR",
    "distill_student_training": "6.3 — Distillation (Edge)",
    "distill_gguf_export": "6.3 — GGUF Export",
    "purple_team_augment": "6.4 — Self-Healing Loop",
    "delta_training": "6.4 — Delta LoRA",
}


def _classify_phase(event_type: str) -> str:
    """Map event_type to phase label."""
    for prefix, label in PHASE_LABELS.items():
        if event_type.startswith(prefix):
            return label
    return "Unknown"


def _classify_status(event_type: str) -> str:
    """Map event_type to status."""
    if "complete" in event_type or "export" in event_type:
        return "completed"
    elif "fail" in event_type:
        return "failed"
    elif "start" in event_type:
        return "running"
    return "info"


@router.get("/ledger")
async def get_training_ledger():
    """Return all DAWN training ledger entries."""
    entries = _read_ledger()

    # Enrich with phase and status labels
    enriched = []
    for entry in entries:
        enriched.append({
            **entry,
            "phase_label": _classify_phase(entry.get("event_type", "")),
            "status": _classify_status(entry.get("event_type", "")),
        })

    return JSONResponse(content={
        "entries": enriched,
        "total": len(enriched),
        "ledger_path": str(LEDGER_PATH),
        "ledger_exists": LEDGER_PATH.exists(),
    })


@router.get("/summary")
async def get_training_summary():
    """Return aggregated training statistics."""
    entries = _read_ledger()

    if not entries:
        return JSONResponse(content={
            "has_data": False,
            "latest_run": None,
            "phase_counts": {},
            "models": [],
            "self_healing": None,
            "total_events": 0,
        })

    # Latest completed run
    completed = [
        e for e in entries
        if "complete" in e.get("event_type", "")
    ]
    latest_run = completed[-1] if completed else None

    # Phase counts
    phase_counts: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        phase = _classify_phase(entry.get("event_type", ""))
        if phase not in phase_counts:
            phase_counts[phase] = {
                "total_events": 0,
                "completed": 0,
                "failed": 0,
                "latest_timestamp": None,
                "latest_loss": None,
            }
        pc = phase_counts[phase]
        pc["total_events"] += 1

        status = _classify_status(entry.get("event_type", ""))
        if status == "completed":
            pc["completed"] += 1
        elif status == "failed":
            pc["failed"] += 1

        pc["latest_timestamp"] = entry.get("timestamp")

        metrics = entry.get("metrics", {})
        if metrics and "train_loss" in metrics:
            pc["latest_loss"] = metrics["train_loss"]

    # Models used
    models_seen = set()
    for entry in entries:
        base = entry.get("base_model")
        if base:
            models_seen.add(base)
        student = entry.get("config", {}).get("student_model") if isinstance(entry.get("config"), dict) else None
        if student:
            models_seen.add(student)

    # Peak VRAM
    peak_vram = None
    for entry in entries:
        metrics = entry.get("metrics", {})
        if metrics and "peak_vram_gb" in metrics:
            vram = metrics["peak_vram_gb"]
            if peak_vram is None or vram > peak_vram:
                peak_vram = vram

    # Self-healing stats
    self_healing = None
    heal_entries = [
        e for e in entries
        if e.get("event_type", "").startswith("purple_team_augment")
    ]
    if heal_entries:
        total_pcaps = sum(
            e.get("metrics", {}).get("total_pcaps", 0)
            if isinstance(e.get("metrics"), dict) else 0
            for e in heal_entries
        )
        families = set()
        for e in heal_entries:
            m = e.get("metrics", {}) if isinstance(e.get("metrics"), dict) else {}
            for fam in m.get("families", []):
                families.add(fam)

        self_healing = {
            "runs": len(heal_entries),
            "total_synthetic_pcaps": total_pcaps,
            "families_augmented": sorted(families),
            "latest_timestamp": heal_entries[-1].get("timestamp"),
        }

    # Active model (latest successful)
    active_model = None
    if latest_run:
        active_model = {
            "name": latest_run.get("base_model", "Unknown"),
            "phase": _classify_phase(latest_run.get("event_type", "")),
            "config_hash": latest_run.get("config_hash"),
            "context_window": latest_run.get("max_seq_length"),
            "lora_r": latest_run.get("lora_r"),
            "lora_alpha": latest_run.get("lora_alpha"),
            "trained_at": latest_run.get("timestamp"),
            "loss": latest_run.get("metrics", {}).get("train_loss")
            if isinstance(latest_run.get("metrics"), dict) else None,
            "dawn_seed": latest_run.get("random_seed"),
        }

    return JSONResponse(content={
        "has_data": True,
        "latest_run": latest_run,
        "active_model": active_model,
        "phase_counts": phase_counts,
        "models": sorted(models_seen),
        "peak_vram_gb": peak_vram,
        "self_healing": self_healing,
        "total_events": len(entries),
    })


@router.get("/config")
async def get_training_config():
    """Return the current fine-tuning configuration from settings."""
    vals: dict = {}
    try:
        from .database import get_session
        from .db_models import SettingsDB

        with get_session() as session:
            settings = session.get(SettingsDB, 1)
            vals = settings.values if settings else {}
    except Exception:
        # V1 database may not be available in V2 deployments
        pass

    return JSONResponse(content={
        "base_model": vals.get("finetune_base_model"),
        "dataset_url": vals.get("finetune_dataset_url"),
        "lora_rank": vals.get("finetune_lora_rank"),
        "learning_rate": vals.get("finetune_learning_rate"),
        "max_seq_length": vals.get("finetune_max_seq_length"),
        "configured": bool(vals.get("finetune_base_model")),
    })


@router.post("/start")
@router.post("/jobs")
async def start_training_job():
    """Trigger a new fine-tuning job using current settings."""
    import urllib.request
    import urllib.error

    os.path.exists("/.dockerenv")

    # Pre-flight: verify host trainer is reachable
    host_trainer_url = os.environ.get("HOST_TRAINER_URL", "http://host.docker.internal:8002")
    launcher_url = os.environ.get("HOST_LAUNCHER_URL", "http://host.docker.internal:8003")

    trainer_ok = False
    try:
        req = urllib.request.Request(f"{host_trainer_url}/health", method="GET")
        urllib.request.urlopen(req, timeout=3)
        trainer_ok = True
    except Exception:
        pass

    # If not running, try to auto-start via the launcher daemon
    if not trainer_ok:
        try:
            req = urllib.request.Request(
                f"{launcher_url}/start", method="POST",
                data=b"{}",
                headers={"Content-Type": "application/json"},
            )
            resp = urllib.request.urlopen(req, timeout=15)
            json.loads(resp.read())
            import time
            time.sleep(1)
            req2 = urllib.request.Request(f"{host_trainer_url}/health", method="GET")
            urllib.request.urlopen(req2, timeout=3)
            trainer_ok = True
        except Exception:
            pass

    if not trainer_ok:
        return JSONResponse(content={
            "status": "error",
            "message": (
                "Host trainer is not running and could not be auto-started. "
                "Run: ./start.sh  (or manually: python finetuning/host_trainer.py)"
            )
        }, status_code=503)

    # Dispatch directly to the host trainer (bypasses Celery which uses
    # a separate worker module that doesn't register this task).
    import uuid as _uuid
    from datetime import datetime, timezone
    from .settings_runtime import get_effective_settings

    effective = get_effective_settings()
    job_id = str(_uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Read fine-tuning params from DB settings
    try:
        from .database import get_session
        from .db_models import SettingsDB
        with get_session() as session:
            settings_row = session.get(SettingsDB, 1)
            vals = settings_row.values if settings_row else {}
    except Exception:
        vals = {}

    # The backend runs in Docker where dataset_storage_path resolves to a
    # container-internal path (e.g. /finetuning/data).  The host trainer
    # runs natively, so we must translate to a host-absolute path.
    host_ws = os.environ.get("HOST_WORKSPACE_ROOT", "").strip()
    if host_ws and host_ws != ".":
        # Explicit workspace root provided
        host_data_dir = Path(host_ws) / "finetuning" / "data"
    elif os.path.exists("/.dockerenv"):
        # Inside Docker without explicit root — try to derive from the
        # Docker-to-host volume convention:  ./finetuning -> /data/finetuning
        # The host path cannot be determined; fall back to a common default.
        try:
            # Ask the host trainer for its workspace root
            _ws_req = urllib.request.Request(f"{host_trainer_url}/health", method="GET")
            with urllib.request.urlopen(_ws_req, timeout=3) as _ws_resp:
                _ws_info = json.loads(_ws_resp.read())
                _scripts_dir = _ws_info.get("scripts_dir", "")
                if _scripts_dir:
                    # scripts_dir is e.g. /home/bc/Documents/AIPAM/finetuning
                    host_data_dir = Path(_scripts_dir) / "data"
                else:
                    host_data_dir = effective.dataset_storage_path
        except Exception:
            host_data_dir = effective.dataset_storage_path
    else:
        host_data_dir = effective.dataset_storage_path

    # ── Merge distilled training data if available ──
    base_train_path = host_data_dir / "training" / "train.jsonl"
    train_data_path = base_train_path  # default: use original

    try:
        from .distillation import merge_distilled_into_training, get_distill_stats
        d_stats = get_distill_stats()
        if d_stats.get("total_samples", 0) > 0:
            merged = merge_distilled_into_training(base_train_path)
            train_data_path = Path(merged["output_path"])
            import logging
            logging.getLogger(__name__).info(
                "Merged %d base + %d distilled = %d total training samples",
                merged["base_samples"],
                merged["distilled_samples"],
                merged["total_samples"],
            )
    except Exception as merge_err:
        import logging
        logging.getLogger(__name__).warning(
            "Distilled data merge failed (using base only): %s", merge_err
        )

    host_config = {
        "job_id": job_id,
        "train_data": str(train_data_path),
        "val_data": str(host_data_dir / "training" / "validation.jsonl"),
        "output_dir": str(host_data_dir / "models" / f"run_{timestamp}"),
        "base_model": vals.get("finetune_base_model", "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit"),
        "batch_size": int(vals.get("finetune_batch_size") or 2),
        "iters": int(vals.get("finetune_iters") or 1000),
        "learning_rate": float(vals.get("finetune_learning_rate") or 1e-5),
        "lora_rank": int(vals.get("finetune_lora_rank") or 8),
        "num_layers": int(vals.get("finetune_num_layers") or 16),
        "max_seq_length": int(vals.get("finetune_max_seq_length") or 1024),
    }

    try:
        req = urllib.request.Request(
            f"{host_trainer_url}/train",
            data=json.dumps(host_config).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return JSONResponse(content={
                "status": "started",
                "task_id": result.get("job_id", job_id),
                "message": "Fine-tuning job started on host trainer."
            }, status_code=202)
    except urllib.error.HTTPError as e:
        body = json.loads(e.read()) if e.fp else {"error": str(e)}
        return JSONResponse(content=body, status_code=e.code)
    except Exception as e:
        return JSONResponse(content={
            "status": "error",
            "message": f"Failed to dispatch training to host trainer: {e}"
        }, status_code=500)


@router.post("/validate_path")
async def validate_storage_path(payload: Dict[str, Any]):
    """Check if a directory path exists and is writable."""
    path_str = payload.get("path")
    if not path_str:
        return JSONResponse(content={"valid": False, "message": "Path is empty"}, status_code=400)
    
    path = Path(path_str).resolve()
    
    # Check existence
    if not path.exists():
        return JSONResponse(content={
            "valid": False,
            "exists": False,
            "writable": False,
            "message": f"Path does not exist: {path}"
        })
    
    # Check directory
    if not path.is_dir():
        return JSONResponse(content={
            "valid": False,
            "exists": True,
            "writable": False,
            "message": f"Path is not a directory: {path}"
        })
        
    # Check writable
    try:
        test_file = path / ".write_test"
        test_file.touch()
        test_file.unlink()
        return JSONResponse(content={
            "valid": True,
            "exists": True,
            "writable": True,
            "message": "Path is valid and writable"
        })
    except Exception as e:
        return JSONResponse(content={
            "valid": False,
            "exists": True,
            "writable": False,
            "message": f"Path exists but is not writable: {e}"
        })


@router.post("/stop")
async def stop_training():
    """Stop the currently running training job."""
    host_trainer_url = os.environ.get(
        "HOST_TRAINER_URL", "http://host.docker.internal:8002"
    )
    try:
        req = urllib.request.Request(
            f"{host_trainer_url}/stop", method="POST",
            data=b"{}", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return JSONResponse(content=json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        body = json.loads(e.read()) if e.fp else {"error": str(e)}
        return JSONResponse(content=body, status_code=e.code)
    except Exception as e:
        return JSONResponse(
            content={"error": f"Cannot reach host trainer: {e}"},
            status_code=503,
        )


@router.post("/pause")
async def pause_training():
    """Pause or resume the currently running training job."""
    host_trainer_url = os.environ.get(
        "HOST_TRAINER_URL", "http://host.docker.internal:8002"
    )
    try:
        req = urllib.request.Request(
            f"{host_trainer_url}/pause", method="POST",
            data=b"{}", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return JSONResponse(content=json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        body = json.loads(e.read()) if e.fp else {"error": str(e)}
        return JSONResponse(content=body, status_code=e.code)
    except Exception as e:
        return JSONResponse(
            content={"error": f"Cannot reach host trainer: {e}"},
            status_code=503,
        )


@router.post("/export")
async def export_model():
    """Trigger LoRA merge + GGUF export + Ollama registration on the host trainer."""
    import urllib.request
    import urllib.error

    host_trainer_url = os.environ.get(
        "HOST_TRAINER_URL", "http://host.docker.internal:8002"
    )
    try:
        req = urllib.request.Request(
            f"{host_trainer_url}/export", method="POST",
            data=b"{}", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return JSONResponse(content=result, status_code=202)
    except urllib.error.HTTPError as e:
        body = json.loads(e.read()) if e.fp else {"error": str(e)}
        return JSONResponse(content=body, status_code=e.code)
    except Exception as e:
        return JSONResponse(
            content={"error": f"Cannot reach host trainer: {e}"},
            status_code=503,
        )


@router.get("/export/status")
async def get_export_status():
    """Return live export job status from the host trainer."""
    host_trainer_url = os.environ.get(
        "HOST_TRAINER_URL", "http://host.docker.internal:8002"
    )
    try:
        req = urllib.request.Request(
            f"{host_trainer_url}/export/status", method="GET",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return JSONResponse(content=json.loads(resp.read()))
    except Exception:
        return JSONResponse(content={
            "status": "offline",
            "message": "Cannot reach host trainer",
        })


@router.get("/status")
async def get_training_status():
    """Return live training job status from the host trainer."""
    host_trainer_url = os.environ.get(
        "HOST_TRAINER_URL", "http://host.docker.internal:8002"
    )
    try:
        req = urllib.request.Request(
            f"{host_trainer_url}/status",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            return JSONResponse(content={
                "trainer_online": True,
                "job_id": data.get("job_id"),
                "status": data.get("status", "unknown"),
                "current_iter": data.get("current_iter", 0),
                "total_iters": data.get("total_iters", 0),
                "percent": data.get("percent", 0),
                "last_loss": data.get("last_loss", 0),
                "it_per_sec": data.get("it_per_sec", 0),
                "elapsed_seconds": data.get("elapsed_seconds"),
                "eta_seconds": data.get("eta_seconds"),
            })
    except Exception:
        return JSONResponse(content={
            "trainer_online": False,
            "job_id": None,
            "status": "offline",
            "current_iter": 0,
            "total_iters": 0,
            "percent": 0,
            "last_loss": 0,
            "it_per_sec": 0,
            "elapsed_seconds": None,
            "eta_seconds": None,
        })


# ═══════════════════════════════════════════════════════════════════════════
# Frontier Knowledge Distillation Routes
# ═══════════════════════════════════════════════════════════════════════════

from .distillation import (
    get_teacher_config,
    update_teacher_config,
    get_distill_stats,
)


@router.get("/distill/config")
async def get_distill_config():
    """Return the current teacher model configuration."""
    tc = get_teacher_config()
    return JSONResponse(content={
        "endpoint": tc.endpoint,
        "model": tc.model,
        "temperature": tc.temperature,
        "max_tokens": tc.max_tokens,
        "timeout_seconds": tc.timeout_seconds,
        "enabled": tc.enabled,
        "configured": tc.is_configured(),
        # Never expose the full API key
        "api_key_set": bool(tc.api_key),
        "api_key_preview": (tc.api_key[:4] + "…" + tc.api_key[-4:]) if len(tc.api_key) > 8 else ("****" if tc.api_key else ""),
    })


@router.post("/distill/config")
async def set_distill_config(payload: Dict[str, Any]):
    """Update the teacher model configuration at runtime."""
    tc = update_teacher_config(payload)
    return JSONResponse(content={
        "status": "updated",
        "configured": tc.is_configured(),
        "enabled": tc.enabled,
        "model": tc.model,
    })


@router.get("/distill/stats")
async def distill_stats():
    """Return statistics about accumulated distilled training data."""
    return JSONResponse(content=get_distill_stats())


@router.post("/distill/test")
async def test_teacher():
    """Send a small test prompt to the teacher to verify connectivity."""
    import httpx
    from .llm_client import SYSTEM_PROMPT

    tc = get_teacher_config()
    if not tc.is_configured():
        return JSONResponse(
            content={"status": "error", "message": "Teacher model not configured"},
            status_code=400,
        )

    test_prompt = (
        "This is a connectivity test. Respond with a short JSON object: "
        '{"status": "ok", "model": "<your model name>"}'
    )

    # Call teacher directly with full error capture
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {tc.api_key}",
    }
    payload = {
        "model": tc.model,
        "temperature": 0.1,
        "max_tokens": 256,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": test_prompt},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(tc.endpoint, json=payload, headers=headers)
            if resp.status_code != 200:
                try:
                    err_body = resp.json()
                except Exception:
                    err_body = {"raw": resp.text[:500]}
                return JSONResponse(
                    content={
                        "status": "error",
                        "message": f"Teacher API returned {resp.status_code}",
                        "api_error": err_body,
                        "model": tc.model,
                        "endpoint": tc.endpoint,
                    },
                    status_code=200,  # Return 200 so frontend doesn't crash
                )
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return JSONResponse(content={
                "status": "ok",
                "response_preview": content.strip()[:500],
                "model": tc.model,
            })
    except httpx.ConnectError as e:
        return JSONResponse(content={
            "status": "error",
            "message": f"Cannot connect to {tc.endpoint}: {e}",
        }, status_code=200)
    except httpx.TimeoutException:
        return JSONResponse(content={
            "status": "error",
            "message": f"Timeout connecting to {tc.endpoint}",
        }, status_code=200)
    except Exception as e:
        return JSONResponse(content={
            "status": "error",
            "message": f"Unexpected error: {e}",
        }, status_code=200)

