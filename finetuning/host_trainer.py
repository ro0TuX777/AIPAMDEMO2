#!/usr/bin/env python3
"""
AIPAM Host Trainer — Native Fine-Tuning Server

Runs on the host system (not inside Docker) so that fine-tuning
can use the GPU directly:
  - macOS: Apple Silicon GPU (Metal) via MLX  → finetune_mlx.py
  - Linux: NVIDIA GPU (CUDA) via Unsloth/PyTorch → finetune_llama.py

The Docker worker sends a POST /train request with training config;
this server runs the appropriate finetune script and streams output.

Usage:
    python finetuning/host_trainer.py
"""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

PORT = 8002
FINETUNING_DIR = Path(__file__).resolve().parent
LEDGER_PATH = FINETUNING_DIR / "dawn_training_ledger.jsonl"

# ── Platform detection ──
import platform as _platform
IS_LINUX = _platform.system() == "Linux"
IS_MACOS = _platform.system() == "Darwin"

# ── Resolve the Python interpreter for training subprocesses ──
# On Linux, prefer the venv_unsloth virtualenv (which has unsloth + torch + CUDA)
# over the system python (which may lack unsloth).
_VENV_PYTHON = FINETUNING_DIR.parent / "venv_unsloth" / "bin" / "python3"
TRAINING_PYTHON = str(_VENV_PYTHON) if (IS_LINUX and _VENV_PYTHON.exists()) else sys.executable

# Track the currently running job
_current_job = {
    "id": None,
    "status": "idle",
    "process": None,
    "current_iter": 0,
    "total_iters": 0,
    "start_time": None,
    "last_loss": 0.0,
    "it_per_sec": 0.0,
}
_lock = threading.Lock()

# ── Ollama → HuggingFace MLX model mapping ──
# Maps common Ollama model names to MLX-compatible HuggingFace models.
# Add entries here as you work with new base models.
OLLAMA_TO_HF = {
    # Llama 3.1 variants
    "llama3.1:8b":              "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit",
    "llama3.1:latest":          "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit",
    "llama3.1:8b-instruct":     "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit",
    # Qwen variants
    "qwen2.5:7b":               "mlx-community/Qwen2.5-7B-Instruct-4bit",
    "qwen2.5:latest":           "mlx-community/Qwen2.5-7B-Instruct-4bit",
    # DeepSeek variants
    "deepseek-r1:8b":           "mlx-community/DeepSeek-R1-Distill-Qwen-7B-4bit",
    "deepseek-r1:latest":       "mlx-community/DeepSeek-R1-Distill-Qwen-7B-4bit",
}

_DEFAULT_MLX_MODEL = "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit"
_DEFAULT_CUDA_MODEL = "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit"

# Map Ollama names → HuggingFace CUDA-compatible models (4-bit via bitsandbytes)
OLLAMA_TO_HF_CUDA = {
    "llama3.1:8b":              "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit",
    "llama3.1:latest":          "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit",
    "llama3.1:8b-instruct":     "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit",
    "qwen2.5:7b":               "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
    "qwen2.5:latest":           "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
    "deepseek-r1:8b":           "unsloth/DeepSeek-R1-Distill-Qwen-7B-bnb-4bit",
    "deepseek-r1:latest":       "unsloth/DeepSeek-R1-Distill-Qwen-7B-bnb-4bit",
}

# Map MLX HuggingFace paths → CUDA HuggingFace paths (for when the backend
# sends an MLX model name but training runs on Linux/CUDA)
_MLX_TO_CUDA = {
    "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit":      "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit",
    "mlx-community/Qwen2.5-7B-Instruct-4bit":             "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
    "mlx-community/DeepSeek-R1-Distill-Qwen-7B-4bit":     "unsloth/DeepSeek-R1-Distill-Qwen-7B-bnb-4bit",
}


def resolve_model_name(name: str) -> str:
    """Convert Ollama model name → HuggingFace model path.

    Uses the CUDA mapping table on Linux, MLX on macOS.
    On Linux, also translates MLX HuggingFace paths to CUDA equivalents.
    """
    mapping = OLLAMA_TO_HF_CUDA if IS_LINUX else OLLAMA_TO_HF
    default = _DEFAULT_CUDA_MODEL if IS_LINUX else _DEFAULT_MLX_MODEL

    if not name or name == "string":
        return default
    # Already a HuggingFace path — but on Linux, check if it's an MLX model
    if "/" in name:
        if IS_LINUX and name in _MLX_TO_CUDA:
            return _MLX_TO_CUDA[name]
        return name
    # Exact match
    key = name.lower().strip()
    if key in mapping:
        return mapping[key]
    # Try without tag (e.g. 'aipam-pcaplog:latest' → check 'aipam-pcaplog')
    base = key.split(":")[0]
    for k, v in mapping.items():
        if k.startswith(base):
            return v
    # Fallback
    print(f"[HOST_TRAINER] WARNING: Unknown model '{name}', falling back to {default}")
    return default


def append_ledger(entry: dict):
    """Append an entry to the host-side training ledger."""
    try:
        with open(LEDGER_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[HOST_TRAINER] Failed to write ledger: {e}")


def run_training(config: dict):
    """Run finetune_mlx.py in a subprocess and update the ledger."""
    global _current_job
    job_id = config.get("job_id", str(uuid.uuid4()))

    # Select the correct training script based on platform
    if IS_LINUX:
        script_path = FINETUNING_DIR / "finetune_llama.py"
    else:
        script_path = FINETUNING_DIR / "finetune_mlx.py"

    if not script_path.exists():
        print(f"[HOST_TRAINER] Script not found: {script_path}")
        with _lock:
            _current_job = {"id": job_id, "status": "failed", "process": None}
        return

    print(f"[HOST_TRAINER] Platform: {'Linux/CUDA' if IS_LINUX else 'macOS/MLX'}, script: {script_path.name}")
    print(f"[HOST_TRAINER] Python interpreter: {TRAINING_PYTHON}")

    # ── Translate Docker container paths to host paths ──
    # The backend runs in Docker where /data/finetuning/ is the mount point.
    # On the host, this corresponds to FINETUNING_DIR.
    _CONTAINER_PREFIX = "/data/finetuning/"
    for key in ("train_data", "val_data", "output_dir"):
        val = config.get(key, "")
        if val.startswith(_CONTAINER_PREFIX):
            host_path = str(FINETUNING_DIR / val[len(_CONTAINER_PREFIX):])
            print(f"[HOST_TRAINER] Path mapped: {val} → {host_path}")
            config[key] = host_path

    # Resolve model name (Ollama → HuggingFace)
    raw_model = config.get("base_model", "")
    hf_model = resolve_model_name(raw_model)
    if hf_model != raw_model:
        print(f"[HOST_TRAINER] Resolved model: {raw_model} → {hf_model}")

    # Build command
    cmd = [
        TRAINING_PYTHON, str(script_path),
        "--data", config["train_data"],
        "--output", config["output_dir"],
        "--base-model", hf_model,
        "--batch-size", str(config.get("batch_size", 2)),
        "--iters", str(config.get("iters", 1000)),
        "--learning-rate", str(config.get("learning_rate", 1e-5)),
        "--lora-rank", str(config.get("lora_rank", 8)),
        "--num-layers", str(config.get("num_layers", 16)),
        "--max-seq-length", str(config.get("max_seq_length", 1024)),
    ]

    if config.get("val_data") and Path(config["val_data"]).exists():
        cmd.extend(["--val-data", config["val_data"]])

    print(f"[HOST_TRAINER] Executing: {' '.join(cmd)}")

    # Ledger: start
    config_str = f"{config.get('base_model', '')}{config.get('lora_rank', 8)}{config.get('learning_rate', 1e-5)}{config.get('max_seq_length', 1024)}"
    config_hash = hashlib.md5(config_str.encode()).hexdigest()

    append_ledger({
        "event_type": "sft_training_start",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "job_id": job_id,
        "base_model": config.get("base_model", ""),
        "config_hash": config_hash,
        "config": {
            "lora_rank": config.get("lora_rank", 8),
            "learning_rate": config.get("learning_rate", 1e-5),
            "max_seq_length": config.get("max_seq_length", 1024),
            "batch_size": config.get("batch_size", 2),
            "iters": config.get("iters", 1000),
        },
    })

    start_time = datetime.now(timezone.utc)
    total_iters = int(config.get("iters", 1000))

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        with _lock:
            _current_job = {
                "id": job_id,
                "status": "running",
                "process": process,
                "current_iter": 0,
                "total_iters": total_iters,
                "start_time": time.time(),
                "last_loss": 0.0,
                "it_per_sec": 0.0,
            }

        # Regex patterns for parsing training output
        # MLX-LM:  "Iter 10: Train loss 2.345, It/sec 1.23"
        # HF/trl:  "{'loss': 1.234, 'learning_rate': 5e-05, 'epoch': 0.5}" or step-based logs
        # tqdm:    " 1%|▏ | 14/1000 [02:03<2:21:00, 8.58s/it]"
        iter_re = re.compile(r"Iter\s+(\d+)", re.IGNORECASE)
        step_re = re.compile(r"['\"]step['\"]:\s*(\d+)")  # HF trainer JSON logs
        tqdm_re = re.compile(r"(\d+)/(\d+)\s*\[")  # tqdm progress: "14/1000 ["
        loss_re = re.compile(r"(?:train\s+)?loss[:\s]+([\d.]+)", re.IGNORECASE)
        hf_loss_re = re.compile(r"['\"]loss['\"]:\s*([\d.]+)")  # HF trainer JSON format
        speed_re = re.compile(r"It/sec[:\s]+([\d.]+)", re.IGNORECASE)
        tqdm_speed_re = re.compile(r"([\d.]+)s/it")  # tqdm: "8.58s/it" → convert to it/s

        log_prefix = "CUDA" if IS_LINUX else "MLX"

        # Stream output and parse for progress
        last_loss = 0.0
        for line in process.stdout:
            line = line.strip()
            if line:
                print(f"[{log_prefix}] {line}")

                # Parse iteration/step number
                # MLX: "Iter 10", HF JSON: "'step': 10", tqdm: "14/1000 ["
                iter_match = iter_re.search(line)
                if not iter_match:
                    iter_match = step_re.search(line)
                if iter_match:
                    cur_iter = int(iter_match.group(1))
                    with _lock:
                        _current_job["current_iter"] = cur_iter
                else:
                    tqdm_match = tqdm_re.search(line)
                    if tqdm_match:
                        cur_iter = int(tqdm_match.group(1))
                        with _lock:
                            _current_job["current_iter"] = cur_iter

                # Parse loss value (MLX: "loss: 1.23", HF: "'loss': 1.23")
                loss_match = loss_re.search(line)
                if not loss_match:
                    loss_match = hf_loss_re.search(line)
                if loss_match:
                    try:
                        last_loss = float(loss_match.group(1))
                        with _lock:
                            _current_job["last_loss"] = last_loss
                    except ValueError:
                        pass

                # Parse iteration speed
                # MLX: "It/sec: 1.23", tqdm: "8.58s/it" (invert to it/s)
                speed_match = speed_re.search(line)
                if speed_match:
                    try:
                        with _lock:
                            _current_job["it_per_sec"] = float(speed_match.group(1))
                    except ValueError:
                        pass
                else:
                    tqdm_speed_match = tqdm_speed_re.search(line)
                    if tqdm_speed_match:
                        try:
                            s_per_it = float(tqdm_speed_match.group(1))
                            if s_per_it > 0:
                                with _lock:
                                    _current_job["it_per_sec"] = 1.0 / s_per_it
                        except (ValueError, ZeroDivisionError):
                            pass

        process.wait()
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        if process.returncode == 0:
            append_ledger({
                "event_type": "sft_training_complete",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "job_id": job_id,
                "base_model": config.get("base_model", ""),
                "config_hash": config_hash,
                "duration_seconds": round(duration, 2),
                "max_seq_length": config.get("max_seq_length", 1024),
                "lora_r": config.get("lora_rank", 8),
                "lora_alpha": config.get("lora_rank", 8) * 2,
                "metrics": {
                    "train_loss": last_loss,
                    "output_dir": config["output_dir"],
                },
            })
            print(f"[HOST_TRAINER] Job {job_id} completed in {duration:.1f}s")
            with _lock:
                _current_job = {
                    "id": job_id, "status": "completed", "process": None,
                    "current_iter": total_iters, "total_iters": total_iters,
                    "start_time": None, "last_loss": last_loss, "it_per_sec": 0.0,
                }
        else:
            append_ledger({
                "event_type": "sft_training_failed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "job_id": job_id,
                "error": f"Process exited with code {process.returncode}",
            })
            print(f"[HOST_TRAINER] Job {job_id} failed (exit code {process.returncode})")
            with _lock:
                _current_job = {
                    "id": job_id, "status": "failed", "process": None,
                    "current_iter": 0, "total_iters": total_iters,
                    "start_time": None, "last_loss": 0.0, "it_per_sec": 0.0,
                }

    except Exception as e:
        append_ledger({
            "event_type": "sft_training_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": job_id,
            "error": str(e),
        })
        print(f"[HOST_TRAINER] Job {job_id} exception: {e}")
        with _lock:
            _current_job = {
                "id": job_id, "status": "failed", "process": None,
                "current_iter": 0, "total_iters": total_iters,
                "start_time": None, "last_loss": 0.0, "it_per_sec": 0.0,
            }


class TrainerHandler(BaseHTTPRequestHandler):
    """HTTP handler for training requests."""

    def do_POST(self):
        if self.path == "/train":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                config = json.loads(body)
            except json.JSONDecodeError:
                self._respond(400, {"error": "Invalid JSON"})
                return

            # Check if a job is already running
            with _lock:
                if _current_job["status"] in ("running", "paused"):
                    self._respond(409, {
                        "error": "A training job is already running",
                        "job_id": _current_job["id"],
                    })
                    return

            # Start training in a background thread
            job_id = config.get("job_id", str(uuid.uuid4()))
            config["job_id"] = job_id
            thread = threading.Thread(target=run_training, args=(config,), daemon=True)
            thread.start()

            self._respond(200, {"status": "started", "job_id": job_id})

        elif self.path == "/stop":
            with _lock:
                proc = _current_job.get("process")
                job_id = _current_job.get("id")
                status = _current_job["status"]
            if status not in ("running", "paused") or proc is None:
                self._respond(400, {"error": "No active training job to stop"})
                return
            try:
                # Resume first if paused, then terminate
                if status == "paused":
                    os.kill(proc.pid, signal.SIGCONT)
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            append_ledger({
                "event_type": "sft_training_failed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "job_id": job_id,
                "error": "Stopped by user",
            })
            with _lock:
                total = _current_job.get("total_iters", 0)
                _current_job.update({
                    "status": "stopped", "process": None,
                    "start_time": None, "it_per_sec": 0.0,
                })
            print(f"[HOST_TRAINER] Job {job_id} stopped by user")
            self._respond(200, {"status": "stopped", "job_id": job_id})

        elif self.path == "/pause":
            with _lock:
                proc = _current_job.get("process")
                job_id = _current_job.get("id")
                status = _current_job["status"]
            if status == "running" and proc:
                os.kill(proc.pid, signal.SIGSTOP)
                with _lock:
                    _current_job["status"] = "paused"
                print(f"[HOST_TRAINER] Job {job_id} paused")
                self._respond(200, {"status": "paused", "job_id": job_id})
            elif status == "paused" and proc:
                os.kill(proc.pid, signal.SIGCONT)
                with _lock:
                    _current_job["status"] = "running"
                print(f"[HOST_TRAINER] Job {job_id} resumed")
                self._respond(200, {"status": "running", "job_id": job_id})
            else:
                self._respond(400, {"error": "No active training job to pause/resume"})

        else:
            self._respond(404, {"error": "Not found"})

    def do_GET(self):
        if self.path == "/status":
            with _lock:
                cur = _current_job.copy()
            # Calculate ETA
            eta_seconds = None
            elapsed = None
            pct = 0.0
            if cur["total_iters"] > 0:
                pct = round(cur["current_iter"] / cur["total_iters"] * 100, 1)
            if cur["status"] == "running" and cur["start_time"]:
                elapsed = round(time.time() - cur["start_time"], 1)
                if cur["it_per_sec"] > 0:
                    remaining = cur["total_iters"] - cur["current_iter"]
                    eta_seconds = round(remaining / cur["it_per_sec"])
                elif cur["current_iter"] > 0 and elapsed > 0:
                    sec_per_iter = elapsed / cur["current_iter"]
                    remaining = cur["total_iters"] - cur["current_iter"]
                    eta_seconds = round(remaining * sec_per_iter)
            status = {
                "job_id": cur["id"],
                "status": cur["status"],
                "current_iter": cur["current_iter"],
                "total_iters": cur["total_iters"],
                "percent": pct,
                "last_loss": cur["last_loss"],
                "it_per_sec": cur["it_per_sec"],
                "elapsed_seconds": elapsed,
                "eta_seconds": eta_seconds,
            }
            self._respond(200, status)
        elif self.path == "/health":
            self._respond(200, {"status": "ok", "scripts_dir": str(FINETUNING_DIR)})
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code: int, body: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        print(f"[HOST_TRAINER] {args[0]}")


def main():
    backend = "CUDA (NVIDIA GPU)" if IS_LINUX else "MLX (Apple Silicon)"
    script = "finetune_llama.py" if IS_LINUX else "finetune_mlx.py"
    print("=" * 60)
    print(f"AIPAM Host Trainer — {backend}")
    print("=" * 60)
    print(f"Listening on 0.0.0.0:{PORT}")
    print(f"Ledger:  {LEDGER_PATH}")
    print(f"Scripts: {FINETUNING_DIR}")
    print(f"Backend: {backend}")
    print(f"Script:  {script}")
    print(f"Python:  {TRAINING_PYTHON}")
    print()
    print("The Docker worker will send training jobs here for")
    print(f"native GPU execution via {backend}.")
    print("=" * 60)

    server = HTTPServer(("0.0.0.0", PORT), TrainerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[HOST_TRAINER] Shutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
