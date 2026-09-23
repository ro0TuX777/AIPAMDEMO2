"""
SensorRunner (§7, §8) — Docker container lifecycle for sensors.

Launches ephemeral Docker containers for each sensor, enforces timeouts
and resource limits, captures logs and exit codes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost
from backend.app.sensors.registry import SensorDef, validate_image_allowlist

logger = logging.getLogger("aipam.sensor_runner")


class DockerClientProtocol(Protocol):
    """Minimal Docker client interface for testability."""

    class images:
        @staticmethod
        def get(image: str) -> Any: ...

    class containers:
        @staticmethod
        def run(**kwargs: Any) -> Any: ...


@dataclass
class SensorResult:
    """Outcome of running a single sensor container."""

    sensor: str
    status: str  # completed | failed | timeout | skipped
    exit_code: int | None = None
    duration_ms: int = 0
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    container_log: str = ""
    error_code: str | None = None


GRACEFUL_SHUTDOWN_SECONDS = 10


def run_sensor(
    sensor_def: SensorDef,
    input_root: Path,
    job_id: str,
    execution_profile: str,
    docker_client: Any = None,
    sensor_config_dir: Path | None = None,
    *, run_output_dir: Path,
) -> SensorResult:
    """Launch a sensor (in-process handler or Docker container) and wait for completion.

    If ``sensor_def.handler`` is set, the sensor runs in-process.
    Otherwise it falls back to launching a Docker container.

    Returns:
        SensorResult with status, exit code, duration, and logs.
    """
    name = sensor_def.name
    started_at = datetime.now(timezone.utc)
    started_str = started_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # --- In-process handler path ---
    if sensor_def.handler is not None:
        return _run_handler(sensor_def, input_root, run_output_dir, job_id, execution_profile, started_at)

    # --- Docker pre-checks ---
    if sensor_def.image is None:
        return SensorResult(
            sensor=name, status="skipped",
            error="No image defined (stage, not a container sensor)",
            started_at=started_str,
        )

    if not validate_image_allowlist(sensor_def.image):
        return SensorResult(
            sensor=name, status="failed",
            error=f"Image {sensor_def.image} not in allowlist",
            started_at=started_str,
        )

    # Verify image exists locally
    try:
        docker_client.images.get(sensor_def.image)
    except (PipelineCanceled, OwnershipLost):
        raise
    except Exception as exc:
        return SensorResult(
            sensor=name, status="failed",
            error=f"Image not found locally: {sensor_def.image} ({exc})",
            started_at=started_str,
        )

    # --- Build mount volumes ---
    sensor_output_dir = run_output_dir / "sensors" / name
    sensor_output_dir.mkdir(parents=True, exist_ok=True)

    volumes = {
        str(input_root): {"bind": "/input", "mode": "ro"},
        str(sensor_output_dir): {"bind": "/output", "mode": "rw"},
    }

    if run_output_dir != input_root:
        volumes.pop(str(input_root))
        volumes[str(run_output_dir)] = {"bind": "/input", "mode": "ro"}
        volumes[str(input_root / "input")] = {"bind": "/input/input", "mode": "ro"}

    # --- Build container kwargs ---
    container_kwargs: dict[str, Any] = {
        "image": sensor_def.image,
        "volumes": volumes,
        "mem_limit": sensor_def.mem_limit,
        "network_mode": "none",
        "read_only": True,
        "pids_limit": sensor_def.pids_limit,
        "detach": True,
        "environment": {
            "JOB_ID": job_id,
            "SENSOR_NAME": name,
            "INPUT_DIR": "/input",
            "OUTPUT_DIR": "/output",
            "CONFIG_DIR": "/config",
            "EXECUTION_PROFILE": execution_profile,
        },
    }

    # CPU limit (optional)
    if sensor_def.cpu_limit is not None:
        container_kwargs["cpu_period"] = 100_000
        container_kwargs["cpu_quota"] = int(sensor_def.cpu_limit * 100_000)

    # --- Launch + wait ---
    container = None
    try:
        logger.info(
            "Launching sensor %s (image=%s, timeout=%ds)",
            name, sensor_def.image, sensor_def.timeout_seconds,
        )
        container = docker_client.containers.run(**container_kwargs)

        # Wait with timeout
        result = container.wait(timeout=sensor_def.timeout_seconds)
        exit_code = result.get("StatusCode", -1)
        status = "completed" if exit_code == 0 else "failed"

    except (PipelineCanceled, OwnershipLost):
        raise
    except Exception as exc:
        # Timeout or other error — attempt graceful then force kill
        exc_str = str(exc)
        is_timeout = "timed out" in exc_str.lower() or "read timeout" in exc_str.lower()

        if container is not None:
            try:
                container.kill()
            except Exception:
                pass

        exit_code = None
        status = "timeout" if is_timeout else "failed"
        error_msg = f"Timeout after {sensor_def.timeout_seconds}s" if is_timeout else exc_str

        ended_at = datetime.now(timezone.utc)
        duration_ms = int((ended_at - started_at).total_seconds() * 1000)

        _write_sensor_meta(
            sensor_output_dir, sensor_def, status, started_str,
            ended_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), duration_ms,
        )

        return SensorResult(
            sensor=name, status=status, exit_code=exit_code,
            duration_ms=duration_ms, error=error_msg,
            started_at=started_str,
            completed_at=ended_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            error_code="ERR_SENSOR_TIMEOUT" if is_timeout else "ERR_PIPELINE_CRASH",
        )

    # --- Capture logs ---
    container_log = ""
    try:
        container_log = container.logs(tail=200).decode("utf-8", errors="replace")
    except Exception:
        pass

    # Clean up container
    try:
        container.remove(force=True)
    except Exception:
        pass

    ended_at = datetime.now(timezone.utc)
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)
    ended_str = ended_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    error_msg = None
    if status == "failed":
        error_msg = f"Sensor exited with code {exit_code}"

    # Write sensor.meta.json to output dir
    _write_sensor_meta(
        sensor_output_dir, sensor_def, status,
        started_str, ended_str, duration_ms,
    )

    # Save container log
    log_path = sensor_output_dir / "container.log"
    log_path.write_text(container_log, encoding="utf-8")

    return SensorResult(
        sensor=name, status=status, exit_code=exit_code,
        duration_ms=duration_ms, error=error_msg,
        started_at=started_str, completed_at=ended_str,
        container_log=container_log,
    )


def _run_handler(
    sensor_def: SensorDef,
    input_root: Path,
    run_output_dir: Path,
    job_id: str,
    execution_profile: str,
    started_at: datetime,
) -> SensorResult:
    """Execute an in-process handler function for a sensor."""
    name = sensor_def.name
    started_str = started_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    sensor_output_dir = run_output_dir / "sensors" / name
    sensor_output_dir.mkdir(parents=True, exist_ok=True)
    (sensor_output_dir / "raw").mkdir(exist_ok=True)

    try:
        logger.info("Running in-process handler for sensor %s", name)
        sensor_def.handler(  # type: ignore[misc]
            input_root=input_root,
            run_output_dir=run_output_dir,
            sensor_output_dir=sensor_output_dir,
            job_id=job_id,
            execution_profile=execution_profile,
        )
        status = "completed"
        exit_code = 0
        error_msg = None
    except (PipelineCanceled, OwnershipLost):
        raise
    except Exception as exc:
        logger.exception("Handler for sensor %s failed", name)
        status = "failed"
        exit_code = 1
        error_msg = str(exc)[:2000]

    ended_at = datetime.now(timezone.utc)
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)
    ended_str = ended_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    _write_sensor_meta(
        sensor_output_dir, sensor_def, status,
        started_str, ended_str, duration_ms,
    )

    return SensorResult(
        sensor=name, status=status, exit_code=exit_code,
        duration_ms=duration_ms, error=error_msg,
        started_at=started_str, completed_at=ended_str,
        error_code="ERR_PIPELINE_CRASH" if status == "failed" else None,
    )


def _write_sensor_meta(
    sensor_output_dir: Path,
    sensor_def: SensorDef,
    status: str,
    started_at: str,
    ended_at: str,
    duration_ms: int,
) -> None:
    """Write sensor.meta.json (§3.1)."""
    meta = {
        "sensor": sensor_def.name,
        "sensor_version": "1.0.0",
        "image": sensor_def.image or "in-process",
        "execution_mode": "handler" if sensor_def.handler else "docker",
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "status": status,
    }
    meta_path = sensor_output_dir / "sensor.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
