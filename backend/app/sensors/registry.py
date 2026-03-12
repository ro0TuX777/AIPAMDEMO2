"""
Sensor Registry (§6) — defines all known sensors and execution profiles.

Each sensor entry describes its Docker image, resource limits, dependencies,
and which execution profiles include it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

SensorType = Literal["stage", "sensor"]
Profile = Literal["triage", "standard", "deep"]
SensorStatus = Literal["completed", "failed", "timeout", "skipped"]

# Type alias for in-process sensor handler functions.
# Signature: handler(job_dir, sensor_output_dir, job_id, execution_profile) -> None
# The handler should write results to sensor_output_dir.  Raise on failure.
SensorHandler = Callable[..., None]


@dataclass(frozen=True)
class SensorDef:
    """Immutable definition of a sensor or stage."""

    name: str
    type: SensorType
    enabled_by_default: bool = True

    # Docker image — used when handler is None (container-based execution)
    image: str | None = None
    image_digest: str | None = None  # Optional sha256 pin

    # In-process handler — when set, the sensor runs inside the worker
    # process instead of launching a Docker container.
    handler: SensorHandler | None = None

    # Resource limits (§7.9)
    timeout_seconds: int = 600
    mem_limit: str = "2g"
    cpu_limit: float | None = None
    pids_limit: int = 256
    max_output_bytes: int = 5_368_709_120  # 5 GB

    # Dependency tracking
    inputs_required: tuple[str, ...] = ()
    skip_if_missing_inputs: bool = False

    # Which profiles include this sensor
    profiles: tuple[Profile, ...] = ("standard", "deep")

    # Expected output files
    produces: tuple[str, ...] = ("sensor.meta.json", "sensor.results.jsonl")


# ---------------------------------------------------------------------------
# Canonical sensor definitions (§6.1)
# ---------------------------------------------------------------------------

# Late-import helper so the module can be loaded without triggering heavy deps
# at import time.  Handlers are resolved lazily on first call.
def _get_handlers() -> dict[str, SensorHandler]:
    from backend.app.pipeline.sensor_handlers import (
        handle_beaconing,
        handle_capa,
        handle_file_triage,
        handle_suricata,
        handle_ti_matcher,
        handle_tls_enrich,
        handle_zeek,
    )
    return {
        "zeek": handle_zeek,
        "suricata": handle_suricata,
        "tls_enrich": handle_tls_enrich,
        "beaconing": handle_beaconing,
        "file_triage": handle_file_triage,
        "capa": handle_capa,
        "ti_matcher": handle_ti_matcher,
    }

_handlers_cache: dict[str, SensorHandler] | None = None

def _handler(name: str) -> SensorHandler:
    global _handlers_cache
    if _handlers_cache is None:
        _handlers_cache = _get_handlers()
    return _handlers_cache[name]


SENSORS: dict[str, SensorDef] = {
    "zeek": SensorDef(
        name="zeek",
        type="stage",
        handler=lambda *a, **kw: _handler("zeek")(*a, **kw),
        timeout_seconds=1800,
        profiles=("triage", "standard", "deep"),
    ),
    "suricata": SensorDef(
        name="suricata",
        type="stage",
        handler=lambda *a, **kw: _handler("suricata")(*a, **kw),
        timeout_seconds=1800,
        profiles=("triage", "standard", "deep"),
    ),
    "tls_enrich": SensorDef(
        name="tls_enrich",
        type="sensor",
        handler=lambda *a, **kw: _handler("tls_enrich")(*a, **kw),
        timeout_seconds=300,
        inputs_required=("zeek",),
        profiles=("triage", "standard", "deep"),
    ),
    "beaconing": SensorDef(
        name="beaconing",
        type="sensor",
        handler=lambda *a, **kw: _handler("beaconing")(*a, **kw),
        timeout_seconds=900,
        inputs_required=("zeek",),
        profiles=("standard", "deep"),
    ),
    "file_triage": SensorDef(
        name="file_triage",
        type="sensor",
        handler=lambda *a, **kw: _handler("file_triage")(*a, **kw),
        timeout_seconds=1200,
        inputs_required=("zeek",),
        skip_if_missing_inputs=True,
        profiles=("standard", "deep"),
    ),
    "capa": SensorDef(
        name="capa",
        type="sensor",
        handler=lambda *a, **kw: _handler("capa")(*a, **kw),
        timeout_seconds=900,
        inputs_required=("file_triage",),
        skip_if_missing_inputs=True,
        profiles=("standard", "deep"),
    ),
    "ti_matcher": SensorDef(
        name="ti_matcher",
        type="sensor",
        handler=lambda *a, **kw: _handler("ti_matcher")(*a, **kw),
        timeout_seconds=600,
        inputs_required=("zeek", "suricata"),
        profiles=("triage", "standard", "deep"),
    ),
}

# Deterministic execution order within each type (§7.11)
STAGE_ORDER: list[str] = ["zeek", "suricata"]
SENSOR_ORDER: list[str] = ["tls_enrich", "beaconing", "file_triage", "capa", "ti_matcher"]


def get_sensors_for_profile(profile: Profile) -> list[SensorDef]:
    """Return sensors (type='sensor' only) enabled for the given profile, in execution order."""
    return [
        SENSORS[name]
        for name in SENSOR_ORDER
        if name in SENSORS
        and SENSORS[name].type == "sensor"
        and profile in SENSORS[name].profiles
        and SENSORS[name].enabled_by_default
    ]


def get_stages_for_profile(profile: Profile) -> list[SensorDef]:
    """Return stages (type='stage') enabled for the given profile, in execution order."""
    return [
        SENSORS[name]
        for name in STAGE_ORDER
        if name in SENSORS
        and SENSORS[name].type == "stage"
        and profile in SENSORS[name].profiles
        and SENSORS[name].enabled_by_default
    ]


def get_all_for_profile(profile: Profile) -> list[SensorDef]:
    """Return stages + sensors for a profile, in full execution order."""
    return get_stages_for_profile(profile) + get_sensors_for_profile(profile)


def validate_image_allowlist(image: str) -> bool:
    """Check if an image is in the sensor registry allowlist (§8)."""
    allowed = {s.image for s in SENSORS.values() if s.image is not None}
    return image in allowed

