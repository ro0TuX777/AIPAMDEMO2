"""Shared loader so tests validate against the real contract schemas.

The schemas cross-reference each other by filename, which needs a resolver
registry; without one the refs silently fail to resolve and the tests pass
while validating nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS = Path(__file__).resolve().parents[1] / "bluescrub" / "contracts"


def _registry() -> Registry:
    registry = Registry()
    for path in CONTRACTS.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        resource = Resource.from_contents(schema)
        # Register under both the filename (how the refs are written) and $id.
        registry = registry.with_resource(path.name, resource)
        if "$id" in schema:
            registry = registry.with_resource(schema["$id"], resource)
    return registry


REGISTRY = _registry()


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / name).read_text())
    return Draft202012Validator(schema, registry=REGISTRY)
