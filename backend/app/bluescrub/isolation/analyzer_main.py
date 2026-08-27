"""Subprocess entry point for vendored analyzers.

The isolation contract admits no in-process exception for pure-Python
analyzers: they parse attacker-authored source, and a thread spinning in a
catastrophic regex cannot be interrupted. This module is what
``run_analyzer`` execs, so every vendored analyzer inherits the rlimits,
privilege drop, and process-group kill that the boundary provides.

Usage:  python -m backend.app.bluescrub.isolation.analyzer_main <Analyzer> <dir>

Writes a JSON envelope to stdout. Never raises: a failure is reported in the
envelope so the caller can classify it rather than parse a traceback.
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        json.dump({"ok": False, "error": "usage: analyzer_main <Analyzer> <directory>"},
                  sys.stdout)
        return 2

    name, directory = argv[1], argv[2]
    try:
        from backend.app.bluescrub.vendored.scanners import analyzers

        cls = getattr(analyzers, name, None)
        if cls is None:
            json.dump({"ok": False, "error": f"unknown analyzer {name!r}"}, sys.stdout)
            return 2

        findings = cls().run(directory)
        json.dump({"ok": True, "analyzer": name, "findings": findings}, sys.stdout,
                  default=str)
        return 0
    except Exception as exc:  # classified by the caller, not raised across the boundary
        json.dump({"ok": False, "analyzer": name,
                   "error": f"{type(exc).__name__}: {exc}"}, sys.stdout, default=str)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
