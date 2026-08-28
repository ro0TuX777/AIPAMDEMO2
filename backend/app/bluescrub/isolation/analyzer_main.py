"""Subprocess entry point for vendored analyzers.

The isolation contract admits no in-process exception for pure-Python
analyzers: they parse attacker-authored source, and a thread spinning in a
catastrophic regex cannot be interrupted. This module is what
``run_analyzer`` execs, so every vendored analyzer inherits the rlimits,
privilege drop, and process-group kill that the boundary provides.

Usage:
    python -m ...analyzer_main <Analyzer> <dir> [pattern]
    python -m ...analyzer_main <directory_fn> <dir> specialised

The two modes exist because the vendored corpus has two interfaces: seven
BaseAnalyzer subclasses with ``run(dir)``, and nine specialised scanners
reachable only through module-level ``analyze_directory_for_*`` functions.

Writes a JSON envelope to stdout. Never raises: a failure is reported in the
envelope so the caller can classify it rather than parse a traceback.
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        json.dump({"ok": False,
                   "error": "usage: analyzer_main <entry> <directory> [pattern|specialised]"},
                  sys.stdout)
        return 2

    name, directory = argv[1], argv[2]
    mode = argv[3] if len(argv) == 4 else "pattern"
    try:
        from backend.app.bluescrub.vendored.scanners import analyzers

        if mode == "binary":
            from backend.app.bluescrub.vendored.scanners.binary import BinaryAnalyzer

            findings = BinaryAnalyzer().analyze_directory(directory)
        elif mode == "dependencies":
            from backend.app.bluescrub.vendored.dependency_scanner import (
                build_dependency_inventory,
            )

            findings = build_dependency_inventory(directory)
        else:
            entry = getattr(analyzers, name, None)
            if entry is None:
                json.dump({"ok": False, "error": f"unknown analyzer {name!r}"}, sys.stdout)
                return 2
            findings = entry(directory) if mode == "specialised" else entry().run(directory)
        json.dump({"ok": True, "analyzer": name, "findings": findings}, sys.stdout,
                  default=str)
        return 0
    except Exception as exc:  # classified by the caller, not raised across the boundary
        json.dump({"ok": False, "analyzer": name,
                   "error": f"{type(exc).__name__}: {exc}"}, sys.stdout, default=str)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
