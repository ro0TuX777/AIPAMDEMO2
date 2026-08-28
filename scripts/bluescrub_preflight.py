#!/usr/bin/env python3
"""Verify BlueScrub's external tooling on a deployment host.

Every external adapter in this pipeline was written against a tool that is not
installed on the development machine. Their **parsers** are tested against
recorded output, which is where the Semgrep adapter's three defects actually
lived — but the **invocation** is not tested by anything, because there is
nothing to invoke. Each `argv` is a documented decision that a deployment has
to confirm, and the failure mode if one is wrong is the quiet kind: a scanner
that reports `unavailable` or `unparseable` and a pillar that degrades, on a
host where the tool is sitting right there on the PATH.

This runs each adapter for real against a purpose-built fixture and reports
what came back. It is the check that cannot be written as a unit test.

    python scripts/bluescrub_preflight.py            # report
    python scripts/bluescrub_preflight.py --strict   # non-zero if required
                                                     # tooling is missing

Exit codes: 0 all required tooling present and working · 1 a required tool is
missing or its invocation failed (only with --strict) · 2 the manifest and the
registry disagree, which is a packaging error regardless of what is installed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

MANIFEST = REPO / "deploy" / "bluescrub" / "tool-manifest.json"

OK, WARN, BAD = "  ok  ", " warn ", " FAIL "


def _fixture(root: Path) -> Path:
    """A tiny artifact that every adapter should find something in.

    Deliberately not clean: an adapter that is wired up wrongly and one that
    is working perfectly both report zero findings on an empty directory.
    """
    src = root / "input" / "source"
    src.mkdir(parents=True)
    (src / "settings.py").write_text(
        "# Maintainer: a.chen@redcell.internal\n"
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'HOST = "buildbox01.redcell.internal"\n'
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.check_output(cmd, shell=True)\n"
    )
    (src / "requirements.txt").write_text("requests==2.6.0\nflask==0.12\n")
    (src / "loader").write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 500
        + b"OPERATION NIGHTFALL\x00"
        + rb"C:\Users\ada.chen\source\repos\loader\obj\Release\loader.pdb" + b"\x00"
    )

    # The history scanners need a repository, and the dirty-word scanner needs
    # a staged list. In a real job the service provides both; without them here
    # two working adapters would report `unavailable` and the check would be
    # crying wolf, which is how a preflight gets ignored.
    _init_repo(src)
    _stage_wordlist(root)
    return src


def _init_repo(src: Path) -> None:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_DATE": "2024-03-01T09:15:00+07:00",
        "GIT_COMMITTER_DATE": "2024-03-01T09:15:00+07:00",
    }
    if not shutil.which("git"):
        return
    for args in (
        ["init", "-q", "."],
        ["config", "user.name", "Preflight Fixture"],
        ["config", "user.email", "fixture@preflight.invalid"],
        ["add", "-A"],
        ["commit", "-qm", "fixture"],
    ):
        try:
            subprocess.run(["git", *args], cwd=src, env=env, check=True,
                           capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return


def _stage_wordlist(root: Path) -> None:
    from backend.app.bluescrub.scanners.dirty_word import WORDLIST_ENV

    path = root / "wordlist.json"
    path.write_text(json.dumps([
        {"term": "NIGHTFALL", "kind": "literal", "category": "codename"},
    ]))
    path.chmod(0o600)
    os.environ[WORDLIST_ENV] = str(path)


def check_manifest_matches_registry() -> list[str]:
    from backend.app.bluescrub.registry import SCANNERS

    manifest = json.loads(MANIFEST.read_text())
    declared = {t["name"] for t in manifest["tools"]}
    aliases = {"osv": "osv-scanner"}
    return [n for n in SCANNERS if aliases.get(n, n) not in declared]


def probe_binaries() -> list[tuple[str, str, str | None, bool]]:
    """(name, status, version, required) for every declared external binary."""
    manifest = json.loads(MANIFEST.read_text())
    binaries = {
        "gitleaks": "gitleaks", "trufflehog": "trufflehog", "semgrep": "semgrep",
        "osv-scanner": "osv-scanner", "grype": "grype", "syft": "syft",
        "gitmeta": "git", "floss": "floss",
    }
    rows = []
    for tool in manifest["tools"]:
        binary = binaries.get(tool["name"])
        if binary is None:
            continue                      # builtin or vendored, nothing to probe
        required = not tool.get("optional", False)
        path = shutil.which(binary)
        if not path:
            rows.append((binary, BAD if required else WARN, None, required))
            continue
        version = None
        for args in (["--version"], ["version"], ["-v"]):
            try:
                out = subprocess.run([path, *args], capture_output=True, text=True,
                                     timeout=30)
            except (OSError, subprocess.SubprocessError):
                continue
            text = (out.stdout or out.stderr or "").strip().splitlines()
            if out.returncode == 0 and text:
                version = text[0][:60]
                break
        rows.append((binary, OK, version or "(no version probe)", required))
    return rows


def exercise_adapters(src: Path, out: Path) -> list[tuple[str, str, str]]:
    """Actually run each adapter. This is the part no unit test can cover."""
    from backend.app.bluescrub.registry import SCANNERS

    os.environ.setdefault("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    results = []
    for name in sorted(SCANNERS):
        spec = SCANNERS[name]
        try:
            outcome = spec.run(src, out / name)
        except Exception as exc:                        # noqa: BLE001
            results.append((name, BAD, f"raised {type(exc).__name__}: {exc}"[:90]))
            continue
        detail = f"{len(outcome.findings)} findings"
        if outcome.reason:
            detail += f" — {outcome.reason[:60]}"
        if outcome.status in ("completed", "completed_truncated"):
            mark = OK if outcome.findings or spec.optional else WARN
        elif outcome.status == "unavailable":
            mark = WARN if spec.optional else BAD
        else:
            # The interesting case: the tool is installed and the adapter still
            # could not read it. That is an argv or a parser defect, and it is
            # exactly what this script exists to surface.
            mark = BAD
        results.append((name, mark, f"{outcome.status}: {detail}"))
    return results


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero when required tooling is missing")
    args = parser.parse_args(argv)

    print("BlueScrub preflight\n" + "=" * 72)

    missing = check_manifest_matches_registry()
    if missing:
        print(f"\n[{BAD}] registry entries with no manifest entry: {missing}")
        print("        A tool reaching an air-gapped deployment with no recorded")
        print("        provenance is a packaging error, not a host problem.")
        return 2
    print(f"[{OK}] every registered scanner has a manifest entry")

    print("\nExternal binaries")
    print("-" * 72)
    failed_required = False
    for name, mark, version, required in probe_binaries():
        tag = "required" if required else "optional"
        print(f"[{mark}] {name:14} {tag:9} {version or 'not on PATH'}")
        if mark is BAD:
            failed_required = True

    print("\nAdapters, run against a fixture")
    print("-" * 72)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = _fixture(root)
        for name, mark, detail in exercise_adapters(src, root / "sensors"):
            print(f"[{mark}] {name:22} {detail}")
            if mark is BAD:
                failed_required = True

    print("\n" + "=" * 72)
    if failed_required:
        print("Required tooling is missing or an adapter could not read a tool that")
        print("is installed. The second case is the one to chase: it means the argv")
        print("in the adapter does not match the version on this host.")
        return 1 if args.strict else 0
    print("All required tooling present; every adapter read its tool.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
