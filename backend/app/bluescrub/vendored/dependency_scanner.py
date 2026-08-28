#!/usr/bin/env python3
"""Offline dependency inventory builder for BlueScrub."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

import logging

logger = logging.getLogger(__name__)
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None


class DependencyScanner:
    """Build a lightweight SBOM-style inventory without network access."""

    SUPPORTED_FILES = {
        "requirements.txt": ("python", "pip"),
        "Pipfile": ("python", "pipenv"),
        "pyproject.toml": ("python", "pyproject"),
        "setup.py": ("python", "setuptools"),
        "package.json": ("javascript", "npm"),
        "package-lock.json": ("javascript", "npm-lock"),
        "go.mod": ("go", "go-mod"),
        "Cargo.toml": ("rust", "cargo"),
    }
    IGNORED_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__", "analysis_results"}

    def __init__(self):
        self.tools_available = {
            "dependency_inventory": True,
            "dependency-check": shutil.which("dependency-check") is not None,
            "safety": shutil.which("safety") is not None,
        }

    def build_dependency_inventory(self, directory):
        root = Path(directory)
        inventory = {
            "directory": str(root),
            "timestamp": datetime.now().isoformat(),
            "offline_only": True,
            "scanner": "DependencyScanner",
            "mode": "offline_manifest_inventory",
            "tools_available": self.tools_available,
            "dependency_files": {},
            "language_scans": {},
            "manifests": [],
            "packages": [],
            "parse_errors": [],
            "owasp_dependency_check": {
                "available": self.tools_available["dependency-check"],
                "executed": False,
                "reason": "Offline manifest inventory only; no external vulnerability database used.",
            },
            "summary": {},
        }

        if not root.exists():
            inventory["summary"] = {
                "total_dependency_files": 0,
                "languages_detected": [],
                "total_packages": 0,
                "unpinned_dependencies": 0,
                "total_vulnerabilities": 0,
                "scan_completed": False,
                "error": f"Directory not found: {directory}",
            }
            inventory["tooling"] = self._build_tooling_payload(inventory)
            return inventory

        for manifest_path in self.find_manifest_files(root):
            parsed = self._parse_manifest(root, manifest_path)
            rel_path = manifest_path.relative_to(root).as_posix()
            manifest_entry = {
                "path": rel_path,
                "language": parsed["language"],
                "manager": parsed["manager"],
                "package_count": len(parsed["packages"]),
            }
            if parsed.get("error"):
                manifest_entry["parse_error"] = parsed["error"]
                inventory["parse_errors"].append({"path": rel_path, "error": parsed["error"]})

            inventory["manifests"].append(manifest_entry)
            inventory["dependency_files"].setdefault(parsed["language"], []).append(rel_path)
            inventory["language_scans"].setdefault(parsed["language"], {})[rel_path] = {
                "manager": parsed["manager"],
                "packages": parsed["packages"],
            }
            inventory["packages"].extend(parsed["packages"])

        languages = sorted(inventory["dependency_files"])
        unpinned_dependencies = sum(1 for package in inventory["packages"] if not package.get("pinned"))
        inventory["summary"] = {
            "total_dependency_files": len(inventory["manifests"]),
            "languages_detected": languages,
            "total_packages": len(inventory["packages"]),
            "unpinned_dependencies": unpinned_dependencies,
            "total_vulnerabilities": 0,
            "parse_errors_count": len(inventory["parse_errors"]),
            "scan_completed": True,
        }
        inventory["tooling"] = self._build_tooling_payload(inventory)
        return inventory

    def analyze_dependencies_comprehensive(self, directory):
        """Backward-compatible alias for legacy callers."""
        return self.build_dependency_inventory(directory)

    def find_manifest_files(self, directory):
        manifests = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS and not d.startswith("backup_")]
            for file_name in files:
                if file_name in self.SUPPORTED_FILES:
                    manifests.append(Path(root) / file_name)
        return sorted(manifests)

    def _parse_manifest(self, root, manifest_path):
        language, manager = self.SUPPORTED_FILES[manifest_path.name]
        try:
            parser_map = {
                "requirements.txt": self._parse_requirements,
                "Pipfile": self._parse_pipfile,
                "pyproject.toml": self._parse_pyproject,
                "setup.py": self._parse_setup_py,
                "package.json": self._parse_package_json,
                "package-lock.json": self._parse_package_lock,
                "go.mod": self._parse_go_mod,
                "Cargo.toml": self._parse_cargo_toml,
            }
            packages = parser_map[manifest_path.name](root, manifest_path)
            return {"language": language, "manager": manager, "packages": packages}
        except Exception as exc:
            return {"language": language, "manager": manager, "packages": [], "error": str(exc)}

    def _parse_requirements(self, root, manifest_path):
        packages = []
        for raw_line in manifest_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(("-r", "--", "git+", "http://", "https://")):
                continue
            if line.startswith("-e ") and "#egg=" in line:
                line = line.split("#egg=", 1)[1]
            package = self._package_from_requirement(root, manifest_path, line, "default")
            if package:
                packages.append(package)
        return packages

    def _parse_pipfile(self, root, manifest_path):
        if tomllib is None:
            raise RuntimeError("tomllib is required to parse Pipfile")
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        packages = []
        for section_name, dependency_type in (("packages", "default"), ("dev-packages", "development")):
            for name, spec in (data.get(section_name) or {}).items():
                version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else "")
                packages.append(self._build_package(root, manifest_path, name, version, dependency_type))
        return packages

    def _parse_pyproject(self, root, manifest_path):
        if tomllib is None:
            raise RuntimeError("tomllib is required to parse pyproject.toml")
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        packages = []
        project = data.get("project") or {}
        for requirement in project.get("dependencies") or []:
            package = self._package_from_requirement(root, manifest_path, requirement, "default")
            if package:
                packages.append(package)
        for group_name, requirements in (project.get("optional-dependencies") or {}).items():
            for requirement in requirements:
                package = self._package_from_requirement(root, manifest_path, requirement, group_name)
                if package:
                    packages.append(package)

        poetry = ((data.get("tool") or {}).get("poetry") or {})
        for section_name, dependency_type in (("dependencies", "default"), ("dev-dependencies", "development")):
            for name, spec in (poetry.get(section_name) or {}).items():
                if name.lower() == "python":
                    continue
                version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else "")
                packages.append(self._build_package(root, manifest_path, name, version, dependency_type))
        for group_name, group_data in (poetry.get("group") or {}).items():
            for name, spec in ((group_data or {}).get("dependencies") or {}).items():
                version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else "")
                packages.append(self._build_package(root, manifest_path, name, version, group_name))
        return packages

    def _parse_setup_py(self, root, manifest_path):
        content = manifest_path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if not match:
            return []
        packages = []
        for requirement in re.findall(r"['\"]([^'\"]+)['\"]", match.group(1)):
            package = self._package_from_requirement(root, manifest_path, requirement, "default")
            if package:
                packages.append(package)
        return packages

    def _parse_package_json(self, root, manifest_path):
        data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        packages = []
        for section_name, dependency_type in (
            ("dependencies", "default"),
            ("devDependencies", "development"),
            ("peerDependencies", "peer"),
            ("optionalDependencies", "optional"),
        ):
            for name, version in (data.get(section_name) or {}).items():
                packages.append(self._build_package(root, manifest_path, name, version, dependency_type))
        return packages

    def _parse_package_lock(self, root, manifest_path):
        data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        packages = []
        for name, details in (data.get("packages") or {}).items():
            if not name:
                continue
            package_name = name.split("node_modules/")[-1]
            version = (details or {}).get("version")
            if package_name and version:
                packages.append(self._build_package(root, manifest_path, package_name, version, "lockfile"))
        if packages:
            return packages
        for name, details in (data.get("dependencies") or {}).items():
            packages.append(self._build_package(root, manifest_path, name, (details or {}).get("version"), "lockfile"))
        return [package for package in packages if package.get("version")]

    def _parse_go_mod(self, root, manifest_path):
        packages = []
        in_block = False
        for raw_line in manifest_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue
            if line == "require (":
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if line.startswith("require "):
                line = line[len("require "):].strip()
            match = re.match(r"^([^\s]+)\s+v([^\s]+)", line)
            if match:
                packages.append(self._build_package(root, manifest_path, match.group(1), match.group(2), "default"))
        return packages

    def _parse_cargo_toml(self, root, manifest_path):
        if tomllib is None:
            raise RuntimeError("tomllib is required to parse Cargo.toml")
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
        packages = []
        for section_name, dependency_type in (("dependencies", "default"), ("dev-dependencies", "development"), ("build-dependencies", "build")):
            for name, spec in (data.get(section_name) or {}).items():
                version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else "")
                packages.append(self._build_package(root, manifest_path, name, version, dependency_type))
        return packages

    def _package_from_requirement(self, root, manifest_path, requirement, dependency_type):
        requirement = requirement.strip().split(";", 1)[0].strip()
        if not requirement:
            return None
        match = re.match(r"^([A-Za-z0-9_.-]+)(.*)$", requirement)
        if not match:
            return None
        name, version = match.group(1), match.group(2).strip()
        return self._build_package(root, manifest_path, name, version, dependency_type, requirement)

    def _build_package(self, root, manifest_path, name, version, dependency_type, raw_requirement=None):
        version = (version or "").strip()
        return {
            "name": name,
            "version": version,
            "requirement": raw_requirement or f"{name}{version}",
            "dependency_type": dependency_type,
            "language": self.SUPPORTED_FILES[manifest_path.name][0],
            "manager": self.SUPPORTED_FILES[manifest_path.name][1],
            "manifest_path": manifest_path.relative_to(root).as_posix(),
            "pinned": self._is_pinned_version(version),
        }

    def _is_pinned_version(self, version):
        cleaned = (version or "").strip().strip("'").strip('"')
        if not cleaned:
            return False
        if cleaned.startswith("=="):
            return True
        if any(marker in cleaned for marker in ("^", "~", "*", ">", "<", "!=", ",", "||", " ")):
            return False
        if cleaned.startswith(("git+", "file:", "path:", "workspace", "latest")):
            return False
        return True

    def _build_tooling_payload(self, inventory):
        summary = inventory.get("summary") or {}
        return {
            "scanner": "DependencyScanner",
            "mode": "offline_manifest_inventory",
            "manifest_count": summary.get("total_dependency_files", 0),
            "package_count": summary.get("total_packages", 0),
            "available_tools": self.tools_available,
            "executed_scans": ["dependency_inventory"],
            "tool_status": {
                "dependency_inventory": {
                    "available": True,
                    "executed": True,
                    "kind": "built_in",
                    "findings_count": summary.get("total_dependency_files", 0),
                },
                "dependency-check": {
                    "available": self.tools_available["dependency-check"],
                    "executed": False,
                    "kind": "external",
                },
            },
        }


def build_dependency_inventory(directory):
    """Convenience wrapper for the active BlueScrub pipeline."""
    return DependencyScanner().build_dependency_inventory(directory)


def main():
    if len(sys.argv) != 2:
        logger.info("Usage: python3 dependency_scanner.py <directory>")
        sys.exit(1)
    result = build_dependency_inventory(sys.argv[1])
    logger.info(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()