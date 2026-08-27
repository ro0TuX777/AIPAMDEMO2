"""Dirty Word / Attribution Leakage Scanner.

Manages per-project word lists and scans uploaded directories for matches.
Word lists are stored as JSON files under ``analysis_results/word_lists/``.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional

WORD_LISTS_DIR = os.path.join("analysis_results", "word_lists")
GLOBAL_LISTS_DIR = os.path.join("analysis_results", "global_word_lists")
DEVELOPER_NOTE_MARKERS = ["TO" + "DO", "FIX" + "ME", "H" + "ACK", "X" * 3, "DEBUG"]

# Binary extensions that should be searched via raw byte matching
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".bin", ".so", ".o", ".obj", ".elf",
    ".sys", ".drv", ".ocx", ".dat", ".raw", ".img",
}

# Max file size to scan (50 MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

# ---------------------------------------------------------------------------
# Default prebuilt data (seeded on first access)
# ---------------------------------------------------------------------------

_DEFAULT_PREBUILT = [
    {
        "id": "prebuilt_common_leaks",
        "name": "🔑 Common Leaks (OPSEC)",
        "description": "Usernames, paths, emails and hostnames that commonly leak into exploit code.",
        "words": [
            "Administrator", "admin", "root", "user", "jdoe", "test",
            "C:\\Users\\", "C:\\Windows\\Temp", "/home/", "/tmp/",
            "@gmail.com", "@outlook.com", "@yahoo.com", "@protonmail.com",
            "localhost", ".internal", ".local", ".corp", ".lab",
            "password", "changeme", "passw0rd", "secret",
            *DEVELOPER_NOTE_MARKERS,
        ],
    },
    {
        "id": "prebuilt_tool_sigs",
        "name": "🔧 Tool Signatures",
        "description": "Strings that fingerprint common exploit frameworks and tools.",
        "words": [
            "msfvenom", "metasploit", "cobaltstrike", "Cobalt Strike", "beacon",
            "meterpreter", "mimikatz", "bloodhound", "rubeus", "seatbelt",
            "sharphound", "powershell empire", "empire", "havoc", "sliver",
            "brute ratel", "poshc2", "covenant", "mythic", "nighthawk",
            "impacket", "crackmapexec", "responder", "evil-winrm",
        ],
    },
    {
        "id": "prebuilt_build_artifacts",
        "name": "🏗️ Build Artifacts",
        "description": "Compiler paths, PDB strings, and build metadata that reveal dev environment.",
        "words": [
            ".pdb", "\\Debug\\", "\\Release\\", "\\x64\\", "\\x86\\",
            "Visual Studio", "MSVC", "gcc", "clang", "mingw",
            "CMakeLists", "Makefile", ".sln", ".vcxproj",
            "__FILE__", "__LINE__", "__FUNCTION__",
            "Build:", "Version:", "Compiled by",
        ],
    },
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_dir():
    os.makedirs(WORD_LISTS_DIR, exist_ok=True)

def _ensure_global_dir():
    os.makedirs(GLOBAL_LISTS_DIR, exist_ok=True)

def _list_path(list_id: str) -> str:
    return os.path.join(WORD_LISTS_DIR, f"{list_id}.json")

def _global_path(list_id: str) -> str:
    return os.path.join(GLOBAL_LISTS_DIR, f"{list_id}.json")

def _save(list_id: str, record: Dict[str, Any]) -> None:
    with open(_list_path(list_id), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

def _save_global(list_id: str, record: Dict[str, Any]) -> None:
    with open(_global_path(list_id), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

# ---------------------------------------------------------------------------
# Global / Pre-built word lists (persistent, user-editable)
# ---------------------------------------------------------------------------

def _seed_prebuilt():
    """Seed the default prebuilt lists if the global dir is empty."""
    _ensure_global_dir()
    if any(f.endswith(".json") for f in os.listdir(GLOBAL_LISTS_DIR)):
        return  # already seeded
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    for entry in _DEFAULT_PREBUILT:
        rec = {
            "id": entry["id"],
            "name": entry["name"],
            "description": entry.get("description", ""),
            "words": _dedupe(entry["words"]),
            "builtin": True,
            "created_at": now,
            "updated_at": now,
        }
        _save_global(rec["id"], rec)


def get_prebuilt_word_lists() -> List[Dict[str, Any]]:
    """Return all global/prebuilt word lists (user-editable)."""
    _seed_prebuilt()
    results = []
    for fname in sorted(os.listdir(GLOBAL_LISTS_DIR)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(GLOBAL_LISTS_DIR, fname), "r", encoding="utf-8") as f:
            results.append(json.load(f))
    return results


def create_prebuilt_word_list(name: str, words: List[str],
                              description: str = "") -> Dict[str, Any]:
    """Create a new global pre-built word list."""
    _ensure_global_dir()
    list_id = "prebuilt_" + str(uuid.uuid4())[:8]
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    rec = {
        "id": list_id,
        "name": name,
        "description": description,
        "words": _dedupe(words),
        "builtin": False,
        "created_at": now,
        "updated_at": now,
    }
    _save_global(list_id, rec)
    return rec


def update_prebuilt_word_list(list_id: str, **kwargs) -> Optional[Dict[str, Any]]:
    """Update a global pre-built word list."""
    path = _global_path(list_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        rec = json.load(f)
    for key in ("name", "description"):
        if key in kwargs:
            rec[key] = kwargs[key]
    if "words" in kwargs:
        rec["words"] = _dedupe(kwargs["words"])
    rec["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _save_global(list_id, rec)
    return rec


def delete_prebuilt_word_list(list_id: str) -> bool:
    """Delete a global pre-built word list."""
    path = _global_path(list_id)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def get_prebuilt_word_list(list_id: str) -> Optional[Dict[str, Any]]:
    """Get a single global pre-built word list."""
    path = _global_path(list_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Per-job word lists
# ---------------------------------------------------------------------------

def create_word_list(name: str, words: List[str], project: str = "",
                     description: str = "",
                     job_id: str = "") -> Dict[str, Any]:
    """Create a new word list. If *job_id* is provided it is scoped to that job."""
    _ensure_dir()
    list_id = str(uuid.uuid4())[:8]
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    record = {
        "id": list_id,
        "name": name,
        "project": project,
        "description": description,
        "words": _dedupe(words),
        "job_id": job_id,
        "created_at": now,
        "updated_at": now,
    }
    _save(list_id, record)
    return record


def get_word_list(list_id: str) -> Optional[Dict[str, Any]]:
    path = _list_path(list_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_word_lists(project: str = "", job_id: str = "") -> List[Dict[str, Any]]:
    """Return word lists, optionally filtered by project or job_id.

    If *job_id* is provided only lists scoped to that job are returned.
    If neither filter is given, all per-job lists are returned.
    """
    _ensure_dir()
    results = []
    for fname in sorted(os.listdir(WORD_LISTS_DIR)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(WORD_LISTS_DIR, fname), "r", encoding="utf-8") as f:
            rec = json.load(f)
        if job_id and rec.get("job_id", "") != job_id:
            continue
        if project and rec.get("project") != project:
            continue
        results.append(rec)
    return results


def update_word_list(list_id: str, **kwargs) -> Optional[Dict[str, Any]]:
    rec = get_word_list(list_id)
    if rec is None:
        return None
    for key in ("name", "description", "project"):
        if key in kwargs:
            rec[key] = kwargs[key]
    if "words" in kwargs:
        rec["words"] = _dedupe(kwargs["words"])
    rec["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _save(list_id, rec)
    return rec


def delete_word_list(list_id: str) -> bool:
    path = _list_path(list_id)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def parse_uploaded_words(text: str) -> List[str]:
    """Parse a newline/comma separated text blob into a word list."""
    words = []
    for line in text.splitlines():
        for part in line.split(","):
            word = part.strip()
            if word:
                words.append(word)
    return _dedupe(words)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan_directory(directory_path: str, words: List[str],
                   case_sensitive: bool = False) -> Dict[str, Any]:
    """Scan *directory_path* for occurrences of each word in *words*.

    Returns a structured result with per-file matches and context.
    """
    if not words:
        return {"matches": [], "total_matches": 0, "files_scanned": 0, "words_used": 0}

    flags = 0 if case_sensitive else re.IGNORECASE
    # Build a single alternation regex for speed
    escaped = [re.escape(w) for w in words]
    pattern = re.compile("|".join(escaped), flags)

    matches: List[Dict[str, Any]] = []
    files_scanned = 0

    for root, _dirs, files in os.walk(directory_path):
        for fname in files:
            full = os.path.join(root, fname)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > MAX_FILE_SIZE or size == 0:
                continue

            rel = os.path.relpath(full, directory_path)
            ext = os.path.splitext(fname)[1].lower()
            is_binary = ext in BINARY_EXTENSIONS

            try:
                file_matches = _scan_file(full, rel, pattern, is_binary)
                if file_matches:
                    matches.extend(file_matches)
                files_scanned += 1
            except Exception:
                continue

    return {
        "matches": matches,
        "total_matches": len(matches),
        "files_scanned": files_scanned,
        "words_used": len(words),
    }


def _scan_file(full_path, rel_path, pattern, is_binary):
    """Return list of match dicts for a single file."""
    results = []
    if is_binary:
        with open(full_path, "rb") as f:
            raw = f.read()
        text = raw.decode("latin-1")
        for m in pattern.finditer(text):
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 20)
            context = repr(text[start:end])
            results.append({
                "file": rel_path,
                "word": m.group(),
                "line": None,
                "offset": m.start(),
                "context": context,
                "type": "binary",
            })
    else:
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return results
        for line_num, line in enumerate(lines, 1):
            for m in pattern.finditer(line):
                context = line.rstrip()
                if len(context) > 200:
                    context = context[:200] + "..."
                results.append({
                    "file": rel_path,
                    "word": m.group(),
                    "line": line_num,
                    "offset": m.start(),
                    "context": context,
                    "type": "text",
                })
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedupe(words):
    seen = set()
    result = []
    for w in words:
        w = w.strip()
        if w and w.lower() not in seen:
            seen.add(w.lower())
            result.append(w)
    return result

