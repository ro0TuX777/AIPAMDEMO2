"""Local durable storage for MNEMOS answer evidence receipts."""

import base64
import hashlib
import json
import logging
import os
import re
import tempfile
from pathlib import Path


logger = logging.getLogger(__name__)
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def _valid_id(receipt_id: object) -> bool:
    return isinstance(receipt_id, str) and _SAFE_ID.fullmatch(receipt_id) is not None


def build_evidence_receipt(
    *, receipt_id: str, created_at: str, job_id: str, conversation_id: str,
    assistant_message_id: str, request_id: str | None, query: str, answer: str,
    model_id: str | None, generation: dict | None, runtime: dict | None,
    retrieval_status: str | None, citations: list[dict], evidence_refs: list[dict],
) -> dict:
    """Build a receipt whose hash covers its canonical factual JSON content."""
    if not _valid_id(receipt_id):
        raise ValueError("Invalid evidence receipt ID")
    receipt = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "created_at": created_at,
        "job_id": job_id,
        "conversation_id": conversation_id,
        "assistant_message_id": assistant_message_id,
        "request_id": request_id,
        "query": query,
        "answer": answer,
        "model_id": model_id,
        "generation": generation,
        "runtime": runtime,
        "retrieval_status": retrieval_status,
        "citations": citations,
        "evidence_refs": evidence_refs,
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    receipt["content_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return receipt


def _read_receipt(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            receipt = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(receipt, dict) or receipt.get("receipt_id") != path.stem:
        return None
    if not _valid_id(receipt["receipt_id"]) or not isinstance(receipt.get("created_at"), str):
        return None
    return receipt


def _active_receipts(receipt_dir: Path) -> list[tuple[Path, dict]]:
    return [(path, receipt) for path in receipt_dir.glob("*.json") if (receipt := _read_receipt(path)) is not None]


def write_evidence_receipt(receipt_dir: Path, receipt: dict, *, max_files: int = 500) -> Path:
    """Publish atomically, then move oldest active receipts into archive/."""
    receipt_id = receipt.get("receipt_id") if isinstance(receipt, dict) else None
    if not _valid_id(receipt_id):
        raise ValueError("Invalid evidence receipt ID")
    if max_files < 1:
        raise ValueError("max_files must be positive")
    receipt_dir = Path(receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = receipt_dir / f"{receipt_id}.json"
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=receipt_dir, delete=False) as handle:
            temp_path = Path(handle.name)
            json.dump(receipt, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, receipt_path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    active = _active_receipts(receipt_dir)
    overflow = len(active) - max_files
    if overflow > 0:
        oldest = sorted(active, key=lambda item: (item[1]["created_at"], item[1]["receipt_id"]))[:overflow]
        try:
            archive = receipt_dir / "archive"
            archive.mkdir(exist_ok=True)
            for path, _ in oldest:
                os.replace(path, archive / path.name)
        except OSError:
            logger.exception("Could not archive evidence receipts in %s", receipt_dir)
    return receipt_path


def load_evidence_receipt(receipt_dir: Path, receipt_id: str) -> dict | None:
    """Load only a safe named receipt from active or archive storage."""
    if not _valid_id(receipt_id):
        return None
    receipt_dir = Path(receipt_dir)
    for directory in (receipt_dir, receipt_dir / "archive"):
        receipt = _read_receipt(directory / f"{receipt_id}.json")
        if receipt is not None:
            return receipt
    return None


def _decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        pair = json.loads(raw)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid evidence receipt cursor") from exc
    if (not isinstance(pair, list) or len(pair) != 2 or
            not isinstance(pair[0], str) or not _valid_id(pair[1])):
        raise ValueError("Invalid evidence receipt cursor")
    return pair[0], pair[1]


def list_evidence_receipts(
    receipt_dir: Path, *, limit: int = 50, cursor: str | None = None,
) -> tuple[list[dict], str | None]:
    """Return a stable descending page from active and archived receipts."""
    if limit < 1:
        raise ValueError("limit must be positive")
    boundary = _decode_cursor(cursor) if cursor is not None else None
    receipt_dir = Path(receipt_dir)
    entries = _active_receipts(receipt_dir) + _active_receipts(receipt_dir / "archive")
    ordered = sorted((receipt for _, receipt in entries),
                     key=lambda item: (item["created_at"], item["receipt_id"]), reverse=True)
    if boundary is not None:
        ordered = [item for item in ordered if (item["created_at"], item["receipt_id"]) < boundary]
    page = ordered[:limit]
    next_cursor = None
    if len(ordered) > limit:
        last = page[-1]
        payload = json.dumps([last["created_at"], last["receipt_id"]], separators=(",", ":"))
        next_cursor = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return page, next_cursor
