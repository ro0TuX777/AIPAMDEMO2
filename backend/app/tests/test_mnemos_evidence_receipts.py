"""Storage contract for AIPAM-owned MNEMOS evidence receipts."""

import hashlib
import json
from pathlib import Path

import pytest

from backend.app.config_v2 import Settings
from backend.app.services import mnemos_evidence_receipts as receipts


def make_receipt(receipt_id: str, created_at: str = "2026-09-24T00:00:00Z") -> dict:
    return receipts.build_evidence_receipt(
        receipt_id=receipt_id,
        created_at=created_at,
        job_id="job-1",
        conversation_id="conversation-1",
        assistant_message_id="assistant-1",
        request_id=None,
        query="What happened?",
        answer="An alert fired.",
        model_id="model-1",
        generation={"temperature": 0.2},
        runtime={"provider": "local"},
        retrieval_status="completed",
        citations=[{"id": "citation-1"}],
        evidence_refs=[{"id": "evidence-1"}],
    )


def test_build_receipt_has_canonical_content_hash():
    receipt = make_receipt("mnemos-assistant-1")
    assert receipt["schema_version"] == 1
    assert receipt["receipt_id"] == "mnemos-assistant-1"
    assert receipt["created_at"] == "2026-09-24T00:00:00Z"
    assert receipt["request_id"] is None
    assert receipt["query"] == "What happened?"
    assert receipt["answer"] == "An alert fired."
    assert receipt["citations"] == [{"id": "citation-1"}]
    assert receipt["evidence_refs"] == [{"id": "evidence-1"}]
    core = {key: value for key, value in receipt.items() if key != "content_hash"}
    digest = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert receipt["content_hash"] == f"sha256:{digest}"


@pytest.mark.parametrize("receipt_id", ["../escape", "a/b", "a\\b", "", ".", "a..b", "a?b"])
def test_unsafe_ids_are_rejected_for_writes_and_reads(tmp_path: Path, receipt_id: str):
    with pytest.raises(ValueError):
        receipts.write_evidence_receipt(tmp_path, {"receipt_id": receipt_id})
    assert receipts.load_evidence_receipt(tmp_path, receipt_id) is None


def test_write_uses_active_directory_and_loads_receipt(tmp_path: Path):
    receipt = make_receipt("mnemos-one")
    path = receipts.write_evidence_receipt(tmp_path, receipt)
    assert path == tmp_path / "mnemos-one.json"
    assert json.loads(path.read_text(encoding="utf-8")) == receipt
    assert receipts.load_evidence_receipt(tmp_path, "mnemos-one") == receipt
    assert list(tmp_path.iterdir()) == [path]


def test_overflow_archives_oldest_active_receipt_without_deleting_it(tmp_path: Path):
    for number in range(3):
        receipts.write_evidence_receipt(tmp_path, make_receipt(f"mnemos-{number}", f"2026-09-24T00:00:0{number}Z"), max_files=2)
    assert sorted(path.name for path in tmp_path.glob("*.json")) == ["mnemos-1.json", "mnemos-2.json"]
    assert (tmp_path / "archive" / "mnemos-0.json").is_file()
    assert receipts.load_evidence_receipt(tmp_path, "mnemos-0")["receipt_id"] == "mnemos-0"


def test_history_includes_archive_and_orders_equal_timestamps_by_id(tmp_path: Path):
    for receipt_id in ("mnemos-a", "mnemos-b", "mnemos-c"):
        receipts.write_evidence_receipt(tmp_path, make_receipt(receipt_id), max_files=2)
    items, cursor = receipts.list_evidence_receipts(tmp_path)
    assert [item["receipt_id"] for item in items] == ["mnemos-c", "mnemos-b", "mnemos-a"]
    assert cursor is None


def test_cursor_pages_are_stable_with_tied_timestamps_and_new_receipts(tmp_path: Path):
    for receipt_id in ("mnemos-a", "mnemos-b", "mnemos-c", "mnemos-d"):
        receipts.write_evidence_receipt(tmp_path, make_receipt(receipt_id), max_files=2)
    first, cursor = receipts.list_evidence_receipts(tmp_path, limit=2)
    assert [item["receipt_id"] for item in first] == ["mnemos-d", "mnemos-c"]
    assert cursor
    receipts.write_evidence_receipt(tmp_path, make_receipt("mnemos-e"), max_files=2)
    second, final_cursor = receipts.list_evidence_receipts(tmp_path, limit=2, cursor=cursor)
    assert [item["receipt_id"] for item in second] == ["mnemos-b", "mnemos-a"]
    assert final_cursor is None


@pytest.mark.parametrize("cursor", ["invalid", "e30", "WzEsMl0", "WyIyMDI2LTA5LTI0IiwgIi4uL2V2aWwiXQ"])
def test_malformed_cursor_is_rejected(tmp_path: Path, cursor: str):
    with pytest.raises(ValueError):
        receipts.list_evidence_receipts(tmp_path, cursor=cursor)


def test_malformed_files_and_nested_files_are_ignored(tmp_path: Path):
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    (tmp_path / "missing-id.json").write_text('{"created_at":"2026-09-24T00:00:00Z"}', encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "mnemos-hidden.json").write_text(json.dumps(make_receipt("mnemos-hidden")), encoding="utf-8")
    assert receipts.list_evidence_receipts(tmp_path) == ([], None)
    assert receipts.load_evidence_receipt(tmp_path, "broken") is None
    assert receipts.load_evidence_receipt(tmp_path, "missing-id") is None
    assert receipts.load_evidence_receipt(tmp_path, "mnemos-hidden") is None
    assert receipts.load_evidence_receipt(tmp_path, "mnemos-missing") is None


def test_failed_publish_removes_temporary_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def fail_replace(source, destination):
        raise OSError("disk failure")

    monkeypatch.setattr(receipts.os, "replace", fail_replace)
    with pytest.raises(OSError, match="disk failure"):
        receipts.write_evidence_receipt(tmp_path, make_receipt("mnemos-one"))
    assert list(tmp_path.iterdir()) == []


def test_archive_failure_retains_active_receipts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    receipts.write_evidence_receipt(tmp_path, make_receipt("mnemos-one"), max_files=1)
    original_replace = receipts.os.replace

    def fail_archive(source, destination):
        if Path(destination).parent.name == "archive":
            raise OSError("archive unavailable")
        return original_replace(source, destination)

    monkeypatch.setattr(receipts.os, "replace", fail_archive)
    receipts.write_evidence_receipt(tmp_path, make_receipt("mnemos-two", "2026-09-24T00:00:01Z"), max_files=1)
    assert (tmp_path / "mnemos-one.json").is_file()
    assert (tmp_path / "mnemos-two.json").is_file()


def test_receipt_settings_use_persistent_api_log_mount(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AIPAM_API_TOKEN", "test-token")
    settings = Settings(_env_file=None)
    assert settings.mnemos_evidence_receipt_dir == Path("/opt/aipam/logs/evidence_receipts")
    assert settings.mnemos_evidence_receipt_max_files == 500
    monkeypatch.setenv("MNEMOS_EVIDENCE_RECEIPT_DIR", "/tmp/receipts")
    assert Settings(_env_file=None).mnemos_evidence_receipt_dir == Path("/tmp/receipts")
