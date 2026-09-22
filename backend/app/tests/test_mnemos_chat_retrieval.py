from __future__ import annotations

import asyncio
import hashlib
import sys
import threading

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.bluescrub import BlueScrubJobLineage
from backend.app.models.finding import Finding
from backend.app.models.job import Job


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    yield db
    db.close()
    engine.dispose()


def add_job(session: Session, job_id: str, *, project_id: str | None = None) -> None:
    session.add(
        Job(
            job_id=job_id,
            status="completed",
            execution_profile="standard",
            priority="normal",
            source_type="pcap",
            created_at="2026-09-22T00:00:00Z",
        )
    )
    session.flush()
    if project_id is not None:
        session.add(
            BlueScrubJobLineage(
                job_id=job_id,
                project_id=project_id,
                compatibility_signature="sha256:test",
                analysis_kind="source_audit",
            )
        )


def add_finding(
    session: Session,
    job_id: str,
    finding_id: str,
    *,
    status: str = "confirmed",
    summary: str = "Beacon every 60 seconds",
) -> Finding:
    finding = Finding(
        job_id=job_id,
        finding_id=finding_id,
        sensor="c2_fusion",
        severity="high",
        category="command_and_control",
        title="C2 callback",
        summary=summary,
        evidence_json='{"dest_ip":"203.0.113.10","interval":60}',
        confidence=0.9,
        analyst_status=status,
    )
    session.add(finding)
    return finding


def hit(document: str, job_id: str, finding_id: str) -> dict:
    return {
        "document": document,
        "metadata": {"job_id": job_id, "finding_id": finding_id},
        "relevance": 0.95,
        "distance": 0.05,
    }


class FakeMnemos:
    def __init__(self, results):
        self.results = results
        self.search_thread_id: int | None = None

    def search(self, query: str, *, top_k: int, filters=None):
        self.search_thread_id = threading.get_ident()
        if isinstance(self.results, Exception):
            raise self.results
        return self.results


def test_stable_document_uses_finding_identity_project_and_content_hash(session) -> None:
    from backend.app.forensic_memory import mnemos_document_for_finding

    add_job(session, "job-old")
    finding = add_finding(session, "job-old", "F-2")
    session.flush()

    document = mnemos_document_for_finding(finding, project_id="project-7")

    expected_content = (
        "Title: C2 callback\n"
        "Severity: high\n"
        "Category: command_and_control\n"
        "Sensor: c2_fusion\n"
        "Summary: Beacon every 60 seconds\n"
        'Evidence: {"dest_ip":"203.0.113.10","interval":60}'
    )
    assert document == {
        "id": "finding:job-old:F-2",
        "content": expected_content,
        "source": "aipam.forensic_memory",
        "neuro_tags": ["forensic_finding", "confirmed"],
        "metadata": {
            "collection": "aipam_forensic_findings",
            "job_id": "job-old",
            "finding_id": "F-2",
            "project_id": "project-7",
            "content_sha256": hashlib.sha256(expected_content.encode("utf-8")).hexdigest(),
        },
    }


def test_stable_document_preserves_missing_project_as_empty_metadata(session) -> None:
    from backend.app.forensic_memory import mnemos_document_for_finding

    add_job(session, "job-old")
    finding = add_finding(session, "job-old", "F-2")
    session.flush()

    assert mnemos_document_for_finding(finding, project_id=None)["metadata"]["project_id"] == ""


def test_retrieval_excludes_current_or_unconfirmed_or_missing_sources(session, monkeypatch) -> None:
    from backend.app.services import mnemos_chat_retrieval as retrieval

    add_job(session, "job-current")
    add_finding(session, "job-current", "F-1")
    add_job(session, "job-old", project_id="project-7")
    add_finding(session, "job-old", "F-stale", status="false_positive")
    add_finding(session, "job-old", "F-2")
    session.commit()

    mnemos = FakeMnemos(
        [
            hit("current", "job-current", "F-1"),
            hit("stale", "job-old", "F-stale"),
            hit("deleted", "job-old", "F-missing"),
            hit("orphan", "job-missing", "F-9"),
            hit("confirmed", "job-old", "F-2"),
            hit("duplicate", "job-old", "F-2"),
        ]
    )
    monkeypatch.setattr(retrieval, "get_mnemos_client", lambda: mnemos)

    caller_thread_id = threading.get_ident()
    result = asyncio.run(
        retrieval.retrieve_historical_findings(
            session,
            current_job_id="job-current",
            query="C2",
        )
    )

    assert result.status == "used"
    assert [citation.id for citation in result.citations] == ["F-2"]
    assert result.citations[0].type == "historical_finding"
    assert result.citations[0].source_job_id == "job-old"
    assert result.citations[0].source_project_id == "project-7"
    assert result.citations[0].href == "/jobs/job-old/findings/F-2"
    assert "Project: project-7" in result.context
    assert "C2 callback" in result.context
    assert "stale" not in result.context
    assert "deleted" not in result.context
    assert mnemos.search_thread_id != caller_thread_id


def test_retrieval_uses_no_project_assigned_without_fabricating_project(session, monkeypatch) -> None:
    from backend.app.services import mnemos_chat_retrieval as retrieval

    add_job(session, "job-current")
    add_job(session, "job-old")
    add_finding(session, "job-old", "F-2")
    session.commit()
    monkeypatch.setattr(
        retrieval,
        "get_mnemos_client",
        lambda: FakeMnemos([hit("untrusted vector text", "job-old", "F-2")]),
    )

    result = asyncio.run(
        retrieval.retrieve_historical_findings(
            session,
            current_job_id="job-current",
            query="C2",
        )
    )

    assert result.status == "used"
    assert result.citations[0].source_project_id is None
    assert "Project: No project assigned" in result.context
    assert "untrusted vector text" not in result.context


@pytest.mark.parametrize(
    ("client", "expected_status"),
    [
        (None, "unavailable"),
        (FakeMnemos(None), "unavailable"),
        (FakeMnemos([]), "no_matches"),
        (FakeMnemos(RuntimeError("boom")), "error"),
    ],
)
def test_retrieval_distinguishes_service_outcomes(
    session, monkeypatch, client, expected_status
) -> None:
    from backend.app import forensic_memory
    from backend.app.services import mnemos_chat_retrieval as retrieval

    monkeypatch.setattr(retrieval, "get_mnemos_client", lambda: client)
    monkeypatch.setattr(
        forensic_memory,
        "get_memory_collection",
        lambda: pytest.fail("MNEMOS chat retrieval must not use local Chroma"),
    )

    result = asyncio.run(
        retrieval.retrieve_historical_findings(
            session,
            current_job_id="job-current",
            query="C2",
        )
    )

    assert result.status == expected_status
    assert result.context == ""
    assert result.citations == []


def test_retrieval_reports_client_configuration_failure_as_error(session, monkeypatch) -> None:
    from backend.app.services import mnemos_chat_retrieval as retrieval

    def fail_to_configure():
        raise RuntimeError("bad MNEMOS configuration")

    monkeypatch.setattr(retrieval, "get_mnemos_client", fail_to_configure)

    result = asyncio.run(
        retrieval.retrieve_historical_findings(
            session,
            current_job_id="job-current",
            query="C2",
        )
    )

    assert result.status == "error"
    assert result.context == ""
    assert result.citations == []


def test_retrieval_caps_deduplicated_records_and_total_prompt_characters(session, monkeypatch) -> None:
    from backend.app.services import mnemos_chat_retrieval as retrieval

    add_job(session, "job-current")
    hits = []
    for index in range(5):
        job_id = f"job-{index}"
        finding_id = f"F-{index}"
        add_job(session, job_id)
        add_finding(session, job_id, finding_id, summary="x" * 5_000)
        hits.extend([hit("ignored", job_id, finding_id), hit("duplicate", job_id, finding_id)])
    session.commit()
    monkeypatch.setattr(retrieval, "get_mnemos_client", lambda: FakeMnemos(hits))

    result = asyncio.run(
        retrieval.retrieve_historical_findings(
            session,
            current_job_id="job-current",
            query="C2",
            top_k=3,
        )
    )

    assert result.status == "used"
    assert len(result.citations) == 3
    assert len({(c.source_job_id, c.id) for c in result.citations}) == 3
    assert len(result.context) <= 4_000


class RecordingIndexer:
    def __init__(self, *, fail_batch: int | None = None) -> None:
        self.batches: list[list[dict]] = []
        self.fail_batch = fail_batch

    def index(self, documents: list[dict]) -> int | None:
        self.batches.append(documents)
        if self.fail_batch == len(self.batches):
            return None
        return len(documents)


def test_reconciliation_batches_confirmed_findings_with_repeatable_ids(session) -> None:
    from backend.app.cli import reconcile_mnemos_findings

    for index in range(3):
        job_id = f"job-{index}"
        add_job(session, job_id, project_id="project-7" if index == 0 else None)
        add_finding(session, job_id, f"F-{index}")
    add_job(session, "job-unconfirmed")
    add_finding(session, "job-unconfirmed", "F-x", status="unreviewed")
    session.commit()

    first = RecordingIndexer()
    first_counts = reconcile_mnemos_findings(session, client=first, batch_size=2)
    second = RecordingIndexer()
    second_counts = reconcile_mnemos_findings(session, client=second, batch_size=2)

    assert first_counts == {"discovered": 3, "indexed": 3, "skipped": 0, "failed": 0}
    assert second_counts == first_counts
    assert [len(batch) for batch in first.batches] == [2, 1]
    first_ids = [document["id"] for batch in first.batches for document in batch]
    second_ids = [document["id"] for batch in second.batches for document in batch]
    assert first_ids == second_ids == [
        "finding:job-0:F-0",
        "finding:job-1:F-1",
        "finding:job-2:F-2",
    ]
    assert first.batches[0][0]["metadata"]["project_id"] == "project-7"
    assert first.batches[0][1]["metadata"]["project_id"] == ""


def test_reconciliation_counts_failed_batch_and_returns_failure(session) -> None:
    from backend.app.cli import reconcile_mnemos_findings

    for index in range(3):
        job_id = f"job-{index}"
        add_job(session, job_id)
        add_finding(session, job_id, f"F-{index}")
    session.commit()

    counts = reconcile_mnemos_findings(
        session,
        client=RecordingIndexer(fail_batch=2),
        batch_size=2,
    )

    assert counts == {"discovered": 3, "indexed": 2, "skipped": 0, "failed": 1}


def test_reconciliation_command_prints_only_counts_and_exits_nonzero_when_unavailable(
    session, monkeypatch, capsys
) -> None:
    from backend.app import cli

    add_job(session, "job-old")
    add_finding(session, "job-old", "F-2")
    session.commit()

    class SessionContext:
        def __enter__(self):
            return session

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        "backend.app.database_v2.get_session_factory",
        lambda: lambda: SessionContext(),
    )
    monkeypatch.setattr("backend.app.mnemos_boundary.get_mnemos_client", lambda: None)
    monkeypatch.setattr(sys, "argv", ["aipam", "reconcile-mnemos-findings"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1
    assert capsys.readouterr().out == "discovered=1 indexed=0 skipped=0 failed=1\n"


def test_reconciliation_command_exits_nonzero_when_unavailable_without_findings(
    session, monkeypatch, capsys
) -> None:
    from backend.app import cli

    class SessionContext:
        def __enter__(self):
            return session

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        "backend.app.database_v2.get_session_factory",
        lambda: lambda: SessionContext(),
    )
    monkeypatch.setattr("backend.app.mnemos_boundary.get_mnemos_client", lambda: None)
    monkeypatch.setattr(sys, "argv", ["aipam", "reconcile-mnemos-findings"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1
    assert capsys.readouterr().out == "discovered=0 indexed=0 skipped=0 failed=0\n"


def test_reconciliation_command_prints_counts_when_client_setup_errors(
    session, monkeypatch, capsys
) -> None:
    from backend.app import cli

    class SessionContext:
        def __enter__(self):
            return session

        def __exit__(self, *args):
            return False

    def fail_to_configure():
        raise RuntimeError("bad MNEMOS configuration")

    monkeypatch.setattr(
        "backend.app.database_v2.get_session_factory",
        lambda: lambda: SessionContext(),
    )
    monkeypatch.setattr("backend.app.mnemos_boundary.get_mnemos_client", fail_to_configure)
    monkeypatch.setattr(sys, "argv", ["aipam", "reconcile-mnemos-findings"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 1
    assert capsys.readouterr().out == "discovered=0 indexed=0 skipped=0 failed=0\n"
