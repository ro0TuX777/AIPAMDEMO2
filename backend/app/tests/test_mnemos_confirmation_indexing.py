import asyncio

import pytest
from fastapi import Response
from sqlalchemy.orm import Session

from backend.app.api import findings, investigation
from backend.app.api.findings import FindingFeedbackRequest
from backend.app.schemas.investigation import StatusUpdateRequest, BulkStatusUpdateRequest
from backend.app.tests.test_mnemos_chat_retrieval import add_job, add_finding


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from backend.app.database_v2 import Base
    engine = create_engine(f"sqlite:///{tmp_path / 'index.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


@pytest.mark.parametrize("path", ["feedback", "single", "bulk"])
def test_confirmation_paths_index_committed_canonical_source(session, monkeypatch, path):
    from backend.app import mnemos_boundary
    from backend.app.forensic_memory import mnemos_document_for_finding
    add_job(session, "source")
    finding = add_finding(session, "source", "F-1", status="unreviewed")
    session.commit()
    documents = []
    class Client:
        def index(self, batch):
            with Session(session.get_bind()) as verifier:
                from backend.app.models.finding import Finding
                assert verifier.get(Finding, finding.id).analyst_status == "confirmed"
            documents.extend(batch)
            return len(batch)
    monkeypatch.setattr(mnemos_boundary, "get_mnemos_client", lambda: Client())
    async def mutate():
        kwargs = dict(job_id="source", response=Response(), db=session, request_id="test")
        if path == "feedback":
            await findings.update_finding_feedback(finding_id="F-1", body=FindingFeedbackRequest(feedback="confirmed"), **kwargs)
        elif path == "single":
            await investigation.update_item_status(item_id="finding:F-1", body=StatusUpdateRequest(analyst_status="confirmed"), **kwargs)
        else:
            await investigation.bulk_update_status(body=BulkStatusUpdateRequest(item_ids=["finding:F-1"], analyst_status="confirmed"), **kwargs)
    asyncio.run(mutate())
    assert documents == [mnemos_document_for_finding(finding, project_id=None)]


def test_confirmed_content_changes_retry_after_commit_without_leaking_failure(session, monkeypatch, caplog):
    from backend.app import mnemos_boundary
    from backend.app.forensic_memory import mnemos_document_for_finding
    add_job(session, "source")
    finding = add_finding(session, "source", "F-1")
    session.commit()
    documents = []
    class Client:
        def index(self, batch):
            documents.extend(batch)
            if len(documents) < 3: raise RuntimeError("secret-token-must-not-leak")
            return len(batch)
    monkeypatch.setattr(mnemos_boundary, "get_mnemos_client", lambda: Client())
    finding.summary = "Corrected confirmed content"
    session.commit()
    assert documents == [mnemos_document_for_finding(finding, project_id=None)] * 3
    assert "secret-token-must-not-leak" not in caplog.text
    documents.clear()
    finding.summary = "Rolled back content"
    session.flush()
    session.rollback()
    assert documents == []


def test_new_carried_forward_confirmed_finding_indexes_after_commit(session, monkeypatch):
    from backend.app import mnemos_boundary
    from backend.app.forensic_memory import mnemos_document_for_finding

    add_job(session, "source")
    session.commit()
    documents = []

    class Client:
        def index(self, batch):
            documents.extend(batch)
            return len(batch)

    monkeypatch.setattr(mnemos_boundary, "get_mnemos_client", lambda: Client())
    finding = add_finding(session, "source", "F-carried", status="confirmed")
    session.commit()

    assert documents == [mnemos_document_for_finding(finding, project_id=None)]


def test_remote_failure_cannot_rollback_feedback_or_leak_request_secrets(session, monkeypatch, caplog):
    from backend.app.mnemos_boundary import MnemosBoundaryClient
    from backend.app import mnemos_boundary
    add_job(session, "source")
    finding = add_finding(session, "source", "F-1", status="unreviewed")
    session.commit()
    calls = []
    def request(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("secret-token-must-not-leak")
    monkeypatch.setattr(mnemos_boundary, "get_mnemos_client", lambda: MnemosBoundaryClient("http://mnemos", request=request))
    asyncio.run(findings.update_finding_feedback("source", "F-1", FindingFeedbackRequest(feedback="confirmed"), Response(), "test", session))
    session.expire_all()
    assert finding.analyst_status == "confirmed"
    assert len(calls) == 3
    assert "secret-token-must-not-leak" not in caplog.text
