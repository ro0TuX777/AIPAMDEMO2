from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from backend.app.api import chat
from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.chat import ChatConversation, ChatMessage
from backend.app.models.job import Job
from backend.app.schemas.chat import (
    ChatRequestBody,
    ChatResponseBody,
    HistoricalChatCitationOut,
)
from backend.app.services.chat_comparisons import create_mnemos_snapshot
from backend.app.services.mnemos_chat_retrieval import (
    HistoricalFindingCitation,
    MnemosRetrievalResult,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    db.add(
        Job(
            job_id="job-1",
            status="completed",
            execution_profile="standard",
            priority="normal",
            source_type="pcap",
            created_at="2026-09-22T00:00:00Z",
        )
    )
    db.commit()
    yield db
    db.close()
    engine.dispose()


@pytest.fixture(autouse=True)
def no_job_kb(monkeypatch):
    async def empty_rag(*args, **kwargs):
        return "", []

    monkeypatch.setattr(chat, "_build_rag_context", empty_rag)
    monkeypatch.setenv("AIPAM_API_TOKEN", "test-token")


def used_result() -> MnemosRetrievalResult:
    return MnemosRetrievalResult(
        status="used",
        context=(
            "Historical finding F-2\n"
            "Job: job-old\n"
            "Project: project-7\n"
            "Title: Historical C2 callback\n"
            "Summary: 203.0.113.10 beaconed every 60 seconds"
        ),
        citations=[
            HistoricalFindingCitation(
                type="historical_finding",
                id="F-2",
                snippet="Historical C2 callback from 203.0.113.10",
                source_job_id="job-old",
                source_project_id="project-7",
                href="/jobs/job-old/findings/F-2",
            )
        ],
    )


def test_baseline_prepare_never_calls_mnemos(monkeypatch, session) -> None:
    async def unexpected_retrieval(*args, **kwargs):
        pytest.fail("unexpected MNEMOS call")

    monkeypatch.setattr(chat, "retrieve_historical_findings", unexpected_retrieval)

    prepared = asyncio.run(
        chat.prepare_chat_turn(
            session,
            job_id="job-1",
            body=ChatRequestBody(message="What happened?"),
        )
    )

    assert prepared.mode == "baseline"
    assert prepared.retrieval_status is None
    assert "HISTORICAL CONFIRMED FINDINGS" not in prepared.messages[0]["content"]


def test_mnemos_history_is_excluded_from_messages_and_rendered_deterministically(
    monkeypatch, session
) -> None:
    async def retrieve(*args, **kwargs):
        return used_result()

    monkeypatch.setattr(chat, "retrieve_historical_findings", retrieve)

    prepared = asyncio.run(
        chat.prepare_chat_turn(
            session,
            job_id="job-1",
            body=ChatRequestBody(message="Is this C2?", mode="mnemos"),
        )
    )

    model_input = "\n".join(message["content"] for message in prepared.messages)
    assert "Historical C2 callback" not in model_input
    assert "job-old" not in model_input
    assert "project-7" not in model_input
    assert "HISTORICAL CONFIRMED FINDINGS" not in model_input
    assert "Use only the current-job evidence above" in prepared.messages[1]["content"]
    assert prepared.retrieval_status == "used"
    assert all(citation.type != "historical_finding" for citation in prepared.citations)
    assert prepared.historical_citations[0].type == "historical_finding"
    historical = prepared.historical_citations[0]
    assert historical.source_project_id == "project-7"
    assert historical.source_job_id == "job-old"
    assert historical.href == "/jobs/job-old/findings/F-2"
    rendered, final_citations = chat._finalize_prepared_chat_response_payload(
        "No current-job evidence supports a C2 conclusion.",
        prepared,
        "Is this C2?",
    )
    assert "Historical comparison" in rendered
    assert "supporting context and are not evidence of the current job" in rendered
    assert "project=project-7 job=job-old finding=F-2" in rendered
    assert "link=/jobs/job-old/findings/F-2" in rendered
    assert rendered.count("Historical C2 callback") == 1
    assert rendered.index("Historical comparison") < rendered.index(
        "Historical C2 callback"
    )
    assert any(citation.type == "historical_finding" for citation in final_citations)


def test_mnemos_no_matches_appends_explicit_no_history_status(
    monkeypatch, session
) -> None:
    async def retrieve(*args, **kwargs):
        return MnemosRetrievalResult(status="no_matches", context="", citations=[])

    monkeypatch.setattr(chat, "retrieve_historical_findings", retrieve)

    prepared = asyncio.run(
        chat.prepare_chat_turn(
            session,
            job_id="job-1",
            body=ChatRequestBody(message="Any similar cases?", mode="mnemos"),
        )
    )

    assert prepared.retrieval_status == "no_matches"
    model_input = "\n".join(message["content"] for message in prepared.messages)
    assert "no relevant historical confirmed findings were found" not in model_input.lower()

    rendered, final_citations = chat._finalize_prepared_chat_response_payload(
        "No current-job evidence supports a conclusion.",
        prepared,
        "Any similar cases?",
    )
    assert "Historical comparison" in rendered
    assert "No relevant historical confirmed findings were found." in rendered
    assert final_citations == []


@pytest.mark.parametrize("status", ["unavailable", "error"])
def test_mnemos_unavailable_or_error_halts_preparation(
    monkeypatch, session, status
) -> None:
    async def retrieve(*args, **kwargs):
        return MnemosRetrievalResult(status=status, context="", citations=[])

    monkeypatch.setattr(chat, "retrieve_historical_findings", retrieve)

    with pytest.raises(chat.MnemosUnavailableError):
        asyncio.run(
            chat.prepare_chat_turn(
                session,
                job_id="job-1",
                body=ChatRequestBody(message="Any similar cases?", mode="mnemos"),
            )
        )


def test_chat_response_metadata_is_additive_and_typed() -> None:
    response = ChatResponseBody(
        response="Historical similarity found.",
        conversation_id="conversation-1",
        retrieval_status="used",
        model_id="aipam-trafficllm-v10",
        generation={"temperature": 0.3, "max_tokens": 4096},
        citations=[
            {
                "type": "historical_finding",
                "id": "F-2",
                "snippet": "Historical C2 callback",
                "source_job_id": "job-old",
                "source_project_id": "project-7",
                "href": "/jobs/job-old/findings/F-2",
            }
        ],
    )

    citation = response.citations[0]
    assert response.retrieval_status == "used"
    assert response.model_id == "aipam-trafficllm-v10"
    assert response.generation.temperature == 0.3
    assert response.generation.max_tokens == 4096
    assert citation.type == "historical_finding"
    assert isinstance(citation, HistoricalChatCitationOut)
    assert citation.source_job_id == "job-old"

    with pytest.raises(ValidationError):
        ChatResponseBody(
            response="Invalid historical source.",
            conversation_id="conversation-1",
            citations=[
                {
                    "type": "historical_finding",
                    "id": "F-2",
                    "snippet": "Missing source provenance",
                }
            ],
        )

    with pytest.raises(ValidationError):
        ChatResponseBody(
            response="Unknown generation field.",
            conversation_id="conversation-1",
            generation={
                "temperature": 0.3,
                "max_tokens": 4096,
                "top_p": 0.9,
            },
        )

    with pytest.raises(ValidationError):
        ChatResponseBody(
            response="Wrong generation field type.",
            conversation_id="conversation-1",
            generation={"temperature": "0.3", "max_tokens": 4096},
        )


@pytest.mark.parametrize(
    "citation",
    [
        {
            "type": "historical_finding",
            "id": "",
            "snippet": "Historical source",
            "source_job_id": "job-old",
            "source_project_id": None,
            "href": "/jobs/job-old/findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": "",
            "source_project_id": None,
            "href": "/jobs/job-old/findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": "job-old",
            "source_project_id": None,
            "href": "https://example.test/jobs/job-old/findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": "job-old",
            "source_project_id": None,
            "href": "/jobs/other-job/findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": "job\\old",
            "source_project_id": None,
            "href": "/jobs/job\\old/findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": "F?2",
            "snippet": "Historical source",
            "source_job_id": "job-old",
            "source_project_id": None,
            "href": "/jobs/job-old/findings/F?2",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": "job#old",
            "source_project_id": None,
            "href": "/jobs/job#old/findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": ".",
            "snippet": "Historical source",
            "source_job_id": "job-old",
            "source_project_id": None,
            "href": "/jobs/job-old/findings/.",
        },
        {
            "type": "historical_finding",
            "id": "..",
            "snippet": "Historical source",
            "source_job_id": "job-old",
            "source_project_id": None,
            "href": "/jobs/job-old/findings/..",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": ".",
            "source_project_id": None,
            "href": "/jobs/./findings/F-2",
        },
        {
            "type": "historical_finding",
            "id": "F-2",
            "snippet": "Historical source",
            "source_job_id": "..",
            "source_project_id": None,
            "href": "/jobs/../findings/F-2",
        },
    ],
)
def test_historical_citation_rejects_invalid_source_identity(citation) -> None:
    with pytest.raises(ValidationError):
        ChatResponseBody(
            response="Invalid historical source.",
            conversation_id="conversation-1",
            citations=[citation],
        )


def test_historical_citation_preserves_canonical_non_dot_segment_href() -> None:
    citation = HistoricalChatCitationOut(
        id="F..2",
        snippet="Historical source",
        source_job_id="job.old",
        source_project_id=None,
        href="/jobs/job.old/findings/F..2",
    )

    assert citation.href == f"/jobs/{citation.source_job_id}/findings/{citation.id}"


@pytest.mark.parametrize(
    "historical_appendix",
    [
        (
            "\r\n\r\n=== Historical comparison ===\r\n\r\n"
            "Historical-only detail from job-old"
        ),
        (
            "\r\r  ===   Historical comparison   ===  \r"
            "Historical-only detail from job-old"
        ),
        (
            " \t=== HISTORICAL COMPARISON ===  \n"
            "Historical-only detail from job-old"
        ),
    ],
)
def test_mnemos_prepare_uses_server_owned_cutoff_history(
    monkeypatch, session, historical_appendix
) -> None:
    root = ChatConversation(
        id="root-1",
        job_id="job-1",
        mode="baseline",
        created_at="2026-09-22T00:00:01Z",
        updated_at="2026-09-22T00:00:01Z",
    )
    session.add(root)
    session.flush()
    session.add_all(
        [
            ChatMessage(
                id="q-1",
                conversation_id=root.id,
                sequence=1,
                role="user",
                content="Earlier question",
                created_at="2026-09-22T00:00:02Z",
            ),
            ChatMessage(
                id="a-1",
                conversation_id=root.id,
                sequence=2,
                role="assistant",
                content="Earlier answer",
                created_at="2026-09-22T00:00:03Z",
            ),
        ]
    )
    session.flush()
    branch = create_mnemos_snapshot(session, root_conversation_id=root.id)
    session.add_all(
        [
            ChatMessage(
                id="branch-q-1",
                conversation_id=branch.conversation_id,
                sequence=1,
                role="user",
                content="Prior comparison question",
                created_at="2026-09-22T00:00:04Z",
            ),
            ChatMessage(
                id="branch-a-1",
                conversation_id=branch.conversation_id,
                sequence=2,
                role="assistant",
                content=f"Prior current-job answer{historical_appendix}",
                created_at="2026-09-22T00:00:05Z",
            ),
        ]
    )
    session.flush()

    async def retrieve(*args, **kwargs):
        return MnemosRetrievalResult(status="no_matches", context="", citations=[])

    monkeypatch.setattr(chat, "retrieve_historical_findings", retrieve)
    prepared = asyncio.run(
        chat.prepare_chat_turn(
            session,
            job_id="job-1",
            body=ChatRequestBody(
                message="New MNEMOS question",
                mode="mnemos",
                conversation_id=branch.conversation_id,
            ),
        )
    )

    assert prepared.history == [
        {"role": "user", "content": "Earlier question"},
        {"role": "assistant", "content": "Earlier answer"},
        {"role": "user", "content": "Prior comparison question"},
        {
            "role": "assistant",
            "content": f"Prior current-job answer{historical_appendix}",
        },
    ]
    assert prepared.messages[-5:] == [
        {"role": "user", "content": "Earlier question"},
        {"role": "assistant", "content": "Earlier answer"},
        {"role": "user", "content": "Prior comparison question"},
        {"role": "assistant", "content": "Prior current-job answer"},
        {"role": "user", "content": "New MNEMOS question"},
    ]
