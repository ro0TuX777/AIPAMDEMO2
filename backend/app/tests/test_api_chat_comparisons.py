from __future__ import annotations

import json
import uuid

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from backend.app.api import chat
from backend.app.api.deps import get_db, verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.chat import (
    ChatComparisonBranch,
    ChatComparisonGroup,
    ChatConversation,
    ChatMessage,
)
from backend.app.models.job import Job
from backend.app.services.mnemos_chat_retrieval import (
    HistoricalFindingCitation,
    MnemosRetrievalResult,
)


class FakeLLM:
    def __init__(self) -> None:
        self.completion_calls = 0
        self.stream_calls = 0
        self.completion_inputs: list[list[dict]] = []
        self.fail_completion = False

    async def chat_completion(self, messages, temperature=0.3):
        self.completion_calls += 1
        self.completion_inputs.append(messages)
        if self.fail_completion:
            self.fail_completion = False
            raise RuntimeError("generation failed")
        return "Current-job answer."

    async def chat_completion_stream(self, messages, temperature=0.3):
        self.stream_calls += 1
        yield "Current-job "
        yield "answer."


@pytest.fixture()
def client(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'chat-api.db'}",
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    app = FastAPI()
    app.include_router(chat.router)

    def _db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[verify_token] = lambda: "test-token"
    app.dependency_overrides[get_settings] = lambda: Settings(
        aipam_api_token="test-token",
        aipam_job_root=tmp_path,
    )

    @app.exception_handler(HTTPException)
    async def _http_error(_request: Request, exc: HTTPException):
        content = exc.detail if isinstance(exc.detail, dict) else {"error": exc.detail}
        return JSONResponse(status_code=exc.status_code, content=content)

    fake_llm = FakeLLM()
    monkeypatch.setattr(chat, "_make_llm_client", lambda _settings: fake_llm)
    monkeypatch.setattr(chat, "get_session_factory", lambda: session_factory)

    async def empty_rag(*_args, **_kwargs):
        return "", []

    monkeypatch.setattr(chat, "_build_rag_context", empty_rag)

    with session_factory() as session:
        session.add(
            Job(
                job_id="job-1",
                status="completed",
                execution_profile="standard",
                priority="normal",
                source_type="pcap",
                created_at="2026-09-22T00:00:00Z",
            )
        )
        session.commit()
        root = ChatConversation(
            id="root-1",
            job_id="job-1",
            mode="baseline",
            title="Original title",
            created_at="2026-09-22T00:00:01Z",
            updated_at="2026-09-22T00:00:04Z",
        )
        session.add(root)
        session.add_all(
            [
                ChatMessage(
                    id="question-1",
                    conversation_id=root.id,
                    sequence=1,
                    role="user",
                    content="Was this C2 activity?",
                    created_at="2026-09-22T00:00:02Z",
                ),
                ChatMessage(
                    id="answer-1",
                    conversation_id=root.id,
                    sequence=2,
                    role="assistant",
                    content="The current evidence is inconclusive.",
                    created_at="2026-09-22T00:00:03Z",
                ),
            ]
        )
        session.commit()

    client = TestClient(app)
    client.session_factory = session_factory
    client.fake_llm = fake_llm
    with client:
        yield client
    engine.dispose()


def _used_result() -> MnemosRetrievalResult:
    return MnemosRetrievalResult(
        status="used",
        context="unused by model",
        citations=[
            HistoricalFindingCitation(
                type="historical_finding",
                id="finding-old",
                snippet="Historical confirmed beacon",
                source_job_id="job-old",
                source_project_id="project-old",
                href="/jobs/job-old/findings/finding-old",
            )
        ],
    )


def _unavailable_result() -> MnemosRetrievalResult:
    return MnemosRetrievalResult(status="unavailable", context="", citations=[])


def _open_comparison(client) -> dict:
    response = client.post(
        "/jobs/job-1/chat/comparisons",
        json={"root_conversation_id": "root-1"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _sse_payloads(response) -> list[dict | str]:
    payloads: list[dict | str] = []
    for line in response.text.splitlines():
        if not line.startswith("data: "):
            continue
        raw = line.removeprefix("data: ")
        payloads.append(raw if raw == "[DONE]" else json.loads(raw))
    return payloads


def test_opening_mnemos_twice_restores_one_snapshot(client) -> None:
    first = _open_comparison(client)
    second = _open_comparison(client)

    assert first["group_id"] == second["group_id"]
    assert first["snapshot_branch_id"] == second["snapshot_branch_id"]
    assert first["active_branch_id"] == first["snapshot_branch_id"]

    with client.session_factory() as session:
        assert session.scalar(select(func.count(ChatComparisonGroup.id))) == 1
        assert session.scalar(select(func.count(ChatComparisonBranch.id))) == 1


def test_restore_returns_group_branches_active_branch_and_messages(client) -> None:
    opened = _open_comparison(client)
    restored = client.get(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}"
    )

    assert restored.status_code == 200, restored.text
    body = restored.json()
    assert body["root_conversation_id"] == "root-1"
    assert body["active_branch_id"] == opened["snapshot_branch_id"]
    assert len(body["branches"]) == 1
    assert body["branches"][0]["conversation_id"] == opened["conversation_id"]
    assert body["branches"][0]["messages"] == []


def test_copy_branch_validates_source_ownership_and_preserves_existing_branch(client) -> None:
    opened = _open_comparison(client)
    branch_request_id = str(uuid.uuid4())
    created = client.post(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}/branches",
        json={
            "source_message_id": "question-1",
            "request_id": branch_request_id,
        },
    )

    assert created.status_code == 201, created.text
    branch = created.json()
    assert branch["source_message_id"] == "question-1"
    assert branch["history_cutoff_sequence"] == 0

    restored = client.get(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}"
    ).json()
    assert restored["active_branch_id"] == branch["id"]
    assert {item["id"] for item in restored["branches"]} == {
        opened["snapshot_branch_id"],
        branch["id"],
    }

    rejected = client.post(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}/branches",
        json={
            "source_message_id": "answer-1",
            "request_id": str(uuid.uuid4()),
        },
    )
    assert rejected.status_code == 400

    duplicate = client.post(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}/branches",
        json={
            "source_message_id": "question-1",
            "request_id": branch_request_id,
        },
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == branch["id"]

    with client.session_factory() as session:
        assert session.scalar(
            select(func.count(ChatComparisonBranch.id)).where(
                ChatComparisonBranch.group_id == opened["group_id"]
            )
        ) == 2


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_mnemos_outage_returns_retryable_error_without_llm_or_messages(
    client, monkeypatch, route
) -> None:
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: _unavailable_result(),
    )
    request_id = str(uuid.uuid4())

    response = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": "compare",
            "mode": "mnemos",
            "request_id": request_id,
        },
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MNEMOS_UNAVAILABLE"
    assert response.json()["retryable"] is True
    assert client.fake_llm.completion_calls == 0
    assert client.fake_llm.stream_calls == 0
    with client.session_factory() as session:
        assert session.scalar(
            select(func.count(ChatMessage.id)).where(
                ChatMessage.request_id == request_id
            )
        ) == 0


def test_mnemos_retrieval_exception_is_the_same_safe_503(client, monkeypatch) -> None:
    def failed_retrieval(**_kwargs):
        raise TimeoutError("internal service detail")

    monkeypatch.setattr(chat, "retrieve_historical_findings", failed_retrieval)
    response = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "compare",
            "mode": "mnemos",
            "request_id": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 503
    assert response.json() == {
        "code": "MNEMOS_UNAVAILABLE",
        "error": "MNEMOS historical retrieval is unavailable",
        "retryable": True,
    }
    assert client.fake_llm.completion_calls == 0


def test_successful_new_mnemos_turn_rejects_non_uuid_request_id(
    client, monkeypatch
) -> None:
    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(
            status="no_matches",
            context="",
            citations=[],
        ),
    )

    response = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "compare",
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": "req-1",
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_REQUEST_ID"
    assert client.fake_llm.completion_calls == 0
    with client.session_factory() as session:
        assert session.scalar(
            select(func.count(ChatMessage.id)).where(
                ChatMessage.conversation_id == opened["conversation_id"]
            )
        ) == 0


def test_json_turn_persists_provenance_and_duplicate_returns_same_turn(
    client, monkeypatch
) -> None:
    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: _used_result(),
    )
    request_id = str(uuid.uuid4())
    payload = {
        "message": "Compare this activity",
        "mode": "mnemos",
        "conversation_id": opened["conversation_id"],
        "request_id": request_id,
    }

    first = client.post("/jobs/job-1/chat", json=payload)
    second = client.post("/jobs/job-1/chat", json=payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json() == second.json()
    assert client.fake_llm.completion_calls == 1
    body = first.json()
    assert body["status"] == "completed"
    assert body["branch_id"] == opened["snapshot_branch_id"]
    assert body["retrieval_status"] == "used"
    assert body["model_id"]
    assert body["generation"]["temperature"] == 0.3
    assert body["citations"][0]["source_job_id"] == "job-old"
    assert "Historical comparison" in body["response"]

    with client.session_factory() as session:
        messages = list(
            session.scalars(
                select(ChatMessage)
                .where(ChatMessage.conversation_id == opened["conversation_id"])
                .order_by(ChatMessage.sequence)
            )
        )
        assert [message.role for message in messages] == ["user", "assistant"]
        metadata = json.loads(messages[1].metadata_json)
        assert metadata["status"] == "completed"
        assert metadata["retrieval_status"] == "used"
        assert metadata["model_id"] == body["model_id"]
        assert metadata["generation"]["temperature"] == 0.3
        assert metadata["citations"][0]["source_job_id"] == "job-old"

    restored = client.get(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}"
    ).json()
    restored_message = restored["branches"][0]["messages"][1]
    assert restored_message["metadata"]["retrieval_status"] == "used"
    assert restored_message["citations"][0]["source_job_id"] == "job-old"


def test_stream_meta_matches_json_provenance_and_completion_is_persisted_first(
    client, monkeypatch
) -> None:
    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: _used_result(),
    )

    response = client.post(
        "/jobs/job-1/chat/stream",
        json={
            "message": "Stream comparison",
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 200, response.text
    payloads = _sse_payloads(response)
    terminal_meta = [
        payload for payload in payloads
        if isinstance(payload, dict)
        and payload.get("type") == "meta"
        and payload.get("status") == "completed"
    ][0]
    assert terminal_meta["conversation_id"] == opened["conversation_id"]
    assert terminal_meta["branch_id"] == opened["snapshot_branch_id"]
    assert terminal_meta["retrieval_status"] == "used"
    assert terminal_meta["citations"][0]["source_job_id"] == "job-old"
    assert terminal_meta["model_id"]
    assert terminal_meta["generation"]["temperature"] == 0.3
    assert payloads[-1] == "[DONE]"

    with client.session_factory() as session:
        persisted = session.scalar(
            select(ChatMessage)
            .where(
                ChatMessage.conversation_id == opened["conversation_id"],
                ChatMessage.role == "assistant",
            )
            .order_by(ChatMessage.sequence.desc())
        )
        assert persisted is not None
        assert json.loads(persisted.metadata_json)["status"] == "completed"


def test_failed_generation_is_persisted_but_excluded_from_next_prompt(
    client, monkeypatch
) -> None:
    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(
            status="no_matches",
            context="",
            citations=[],
        ),
    )
    client.fake_llm.fail_completion = True

    failed = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "Failed prompt must not leak",
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": str(uuid.uuid4()),
        },
    )
    assert failed.status_code == 200
    assert failed.json()["status"] == "error"

    completed = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "Fresh prompt",
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": str(uuid.uuid4()),
        },
    )
    assert completed.status_code == 200
    second_model_input = "\n".join(
        item["content"] for item in client.fake_llm.completion_inputs[-1]
    )
    assert "Failed prompt must not leak" not in second_model_input
    assert "couldn't generate a response" not in second_model_input


def test_list_rename_and_delete_operate_on_comparison_root(client) -> None:
    opened = _open_comparison(client)

    listed = client.get("/jobs/job-1/conversations")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == ["root-1"]

    renamed = client.patch(
        "/jobs/job-1/conversations/root-1",
        json={"title": "Renamed pair"},
    )
    assert renamed.status_code == 200
    restored = client.get(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}"
    ).json()
    assert restored["title"] == "Renamed pair"

    deleted = client.delete("/jobs/job-1/conversations/root-1")
    assert deleted.status_code == 204
    with client.session_factory() as session:
        assert session.scalar(select(func.count(ChatComparisonGroup.id))) == 0
        assert session.scalar(select(func.count(ChatComparisonBranch.id))) == 0
        assert session.scalar(select(func.count(ChatConversation.id))) == 0
        assert session.scalar(select(func.count(ChatMessage.id))) == 0
