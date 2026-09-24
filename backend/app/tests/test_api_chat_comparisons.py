from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import OperationalError
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
    session_factory = sessionmaker(bind=engine, expire_on_commit=True)

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
        mnemos_evidence_receipt_dir=tmp_path / "evidence_receipts",
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
    client.receipt_dir = tmp_path / "evidence_receipts"
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


def test_first_baseline_turn_replays_without_conversation_id_across_transports(client):
    body = {"message": "First question", "request_id": str(uuid.uuid4())}
    streamed = client.post("/jobs/job-1/chat/stream", json=body)
    assert streamed.status_code == 200
    replay = client.post("/jobs/job-1/chat", json=body)
    assert replay.status_code == 200
    replay2 = client.post("/jobs/job-1/chat", json=body)
    assert replay.json() == replay2.json()
    assert client.fake_llm.completion_calls == 0
    assert client.fake_llm.stream_calls == 1
    with client.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ChatMessage).where(ChatMessage.request_id == body["request_id"])) == 1
    conflict = client.post("/jobs/job-1/chat", json={**body, "message": "Different question"})
    assert conflict.status_code == 409


def test_request_uuid_cannot_create_a_second_turn_in_another_root(client):
    body = {"message": "First question", "request_id": str(uuid.uuid4())}
    first = client.post("/jobs/job-1/chat", json=body)
    assert first.status_code == 200
    other = client.post("/jobs/job-1/chat", json={**body, "conversation_id": "root-1"})
    assert other.status_code == 409
    assert other.json()["code"] == "REQUEST_ID_CONFLICT"
    assert client.fake_llm.completion_calls == 1


@pytest.mark.parametrize("stream", [False, True])
def test_legacy_baseline_turn_without_request_id_uses_its_own_answer(client, stream):
    body = {"message": "A new legacy-client question", "conversation_id": "root-1"}
    response = client.post("/jobs/job-1/chat" + ("/stream" if stream else ""), json=body)
    assert response.status_code == 200, response.text
    if stream:
        payloads = _sse_payloads(response)
        rendered = "".join(
            payload.get("content", "")
            for payload in payloads
            if isinstance(payload, dict) and payload.get("type") in {"token", "replace"}
        )
        assert "Current-job answer." in rendered
        assert "inconclusive" not in rendered
    else:
        assert response.json()["response"].startswith("Current-job answer.")
        assert "inconclusive" not in response.json()["response"]
    follow_up = client.post(
        "/jobs/job-1/chat",
        json={"message": "Another legacy-client question", "conversation_id": "root-1"},
    )
    assert follow_up.status_code == 200, follow_up.text
    assert follow_up.json()["status"] == "completed"


def test_expired_legacy_pending_turn_without_request_id_recovers(client):
    with client.session_factory() as db:
        db.add(ChatMessage(
            id="legacy-pending",
            conversation_id="root-1",
            role="user",
            content="Interrupted legacy request",
            created_at="2000-01-01T00:00:00Z",
        ))
        db.commit()
    response = client.post(
        "/jobs/job-1/chat",
        json={"message": "Continue after interruption", "conversation_id": "root-1"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "completed"
    with client.session_factory() as db:
        interrupted = db.get(ChatMessage, "legacy-pending")
        recovered = chat._find_assistant_for_user_turn(db, user_message=interrupted)
        assert recovered is not None
        assert json.loads(recovered.metadata_json)["error_code"] == "TURN_INTERRUPTED"


@pytest.mark.parametrize("stream", [False, True])
def test_actual_generation_cancellation_terminalizes_admitted_turn(client, monkeypatch, stream):
    request_id = str(uuid.uuid4())
    async def exercise():
        started = asyncio.Event()
        async def completion(*args, **kwargs):
            started.set()
            await asyncio.Event().wait()
        async def streaming(*args, **kwargs):
            started.set()
            await asyncio.Event().wait()
            yield "never"
        monkeypatch.setattr(client.fake_llm, "chat_completion", completion)
        monkeypatch.setattr(client.fake_llm, "chat_completion_stream", streaming)
        with client.session_factory() as db:
            body = chat.ChatRequestBody(message="Cancel me", conversation_id="root-1", request_id=request_id)
            settings = Settings(aipam_api_token="test")
            if stream:
                await chat.chat_about_job_stream("job-1", body, db, settings)
                await started.wait()
                tasks = list(chat._background_tasks)
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                task = asyncio.create_task(chat.chat_about_job("job-1", body, db, settings))
                await started.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(exercise())
    replay = client.post("/jobs/job-1/chat", json={"message": "Cancel me", "conversation_id": "root-1", "request_id": request_id})
    assert replay.json()["status"] == "error"
    with client.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ChatMessage).where(ChatMessage.conversation_id == "root-1")) == 4


def test_expired_pending_turn_recovers_durably_and_rejects_late_completion(client):
    request_id = str(uuid.uuid4())
    with client.session_factory() as db:
        user = ChatMessage(id="interrupted", conversation_id="root-1", role="user", content="Interrupted", request_id=request_id,
                           created_at="2000-01-01T00:00:00Z")
        db.add(user)
        db.commit()
    body = {"conversation_id": "root-1", "message": "Interrupted", "request_id": request_id}
    recovered = client.post("/jobs/job-1/chat", json=body).json()
    assert recovered["status"] == "error"
    assert client.post("/jobs/job-1/chat", json=body).json() == recovered
    assert client.post("/jobs/job-1/chat", json={**body, "message": "New turn", "request_id": str(uuid.uuid4())}).json()["status"] == "completed"
    with client.session_factory() as db:
        late = chat._persist_assistant_turn(db, conversation_id="root-1", user_message_id="interrupted", request_id=request_id,
                                          response_text="LATE SUCCESS", final_citations=[], metadata={"status": "completed"})
        assert "LATE SUCCESS" not in late.content
    assert client.post("/jobs/job-1/chat", json=body).json() == recovered


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("late_fails", [False, True])
def test_late_generator_returns_saved_recovery_instead_of_local_result(client, monkeypatch, stream, late_fails):
    async def exercise():
        started, release = asyncio.Event(), asyncio.Event()
        async def generate(*args, **kwargs):
            started.set()
            await release.wait()
            if late_fails:
                raise RuntimeError("late failure")
            return "Too late"
        async def generate_stream(*args, **kwargs):
            yield await generate()
        monkeypatch.setattr(client.fake_llm, "chat_completion", generate)
        monkeypatch.setattr(client.fake_llm, "chat_completion_stream", generate_stream)
        body = {"message": "Long turn", "request_id": str(uuid.uuid4())}
        async with AsyncClient(transport=ASGITransport(app=client.app), base_url="http://test") as api:
            original = asyncio.create_task(api.post("/jobs/job-1/chat" + ("/stream" if stream else ""), json=body))
            await started.wait()
            pending = await api.post("/jobs/job-1/chat", json=body)
            assert pending.json()["status"] == "pending"
            assert pending.json().get("receipt_id") is None
            assert pending.json()["retry_after_seconds"] == 2
            with client.session_factory() as db:
                user = db.scalar(select(ChatMessage).where(ChatMessage.request_id == body["request_id"]))
                user.metadata_json = '{"lease_expires_at":"2000-01-01T00:00:00Z"}'
                db.commit()
            recovered = (await api.post("/jobs/job-1/chat", json=body)).json()
            release.set()
            result = await original
            if stream:
                events = [json.loads(line[6:]) for line in result.text.splitlines() if line.startswith("data: {")]
                assert [event for event in events if event["type"] == "meta"][-1]["status"] == "error"
                assert [event for event in events if event["type"] == "replace"][-1]["content"] == recovered["response"]
            else:
                assert result.json() == recovered
    asyncio.run(exercise())


@pytest.mark.parametrize("change", ["finding_deleted", "job_deleted", "revoked", "changed"])
def test_saved_citations_keep_version_and_retrieval_outcome_when_source_changes(client, monkeypatch, change):
    from backend.app.models.finding import Finding
    from backend.app.services import mnemos_chat_retrieval as retrieval
    from backend.app.tests.test_mnemos_chat_retrieval import add_job, add_finding, hit, FakeMnemos
    from backend.app.forensic_memory import finding_content_sha256

    with client.session_factory() as db:
        add_job(db, "job-old")
        finding = add_finding(db, "job-old", "finding-old")
        db.commit()
        source_hash = finding_content_sha256(finding)
    monkeypatch.setattr(retrieval, "get_mnemos_client", lambda: FakeMnemos([hit("x", "job-old", "finding-old")]))
    group = _open_comparison(client)
    body = {"conversation_id": group["conversation_id"], "mode": "mnemos", "request_id": str(uuid.uuid4()), "message": "What happened?"}
    result = client.post("/jobs/job-1/chat", json=body)
    assert result.status_code == 200
    saved = next(c for c in result.json()["citations"] if c["type"] == "historical_finding")
    assert saved["source_content_sha256"] == source_hash
    with client.session_factory() as db:
        finding = db.scalar(select(Finding).where(Finding.job_id == "job-old"))
        if change == "finding_deleted": db.delete(finding)
        elif change == "job_deleted": db.get(Job, "job-old").status = "deleted"
        elif change == "revoked": finding.analyst_status = "false_positive"
        else: finding.summary = "Edited source"
        db.commit()
    history = client.get(f'/jobs/job-1/conversations/{group["conversation_id"]}').json()
    answer = history["messages"][-1]
    citation = next(c for c in answer["citations"] if c["type"] == "historical_finding")
    assert citation["source_content_sha256"] == source_hash
    assert citation["source_availability"] == ("changed" if change == "changed" else "unavailable")
    assert answer["metadata"]["retrieval_status"] == "used"
    replay = client.post("/jobs/job-1/chat", json=body)
    replay_citation = next(c for c in replay.json()["citations"] if c["type"] == "historical_finding")
    assert replay_citation["source_availability"] == citation["source_availability"]
    streamed = client.post("/jobs/job-1/chat/stream", json=body)
    terminal_meta = [
        payload for payload in _sse_payloads(streamed)
        if isinstance(payload, dict) and payload.get("type") == "meta"
    ][-1]
    streamed_citation = next(c for c in terminal_meta["citations"] if c["type"] == "historical_finding")
    assert streamed_citation["source_availability"] == citation["source_availability"]


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


def test_restore_exposes_server_authorized_prefix_and_persists_owned_active_branch(client) -> None:
    opened = _open_comparison(client)
    snapshot = opened["branches"][0]

    # The snapshot receives the completed baseline transcript as a display-only
    # server projection; its own conversation remains empty.
    assert [message["id"] for message in snapshot["inherited_messages"]] == [
        "question-1", "answer-1",
    ]
    assert snapshot["inherited_root_conversation_id"] == "root-1"
    assert snapshot["inherited_cutoff_sequence"] == 2

    created = client.post(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}/branches",
        json={"source_message_id": "question-1", "request_id": str(uuid.uuid4())},
    )
    assert created.status_code == 201, created.text
    branch = created.json()
    assert branch["inherited_cutoff_sequence"] == 0
    assert branch["inherited_messages"] == []

    selected = client.patch(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}",
        json={"active_branch_id": opened["snapshot_branch_id"]},
    )
    assert selected.status_code == 200, selected.text
    assert selected.json()["active_branch_id"] == opened["snapshot_branch_id"]

    restored = client.get(f"/jobs/job-1/chat/comparisons/{opened['group_id']}")
    assert restored.status_code == 200
    assert restored.json()["active_branch_id"] == opened["snapshot_branch_id"]

    rejected = client.patch(
        f"/jobs/job-1/chat/comparisons/{opened['group_id']}",
        json={"active_branch_id": "not-owned"},
    )
    assert rejected.status_code == 400


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


def test_stream_replay_revalidates_job_and_immutable_mode(
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
    request_id = str(uuid.uuid4())
    payload = {
        "message": "private persisted answer",
        "mode": "mnemos",
        "conversation_id": opened["conversation_id"],
        "request_id": request_id,
    }
    created = client.post("/jobs/job-1/chat", json=payload)
    assert created.status_code == 200

    with client.session_factory() as session:
        session.add(
            Job(
                job_id="job-2",
                status="completed",
                execution_profile="standard",
                priority="normal",
                source_type="pcap",
                created_at="2026-09-22T00:00:00Z",
            )
        )
        session.commit()

    cross_job = client.post("/jobs/job-2/chat/stream", json=payload)
    wrong_mode = client.post(
        "/jobs/job-1/chat/stream",
        json={**payload, "mode": "baseline"},
    )

    assert cross_job.status_code == 404
    assert wrong_mode.status_code == 400
    for response in (cross_job, wrong_mode):
        assert "Current-job answer" not in response.text
        assert "private persisted answer" not in response.text


def test_concurrent_json_and_sse_turns_admit_one_and_persist_one_explicit_pair(
    client, monkeypatch
) -> None:
    opened = _open_comparison(client)

    async def scenario() -> tuple[list, list[str]]:
        retrieval_arrivals = 0
        retrieval_release = asyncio.Event()
        llm_entered = asyncio.Event()
        llm_release = asyncio.Event()

        async def synchronized_retrieval(**_kwargs):
            nonlocal retrieval_arrivals
            retrieval_arrivals += 1
            if retrieval_arrivals == 2:
                retrieval_release.set()
            await retrieval_release.wait()
            return MnemosRetrievalResult(
                status="no_matches",
                context="",
                citations=[],
            )

        async def blocked_completion(messages, temperature=0.3):
            client.fake_llm.completion_calls += 1
            client.fake_llm.completion_inputs.append(messages)
            llm_entered.set()
            await llm_release.wait()
            return "Concurrent winner answer."

        async def blocked_stream(messages, temperature=0.3):
            client.fake_llm.stream_calls += 1
            llm_entered.set()
            await llm_release.wait()
            yield "Concurrent winner answer."

        monkeypatch.setattr(
            chat,
            "retrieve_historical_findings",
            synchronized_retrieval,
        )
        client.fake_llm.chat_completion = blocked_completion
        client.fake_llm.chat_completion_stream = blocked_stream

        request_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        transport = ASGITransport(app=client.app)
        async with AsyncClient(transport=transport, base_url="http://test") as api:
            tasks = [
                asyncio.create_task(
                    api.post(
                        f"/jobs/job-1/{route}",
                        json={
                            "message": f"Concurrent prompt {index}",
                            "mode": "mnemos",
                            "conversation_id": opened["conversation_id"],
                            "request_id": request_id,
                        },
                    )
                )
                for index, (route, request_id) in enumerate(
                    zip(("chat", "chat/stream"), request_ids, strict=True)
                )
            ]
            await asyncio.wait_for(llm_entered.wait(), timeout=2)
            done, _pending = await asyncio.wait(
                tasks,
                timeout=2,
                return_when=asyncio.FIRST_COMPLETED,
            )
            assert len(done) == 1, "the distinct pending turn must be rejected"
            llm_release.set()
            responses = await asyncio.gather(*tasks)
        return responses, request_ids

    responses, request_ids = asyncio.run(scenario())

    assert sorted(response.status_code for response in responses) == [200, 409]
    assert client.fake_llm.completion_calls + client.fake_llm.stream_calls == 1
    winner = next(response for response in responses if response.status_code == 200)
    if winner.headers["content-type"].startswith("application/json"):
        assert winner.json()["status"] == "completed"
    else:
        assert '"status": "completed"' in winner.text
        assert "data: [DONE]" in winner.text

    with client.session_factory() as session:
        messages = list(
            session.scalars(
                select(ChatMessage)
                .where(ChatMessage.conversation_id == opened["conversation_id"])
                .order_by(ChatMessage.sequence)
            )
        )
        assert [message.role for message in messages] == ["user", "assistant"]
        user, assistant = messages
        assert user.request_id in request_ids
        metadata = json.loads(assistant.metadata_json)
        assert metadata["request_id"] == user.request_id
        assert metadata["user_message_id"] == user.id

    replay = client.post(
        "/jobs/job-1/chat",
        json={
            "message": user.content,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": user.request_id,
        },
    )
    assert replay.status_code == 200
    assert replay.json()["status"] == "completed"
    assert "Concurrent winner answer." in replay.json()["response"]


def test_replay_uses_explicit_assistant_origin_instead_of_adjacent_sequence(
    client,
) -> None:
    opened = _open_comparison(client)
    first_request_id = str(uuid.uuid4())
    second_request_id = str(uuid.uuid4())
    with client.session_factory() as session:
        session.add_all(
            [
                ChatMessage(
                    id="interleaved-user-1",
                    conversation_id=opened["conversation_id"],
                    sequence=1,
                    role="user",
                    content="First interleaved prompt",
                    request_id=first_request_id,
                    created_at="2026-09-22T01:00:00Z",
                ),
                ChatMessage(
                    id="interleaved-user-2",
                    conversation_id=opened["conversation_id"],
                    sequence=2,
                    role="user",
                    content="Second interleaved prompt",
                    request_id=second_request_id,
                    created_at="2026-09-22T01:00:01Z",
                ),
                ChatMessage(
                    id="interleaved-answer-1",
                    conversation_id=opened["conversation_id"],
                    sequence=3,
                    role="assistant",
                    content="Answer associated with first request",
                    metadata_json=json.dumps(
                        {
                            "status": "completed",
                            "request_id": first_request_id,
                            "user_message_id": "interleaved-user-1",
                        }
                    ),
                    created_at="2026-09-22T01:00:02Z",
                ),
                ChatMessage(
                    id="interleaved-answer-2",
                    conversation_id=opened["conversation_id"],
                    sequence=4,
                    role="assistant",
                    content="Answer associated with second request",
                    metadata_json=json.dumps(
                        {
                            "status": "completed",
                            "request_id": second_request_id,
                            "user_message_id": "interleaved-user-2",
                        }
                    ),
                    created_at="2026-09-22T01:00:03Z",
                ),
            ]
        )
        session.commit()

    replay = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "First interleaved prompt",
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": first_request_id,
        },
    )

    assert replay.status_code == 200
    assert replay.json()["response"] == "Answer associated with first request"


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


def test_completed_mnemos_json_turn_writes_and_replays_receipt(client, monkeypatch) -> None:
    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat, "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(status="no_matches", context="", citations=[]),
    )
    request_id = str(uuid.uuid4())
    body = {
        "message": "Summarize the evidence",
        "mode": "mnemos",
        "conversation_id": opened["conversation_id"],
        "request_id": request_id,
    }

    response = client.post("/jobs/job-1/chat", json=body)

    assert response.status_code == 200, response.text
    payload = response.json()
    receipt_id = payload["receipt_id"]
    assert receipt_id.startswith("mnemos-")
    receipt_files = list(client.receipt_dir.glob("*.json"))
    assert len(receipt_files) == 1
    receipt = json.loads(receipt_files[0].read_text(encoding="utf-8"))
    assert receipt["receipt_id"] == receipt_id
    assert receipt["query"] == body["message"]
    assert receipt["answer"] == payload["response"]
    assert receipt["conversation_id"] == opened["conversation_id"]

    with client.session_factory() as session:
        assistant = session.scalar(select(ChatMessage).where(
            ChatMessage.conversation_id == opened["conversation_id"],
            ChatMessage.role == "assistant",
        ))
        assert assistant is not None
        assert json.loads(assistant.metadata_json)["receipt_id"] == receipt_id

    replay = client.post("/jobs/job-1/chat", json=body)
    assert replay.status_code == 200
    assert replay.json()["receipt_id"] == receipt_id
    assert len(list(client.receipt_dir.glob("*.json"))) == 1


def test_completed_mnemos_stream_receipt_is_in_terminal_meta_and_replay(client, monkeypatch) -> None:
    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat, "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(status="no_matches", context="", citations=[]),
    )
    body = {
        "message": "Stream a receipt",
        "mode": "mnemos",
        "conversation_id": opened["conversation_id"],
        "request_id": str(uuid.uuid4()),
    }

    response = client.post("/jobs/job-1/chat/stream", json=body)
    assert response.status_code == 200, response.text
    terminal_meta = [
        payload for payload in _sse_payloads(response)
        if isinstance(payload, dict) and payload.get("type") == "meta"
        and payload.get("status") == "completed"
    ][0]
    receipt_id = terminal_meta["receipt_id"]
    assert receipt_id.startswith("mnemos-")
    assert len(list(client.receipt_dir.glob("*.json"))) == 1

    replay = client.post("/jobs/job-1/chat/stream", json=body)
    replay_meta = [
        payload for payload in _sse_payloads(replay)
        if isinstance(payload, dict) and payload.get("type") == "meta"
    ][0]
    assert replay_meta["receipt_id"] == receipt_id
    assert len(list(client.receipt_dir.glob("*.json"))) == 1


def test_baseline_failed_and_receipt_write_failure_do_not_return_dead_links(client, monkeypatch) -> None:
    baseline = client.post("/jobs/job-1/chat", json={
        "message": "Baseline question", "request_id": str(uuid.uuid4()),
    })
    assert baseline.status_code == 200
    assert baseline.json().get("receipt_id") is None

    opened = _open_comparison(client)
    monkeypatch.setattr(
        chat, "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(status="no_matches", context="", citations=[]),
    )
    client.fake_llm.fail_completion = True
    failed = client.post("/jobs/job-1/chat", json={
        "message": "Failed question", "mode": "mnemos",
        "conversation_id": opened["conversation_id"], "request_id": str(uuid.uuid4()),
    })
    assert failed.status_code == 200
    assert failed.json()["status"] == "error"
    assert failed.json().get("receipt_id") is None

    def broken_writer(*_args, **_kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(chat, "write_evidence_receipt", broken_writer)
    completed = client.post("/jobs/job-1/chat", json={
        "message": "Still answer successfully", "mode": "mnemos",
        "conversation_id": opened["conversation_id"], "request_id": str(uuid.uuid4()),
    })
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json().get("receipt_id") is None


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


def _assert_terminal_error_response(response, *, streamed: bool) -> None:
    assert response.status_code == 200, response.text
    if not streamed:
        assert response.json()["status"] == "error"
        return
    payloads = _sse_payloads(response)
    assert any(
        isinstance(payload, dict)
        and payload.get("type") == "meta"
        and payload.get("status") == "error"
        for payload in payloads
    )
    assert payloads[-1] == "[DONE]"


def _assert_failed_turn_replays_and_conversation_recovers(
    client,
    *,
    conversation_id: str,
    failed_request_id: str,
    failed_message: str,
) -> None:
    next_request_id = str(uuid.uuid4())
    completed = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "A distinct request after the failure",
            "mode": "mnemos",
            "conversation_id": conversation_id,
            "request_id": next_request_id,
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"

    replay = client.post(
        "/jobs/job-1/chat",
        json={
            "message": failed_message,
            "mode": "mnemos",
            "conversation_id": conversation_id,
            "request_id": failed_request_id,
        },
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["status"] == "error"
    assert "Current-job answer." not in replay.json()["response"]

    with client.session_factory() as session:
        messages = list(
            session.scalars(
                select(ChatMessage)
                .where(ChatMessage.conversation_id == conversation_id)
                .order_by(ChatMessage.sequence)
            )
        )
    assert [message.role for message in messages] == [
        "user",
        "assistant",
        "user",
        "assistant",
    ]
    for user, assistant in zip(messages[::2], messages[1::2], strict=True):
        metadata = json.loads(assistant.metadata_json)
        assert metadata["request_id"] == user.request_id
        assert metadata["user_message_id"] == user.id
    assert json.loads(messages[1].metadata_json)["status"] == "error"
    assert json.loads(messages[3].metadata_json)["status"] == "completed"


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_client_creation_failure_after_admission_is_terminal_and_recoverable(
    client, monkeypatch, route
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
    attempts = 0

    def fail_once(_settings):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("client construction failed")
        return client.fake_llm

    monkeypatch.setattr(chat, "_make_llm_client", fail_once)
    request_id = str(uuid.uuid4())
    message = f"Client construction failure through {route}"

    failed = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )

    _assert_terminal_error_response(failed, streamed=route.endswith("stream"))
    _assert_failed_turn_replays_and_conversation_recovers(
        client,
        conversation_id=opened["conversation_id"],
        failed_request_id=request_id,
        failed_message=message,
    )


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_client_runtime_failure_is_terminal_and_recoverable(
    client, monkeypatch, route
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
    if route == "chat":
        client.fake_llm.fail_completion = True
    else:
        original_stream = client.fake_llm.chat_completion_stream
        attempts = 0

        async def fail_stream_once(messages, temperature=0.3):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("stream runtime failed")
            async for token in original_stream(messages, temperature):
                yield token

        client.fake_llm.chat_completion_stream = fail_stream_once

    request_id = str(uuid.uuid4())
    message = f"Runtime failure through {route}"
    failed = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )

    _assert_terminal_error_response(failed, streamed=route.endswith("stream"))
    _assert_failed_turn_replays_and_conversation_recovers(
        client,
        conversation_id=opened["conversation_id"],
        failed_request_id=request_id,
        failed_message=message,
    )


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_post_generation_runtime_failure_is_terminal_and_recoverable(
    client, monkeypatch, route
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
    original_post_process = chat._post_process_response
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("post-generation processing failed")
        return original_post_process(*args, **kwargs)

    monkeypatch.setattr(chat, "_post_process_response", fail_once)
    request_id = str(uuid.uuid4())
    message = f"Post-generation failure through {route}"
    failed = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )

    _assert_terminal_error_response(failed, streamed=route.endswith("stream"))
    _assert_failed_turn_replays_and_conversation_recovers(
        client,
        conversation_id=opened["conversation_id"],
        failed_request_id=request_id,
        failed_message=message,
    )


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_one_shot_assistant_persistence_failure_recovers_with_terminal_error(
    client, monkeypatch, route
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
    original_persist = chat._persist_assistant_turn
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("one-shot persistence failure")
        return original_persist(*args, **kwargs)

    monkeypatch.setattr(chat, "_persist_assistant_turn", fail_once)
    request_id = str(uuid.uuid4())
    message = f"Persistence failure through {route}"
    failed = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )

    _assert_terminal_error_response(failed, streamed=route.endswith("stream"))
    assert attempts >= 2
    _assert_failed_turn_replays_and_conversation_recovers(
        client,
        conversation_id=opened["conversation_id"],
        failed_request_id=request_id,
        failed_message=message,
    )


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_one_shot_terminal_error_persistence_failure_is_retried(
    client, monkeypatch, route
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
    client_attempts = 0

    def fail_client_once(_settings):
        nonlocal client_attempts
        client_attempts += 1
        if client_attempts == 1:
            raise RuntimeError("client construction failed")
        return client.fake_llm

    original_persist = chat._persist_assistant_turn
    persistence_attempts = 0

    def fail_terminal_persist_once(*args, **kwargs):
        nonlocal persistence_attempts
        persistence_attempts += 1
        if persistence_attempts == 1:
            raise RuntimeError("one-shot terminal persistence failure")
        return original_persist(*args, **kwargs)

    monkeypatch.setattr(chat, "_make_llm_client", fail_client_once)
    monkeypatch.setattr(chat, "_persist_assistant_turn", fail_terminal_persist_once)
    request_id = str(uuid.uuid4())
    message = f"Terminal persistence retry through {route}"
    failed = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )

    _assert_terminal_error_response(failed, streamed=route.endswith("stream"))
    assert persistence_attempts == 2
    _assert_failed_turn_replays_and_conversation_recovers(
        client,
        conversation_id=opened["conversation_id"],
        failed_request_id=request_id,
        failed_message=message,
    )


def test_json_assistant_insert_operational_error_rolls_back_and_terminalizes(
    client, monkeypatch
) -> None:
    opened = _open_comparison(client)
    client.session_factory.configure(expire_on_commit=True)
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(
            status="no_matches",
            context="",
            citations=[],
        ),
    )
    engine = client.session_factory.kw["bind"]
    insert_failed = False

    def fail_first_assistant_insert(cursor, statement, parameters, context):
        nonlocal insert_failed
        if (
            not insert_failed
            and statement.lstrip().upper().startswith("INSERT INTO CHAT_MESSAGES")
            and isinstance(parameters, (tuple, list))
            and "assistant" in parameters
        ):
            insert_failed = True
            raise sqlite3.OperationalError("one-shot assistant INSERT failure")

    event.listen(engine, "do_execute", fail_first_assistant_insert)
    request_id = str(uuid.uuid4())
    message = "A real database flush failure"
    try:
        failed = client.post(
            "/jobs/job-1/chat",
            json={
                "message": message,
                "mode": "mnemos",
                "conversation_id": opened["conversation_id"],
                "request_id": request_id,
            },
        )
    finally:
        event.remove(engine, "do_execute", fail_first_assistant_insert)

    assert insert_failed
    _assert_terminal_error_response(failed, streamed=False)
    _assert_failed_turn_replays_and_conversation_recovers(
        client,
        conversation_id=opened["conversation_id"],
        failed_request_id=request_id,
        failed_message=message,
    )


@pytest.mark.parametrize("route", ["chat", "chat/stream"])
def test_admission_refresh_operational_error_recovers_committed_user_turn(
    client, monkeypatch, route
) -> None:
    opened = _open_comparison(client)
    client.session_factory.configure(expire_on_commit=True)
    monkeypatch.setattr(
        chat,
        "retrieve_historical_findings",
        lambda **_kwargs: MnemosRetrievalResult(
            status="no_matches",
            context="",
            citations=[],
        ),
    )
    session_class = client.session_factory.class_
    original_refresh = session_class.refresh
    refresh_failed = False

    def fail_first_message_refresh(session, instance, *args, **kwargs):
        nonlocal refresh_failed
        if not refresh_failed and isinstance(instance, ChatMessage):
            refresh_failed = True
            raise OperationalError(
                "SELECT chat_messages",
                {},
                sqlite3.OperationalError("one-shot refresh failure"),
            )
        return original_refresh(session, instance, *args, **kwargs)

    monkeypatch.setattr(session_class, "refresh", fail_first_message_refresh)
    request_id = str(uuid.uuid4())
    message = f"Admission refresh failure through {route}"
    response = client.post(
        f"/jobs/job-1/{route}",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )

    assert refresh_failed
    assert response.status_code == 200, response.text
    if route == "chat":
        assert response.json()["status"] == "completed"
    else:
        payloads = _sse_payloads(response)
        assert any(
            isinstance(payload, dict)
            and payload.get("type") == "meta"
            and payload.get("status") == "completed"
            for payload in payloads
        )
        assert payloads[-1] == "[DONE]"

    replay = client.post(
        "/jobs/job-1/chat",
        json={
            "message": message,
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": request_id,
        },
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["status"] == "completed"

    next_turn = client.post(
        "/jobs/job-1/chat",
        json={
            "message": "A distinct turn after refresh recovery",
            "mode": "mnemos",
            "conversation_id": opened["conversation_id"],
            "request_id": str(uuid.uuid4()),
        },
    )
    assert next_turn.status_code == 200, next_turn.text
    assert next_turn.json()["status"] == "completed"


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
