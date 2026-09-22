from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.chat import (
    ChatComparisonBranch,
    ChatComparisonGroup,
    ChatConversation,
    ChatMessage,
)
from backend.app.models.job import Job
from backend.app.schemas.chat import ChatRequestBody
from backend.app.services.chat_comparisons import (
    ComparisonValidationError,
    create_mnemos_copy_branch,
    create_mnemos_snapshot,
    prompt_history_for_branch,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    yield db
    db.close()
    engine.dispose()


def _add_job(session: Session, job_id: str = "job-1") -> Job:
    job = Job(
        job_id=job_id,
        status="completed",
        execution_profile="standard",
        priority="normal",
        source_type="pcap",
        created_at="2026-09-22T00:00:00Z",
    )
    session.add(job)
    session.flush()
    return job


def _add_root(session: Session, *, job_id: str = "job-1") -> ChatConversation:
    _add_job(session, job_id)
    root = ChatConversation(
        id=f"root-{job_id}",
        job_id=job_id,
        title="Investigation chat",
        mode="baseline",
        created_at="2026-09-22T00:00:00Z",
        updated_at="2026-09-22T00:00:00Z",
    )
    session.add(root)
    session.flush()
    return root


def _add_message(
    session: Session,
    conversation_id: str,
    *,
    message_id: str,
    sequence: int,
    role: str,
    content: str,
    created_at: str,
    request_id: str | None = None,
) -> ChatMessage:
    message = ChatMessage(
        id=message_id,
        conversation_id=conversation_id,
        sequence=sequence,
        role=role,
        content=content,
        created_at=created_at,
        request_id=request_id,
    )
    session.add(message)
    return message


def seed_baseline_turns(session: Session):
    root = _add_root(session)
    question = _add_message(
        session,
        root.id,
        message_id="question-1",
        sequence=1,
        role="user",
        content="What contacted the host?",
        created_at="2026-09-22T00:00:03Z",
    )
    answer = _add_message(
        session,
        root.id,
        message_id="answer-1",
        sequence=2,
        role="assistant",
        content="A periodic HTTPS destination.",
        created_at="2026-09-22T00:00:01Z",
    )
    later = _add_message(
        session,
        root.id,
        message_id="question-2",
        sequence=3,
        role="user",
        content="Was it confirmed malicious?",
        created_at="2026-09-22T00:00:02Z",
    )
    _add_message(
        session,
        root.id,
        message_id="answer-2",
        sequence=4,
        role="assistant",
        content="The current evidence does not confirm that.",
        created_at="2026-09-22T00:00:00Z",
    )
    session.commit()
    return root, question, answer, later


def test_copy_branch_contains_only_messages_before_the_source_question(session) -> None:
    root, question, _answer, _later = seed_baseline_turns(session)

    branch = create_mnemos_copy_branch(
        session,
        root_conversation_id=root.id,
        source_message_id=question.id,
    )

    assert prompt_history_for_branch(session, branch.id) == []
    assert branch.source_message_id == question.id
    assert branch.history_cutoff_sequence == question.sequence - 1


def test_copy_source_must_be_a_user_message_in_the_selected_root(session) -> None:
    root, _question, answer, _later = seed_baseline_turns(session)

    with pytest.raises(ComparisonValidationError, match="user message"):
        create_mnemos_copy_branch(
            session,
            root_conversation_id=root.id,
            source_message_id=answer.id,
        )


def test_copy_source_must_have_a_completed_answer(session) -> None:
    root, _question, _answer, later = seed_baseline_turns(session)
    session.delete(
        session.scalar(
            select(ChatMessage).where(
                ChatMessage.conversation_id == root.id,
                ChatMessage.sequence == later.sequence + 1,
            )
        )
    )
    session.commit()

    with pytest.raises(ComparisonValidationError, match="completed"):
        create_mnemos_copy_branch(
            session,
            root_conversation_id=root.id,
            source_message_id=later.id,
        )


def test_copy_source_must_belong_to_the_selected_root(session) -> None:
    root, _question, _answer, _later = seed_baseline_turns(session)
    other = _add_root(session, job_id="job-2")
    other_question = _add_message(
        session,
        other.id,
        message_id="other-question",
        sequence=1,
        role="user",
        content="Other question",
        created_at="2026-09-22T01:00:00Z",
    )
    _add_message(
        session,
        other.id,
        message_id="other-answer",
        sequence=2,
        role="assistant",
        content="Other answer",
        created_at="2026-09-22T01:00:01Z",
    )
    session.commit()

    with pytest.raises(ComparisonValidationError, match="selected root"):
        create_mnemos_copy_branch(
            session,
            root_conversation_id=root.id,
            source_message_id=other_question.id,
        )


def test_first_snapshot_is_reused_and_stops_at_latest_completed_root_message(session) -> None:
    root, _question, _answer, _later = seed_baseline_turns(session)
    _add_message(
        session,
        root.id,
        message_id="in-flight-question",
        sequence=5,
        role="user",
        content="This turn is still running",
        created_at="2026-09-22T00:00:05Z",
    )
    session.commit()

    first = create_mnemos_snapshot(session, root_conversation_id=root.id)
    second = create_mnemos_snapshot(session, root_conversation_id=root.id)

    assert second.id == first.id
    assert first.history_cutoff_sequence == 4
    assert prompt_history_for_branch(session, first.id) == [
        {"role": "user", "content": "What contacted the host?"},
        {"role": "assistant", "content": "A periodic HTTPS destination."},
        {"role": "user", "content": "Was it confirmed malicious?"},
        {
            "role": "assistant",
            "content": "The current evidence does not confirm that.",
        },
    ]
    assert (
        session.scalar(
            select(func.count(ChatComparisonBranch.id)).where(
                ChatComparisonBranch.group_id == first.group_id,
                ChatComparisonBranch.source_message_id.is_(None),
            )
        )
        == 1
    )


def test_copy_creates_distinct_branches_and_preserves_branch_local_history(session) -> None:
    root, question, _answer, later = seed_baseline_turns(session)
    first = create_mnemos_copy_branch(
        session,
        root_conversation_id=root.id,
        source_message_id=question.id,
    )
    _add_message(
        session,
        first.conversation_id,
        message_id="mnemos-question",
        sequence=1,
        role="user",
        content="Edited comparison prompt",
        created_at="2026-09-22T03:00:02Z",
    )
    _add_message(
        session,
        first.conversation_id,
        message_id="mnemos-answer",
        sequence=2,
        role="assistant",
        content="Historical context answer",
        created_at="2026-09-22T03:00:01Z",
    )
    session.commit()

    second = create_mnemos_copy_branch(
        session,
        root_conversation_id=root.id,
        source_message_id=later.id,
    )

    assert second.id != first.id
    assert session.get(ChatComparisonBranch, first.id) is not None
    assert prompt_history_for_branch(session, first.id) == [
        {"role": "user", "content": "Edited comparison prompt"},
        {"role": "assistant", "content": "Historical context answer"},
    ]
    assert prompt_history_for_branch(session, second.id) == [
        {"role": "user", "content": "What contacted the host?"},
        {"role": "assistant", "content": "A periodic HTTPS destination."},
    ]
    group = session.get(ChatComparisonGroup, second.group_id)
    assert group.active_branch_id == second.id


def test_branch_history_ignores_incomplete_branch_turn(session) -> None:
    root, question, _answer, _later = seed_baseline_turns(session)
    branch = create_mnemos_copy_branch(
        session,
        root_conversation_id=root.id,
        source_message_id=question.id,
    )
    _add_message(
        session,
        branch.conversation_id,
        message_id="unfinished",
        sequence=1,
        role="user",
        content="Do not leak a failed or running turn",
        created_at="2026-09-22T04:00:00Z",
    )
    session.commit()

    assert prompt_history_for_branch(session, branch.id) == []


def test_root_must_be_a_baseline_conversation(session) -> None:
    root = _add_root(session)
    root.mode = "mnemos"
    session.commit()

    with pytest.raises(ComparisonValidationError, match="baseline"):
        create_mnemos_snapshot(session, root_conversation_id=root.id)


def test_duplicate_request_identity_is_rejected_within_one_conversation(session) -> None:
    root = _add_root(session)
    _add_message(
        session,
        root.id,
        message_id="request-1",
        sequence=1,
        role="user",
        content="First submission",
        created_at="2026-09-22T00:00:00Z",
        request_id="req-1",
    )
    session.commit()
    _add_message(
        session,
        root.id,
        message_id="request-2",
        sequence=2,
        role="user",
        content="Retry of the same submission",
        created_at="2026-09-22T00:00:01Z",
        request_id="req-1",
    )

    with pytest.raises(IntegrityError):
        session.commit()


def test_legacy_message_writes_receive_monotonic_sequences(session) -> None:
    root = _add_root(session)
    session.add_all(
        [
            ChatMessage(
                id="implicit-1",
                conversation_id=root.id,
                role="user",
                content="Question",
                created_at="2026-09-22T00:00:00Z",
            ),
            ChatMessage(
                id="implicit-2",
                conversation_id=root.id,
                role="assistant",
                content="Answer",
                created_at="2026-09-22T00:00:01Z",
            ),
        ]
    )
    session.commit()

    assert list(
        session.scalars(
            select(ChatMessage.sequence)
            .where(ChatMessage.conversation_id == root.id)
            .order_by(ChatMessage.sequence)
        )
    ) == [1, 2]


def test_request_schema_defaults_to_baseline_and_accepts_comparison_fields() -> None:
    assert ChatRequestBody(message="question").mode == "baseline"
    body = ChatRequestBody(
        message="question",
        mode="mnemos",
        request_id="req-1",
        comparison_source_message_id="message-1",
    )
    assert body.mode == "mnemos"
    assert body.request_id == "req-1"
    assert body.comparison_source_message_id == "message-1"

    with pytest.raises(ValidationError):
        ChatRequestBody(message="question", mode="unsupported")
