"""Server-owned creation and history rules for paired chat comparisons."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.models.chat import (
    ChatComparisonBranch,
    ChatComparisonGroup,
    ChatConversation,
    ChatMessage,
)


class ComparisonValidationError(ValueError):
    """A comparison request violates persisted ownership or cutoff rules."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root_conversation(db: Session, root_conversation_id: str) -> ChatConversation:
    root = db.get(ChatConversation, root_conversation_id)
    if root is None:
        raise ComparisonValidationError("baseline root conversation was not found")
    if root.mode != "baseline" or root.parent_branch_id is not None:
        raise ComparisonValidationError("selected root must be a baseline conversation")
    return root


def _comparison_group(
    db: Session,
    root: ChatConversation,
) -> ChatComparisonGroup:
    group = None
    if root.comparison_group_id is not None:
        group = db.get(ChatComparisonGroup, root.comparison_group_id)
    if group is None:
        group = db.scalar(
            select(ChatComparisonGroup).where(
                ChatComparisonGroup.root_conversation_id == root.id
            )
        )
    if group is not None:
        if group.job_id != root.job_id or group.root_conversation_id != root.id:
            raise ComparisonValidationError(
                "comparison group does not belong to the selected root job"
            )
        if root.comparison_group_id is None:
            root.comparison_group_id = group.id
        return group

    now = _now_iso()
    candidate = ChatComparisonGroup(
        id=str(uuid.uuid4()),
        job_id=root.job_id,
        root_conversation_id=root.id,
        title=root.title,
        created_at=now,
        updated_at=now,
    )
    try:
        with db.begin_nested():
            db.add(candidate)
            db.flush()
        group = candidate
    except IntegrityError:
        group = db.scalar(
            select(ChatComparisonGroup).where(
                ChatComparisonGroup.root_conversation_id == root.id
            )
        )
        if group is None:
            raise
    root.comparison_group_id = group.id
    db.flush()
    return group


def _new_branch(
    db: Session,
    *,
    root: ChatConversation,
    group: ChatComparisonGroup,
    label: str,
    source_message_id: str | None,
    history_cutoff_sequence: int,
) -> ChatComparisonBranch:
    now = _now_iso()
    conversation = ChatConversation(
        id=str(uuid.uuid4()),
        job_id=root.job_id,
        comparison_group_id=group.id,
        mode="mnemos",
        parent_branch_id=root.id,
        source_message_id=source_message_id,
        history_cutoff_sequence=history_cutoff_sequence,
        title=root.title,
        created_at=now,
        updated_at=now,
    )
    db.add(conversation)
    db.flush()
    branch = ChatComparisonBranch(
        id=str(uuid.uuid4()),
        group_id=group.id,
        conversation_id=conversation.id,
        label=label,
        source_message_id=source_message_id,
        history_cutoff_sequence=history_cutoff_sequence,
        created_at=now,
        updated_at=now,
    )
    db.add(branch)
    db.flush()
    group.active_branch_id = branch.id
    group.updated_at = now
    db.flush()
    return branch


def create_mnemos_snapshot(
    db: Session,
    *,
    root_conversation_id: str,
) -> ChatComparisonBranch:
    """Create the root's initial completed-history snapshot exactly once."""
    root = _root_conversation(db, root_conversation_id)
    group = _comparison_group(db, root)
    existing = db.scalar(
        select(ChatComparisonBranch).where(
            ChatComparisonBranch.group_id == group.id,
            ChatComparisonBranch.source_message_id.is_(None),
        )
    )
    if existing is not None:
        return existing

    cutoff = db.scalar(
        select(func.max(ChatMessage.sequence)).where(
            ChatMessage.conversation_id == root.id,
            ChatMessage.role == "assistant",
        )
    )
    try:
        with db.begin_nested():
            branch = _new_branch(
                db,
                root=root,
                group=group,
                label="MNEMOS snapshot",
                source_message_id=None,
                history_cutoff_sequence=cutoff or 0,
            )
        return branch
    except IntegrityError:
        existing = db.scalar(
            select(ChatComparisonBranch).where(
                ChatComparisonBranch.group_id == group.id,
                ChatComparisonBranch.source_message_id.is_(None),
            )
        )
        if existing is None:
            raise
        return existing


def create_mnemos_copy_branch(
    db: Session,
    *,
    root_conversation_id: str,
    source_message_id: str,
) -> ChatComparisonBranch:
    """Create a comparison branch immediately before a completed root question."""
    root = _root_conversation(db, root_conversation_id)
    source = db.get(ChatMessage, source_message_id)
    if source is None or source.conversation_id != root.id:
        raise ComparisonValidationError(
            "source message must belong to the selected root conversation"
        )
    if source.role != "user":
        raise ComparisonValidationError("comparison source must be a user message")

    completed_answer = db.scalar(
        select(ChatMessage.id).where(
            ChatMessage.conversation_id == root.id,
            ChatMessage.sequence == source.sequence + 1,
            ChatMessage.role == "assistant",
        )
    )
    if completed_answer is None:
        raise ComparisonValidationError(
            "comparison source must have a completed assistant answer"
        )

    group = _comparison_group(db, root)
    return _new_branch(
        db,
        root=root,
        group=group,
        label=f"Comparison from message {source.sequence}",
        source_message_id=source.id,
        history_cutoff_sequence=source.sequence - 1,
    )


def _completed_messages(
    db: Session,
    *,
    conversation_id: str,
    maximum_sequence: int | None = None,
) -> list[ChatMessage]:
    completed_sequence = db.scalar(
        select(func.max(ChatMessage.sequence)).where(
            ChatMessage.conversation_id == conversation_id,
            ChatMessage.role == "assistant",
            *(
                (ChatMessage.sequence <= maximum_sequence,)
                if maximum_sequence is not None
                else ()
            ),
        )
    )
    if completed_sequence is None:
        return []
    return list(
        db.scalars(
            select(ChatMessage)
            .where(
                ChatMessage.conversation_id == conversation_id,
                ChatMessage.sequence <= completed_sequence,
            )
            .order_by(ChatMessage.sequence.asc())
        )
    )


def prompt_history_for_branch(
    db: Session,
    branch_id: str,
) -> list[dict[str, str]]:
    """Return the immutable root prefix plus this branch's completed turns."""
    branch = db.get(ChatComparisonBranch, branch_id)
    if branch is None:
        raise ComparisonValidationError("comparison branch was not found")
    group = db.get(ChatComparisonGroup, branch.group_id)
    if group is None:
        raise ComparisonValidationError("comparison group was not found")
    conversation = db.get(ChatConversation, branch.conversation_id)
    if (
        conversation is None
        or conversation.mode != "mnemos"
        or conversation.job_id != group.job_id
        or conversation.comparison_group_id != group.id
        or conversation.parent_branch_id != group.root_conversation_id
        or conversation.history_cutoff_sequence is None
    ):
        raise ComparisonValidationError(
            "comparison branch does not belong to its persisted group"
        )

    if conversation.source_message_id is not None:
        source = db.get(ChatMessage, conversation.source_message_id)
        if (
            source is None
            or source.conversation_id != conversation.parent_branch_id
            or source.role != "user"
            or source.sequence - 1 != conversation.history_cutoff_sequence
        ):
            raise ComparisonValidationError(
                "comparison conversation has invalid source provenance"
            )

    root_messages = _completed_messages(
        db,
        conversation_id=conversation.parent_branch_id,
        maximum_sequence=conversation.history_cutoff_sequence,
    )
    branch_messages = _completed_messages(db, conversation_id=branch.conversation_id)
    return [
        {"role": message.role, "content": message.content}
        for message in [*root_messages, *branch_messages]
    ]
