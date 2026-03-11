"""
Reusable cursor-based pagination helper (§3.2).

Provides keyset pagination for any SQLAlchemy model using (sort_col, id_col)
as the composite cursor key. All list endpoints use this.
"""

import base64
import json
from typing import Any, Sequence

from fastapi import HTTPException, Query
from sqlalchemy import Column, Select
from sqlalchemy.orm import Session

from backend.app.schemas.common import PageInfo


def encode_cursor(sort_val: str, id_val: str | int) -> str:
    """Encode pagination cursor as base64 JSON."""
    payload = json.dumps({"s": sort_val, "id": str(id_val)})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def decode_cursor(cursor: str) -> tuple[str, str]:
    """Decode pagination cursor. Returns (sort_val, id_val)."""
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor))
        return payload["s"], payload["id"]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")


def paginate(
    db: Session,
    query: Select,
    sort_col: Column,
    id_col: Column,
    cursor: str | None,
    limit: int,
    order: str = "desc",
) -> tuple[Sequence[Any], PageInfo]:
    """
    Apply keyset pagination to a query.

    Returns (items, page_info).
    """
    if order == "desc":
        query = query.order_by(sort_col.desc(), id_col.desc())
        if cursor:
            sv, iv = decode_cursor(cursor)
            query = query.where(
                (sort_col < sv) | ((sort_col == sv) & (id_col < iv))
            )
    else:
        query = query.order_by(sort_col.asc(), id_col.asc())
        if cursor:
            sv, iv = decode_cursor(cursor)
            query = query.where(
                (sort_col > sv) | ((sort_col == sv) & (id_col > iv))
            )

    rows = db.execute(query.limit(limit + 1)).scalars().all()
    has_more = len(rows) > limit
    items = rows[:limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        sort_val = str(getattr(last, sort_col.key))
        id_val = str(getattr(last, id_col.key))
        next_cursor = encode_cursor(sort_val, id_val)

    return items, PageInfo(next_cursor=next_cursor, has_more=has_more)

