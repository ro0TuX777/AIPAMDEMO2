"""Authenticated access to locally stored MNEMOS evidence receipts."""

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.api.deps import verify_token
from backend.app.config_v2 import Settings, get_settings
from backend.app.services.mnemos_evidence_receipts import (
    list_evidence_receipts,
    load_evidence_receipt,
)


router = APIRouter(tags=["MNEMOS evidence receipts"])


@router.get("/mnemos/evidence-receipts")
def receipt_history(
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    _token: str = Depends(verify_token),
    settings: Settings = Depends(get_settings),
):
    """Return a stable page of receipts from active and archived storage."""
    try:
        items, next_cursor = list_evidence_receipts(
            settings.mnemos_evidence_receipt_dir, limit=limit, cursor=cursor
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid evidence receipt cursor") from exc
    return {
        "items": items,
        "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None},
    }


@router.get("/mnemos/evidence-receipts/{receipt_id}")
def receipt_detail(
    receipt_id: str,
    _token: str = Depends(verify_token),
    settings: Settings = Depends(get_settings),
):
    """Return one validated receipt, without exposing its storage path."""
    receipt = load_evidence_receipt(settings.mnemos_evidence_receipt_dir, receipt_id)
    if receipt is None:
        raise HTTPException(status_code=404, detail="Evidence receipt not found")
    return receipt
