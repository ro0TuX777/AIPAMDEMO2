from typing import Any, Dict, Optional
from fastapi import HTTPException
from backend.app.schemas.common import ErrorCode

def raise_error(
    status_code: int, 
    code: ErrorCode, 
    message: str, 
    details: Optional[Dict[str, Any]] = None
):
    """Raise a structured HTTPException with an ErrorCode."""
    raise HTTPException(
        status_code=status_code,
        detail={
            "error": message,
            "code": code,
            "details": details
        }
    )
