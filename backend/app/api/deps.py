"""
Shared FastAPI dependencies (§1.6 auth, request-id).

- verify_token: Bearer token validation
- get_request_id: X-Request-Id header handling
- get_db: re-exported from database_v2 for convenience
"""

import uuid

from fastapi import Depends, Header, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.config_v2 import Settings, get_settings
from backend.app.database_v2 import get_db  # noqa: F401  re-export

_bearer_scheme = HTTPBearer()


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> str:
    """Validate the Bearer token against AIPAM_API_TOKEN.

    Returns the token string on success; raises 401 otherwise.
    """
    if credentials.credentials != settings.aipam_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


_bearer_scheme_optional = HTTPBearer(auto_error=False)


async def verify_token_or_query(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme_optional),
    token: str | None = Query(None, alias="token"),
    settings: Settings = Depends(get_settings),
) -> str:
    """Like verify_token but also accepts ``?token=...`` query parameter.

    This is required for SSE (``EventSource``) which cannot send custom
    headers.  Falls back to the query param when no Authorization header
    is present.
    """
    candidate = None
    if credentials and credentials.credentials:
        candidate = credentials.credentials
    elif token:
        candidate = token

    if not candidate or candidate != settings.aipam_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return candidate


def get_request_id(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> str:
    """Return the caller-supplied X-Request-Id or generate a new UUID."""
    return x_request_id or str(uuid.uuid4())

