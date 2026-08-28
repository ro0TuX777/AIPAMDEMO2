"""
BlueScrub structured exceptions.

Provides a hierarchy of typed errors so that route handlers and the scan
service can distinguish between user errors, missing resources, and
internal failures without parsing exception messages.
"""


class BlueScrubError(Exception):
    """Base exception for all BlueScrub errors."""

    status_code: int = 500

    def __init__(self, message: str = "", *, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict:
        d: dict = {"success": False, "error": self.message}
        if self.detail:
            d["detail"] = self.detail
        return d


# ── Scan errors ──────────────────────────────────────────────────────────


class ScanError(BlueScrubError):
    """Raised when a scan cannot complete."""
    status_code = 500


class ScanTargetNotFoundError(ScanError):
    """The requested scan directory does not exist."""
    status_code = 404


class ScanProfileError(ScanError):
    """An invalid scan profile was requested."""
    status_code = 400


class ScanTimeoutError(ScanError):
    """A scan or individual analyzer exceeded its time budget."""
    status_code = 504


# ── Report errors ────────────────────────────────────────────────────────


class ReportError(BlueScrubError):
    """Raised when report generation or retrieval fails."""
    status_code = 500


class ReportNotFoundError(ReportError):
    """The requested report does not exist on disk."""
    status_code = 404


# ── Upload / input errors ───────────────────────────────────────────────


class UploadError(BlueScrubError):
    """Raised for file-upload validation failures."""
    status_code = 400


class ValidationError(BlueScrubError):
    """Generic request-validation failure (missing fields, bad values)."""
    status_code = 400


# ── Job errors ───────────────────────────────────────────────────────────


class JobError(BlueScrubError):
    """Raised for job-management failures."""
    status_code = 400


class JobNotFoundError(JobError):
    """The requested job does not exist."""
    status_code = 404


class JobStateError(JobError):
    """The job is not in a valid state for the requested operation."""
    status_code = 409

