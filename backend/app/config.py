import os
from pathlib import Path

# Shared configuration for paths and other settings used across the backend.

FILE_STORAGE_PATH = os.getenv("FILE_STORAGE_PATH", "/tmp/aipam_storage")
REPORTS_PATH = os.getenv("REPORTS_PATH") or str(Path(FILE_STORAGE_PATH) / "reports")

