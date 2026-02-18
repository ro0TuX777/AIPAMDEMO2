"""Pytest configuration for gold-standard tests.

Adds the backend directory to sys.path so imports resolve correctly
when running from the gold_standard_tests/ directory.
"""

import sys
from pathlib import Path

# Ensure backend/ is on the path so `app.*` imports work
backend_dir = Path(__file__).parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
