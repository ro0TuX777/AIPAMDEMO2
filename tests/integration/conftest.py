"""Integration test fixtures.

Provides golden PCAP paths and an integration-ready API client.
"""

import json
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).parent.parent / "fixtures" / "golden"


@pytest.fixture(scope="session")
def golden_pcaps() -> dict[str, Path]:
    """Return a mapping of golden PCAP name → file path.

    Generates PCAPs on first access if they don't exist.
    """
    expected_file = GOLDEN_DIR / "expected_findings.json"
    if not expected_file.exists():
        from tests.fixtures.golden.generate_golden_pcaps import generate_all
        generate_all()

    pcaps = {}
    for p in sorted(GOLDEN_DIR.glob("*.pcap")):
        pcaps[p.name] = p
    return pcaps


@pytest.fixture(scope="session")
def expected_findings() -> dict:
    """Load expected_findings.json for golden PCAPs."""
    path = GOLDEN_DIR / "expected_findings.json"
    if not path.exists():
        from tests.fixtures.golden.generate_golden_pcaps import generate_all
        generate_all()
    return json.loads(path.read_text())

