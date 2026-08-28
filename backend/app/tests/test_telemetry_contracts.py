"""Phase 0 contract tests — schema validation, model imports, enum completeness, parser contract.

These tests verify that the telemetry fusion foundation is correctly defined
and that all contracts are enforceable before Phase 1 implementation begins.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

from backend.app.schemas.common import (
    EvidenceStatus,
    NormalizedEventType,
    SourceType,
)
from backend.app.schemas.telemetry import (
    Corroboration,
    CorroborationLink,
    NormalizedEventEnvelope,
    Provenance,
    SourceEntry,
    SourceManifest,
)
from backend.app.parsers.base import BaseParser, ParserResult
from backend.app.parsers.registry import ParserRegistry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "telemetry"


# ---------------------------------------------------------------------------
# Enum completeness tests
# ---------------------------------------------------------------------------


class TestSourceTypeEnum:
    def test_contains_pcap(self):
        assert SourceType.pcap == "pcap"

    def test_contains_log_bundle(self):
        assert SourceType.log_bundle == "log_bundle"

    def test_contains_netflow_bundle(self):
        assert SourceType.netflow_bundle == "netflow_bundle"

    def test_contains_c2_bundle(self):
        assert SourceType.c2_bundle == "c2_bundle"

    def test_contains_exercise_bundle(self):
        assert SourceType.exercise_bundle == "exercise_bundle"

    def test_all_values(self):
        expected = {
            "pcap",
            "pcap+logs",
            "log_bundle",
            "netflow_bundle",
            "c2_bundle",
            "exercise_bundle",
            "binary",
            "code_artifact",
        }
        actual = {e.value for e in SourceType}
        assert actual == expected

    def test_contains_code_artifact(self):
        assert SourceType.code_artifact == "code_artifact"


class TestEvidenceStatusEnum:
    def test_lifecycle_order(self):
        statuses = [e.value for e in EvidenceStatus]
        assert statuses == ["observed", "inferred", "corroborated", "confirmed"]


class TestNormalizedEventTypeEnum:
    def test_has_minimum_families(self):
        required = {
            "connection", "netflow", "dns", "http", "proxy", "tls",
            "alert", "auth", "process", "file", "config_change",
            "asset_status", "interface_event", "c2_callback", "c2_task",
            "finding", "ioc",
        }
        actual = {e.value for e in NormalizedEventType}
        assert required.issubset(actual), f"Missing: {required - actual}"


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------


class TestSourceManifest:
    def test_minimal_manifest(self):
        m = SourceManifest(
            job_id="job-001",
            created_at=datetime.now(timezone.utc),
        )
        assert m.job_id == "job-001"
        assert m.entries == []

    def test_manifest_with_entries(self):
        entry = SourceEntry(
            filename="auth.log",
            source_type=SourceType.log_bundle,
            source_system="linux_auth",
            size_bytes=4096,
        )
        m = SourceManifest(
            job_id="job-002",
            exercise_id="exercise-alpha",
            created_at=datetime.now(timezone.utc),
            entries=[entry],
        )
        assert len(m.entries) == 1
        assert m.entries[0].source_system == "linux_auth"
        assert m.exercise_id == "exercise-alpha"


class TestProvenance:
    def test_provenance_creation(self):
        p = Provenance(
            source_type=SourceType.c2_bundle,
            source_system="cobalt_strike",
            parser_name="c2_callback",
            parser_version="0.1.0",
        )
        assert p.source_type == SourceType.c2_bundle
        assert p.source_system == "cobalt_strike"


class TestCorroboration:
    def test_corroboration_with_links(self):
        link = CorroborationLink(
            source_event_id="evt-001",
            target_event_id="evt-002",
            correlation_key="community_id",
            correlation_value="1:abc/def",
            confidence=0.9,
        )
        c = Corroboration(
            event_id="evt-001",
            evidence_status=EvidenceStatus.corroborated,
            supporting_sources=["pcap", "proxy"],
            links=[link],
            corroboration_score=0.85,
        )
        assert c.corroboration_score == 0.85
        assert len(c.links) == 1


class TestNormalizedEventEnvelope:
    def test_envelope_roundtrip(self):
        env = NormalizedEventEnvelope(
            event_id="ne-001",
            job_id="job-001",
            event_type=NormalizedEventType.auth,
            timestamp=datetime(2026, 3, 15, 14, 30, tzinfo=timezone.utc),
            provenance=Provenance(
                source_type=SourceType.log_bundle,
                source_system="windows_security",
                parser_name="windows_evtx",
            ),
            evidence_status=EvidenceStatus.observed,
            correlation_keys={"hostname": "WORKSTATION-01", "username": "jdoe"},
            data={"logon_type": "10", "event_id": 4624},
        )
        d = env.model_dump()
        rebuilt = NormalizedEventEnvelope.model_validate(d)
        assert rebuilt.event_id == "ne-001"
        assert rebuilt.event_type == NormalizedEventType.auth


# ---------------------------------------------------------------------------
# Parser contract tests
# ---------------------------------------------------------------------------


class _DummyParser(BaseParser):
    """Minimal parser for testing the contract."""

    @property
    def name(self) -> str:
        return "dummy_test"

    @property
    def version(self) -> str:
        return "0.0.1"

    @property
    def supported_source_systems(self) -> list[str]:
        return ["dummy"]

    def can_parse(self, path: Path, hint: str | None = None) -> bool:
        return path.suffix == ".dummy"

    def parse(self, path, job_id, source_type=SourceType.log_bundle, exercise_id=None) -> Iterator[ParserResult]:
        yield ParserResult(
            event_type=NormalizedEventType.auth,
            timestamp=datetime(2026, 3, 15, 14, 30, tzinfo=timezone.utc),
            data={"test": True},
            hostname="test-host",
            username="testuser",
        )


class TestBaseParserContract:
    def test_dummy_parser_implements_contract(self):
        p = _DummyParser()
        assert p.name == "dummy_test"
        assert p.version == "0.0.1"
        assert "dummy" in p.supported_source_systems

    def test_parser_yields_results(self, tmp_path):
        p = _DummyParser()
        dummy_file = tmp_path / "test.dummy"
        dummy_file.write_text("test data")
        results = list(p.parse(dummy_file, "job-001"))
        assert len(results) == 1
        assert results[0].event_type == NormalizedEventType.auth
        assert results[0].hostname == "test-host"

    def test_fill_provenance(self, tmp_path):
        p = _DummyParser()
        dummy_file = tmp_path / "test.dummy"
        dummy_file.write_text("test data")
        results = list(p.parse(dummy_file, "job-001"))
        result = p._fill_provenance(results[0], dummy_file)
        assert result.parser_name == "dummy_test"
        assert result.parser_version == "0.0.1"
        assert result.source_filename == "test.dummy"

    def test_can_parse_checks_extension(self, tmp_path):
        p = _DummyParser()
        assert p.can_parse(tmp_path / "test.dummy")
        assert not p.can_parse(tmp_path / "test.json")


class TestParserRegistry:
    def test_register_and_get(self):
        reg = ParserRegistry()
        p = _DummyParser()
        reg.register(p)
        assert reg.get("dummy_test") is p
        assert len(reg) == 1
        assert "dummy_test" in reg

    def test_find_by_source_system(self):
        reg = ParserRegistry()
        reg.register(_DummyParser())
        found = reg.find_by_source_system("dummy")
        assert len(found) == 1
        assert found[0].name == "dummy_test"

    def test_find_for_file_with_hint(self, tmp_path):
        reg = ParserRegistry()
        reg.register(_DummyParser())
        f = tmp_path / "test.dummy"
        f.write_text("data")
        parser = reg.find_for_file(f, hint="dummy_test")
        assert parser is not None
        assert parser.name == "dummy_test"

    def test_find_for_file_autodetect(self, tmp_path):
        reg = ParserRegistry()
        reg.register(_DummyParser())
        f = tmp_path / "test.dummy"
        f.write_text("data")
        parser = reg.find_for_file(f)
        assert parser is not None

    def test_find_for_file_no_match(self, tmp_path):
        reg = ParserRegistry()
        reg.register(_DummyParser())
        f = tmp_path / "test.xyz"
        f.write_text("data")
        parser = reg.find_for_file(f)
        assert parser is None

    def test_registered_parsers(self):
        reg = ParserRegistry()
        reg.register(_DummyParser())
        assert reg.registered_parsers == ["dummy_test"]


# ---------------------------------------------------------------------------
# Model import tests
# ---------------------------------------------------------------------------


class TestModelImports:
    def test_normalized_event_importable(self):
        from backend.app.models import NormalizedEvent
        assert NormalizedEvent.__tablename__ == "normalized_events"

    def test_job_has_source_type_column(self):
        from backend.app.models.job import Job
        cols = {c.name for c in Job.__table__.columns}
        assert "source_type" in cols
        assert "exercise_id" in cols
        assert "source_manifest_json" in cols


# ---------------------------------------------------------------------------
# Fixture validation tests
# ---------------------------------------------------------------------------


class TestFixtureFiles:
    @pytest.mark.parametrize("subdir,filename", [
        ("windows", "sample_evtx.json"),
        ("windows", "sample_sysmon.json"),
        ("network", "sample_firewall.json"),
        ("network", "sample_proxy.json"),
        ("network", "sample_dns.json"),
        ("c2", "sample_callbacks.json"),
        ("c2", "sample_tasking.json"),
        ("custom", "sample_vsat.json"),
    ])
    def test_fixture_exists_and_valid_json(self, subdir, filename):
        path = FIXTURES_DIR / subdir / filename
        assert path.exists(), f"Fixture missing: {path}"
        data = json.loads(path.read_text())
        assert isinstance(data, list)
        assert len(data) > 0

    def test_linux_auth_fixture_exists(self):
        path = FIXTURES_DIR / "linux" / "sample_auth.log"
        assert path.exists()
        content = path.read_text()
        assert "sshd" in content

