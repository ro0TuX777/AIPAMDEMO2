"""Phase 2 tests — parser implementations against fixture data.

Tests verify:
- Each parser correctly identifies files it can parse
- Parsed output has correct event types and correlation keys
- Provenance fields are auto-filled
- Malformed input is handled gracefully
- Registry integration works end-to-end
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.parsers.base import ParserResult
from backend.app.parsers.dns import DnsParser
from backend.app.parsers.firewall import FirewallParser
from backend.app.parsers.linux_auth import LinuxAuthParser
from backend.app.parsers.proxy import ProxyParser
from backend.app.parsers.sysmon import SysmonParser
from backend.app.parsers.windows_evtx import WindowsEvtxParser
from backend.app.schemas.common import NormalizedEventType, SourceType

_FIXTURES = Path(__file__).parent / "fixtures" / "telemetry"


# ---------------------------------------------------------------------------
# Windows EVTX parser
# ---------------------------------------------------------------------------


class TestWindowsEvtxParser:
    def setup_method(self):
        self.parser = WindowsEvtxParser()

    def test_can_parse_fixture(self):
        assert self.parser.can_parse(_FIXTURES / "windows" / "sample_evtx.json")

    def test_can_parse_with_hint(self):
        assert self.parser.can_parse(Path("any.json"), hint="windows_evtx")

    def test_cannot_parse_non_json(self):
        assert not self.parser.can_parse(Path("auth.log"))

    def test_parse_fixture(self):
        results = list(self.parser.parse(
            _FIXTURES / "windows" / "sample_evtx.json", "job-test"
        ))
        assert len(results) == 2

        # First event: 4624 (logon success)
        r0 = results[0]
        assert r0.event_type == NormalizedEventType.auth
        assert r0.data["sub_type"] == "logon_success"
        assert r0.data["event_id"] == 4624
        assert r0.hostname == "WORKSTATION-01"
        assert r0.username == "CORP\\jdoe"
        assert r0.src_ip == "192.168.1.100"
        assert "hostname" in r0.correlation_keys
        assert "src_ip" in r0.correlation_keys

        # Second event: 4625 (logon failure)
        r1 = results[1]
        assert r1.data["sub_type"] == "logon_failure"
        assert r1.data["event_id"] == 4625
        assert r1.src_ip == "10.0.0.50"

    def test_provenance_filled(self):
        results = list(self.parser.parse(
            _FIXTURES / "windows" / "sample_evtx.json", "job-test"
        ))
        assert results[0].parser_name == "windows_evtx"
        assert results[0].parser_version == "0.1.0"
        assert results[0].source_system == "windows_evtx"
        assert results[0].source_filename == "sample_evtx.json"

    def test_malformed_json(self, tmp_path):
        bad = tmp_path / "bad_evtx.json"
        bad.write_text("not json {{{")
        results = list(self.parser.parse(bad, "job-test"))
        assert results == []

    def test_empty_list(self, tmp_path):
        empty = tmp_path / "empty_evtx.json"
        empty.write_text("[]")
        results = list(self.parser.parse(empty, "job-test"))
        assert results == []


# ---------------------------------------------------------------------------
# Sysmon parser
# ---------------------------------------------------------------------------


class TestSysmonParser:
    def setup_method(self):
        self.parser = SysmonParser()

    def test_can_parse_fixture(self):
        assert self.parser.can_parse(_FIXTURES / "windows" / "sample_sysmon.json")

    def test_can_parse_with_hint(self):
        assert self.parser.can_parse(Path("any.json"), hint="sysmon")

    def test_parse_fixture(self):
        results = list(self.parser.parse(
            _FIXTURES / "windows" / "sample_sysmon.json", "job-test"
        ))
        assert len(results) == 2

        # EventID 1: process create
        r0 = results[0]
        assert r0.event_type == NormalizedEventType.process
        assert r0.data["sub_type"] == "process_create"
        assert r0.data["image"] == "C:\\Windows\\System32\\cmd.exe"
        assert r0.data["command_line"] == "cmd.exe /c whoami"
        assert r0.process_guid is not None

        # EventID 3: network connect
        r1 = results[1]
        assert r1.event_type == NormalizedEventType.connection
        assert r1.data["sub_type"] == "network_connect"
        assert r1.src_ip == "192.168.1.100"
        assert r1.dest_ip == "10.10.10.10"
        assert r1.dest_port == 443
        assert r1.proto == "tcp"

    def test_provenance_filled(self):
        results = list(self.parser.parse(
            _FIXTURES / "windows" / "sample_sysmon.json", "job-test"
        ))
        assert results[0].parser_name == "sysmon"
        assert results[0].source_system == "sysmon"


# ---------------------------------------------------------------------------
# Linux auth parser
# ---------------------------------------------------------------------------


class TestLinuxAuthParser:
    def setup_method(self):
        self.parser = LinuxAuthParser()

    def test_can_parse_fixture(self):
        assert self.parser.can_parse(_FIXTURES / "linux" / "sample_auth.log")

    def test_can_parse_with_hint(self):
        assert self.parser.can_parse(Path("secure"), hint="linux_auth")

    def test_sudo_fields(self):
        results = list(self.parser.parse(
            _FIXTURES / "linux" / "sample_auth.log", "job-test"
        ))
        sudo = [r for r in results if r.data["sub_type"] == "sudo"][0]
        assert sudo.username == "admin"
        assert sudo.hostname == "webserver01"
        assert "command" in sudo.data
        assert "/bin/bash" in sudo.data["command"]

    def test_provenance_filled(self):
        results = list(self.parser.parse(
            _FIXTURES / "linux" / "sample_auth.log", "job-test"
        ))
        assert results[0].parser_name == "linux_auth"
        assert results[0].source_system == "linux_auth"

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty_auth.log"
        empty.write_text("")
        results = list(self.parser.parse(empty, "job-test"))
        assert results == []


# ---------------------------------------------------------------------------
# Firewall parser
# ---------------------------------------------------------------------------


class TestFirewallParser:
    def setup_method(self):
        self.parser = FirewallParser()

    def test_can_parse_fixture(self):
        assert self.parser.can_parse(_FIXTURES / "network" / "sample_firewall.json")

    def test_can_parse_with_hint(self):
        assert self.parser.can_parse(Path("any.json"), hint="firewall")

    def test_parse_fixture(self):
        results = list(self.parser.parse(
            _FIXTURES / "network" / "sample_firewall.json", "job-test"
        ))
        assert len(results) == 2

        r0 = results[0]
        assert r0.event_type == NormalizedEventType.connection
        assert r0.data["sub_type"] == "allow"
        assert r0.src_ip == "192.168.1.100"
        assert r0.dest_ip == "10.10.10.10"
        assert r0.dest_port == 443
        assert r0.proto == "tcp"
        assert r0.data["rule_name"] == "allow-https-outbound"

        r1 = results[1]
        assert r1.data["sub_type"] == "deny"
        assert r1.dest_port == 22

    def test_correlation_keys(self):
        results = list(self.parser.parse(
            _FIXTURES / "network" / "sample_firewall.json", "job-test"
        ))
        assert "src_ip" in results[0].correlation_keys
        assert "dest_ip" in results[0].correlation_keys


# ---------------------------------------------------------------------------
# Proxy parser
# ---------------------------------------------------------------------------


class TestProxyParser:
    def setup_method(self):
        self.parser = ProxyParser()

    def test_can_parse_fixture(self):
        assert self.parser.can_parse(_FIXTURES / "network" / "sample_proxy.json")

    def test_parse_fixture(self):
        results = list(self.parser.parse(
            _FIXTURES / "network" / "sample_proxy.json", "job-test"
        ))
        assert len(results) == 2

        r0 = results[0]
        assert r0.event_type == NormalizedEventType.proxy
        assert r0.src_ip == "192.168.1.100"
        assert r0.data["method"] == "GET"
        assert "suspicious.example.com" in r0.data["url"]
        assert r0.data["status_code"] == 200
        assert r0.data["bytes_transferred"] == 524288

        r1 = results[1]
        assert r1.data["method"] == "POST"
        assert "callback" in r1.data["url"]

    def test_correlation_keys_extract_host(self):
        results = list(self.parser.parse(
            _FIXTURES / "network" / "sample_proxy.json", "job-test"
        ))
        assert "dest_host" in results[0].correlation_keys
        assert results[0].correlation_keys["dest_host"] == "suspicious.example.com"


# ---------------------------------------------------------------------------
# DNS parser
# ---------------------------------------------------------------------------


class TestDnsParser:
    def setup_method(self):
        self.parser = DnsParser()

    def test_can_parse_fixture(self):
        assert self.parser.can_parse(_FIXTURES / "network" / "sample_dns.json")

    def test_parse_fixture(self):
        results = list(self.parser.parse(
            _FIXTURES / "network" / "sample_dns.json", "job-test"
        ))
        assert len(results) == 2

        r0 = results[0]
        assert r0.event_type == NormalizedEventType.dns
        assert r0.data["query"] == "suspicious.example.com"
        assert r0.data["query_type"] == "A"
        assert r0.data["response"] == "10.10.10.10"
        assert r0.data["response_code"] == "NOERROR"
        assert r0.src_ip == "192.168.1.100"

        r1 = results[1]
        assert r1.data["query"] == "c2-beacon.evil.net"
        assert r1.data["query_type"] == "TXT"

    def test_correlation_keys(self):
        results = list(self.parser.parse(
            _FIXTURES / "network" / "sample_dns.json", "job-test"
        ))
        assert "dns_query" in results[0].correlation_keys
        assert "src_ip" in results[0].correlation_keys
        assert "dest_ip" in results[0].correlation_keys


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


class TestParserRegistryIntegration:
    def test_register_all_parsers(self):
        from backend.app.parsers import register_all_parsers
        registry = register_all_parsers()
        assert len(registry) >= 6
        assert "windows_evtx" in registry
        assert "sysmon" in registry
        assert "linux_auth" in registry
        assert "firewall" in registry
        assert "proxy" in registry
        assert "dns" in registry

    def test_find_by_source_system(self):
        from backend.app.parsers import register_all_parsers
        registry = register_all_parsers()
        assert len(registry.find_by_source_system("sysmon")) >= 1
        assert len(registry.find_by_source_system("paloalto")) >= 1  # firewall supports it

    def test_find_for_file_with_hint(self):
        from backend.app.parsers import register_all_parsers
        registry = register_all_parsers()
        parser = registry.find_for_file(Path("data.json"), hint="dns")
        assert parser is not None
        assert parser.name == "dns"

    def test_find_for_file_autodetect(self):
        from backend.app.parsers import register_all_parsers
        registry = register_all_parsers()
        parser = registry.find_for_file(_FIXTURES / "windows" / "sample_sysmon.json")
        assert parser is not None
        assert parser.name == "sysmon"

    def test_exercise_id_propagation(self):
        """Verify exercise_id flows through parsing."""
        parser = DnsParser()
        results = list(parser.parse(
            _FIXTURES / "network" / "sample_dns.json",
            "job-test",
            exercise_id="exercise-bravo",
        ))
        assert all(r.exercise_id == "exercise-bravo" for r in results)

