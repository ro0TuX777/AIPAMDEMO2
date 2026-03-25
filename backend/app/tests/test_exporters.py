"""Tests for app/core/exporters.py — Suricata and Sigma rule generation."""

import json
import pytest

from unittest.mock import AsyncMock, MagicMock

from backend.app.core.exporters import SuricataExporter, SigmaExporter, ExportedRule


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


def make_finding():
    """Create a mock finding for export testing."""
    f = MagicMock()
    f.id = "finding-001"
    f.mitre_technique_id = "T1071.001"
    f.mitre_technique_name = "Web Protocols"
    f.classification = "IcedID"
    f.severity = "critical"
    f.title = "Suspicious HTTPS C2"
    f.description = "Long-duration TLS session with beaconing intervals"
    f.affected_hosts = ["192.168.1.100", "185.70.40.20"]
    return f


# -------------------------------------------------------------------------
# SuricataExporter
# -------------------------------------------------------------------------

class TestSuricataExporter:
    """Generate Suricata rules from findings."""

    @pytest.mark.asyncio
    async def test_generates_rule_from_json(self):
        """When LLM returns JSON, extract the rule field."""
        provider = MagicMock()
        provider.model = "llama3.1:8b"

        llm_response = json.dumps({
            "rule": 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"AIPAM IcedID C2 Beaconing"; sid:9000001; rev:1;)',
            "description": "Detects IcedID C2 beaconing via TLS",
        })
        provider.send = AsyncMock(return_value=llm_response)

        exporter = SuricataExporter(provider=provider)
        result = await exporter.generate(make_finding(), ["TLS 192.168.1.100 → 185.70.40.20:443"])

        assert isinstance(result, ExportedRule)
        assert result.rule_type == "suricata"
        assert "9000001" in result.rule_text
        assert result.finding_id == "finding-001"
        assert result.description == "Detects IcedID C2 beaconing via TLS"
        provider.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_raw_text_fallback(self):
        """When LLM returns raw text (not JSON), use it as-is."""
        provider = MagicMock()
        provider.model = "llama3.1:8b"

        raw = 'alert tls any any -> any any (msg:"C2 Traffic"; sid:9000001; rev:1;)'
        provider.send = AsyncMock(return_value=raw)

        exporter = SuricataExporter(provider=provider)
        result = await exporter.generate(make_finding())

        assert result.rule_type == "suricata"
        assert result.rule_text == raw

    @pytest.mark.asyncio
    async def test_passes_evidence_snippets(self):
        """Evidence snippets are included in the prompt."""
        provider = MagicMock()
        provider.model = "test"
        provider.send = AsyncMock(return_value='{"rule": "alert tcp any any -> any any (sid:1;)", "description": "test"}')

        exporter = SuricataExporter(provider=provider)
        snippets = ["TCP 192.168.1.100:49152 → 185.70.40.20:443 TLS1.2"]
        await exporter.generate(make_finding(), snippets)

        # Verify send was called with prompt containing the snippets
        call_args = provider.send.call_args
        messages = call_args[1].get("messages", call_args[0][0] if call_args[0] else [])
        user_msg = [m for m in messages if m["role"] == "user"][0]["content"]
        assert "192.168.1.100:49152" in user_msg


# -------------------------------------------------------------------------
# SigmaExporter
# -------------------------------------------------------------------------

class TestSigmaExporter:
    """Generate Sigma rules from findings."""

    @pytest.mark.asyncio
    async def test_generates_sigma_yaml(self):
        """When LLM returns JSON, extract the rule field."""
        provider = MagicMock()
        provider.model = "llama3.1:8b"

        sigma_yaml = "title: IcedID C2 Detection\nstatus: experimental\nlogsource:\n  category: network_connection"
        llm_response = json.dumps({
            "rule": sigma_yaml,
            "description": "Sigma rule for IcedID C2",
        })
        provider.send = AsyncMock(return_value=llm_response)

        exporter = SigmaExporter(provider=provider)
        result = await exporter.generate(make_finding())

        assert result.rule_type == "sigma"
        assert "IcedID C2 Detection" in result.rule_text
        assert result.description == "Sigma rule for IcedID C2"

    @pytest.mark.asyncio
    async def test_raw_text_fallback(self):
        """Raw text fallback for non-JSON responses."""
        provider = MagicMock()
        provider.model = "test"

        raw_yaml = "title: Test Rule\nstatus: experimental"
        provider.send = AsyncMock(return_value=raw_yaml)

        exporter = SigmaExporter(provider=provider)
        result = await exporter.generate(make_finding())

        assert result.rule_type == "sigma"
        assert "Test Rule" in result.rule_text
