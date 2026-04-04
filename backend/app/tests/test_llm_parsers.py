"""Tests for app/llm/parsers.py — JSON extraction, repair, and text helpers."""


from backend.app.llm.parsers import (
    parse_llm_response,
    repair_llm_output,
    extract_mitre_techniques,
    extract_ip_addresses,
    extract_flow_ids,
)


# -------------------------------------------------------------------------
# parse_llm_response
# -------------------------------------------------------------------------

class TestParseLLMResponse:
    """JSON extraction from raw LLM output."""

    def test_pure_json(self):
        raw = '{"classification": "IcedID", "severity": "high"}'
        result = parse_llm_response(raw)
        assert result == {"classification": "IcedID", "severity": "high"}

    def test_markdown_json_fence(self):
        raw = 'Here is my analysis:\n```json\n{"classification": "Emotet"}\n```\nDone.'
        result = parse_llm_response(raw)
        assert result["classification"] == "Emotet"

    def test_markdown_fence_without_lang(self):
        raw = 'Analysis:\n```\n{"classification": "Pikabot"}\n```'
        result = parse_llm_response(raw)
        assert result["classification"] == "Pikabot"

    def test_embedded_json(self):
        raw = 'The traffic shows {"classification": "CobaltStrike"} in the data.'
        result = parse_llm_response(raw)
        assert result["classification"] == "CobaltStrike"

    def test_empty_string(self):
        assert parse_llm_response("") is None

    def test_none_input(self):
        assert parse_llm_response(None) is None

    def test_invalid_json(self):
        assert parse_llm_response("This is just text without JSON.") is None


# -------------------------------------------------------------------------
# repair_llm_output
# -------------------------------------------------------------------------

class TestRepairLLMOutput:
    """Schema repair for malformed LLM outputs."""

    def test_minimal_input(self):
        raw = {"classification": "IcedID"}
        result = repair_llm_output(raw)
        assert result["classification"] == "IcedID"
        assert result["overall_severity"] == "medium"
        assert result["attack_chain"] == []
        assert result["host_findings"] == []
        assert result["anomalies"] == []
        assert result["mitre_techniques_overall"] == []

    def test_string_items_in_attack_chain(self):
        raw = {"attack_chain": ["step 1: execution", "step 2: c2"]}
        result = repair_llm_output(raw)
        assert len(result["attack_chain"]) == 2
        assert result["attack_chain"][0]["stage"] == "unknown"
        assert "step 1" in result["attack_chain"][0]["description"]

    def test_dict_host_findings(self):
        raw = {"host_findings": {"192.168.1.1": "victim host"}}
        result = repair_llm_output(raw)
        assert len(result["host_findings"]) == 1
        assert result["host_findings"][0]["ip"] == "192.168.1.1"
        assert result["host_findings"][0]["summary"] == "victim host"

    def test_dict_anomalies(self):
        raw = {"anomalies": {"unusual DNS": 0.85}}
        result = repair_llm_output(raw)
        assert len(result["anomalies"]) == 1
        assert result["anomalies"][0]["description"] == "unusual DNS"
        assert result["anomalies"][0]["confidence"] == 0.85

    def test_string_mitre_techniques(self):
        raw = {"mitre_techniques_overall": ["T1071.001", "T1059"]}
        result = repair_llm_output(raw)
        assert len(result["mitre_techniques_overall"]) == 2
        assert result["mitre_techniques_overall"][0]["id"] == "T1071.001"

    def test_severity_inferred(self):
        raw = {}
        result = repair_llm_output(raw, content="This is critical ransomware")
        assert result["overall_severity"] == "critical"

    def test_severity_benign(self):
        raw = {}
        result = repair_llm_output(raw, content="Normal benign web traffic")
        assert result["overall_severity"] == "low"


# -------------------------------------------------------------------------
# Text Extraction Helpers
# -------------------------------------------------------------------------

class TestExtractMITRE:
    """MITRE technique ID extraction from freetext."""

    def test_basic_techniques(self):
        text = "The attacker used T1071.001 and T1059 to establish C2."
        result = extract_mitre_techniques(text)
        ids = {t["id"] for t in result}
        assert "T1071.001" in ids
        assert "T1059" in ids

    def test_no_techniques(self):
        assert extract_mitre_techniques("No techniques here.") == []

    def test_deduplication(self):
        text = "T1071 used in phase 1, then T1071 again in phase 2."
        result = extract_mitre_techniques(text)
        assert len(result) == 1


class TestExtractIPs:
    """IPv4 address extraction."""

    def test_basic(self):
        text = "Traffic from 192.168.1.100 to 10.0.0.1 detected."
        result = extract_ip_addresses(text)
        assert "192.168.1.100" in result
        assert "10.0.0.1" in result

    def test_no_ips(self):
        assert extract_ip_addresses("No IP addresses here.") == []

    def test_deduplication(self):
        text = "192.168.1.1 connected to 192.168.1.1 again"
        result = extract_ip_addresses(text)
        assert len(result) == 1


class TestExtractFlowIDs:
    """Flow ID extraction from text."""

    def test_zeek_uid(self):
        text = "Flow CdhXbc2WnVWrx1hLXl was suspicious."
        result = extract_flow_ids(text)
        assert any("CdhXbc2WnVWrx1hLXl" in fid for fid in result)

    def test_composite_id(self):
        text = "See flow job-001:CAbcDEFghIjkLMnOp for details."
        result = extract_flow_ids(text)
        assert any("job-001:CAbcDEFghIjkLMnOp" in fid for fid in result)
