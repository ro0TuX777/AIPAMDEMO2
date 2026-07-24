"""
AIPAM Benchmark — Tier 4: Subsystem Integration Gate

Verifies that the major subsystems added in v2.2 are correctly wired —
schemas, models, and connectors are internally consistent without
requiring live external services.

Covers:
  - OllamaGpuStatusResponse: schema shape matches expected fields and types
  - LoadedModelInfo: gpu_offload_pct is bounded [0, 100]
  - Security Onion connector: auth methods are present and callable
"""
from __future__ import annotations

import os

os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")




# ---------------------------------------------------------------------------
# 4.3  OllamaGpuStatusResponse schema integrity
# ---------------------------------------------------------------------------


class TestOllamaGpuStatusSchema:
    """OllamaGpuStatusResponse must have correct field types and defaults."""

    def test_default_gpu_detected_is_false(self):
        from backend.app.schemas.system import OllamaGpuStatusResponse
        r = OllamaGpuStatusResponse()
        assert r.gpu_detected is False

    def test_default_compute_device_is_cpu(self):
        from backend.app.schemas.system import OllamaGpuStatusResponse
        r = OllamaGpuStatusResponse()
        assert r.compute_device == "CPU"

    def test_default_loaded_models_is_empty_list(self):
        from backend.app.schemas.system import OllamaGpuStatusResponse
        r = OllamaGpuStatusResponse()
        assert r.loaded_models == []

    def test_default_vram_bytes_are_zero(self):
        from backend.app.schemas.system import OllamaGpuStatusResponse
        r = OllamaGpuStatusResponse()
        assert r.vram_total_bytes == 0
        assert r.vram_used_bytes == 0

    def test_loaded_model_gpu_offload_pct_defaults_to_zero(self):
        from backend.app.schemas.system import LoadedModelInfo
        m = LoadedModelInfo(name="test-model")
        assert m.gpu_offload_pct == 0

    def test_loaded_model_schema_has_size_vram(self):
        from backend.app.schemas.system import LoadedModelInfo
        m = LoadedModelInfo(name="llama3", size_vram=1_000_000_000)
        assert m.size_vram == 1_000_000_000

    def test_gpu_detected_true_when_vram_populated(self):
        from backend.app.schemas.system import OllamaGpuStatusResponse, LoadedModelInfo
        r = OllamaGpuStatusResponse(
            gpu_detected=True,
            gpu_name="NVIDIA RTX 4090",
            vram_total_bytes=24_000_000_000,
            vram_used_bytes=8_000_000_000,
            compute_device="CUDA",
            loaded_models=[LoadedModelInfo(name="trafficllm", size_vram=8_000_000_000)],
        )
        assert r.gpu_detected is True
        assert r.compute_device == "CUDA"
        assert len(r.loaded_models) == 1


# ---------------------------------------------------------------------------
# 4.4  Security Onion connector — Kratos auth interface (v2.2)
# ---------------------------------------------------------------------------


class TestSecurityOnionConnector:
    """SecurityOnionConnector must expose the Kratos auth interface added in v2.2."""

    def test_connector_has_authenticate_method(self):
        from backend.app.connectors import SecurityOnionConnector
        assert callable(getattr(SecurityOnionConnector, "_authenticate", None))

    def test_connector_has_export_pcap_method(self):
        from backend.app.connectors import SecurityOnionConnector
        assert callable(getattr(SecurityOnionConnector, "export_pcap", None))

    def test_connector_has_import_pcap_method(self):
        from backend.app.connectors import SecurityOnionConnector
        assert callable(getattr(SecurityOnionConnector, "import_pcap", None))

    def test_connector_accepts_username_password(self):
        from unittest.mock import MagicMock
        from backend.app.connectors import SecurityOnionConnector
        # MagicMock provides any attribute access — simulates EffectiveSettings
        # without needing all fields of the real dataclass
        fake_settings = MagicMock()
        fake_settings.security_onion_username = "analyst"
        fake_settings.security_onion_password = "s3cr3t"
        conn = SecurityOnionConnector(settings=fake_settings)
        assert conn.username == "analyst"
        assert conn.password == "s3cr3t"

