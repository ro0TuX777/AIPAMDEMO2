from __future__ import annotations

import hashlib

import pytest


class _Response:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_search_returns_evidence_hits_from_a_healthy_mnemos_service() -> None:
    """AIPAM must retain MNEMOS evidence metadata when the remote read succeeds."""
    from backend.app.mnemos_boundary import MnemosBoundaryClient

    recorded: dict = {}

    def request(method: str, url: str, **kwargs):
        recorded.update(method=method, url=url, payload=kwargs["json"])
        return _Response(
            {
                "status": "healthy",
                "results": [
                    {
                        "engram": {"content": "Confirmed C2 beacon", "metadata": {"job_id": "job-1"}},
                        "score": 0.92,
                        "evidence": {"source": "forensic_memory"},
                    }
                ],
            }
        )

    client = MnemosBoundaryClient("http://mnemos-service:8700", request=request)

    assert client.search("Which C2 activity was confirmed?", top_k=3) == [
        {
            "document": "Confirmed C2 beacon",
            "metadata": {"job_id": "job-1"},
            "relevance": 0.92,
            "distance": 0.08,
            "evidence": {"source": "forensic_memory"},
        }
    ]
    assert recorded == {
        "method": "POST",
        "url": "http://mnemos-service:8700/v1/mnemos/search",
        "payload": {"query": "Which C2 activity was confirmed?", "top_k": 3, "filters": {"metadata.collection": "aipam_forensic_findings"}},
    }


def test_search_raises_when_mnemos_is_unavailable() -> None:
    """Transport failure must be a protocol error, not an empty search."""
    from backend.app.mnemos_boundary import MnemosBoundaryClient, MnemosBoundaryError

    def request(method: str, url: str, **kwargs):
        raise ConnectionError("service unavailable")

    client = MnemosBoundaryClient("http://mnemos-service:8700", request=request)

    with pytest.raises(MnemosBoundaryError):
        client.search("recent findings")


def test_search_rejects_healthy_payload_without_a_results_list() -> None:
    """A malformed success must not be mistaken for a valid empty search."""
    from backend.app.mnemos_boundary import MnemosBoundaryClient, MnemosBoundaryError

    client = MnemosBoundaryClient(
        "http://mnemos",
        request=lambda *args, **kwargs: _Response({"status": "healthy"}),
    )

    with pytest.raises(MnemosBoundaryError):
        client.search("confirmed C2")


def test_search_returns_empty_only_for_a_healthy_empty_results_list() -> None:
    from backend.app.mnemos_boundary import MnemosBoundaryClient

    client = MnemosBoundaryClient(
        "http://mnemos",
        request=lambda *args, **kwargs: _Response(
            {"status": "healthy", "results": []}
        ),
    )

    assert client.search("confirmed C2") == []


@pytest.mark.parametrize(
    "response",
    [
        _Response({"status": "degraded", "error": "warming"}),
        _Response({"detail": "unauthorized"}, status_code=401),
    ],
)
def test_search_raises_for_unhealthy_or_http_error_responses(response) -> None:
    from backend.app.mnemos_boundary import MnemosBoundaryClient, MnemosBoundaryError

    client = MnemosBoundaryClient(
        "http://mnemos",
        request=lambda *args, **kwargs: response,
    )

    with pytest.raises(MnemosBoundaryError):
        client.search("confirmed C2")


@pytest.mark.parametrize("failure", [TimeoutError("timed out"), ConnectionError("refused")])
def test_search_wraps_transport_failures_in_boundary_error(failure) -> None:
    from backend.app.mnemos_boundary import MnemosBoundaryClient, MnemosBoundaryError

    def request(*args, **kwargs):
        raise failure

    client = MnemosBoundaryClient("http://mnemos", request=request)

    with pytest.raises(MnemosBoundaryError):
        client.search("confirmed C2")


def test_search_wraps_non_object_json_as_boundary_error() -> None:
    from backend.app.mnemos_boundary import MnemosBoundaryClient, MnemosBoundaryError

    client = MnemosBoundaryClient(
        "http://mnemos",
        request=lambda *args, **kwargs: _Response(["not", "an", "object"]),
    )

    with pytest.raises(MnemosBoundaryError):
        client.search("confirmed C2")


@pytest.mark.parametrize(
    "raw_hit",
    [
        "not an object",
        {"score": 0.9},
        {"engram": {"content": "missing metadata"}, "score": 0.9},
        {"engram": {"content": "bad score", "metadata": {}}, "score": "high"},
    ],
)
def test_search_rejects_malformed_items_in_nonempty_results(raw_hit) -> None:
    from backend.app.mnemos_boundary import MnemosBoundaryClient, MnemosBoundaryError

    client = MnemosBoundaryClient(
        "http://mnemos",
        request=lambda *args, **kwargs: _Response(
            {"status": "healthy", "results": [raw_hit]}
        ),
    )

    with pytest.raises(MnemosBoundaryError):
        client.search("confirmed C2")


def test_index_returns_the_service_count_only_after_a_healthy_response() -> None:
    """AIPAM must not treat a degraded write response as a completed MNEMOS write."""
    from backend.app.mnemos_boundary import MnemosBoundaryClient

    responses = iter(
        [
            _Response({"status": "degraded", "error": "warming"}),
            _Response({"status": "healthy", "result": {"indexed": 1, "engram_ids": ["engram-1"]}}),
        ]
    )

    def request(method: str, url: str, **kwargs):
        return next(responses)

    client = MnemosBoundaryClient("http://mnemos-service:8700", request=request)
    document = {"id": "finding-1", "content": "Confirmed C2 beacon", "metadata": {"job_id": "job-1"}}

    assert client.index([document]) is None
    assert client.index([document]) == 1


def test_confirmed_findings_dual_write_to_mnemos_without_removing_local_memory(monkeypatch) -> None:
    """A remote MNEMOS outage must never prevent the established ChromaDB write."""
    from backend.app import forensic_memory

    class LocalCollection:
        def __init__(self) -> None:
            self.documents: list[dict] = []

        def upsert(self, **kwargs) -> None:
            self.documents.append(kwargs)

    class Mnemos:
        def __init__(self) -> None:
            self.documents: list[dict] = []

        def index(self, documents: list[dict]) -> int:
            self.documents.extend(documents)
            return len(documents)

    local = LocalCollection()
    mnemos = Mnemos()
    monkeypatch.setattr(forensic_memory, "get_memory_collection", lambda: local)
    monkeypatch.setattr("backend.app.mnemos_boundary.get_mnemos_client", lambda: mnemos)

    indexed = forensic_memory.store_findings(
        "job-1",
        "project-1",
        [
            {
                "finding_id": "F-1",
                "analyst_status": "confirmed",
                "title": "C2 callback",
                "severity": "high",
                "category": "command_and_control",
                "sensor": "c2_fusion",
                "summary": "Beacon every 60 seconds",
                "evidence_json": '{"dest_ip":"203.0.113.10","interval":60}',
            },
            {
                "finding_id": "F-2",
                "analyst_status": "dismissed",
                "classification": "benign",
                "severity": "low",
            },
        ],
    )

    assert indexed == 1
    assert len(local.documents) == 1
    expected_content = (
        "Title: C2 callback\n"
        "Severity: high\n"
        "Category: command_and_control\n"
        "Sensor: c2_fusion\n"
        "Summary: Beacon every 60 seconds\n"
        'Evidence: {"dest_ip":"203.0.113.10","interval":60}'
    )
    assert mnemos.documents == [
        {
            "id": "finding:job-1:F-1",
            "content": expected_content,
            "source": "aipam.forensic_memory",
            "neuro_tags": ["forensic_finding", "confirmed"],
            "metadata": {
                "collection": "aipam_forensic_findings",
                "job_id": "job-1",
                "finding_id": "F-1",
                "project_id": "project-1",
                "content_sha256": hashlib.sha256(
                    expected_content.encode("utf-8")
                ).hexdigest(),
            },
        }
    ]


def test_memory_reads_use_mnemos_when_healthy_and_local_memory_on_outage(monkeypatch) -> None:
    """AIPAM should promote reads only after MNEMOS has produced a valid response."""
    from backend.app import forensic_memory

    class Mnemos:
        def __init__(self, result):
            self.result = result

        def search(self, *args, **kwargs):
            return self.result

    remote_hit = [{"document": "Remote confirmed C2", "metadata": {}, "relevance": 0.9, "distance": 0.1}]
    monkeypatch.setattr("backend.app.mnemos_boundary.get_mnemos_client", lambda: Mnemos(remote_hit))
    monkeypatch.setattr(
        forensic_memory,
        "get_memory_collection",
        lambda: (_ for _ in ()).throw(AssertionError("local read should not run")),
    )
    assert forensic_memory.query_memory("confirmed C2") == remote_hit

    class LocalCollection:
        def count(self) -> int:
            return 1

        def query(self, **kwargs) -> dict:
            return {
                "documents": [["Local confirmed C2"]],
                "metadatas": [[{"job_id": "job-2"}]],
                "distances": [[0.2]],
            }

    monkeypatch.setattr("backend.app.mnemos_boundary.get_mnemos_client", lambda: Mnemos(None))
    monkeypatch.setattr(forensic_memory, "get_memory_collection", LocalCollection)
    assert forensic_memory.query_memory("confirmed C2") == [
        {
            "document": "Local confirmed C2",
            "metadata": {"job_id": "job-2"},
            "distance": 0.2,
            "relevance": 0.8,
        }
    ]


def test_settings_default_to_aipam_owned_mnemos_endpoint(monkeypatch) -> None:
    """The container network address must be independent from any host MNEMOS instance."""
    from backend.app.config_v2 import Settings

    monkeypatch.delenv("MNEMOS_ENABLED", raising=False)
    monkeypatch.delenv("MNEMOS_BASE_URL", raising=False)
    settings = Settings(aipam_api_token="test-token")

    assert settings.mnemos_enabled is False
    assert settings.mnemos_base_url == "http://mnemos-service:8700"
