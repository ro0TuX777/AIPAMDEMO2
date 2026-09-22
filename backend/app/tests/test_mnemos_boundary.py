from __future__ import annotations


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


def test_search_returns_none_when_mnemos_is_unavailable() -> None:
    """AIPAM must distinguish an unavailable MNEMOS service from an empty result set."""
    from backend.app.mnemos_boundary import MnemosBoundaryClient

    def request(method: str, url: str, **kwargs):
        raise ConnectionError("service unavailable")

    client = MnemosBoundaryClient("http://mnemos-service:8700", request=request)

    assert client.search("recent findings") is None


def test_search_rejects_healthy_payload_without_a_results_list() -> None:
    """A malformed success must not be mistaken for a valid empty search."""
    from backend.app.mnemos_boundary import MnemosBoundaryClient

    client = MnemosBoundaryClient(
        "http://mnemos",
        request=lambda *args, **kwargs: _Response({"status": "healthy"}),
    )

    assert client.search("confirmed C2") is None


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
                "classification": "C2",
                "severity": "high",
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
    assert mnemos.documents == [
        {
            "id": "finding:job-1:F-1",
            "content": "Classification: C2\nSeverity: high",
            "source": "aipam.forensic_memory",
            "neuro_tags": ["forensic_finding", "confirmed"],
            "metadata": {
                "collection": "aipam_forensic_findings",
                "job_id": "job-1",
                "finding_id": "F-1",
                "project_id": "project-1",
                "content_sha256": "4c79e73570ca632cbf2f19832943930741eb1ecc19d161210eb1c69f7b0b1390",
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
