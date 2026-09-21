from __future__ import annotations

import asyncio

from backend.app.services.embedding_models import EmbeddingModelConfig


def test_index_document_uses_the_selected_models_collection(monkeypatch):
    from backend.app.services import kb_service

    selected = EmbeddingModelConfig(
        model="new-embed",
        dimension=3,
        collection_name="aipam_kb_newembed",
    )
    calls: dict[str, object] = {}

    async def fake_embeddings(texts, **kwargs):
        calls["model"] = kwargs["model"]
        calls["dimension"] = kwargs["expected_dimension"]
        return [[0.1, 0.2, 0.3] for _ in texts]

    class Collection:
        def upsert(self, **kwargs):
            calls["upsert"] = kwargs

    def fake_collection(persist_dir, collection_name):
        calls["collection_name"] = collection_name
        return Collection()

    monkeypatch.setattr(kb_service, "get_embeddings", fake_embeddings)
    monkeypatch.setattr(kb_service, "_get_collection", fake_collection)

    result = asyncio.run(
        kb_service.index_document(
            doc_id="doc-1",
            content="A compact document about suspicious traffic.",
            doc_name="Evidence",
            doc_type="reference",
            embedding_config=selected,
        )
    )

    assert result.chunk_count == 1
    assert calls["model"] == "new-embed"
    assert calls["dimension"] == 3
    assert calls["collection_name"] == "aipam_kb_newembed"


def test_index_document_rejects_vectors_with_wrong_selected_dimension(monkeypatch):
    from backend.app.services import kb_service

    selected = EmbeddingModelConfig("new-embed", 3, "aipam_kb_newembed")

    async def wrong_embeddings(texts, **kwargs):
        raise kb_service.EmbeddingError("returned 2 dimensions; expected 3")

    monkeypatch.setattr(kb_service, "get_embeddings", wrong_embeddings)

    try:
        asyncio.run(
            kb_service.index_document(
                doc_id="doc-1",
                content="Evidence",
                doc_name="Evidence",
                doc_type="reference",
                embedding_config=selected,
            )
        )
    except kb_service.EmbeddingError as exc:
        assert "expected 3" in str(exc)
    else:
        raise AssertionError("wrong-dimension embeddings must not be indexed")


def test_index_documents_batches_multiple_documents_into_one_embedding_request(monkeypatch):
    from backend.app.services import kb_service

    selected = EmbeddingModelConfig("new-embed", 3, "aipam_kb_newembed")
    calls: dict[str, object] = {"embedding_batches": 0}

    async def fake_embeddings(texts, **kwargs):
        calls["embedding_batches"] = int(calls["embedding_batches"]) + 1
        calls["text_count"] = len(texts)
        return [[0.1, 0.2, 0.3] for _ in texts]

    class Collection:
        def upsert(self, **kwargs):
            calls["ids"] = kwargs["ids"]

    monkeypatch.setattr(kb_service, "get_embeddings", fake_embeddings)
    monkeypatch.setattr(kb_service, "_get_collection", lambda *_: Collection())

    counts = asyncio.run(
        kb_service.index_documents(
            [
                {"doc_id": "host-1", "content": "Host one", "doc_name": "Host one", "doc_type": "host", "job_id": "job-1"},
                {"doc_id": "host-2", "content": "Host two", "doc_name": "Host two", "doc_type": "host", "job_id": "job-1"},
            ],
            ollama_url="http://ollama:11434",
            embedding_config=selected,
        )
    )

    assert counts == {"host-1": 1, "host-2": 1}
    assert calls["embedding_batches"] == 1
    assert calls["text_count"] == 2
    assert calls["ids"] == ["host-1_chunk_0", "host-2_chunk_0"]
