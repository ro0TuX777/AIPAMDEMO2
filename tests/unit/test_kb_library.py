"""Global KB reference library + job∪global union retrieval (Tier 1).

Embeddings are stubbed with a constant vector so the ``job_id`` scope *filter*
is what's under test, not similarity ranking.
"""


import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app.models.knowledge_base import KBDocument
from backend.app.services import kb_service

AUTH = {"Authorization": "Bearer test-token-v2"}


async def _const_embed(texts, ollama_url="", model="", _stats=None):
    return [[1.0] + [0.0] * 1023 for _ in texts]


# ── Service-level: the scope filter ──────────────────────────────────────


@pytest.fixture()
def kb_store(tmp_path, monkeypatch):
    kb_service.reset_collection()
    monkeypatch.setattr(kb_service, "get_embeddings", _const_embed)
    yield str(tmp_path / "vector_store")
    kb_service.reset_collection()


async def _index(persist, doc_id, job_id, doc_type="user_guide"):
    return await kb_service.index_document(
        doc_id=doc_id,
        content=f"content for {doc_id}",
        doc_name=doc_id,
        doc_type=doc_type,
        job_id=job_id,
        persist_dir=persist,
    )


def test_job_retrieval_unions_global_library(kb_store):
    # Run inside a single event loop (no pytest-asyncio dependency).
    async def _run():
        await _index(kb_store, "d_jobA", "jobA")
        await _index(kb_store, "d_glob", kb_service.GLOBAL_JOB_SENTINEL)

        def ids(res):
            return {r["doc_id"] for r in res}

        # Job A sees its own doc AND the global library.
        r = await kb_service.retrieve("q", n_results=10, job_id="jobA", persist_dir=kb_store)
        assert ids(r) == {"d_jobA", "d_glob"}

        # A different job sees only the global doc — never job A's private doc.
        r = await kb_service.retrieve("q", n_results=10, job_id="jobB", persist_dir=kb_store)
        assert ids(r) == {"d_glob"}

        # No job context → global library only.
        r = await kb_service.retrieve("q", n_results=10, job_id=None, include_global=True, persist_dir=kb_store)
        assert ids(r) == {"d_glob"}

        # Explicit opt-out of global → that job's docs only.
        r = await kb_service.retrieve("q", n_results=10, job_id="jobA", include_global=False, persist_dir=kb_store)
        assert ids(r) == {"d_jobA"}

    asyncio.run(_run())


def test_delete_global_doc_removes_its_chunks(kb_store):
    async def _run():
        await _index(kb_store, "d_glob", kb_service.GLOBAL_JOB_SENTINEL)
        r = await kb_service.retrieve("q", n_results=10, job_id="jobX", persist_dir=kb_store)
        assert {x["doc_id"] for x in r} == {"d_glob"}

        await kb_service.delete_document("d_glob", persist_dir=kb_store)
        r = await kb_service.retrieve("q", n_results=10, job_id="jobX", persist_dir=kb_store)
        assert r == []

    asyncio.run(_run())


def test_is_global_property():
    glob = KBDocument(id="1", job_id=None, name="m", doc_type="user_guide",
                      content="x", created_at="t", updated_at="t")
    scoped = KBDocument(id="2", job_id="jobA", name="m", doc_type="asset_inventory",
                        content="x", created_at="t", updated_at="t")
    assert glob.is_global is True
    assert scoped.is_global is False


# ── API-level: library endpoints ─────────────────────────────────────────


def _file_backed_app(tmp_path, monkeypatch, embed=_const_embed, admin_token=None):
    """Build a TestClient over a real file-based SQLite engine.

    Indexing runs in a BackgroundTask on its own session, so — like production —
    the app must use a normal session-per-connection factory (not one shared
    in-memory connection) for the task's commit to be visible to later requests.
    Returns (client, cleanup).
    """
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    import backend.app.models.knowledge_base  # noqa: F401  register kb_documents
    from backend.app.api.deps import get_db
    from backend.app.config_v2 import Settings, get_settings
    from backend.app.database_v2 import Base, _set_sqlite_pragmas
    from backend.app.main_v2 import create_app

    kb_service.reset_collection()
    monkeypatch.setattr(kb_service, "get_embeddings", embed)

    db_path = tmp_path / "aipam.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(engine)
    session_mk = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _override_db():
        db = session_mk()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    settings = Settings(
        aipam_api_token="test-token-v2",
        aipam_db_path=db_path,
        aipam_kb_admin_token=admin_token,
    )
    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_settings] = lambda: settings

    def _cleanup():
        engine.dispose()
        kb_service.reset_collection()

    return TestClient(app), _cleanup


@pytest.fixture()
def lib_client(tmp_path, monkeypatch):
    client, cleanup = _file_backed_app(tmp_path, monkeypatch)
    yield client
    cleanup()


def test_library_document_crud_and_scope(lib_client):
    # Add a global reference-library document (an "exploit manual").
    r = lib_client.post(
        "/api/v1/kb/library/documents", headers=AUTH,
        json={"name": "Exploit Manual", "doc_type": "user_guide",
              "content": "Payload options: set LHOST and LPORT before running."},
    )
    assert r.status_code == 201, r.text
    doc = r.json()
    assert doc["is_global"] is True
    assert doc["job_id"] is None
    doc_id = doc["id"]

    # Indexing runs in the background (BackgroundTasks complete before the test
    # client returns), so by now the document has settled to "indexed".
    r = lib_client.get(f"/api/v1/kb/library/documents/{doc_id}", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["status"] == "indexed"

    # It appears in the library listing.
    r = lib_client.get("/api/v1/kb/library/documents", headers=AUTH)
    assert any(d["id"] == doc_id for d in r.json()["items"])

    # Library search finds it.
    r = lib_client.post("/api/v1/kb/library/search", headers=AUTH, json={"query": "payload"})
    assert r.status_code == 200
    assert any(x["doc_id"] == doc_id for x in r.json()["results"])

    # Re-index works and returns to indexed.
    r = lib_client.post(f"/api/v1/kb/library/documents/{doc_id}/reindex", headers=AUTH)
    assert r.status_code == 200, r.text
    r = lib_client.get(f"/api/v1/kb/library/documents/{doc_id}", headers=AUTH)
    assert r.json()["status"] == "indexed"

    # Delete removes it from the listing.
    r = lib_client.delete(f"/api/v1/kb/library/documents/{doc_id}", headers=AUTH)
    assert r.status_code == 204
    r = lib_client.get("/api/v1/kb/library/documents", headers=AUTH)
    assert not any(d["id"] == doc_id for d in r.json()["items"])


def test_degraded_status_when_embeddings_fall_back(tmp_path, monkeypatch):
    """If the embedding model is unavailable, the doc is flagged 'degraded'."""
    # Force every chunk onto the hash fallback path and record it in _stats,
    # mirroring what get_embeddings does when Ollama is unreachable.
    async def _all_fallback(texts, ollama_url="", model="", _stats=None):
        if _stats is not None:
            _stats["fallback"] = _stats.get("fallback", 0) + len(texts)
        return [kb_service._fallback_embedding(t) for t in texts]

    client, cleanup = _file_backed_app(tmp_path, monkeypatch, embed=_all_fallback)
    try:
        r = client.post("/api/v1/kb/library/documents", headers=AUTH,
                        json={"name": "Big Manual", "doc_type": "user_guide", "content": "x" * 5000})
        assert r.status_code == 201
        doc_id = r.json()["id"]

        r = client.get(f"/api/v1/kb/library/documents/{doc_id}", headers=AUTH)
        body = r.json()
        assert body["status"] == "degraded"
        assert "Re-index" in (body["error_message"] or "")
    finally:
        cleanup()


def test_library_endpoints_require_auth(lib_client):
    assert lib_client.get("/api/v1/kb/library/documents").status_code in (401, 403)


def test_duplicate_upload_is_rejected(lib_client):
    payload = {"name": "Manual v1", "doc_type": "user_guide", "content": "identical body text"}
    assert lib_client.post("/api/v1/kb/library/documents", headers=AUTH, json=payload).status_code == 201
    # Same content in the same scope → 409, even under a different name.
    dup = lib_client.post("/api/v1/kb/library/documents", headers=AUTH,
                          json={**payload, "name": "Manual copy"})
    assert dup.status_code == 409
    assert "already in the knowledge base" in dup.json()["error"].lower()


# ── Tier 3: structure-aware chunking ─────────────────────────────────────


def test_chunk_structured_builds_heading_breadcrumbs():
    text = (
        "# Setup\n"
        "Install the toolkit first.\n\n"
        "## Payload options\n"
        "Set LHOST and LPORT.\n\n"
        "# Cleanup\n"
        "Remove artifacts."
    )
    pairs = kb_service.chunk_structured(text)
    labels = {label for _, label in pairs}
    assert "Setup" in labels
    assert "Setup › Payload options" in labels
    assert "Cleanup" in labels


def test_chunk_structured_labels_page_markers():
    text = "--- Page 1 ---\nintro text\n\n--- Page 2 ---\nmore text"
    labels = {label for _, label in kb_service.chunk_structured(text)}
    assert any(label.startswith("Page 1") for label in labels)
    assert any(label.startswith("Page 2") for label in labels)


def test_chunk_structured_plain_text_single_section():
    pairs = kb_service.chunk_structured("just a short note with no structure")
    assert len(pairs) == 1
    assert pairs[0][1] == ""


# ── Tier 3: PPTX extraction ──────────────────────────────────────────────


def test_pptx_text_extraction():
    pptx = pytest.importorskip("pptx")
    import io

    from backend.app.api.knowledge_base import _extract_text_from_binary

    prs = pptx.Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = "Capability Overview"
    buf = io.BytesIO()
    prs.save(buf)

    text = _extract_text_from_binary("brief.pptx", buf.getvalue())
    assert "--- Slide 1 ---" in text
    assert "Capability Overview" in text


# ── Tier 4: OCR graceful degradation ─────────────────────────────────────


def test_ocr_pdf_pages_never_raises():
    """OCR is best-effort — missing stack / bad input returns {}, never raises."""
    from backend.app.api.knowledge_base import _ocr_pdf_pages
    assert _ocr_pdf_pages(b"", []) == {}
    assert _ocr_pdf_pages(b"not a real pdf", [0]) == {}


# ── Tier 4: shared-library access gating ─────────────────────────────────


def test_library_config_open_by_default(lib_client):
    r = lib_client.get("/api/v1/kb/library/config", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["admin_required"] is False


def test_library_admin_token_gates_writes_not_reads(tmp_path, monkeypatch):
    client, cleanup = _file_backed_app(tmp_path, monkeypatch, admin_token="s3cret")
    admin = {**AUTH, "X-KB-Admin-Token": "s3cret"}
    payload = {"name": "Exploit Manual", "doc_type": "user_guide", "content": "payload body"}
    try:
        # Config advertises the gate.
        assert client.get("/api/v1/kb/library/config", headers=AUTH).json()["admin_required"] is True

        # Write without / with a wrong admin token → 403.
        assert client.post("/api/v1/kb/library/documents", headers=AUTH, json=payload).status_code == 403
        assert client.post("/api/v1/kb/library/documents",
                           headers={**AUTH, "X-KB-Admin-Token": "nope"}, json=payload).status_code == 403

        # Correct admin token → created.
        r = client.post("/api/v1/kb/library/documents", headers=admin, json=payload)
        assert r.status_code == 201, r.text
        doc_id = r.json()["id"]

        # Reads stay open to any valid API token (no admin header needed).
        assert client.get("/api/v1/kb/library/documents", headers=AUTH).status_code == 200
        assert client.post("/api/v1/kb/library/search", headers=AUTH,
                           json={"query": "payload"}).status_code == 200

        # Delete is gated too.
        assert client.delete(f"/api/v1/kb/library/documents/{doc_id}", headers=AUTH).status_code == 403
        assert client.delete(f"/api/v1/kb/library/documents/{doc_id}", headers=admin).status_code == 204
    finally:
        cleanup()
