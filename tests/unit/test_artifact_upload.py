"""Generic artifact upload + classification tests (Phase 2)."""

from backend.app.pipeline.artifact_classifier import (
    ARCHIVE,
    BINARY,
    LOG,
    PCAP,
    UNKNOWN,
    classify_artifact,
)

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}
OCTET = {"Content-Type": "application/octet-stream"}

PCAP_BODY = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64
ELF_BODY = b"\x7fELF" + b"\x00" * 64
PE_BODY = b"MZ" + b"\x00" * 64
ZIP_BODY = b"PK\x03\x04" + b"\x00" * 64
GZIP_BODY = b"\x1f\x8b" + b"\x00" * 64
TEXT_BODY = b"Jan 1 00:00:00 host sshd[1]: Accepted password for root\n" * 3


class TestClassifier:
    def test_pcap_magic(self, tmp_path):
        p = tmp_path / "x.bin"
        p.write_bytes(PCAP_BODY)
        assert classify_artifact(p).artifact_class == PCAP

    def test_elf_magic(self, tmp_path):
        p = tmp_path / "x.bin"
        p.write_bytes(ELF_BODY)
        r = classify_artifact(p)
        assert r.artifact_class == BINARY
        assert r.format == "elf"

    def test_pe_magic(self, tmp_path):
        p = tmp_path / "x.dat"
        p.write_bytes(PE_BODY)
        assert classify_artifact(p).format == "pe"

    def test_zip_magic(self, tmp_path):
        p = tmp_path / "x.dat"
        p.write_bytes(ZIP_BODY)
        assert classify_artifact(p).artifact_class == ARCHIVE

    def test_text_heuristic(self, tmp_path):
        p = tmp_path / "noext"
        p.write_bytes(TEXT_BODY)
        assert classify_artifact(p).artifact_class == LOG

    def test_extension_fallback_binary(self, tmp_path):
        p = tmp_path / "tool.dll"
        p.write_bytes(b"\x99\x98\x97\x00" * 20)
        assert classify_artifact(p).artifact_class == BINARY

    def test_unknown(self, tmp_path):
        p = tmp_path / "noext"
        p.write_bytes(b"\x00\x99\x01\x02\xff" * 20)
        assert classify_artifact(p).artifact_class == UNKNOWN


class TestArtifactUpload:
    def _upload(self, client, name, body):
        return client.post(
            f"/api/v1/uploads/artifact?filename={name}",
            content=body,
            headers={**AUTH_HEADER, **OCTET},
        )

    def test_upload_pcap_classified(self, app_client):
        client, _ = app_client
        r = self._upload(client, "capture.pcap", PCAP_BODY)
        assert r.status_code == 201
        body = r.json()
        assert body["artifact_class"] == PCAP
        assert body["upload_id"]
        assert body["sha256"]

    def test_upload_binary_classified(self, app_client):
        client, _ = app_client
        r = self._upload(client, "malware", ELF_BODY)
        assert r.status_code == 201
        assert r.json()["artifact_class"] == BINARY

    def test_upload_log_classified(self, app_client):
        client, _ = app_client
        r = self._upload(client, "auth.log", TEXT_BODY)
        assert r.status_code == 201
        assert r.json()["artifact_class"] == LOG

    def test_upload_empty_returns_400(self, app_client):
        client, _ = app_client
        r = self._upload(client, "empty.bin", b"")
        assert r.status_code == 400

    def test_upload_requires_auth(self, app_client):
        client, _ = app_client
        r = client.post(
            "/api/v1/uploads/artifact?filename=x.bin",
            content=PCAP_BODY,
            headers=OCTET,
        )
        assert r.status_code == 401


class TestClassifyExisting:
    def test_classify_existing_upload(self, app_client):
        client, _ = app_client
        # Upload via standard PCAP endpoint (no artifact_class set)
        up = client.post(
            "/api/v1/uploads?filename=c.pcap",
            content=PCAP_BODY,
            headers={**AUTH_HEADER, **OCTET},
        )
        upload_id = up.json()["upload_id"]
        r = client.post(
            f"/api/v1/uploads/{upload_id}/classify",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["artifact_class"] == PCAP
        assert body["upload_id"] == upload_id

    def test_classify_missing_upload_404(self, app_client):
        client, _ = app_client
        r = client.post("/api/v1/uploads/does-not-exist/classify", headers=AUTH_HEADER)
        assert r.status_code == 404
