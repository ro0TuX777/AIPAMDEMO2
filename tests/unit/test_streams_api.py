"""Stream forensics API tests: transcript / hexdump / carving."""

import subprocess
from datetime import datetime, timezone

from backend.app.models.job import Job

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_job(db, job_root, *, with_pcap=True) -> str:
    job = Job(
        job_id="11111111-1111-1111-1111-111111111111",
        job_name="Stream Job",
        status="completed",
        execution_profile="standard",
        priority="normal",
        created_at=_now_iso(),
    )
    db.add(job)
    db.commit()
    input_dir = job_root / job.job_id / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    if with_pcap:
        (input_dir / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    return job.job_id


def _fake_completed(stdout: bytes):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=b"")


class TestStreamList:
    def test_list_pcaps(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"])
        r = client.get(f"/api/v1/jobs/{job_id}/streams", headers=AUTH_HEADER)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["name"] == "capture.pcap"

    def test_list_job_not_found(self, app_client, tmp_dirs):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nope/streams", headers=AUTH_HEADER)
        assert r.status_code == 404


class TestAscii:
    def test_ascii_transcript(self, app_client, tmp_dirs, monkeypatch):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"])
        monkeypatch.setattr("backend.app.api.streams.shutil.which", lambda n: "/usr/bin/tshark")
        monkeypatch.setattr(
            "backend.app.api.streams.subprocess.run",
            lambda *a, **k: _fake_completed(b"GET / HTTP/1.1\r\nHost: x\r\n"),
        )
        r = client.get(
            f"/api/v1/jobs/{job_id}/streams/ascii",
            params={"src": "10.0.0.1", "sport": 1234, "dst": "10.0.0.2", "dport": 80},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert "GET /" in body["transcript"]
        assert body["protocol"] == "tcp"
        assert body["truncated"] is False

    def test_ascii_invalid_ip(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"])
        r = client.get(
            f"/api/v1/jobs/{job_id}/streams/ascii",
            params={"src": "not-an-ip", "sport": 1, "dst": "10.0.0.2", "dport": 80},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 400

    def test_ascii_invalid_proto(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"])
        r = client.get(
            f"/api/v1/jobs/{job_id}/streams/ascii",
            params={"src": "10.0.0.1", "sport": 1, "dst": "10.0.0.2", "dport": 80, "proto": "icmp"},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 400

    def test_ascii_no_pcap(self, app_client, tmp_dirs):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"], with_pcap=False)
        r = client.get(
            f"/api/v1/jobs/{job_id}/streams/ascii",
            params={"src": "10.0.0.1", "sport": 1, "dst": "10.0.0.2", "dport": 80},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 404


class TestHexdump:
    def test_hexdump_parsed(self, app_client, tmp_dirs, monkeypatch):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"])
        raw = (
            b"12:00:00.1 IP 10.0.0.1.1234 > 10.0.0.2.80: tcp 0\n"
            b"\t0x0000:  4500 0028 abcd\n"
            b"12:00:00.2 IP 10.0.0.2.80 > 10.0.0.1.1234: tcp 0\n"
            b"\t0x0000:  4500 0028 ef01\n"
        )
        monkeypatch.setattr("backend.app.api.streams.shutil.which", lambda n: "/usr/bin/tcpdump")
        monkeypatch.setattr(
            "backend.app.api.streams.subprocess.run", lambda *a, **k: _fake_completed(raw)
        )
        r = client.get(
            f"/api/v1/jobs/{job_id}/streams/hexdump",
            params={"src": "10.0.0.1", "sport": 1234, "dst": "10.0.0.2", "dport": 80},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        packets = r.json()["packets"]
        assert len(packets) == 2
        assert packets[0]["lines"][0].startswith("0x0000")


class TestCarve:
    def test_carve_download(self, app_client, tmp_dirs, monkeypatch):
        client, db = app_client
        job_id = _make_job(db, tmp_dirs["job_root"])
        monkeypatch.setattr("backend.app.api.streams.shutil.which", lambda n: "/usr/bin/tcpdump")

        def _fake_run(cmd, *a, **k):
            out = cmd[cmd.index("-w") + 1]
            with open(out, "wb") as f:
                f.write(b"\xd4\xc3\xb2\xa1carved")
            return _fake_completed(b"")

        monkeypatch.setattr("backend.app.api.streams.subprocess.run", _fake_run)
        r = client.get(
            f"/api/v1/jobs/{job_id}/streams/pcap",
            params={"src": "10.0.0.1", "sport": 1234, "dst": "10.0.0.2", "dport": 80},
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        assert r.content.startswith(b"\xd4\xc3\xb2\xa1")
