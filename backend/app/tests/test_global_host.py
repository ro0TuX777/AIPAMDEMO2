import json
import pytest
from pathlib import Path
from backend.app.normalize.correlate import correlate_job
from backend.app.normalize.post_process import update_global_host_stats
from backend.app.models.host import Host
from backend.app.models.global_host import GlobalHost
from backend.app.models.job import Job
from backend.app.database_v2 import init_v2_db, get_session_factory
from backend.app.config_v2 import get_settings
from sqlalchemy import select

TOKEN = "test-token-v2"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

def test_cross_job_host_forensics(tmp_path, monkeypatch):
    # 0. Setup isolated environment
    monkeypatch.setenv("AIPAM_API_TOKEN", "test-token")
    db_file = tmp_path / "test_global.db"
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    
    settings = get_settings()
    monkeypatch.setattr(settings, "aipam_db_path", db_file)
    monkeypatch.setattr(settings, "aipam_job_root", job_root)
    
    init_v2_db()
    session_factory = get_session_factory()
    db = session_factory()
    
    ip = "10.0.0.50"
    
    # --- JOB A ---
    job_a_id = "job_a"
    db.add(Job(job_id=job_a_id, status="completed", execution_profile="standard", created_at="2024-01-01T10:00:00Z"))
    db.commit()
    
    # Create sensors directory and results
    job_a_dir = job_root / job_a_id
    sensor_dir = job_a_dir / "sensors" / "zeek"
    sensor_dir.mkdir(parents=True)
    
    results_a = [
        {"type": "conn", "data": {"src_ip": ip, "dst_ip": "8.8.8.8", "proto": "TCP", "ts": "2024-01-01T10:00:00Z"}},
        {"type": "alert", "data": {"src_ip": ip, "signature": "Test Alert A", "severity": "high", "ts": "2024-01-01T10:05:00Z"}}
    ]
    with open(sensor_dir / "sensor.results.jsonl", "w") as f:
        for r in results_a:
            f.write(json.dumps(r) + "\n")
            
    # Correlate Job A
    correlate_job(job_a_id, job_a_dir, db)
    update_global_host_stats(db, job_a_id)
    
    # Verify GlobalHost A
    gh = db.get(GlobalHost, ip)
    assert gh is not None
    assert gh.job_count == 1
    assert gh.total_alerts == 1
    assert gh.first_seen == "2024-01-01T10:00:00Z"
    
    # --- JOB B ---
    job_b_id = "job_b"
    db.add(Job(job_id=job_b_id, status="completed", execution_profile="standard", created_at="2024-01-02T10:00:00Z"))
    db.commit()
    
    job_b_dir = job_root / job_b_id
    sensor_dir_b = job_b_dir / "sensors" / "suricata"
    sensor_dir_b.mkdir(parents=True)
    
    results_b = [
        {"type": "conn", "data": {"src_ip": ip, "dst_ip": "1.2.3.4", "proto": "TCP", "ts": "2024-01-02T10:00:00Z"}},
        {"type": "alert", "data": {"src_ip": ip, "signature": "Test Alert B", "severity": "critical", "ts": "2024-01-02T10:10:00Z"}},
        {"type": "alert", "data": {"src_ip": ip, "signature": "Test Alert C", "severity": "medium", "ts": "2024-01-02T10:15:00Z"}}
    ]
    with open(sensor_dir_b / "sensor.results.jsonl", "w") as f:
        for r in results_b:
            f.write(json.dumps(r) + "\n")
            
    # Correlate Job B
    correlate_job(job_b_id, job_b_dir, db)
    update_global_host_stats(db, job_b_id)
    
    # Verify Aggregated Stats
    db.expire_all()
    gh = db.get(GlobalHost, ip)
    assert gh.job_count == 2
    assert gh.total_alerts == 3 # 1 from A + 2 from B
    assert gh.last_seen == "2024-01-02T10:15:00Z"
    
    history = json.loads(gh.history_json)
    assert len(history) == 2
    assert history[0]["job_id"] == "job_b" # Sorted descending
    assert history[1]["job_id"] == "job_a"
    
    db.close()


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

from unittest.mock import patch
from pathlib import Path as _Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from backend.app.database_v2 import Base, _set_sqlite_pragmas, get_db
from backend.app.main_v2 import create_app
from backend.app.config_v2 import Settings, get_settings


@pytest.fixture()
def api_client(tmp_path):
    """Standalone FastAPI TestClient with in-memory DB for global host tests."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)

    app = create_app()
    connection = engine.connect()

    def _override_db():
        db = Session(bind=connection)
        try:
            yield db
        finally:
            db.close()

    _test_settings = Settings(
        aipam_api_token="test-token-v2",
        aipam_upload_root=tmp_path / "uploads",
        aipam_job_root=tmp_path / "jobs",
        aipam_db_path=_Path("/tmp/unused.db"),
    )
    (tmp_path / "uploads").mkdir(exist_ok=True)
    (tmp_path / "jobs").mkdir(exist_ok=True)

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_settings] = lambda: _test_settings

    with patch("backend.app.api.jobs._dispatch_job"):
        client = TestClient(app)
        db = Session(bind=connection)
        yield client, db
        db.close()
    connection.close()
    engine.dispose()


def _insert_global_host(db, ip, job_count=1, total_alerts=0, total_findings=0,
                        seen_as_internal=False, roles=None, history=None,
                        first_seen="2024-01-01T10:00:00Z",
                        last_seen="2024-01-01T10:00:00Z", hostname=None):
    gh = GlobalHost(
        ip=ip,
        hostname=hostname,
        first_seen=first_seen,
        last_seen=last_seen,
        job_count=job_count,
        total_alerts=total_alerts,
        total_findings=total_findings,
        seen_as_internal=seen_as_internal,
        roles_json=json.dumps(roles or []),
        history_json=json.dumps(history or []),
    )
    db.add(gh)
    db.commit()
    return gh


def test_list_global_hosts_empty(api_client):
    client, db = api_client
    resp = client.get("/api/v1/hosts", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert "page" in data


def test_list_global_hosts_returns_items(api_client):
    client, db = api_client
    _insert_global_host(db, "10.0.0.1", job_count=3, total_alerts=5,
                        seen_as_internal=True, roles=["internal", "client"])
    _insert_global_host(db, "8.8.8.8", job_count=1, total_alerts=0,
                        seen_as_internal=False, roles=["external"])

    resp = client.get("/api/v1/hosts", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2

    ips = {item["ip"] for item in data["items"]}
    assert ips == {"10.0.0.1", "8.8.8.8"}


def test_list_global_hosts_internal_only_filter(api_client):
    client, db = api_client
    _insert_global_host(db, "10.0.0.1", seen_as_internal=True)
    _insert_global_host(db, "8.8.8.8", seen_as_internal=False)

    # Filter internal only
    resp = client.get("/api/v1/hosts?internal_only=true", headers=AUTH)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["ip"] == "10.0.0.1"

    # Filter external only
    resp = client.get("/api/v1/hosts?internal_only=false", headers=AUTH)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["ip"] == "8.8.8.8"


def test_list_global_hosts_pagination(api_client):
    client, db = api_client
    for i in range(5):
        _insert_global_host(db, f"10.0.0.{i}", job_count=5 - i)

    resp = client.get("/api/v1/hosts?limit=2", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["page"]["has_more"] is True
    assert data["page"]["next_cursor"] is not None


def test_get_global_host_found(api_client):
    client, db = api_client
    history = [
        {"job_id": "job_a", "ts": "2024-01-01T10:00:00Z", "role": "internal",
         "alert_count": 2, "finding_count": 1},
    ]
    _insert_global_host(db, "192.168.1.1", job_count=1, total_alerts=2,
                        total_findings=1, seen_as_internal=True,
                        roles=["internal"], history=history,
                        hostname="workstation-1")

    resp = client.get("/api/v1/hosts/192.168.1.1", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    host = data["host"]
    assert host["ip"] == "192.168.1.1"
    assert host["hostname"] == "workstation-1"
    assert host["job_count"] == 1
    assert host["total_alerts"] == 2
    assert host["total_findings"] == 1
    assert host["seen_as_internal"] is True
    assert host["roles"] == ["internal"]
    assert len(host["history"]) == 1
    assert host["history"][0]["job_id"] == "job_a"


def test_get_global_host_not_found(api_client):
    client, db = api_client
    resp = client.get("/api/v1/hosts/99.99.99.99", headers=AUTH)
    assert resp.status_code == 404
