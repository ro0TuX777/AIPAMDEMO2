"""Raw event explorer tests (Phase 5: search, aggregation, flow)."""

import json
import uuid
from datetime import datetime, timezone

from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_job(db) -> str:
    job = Job(
        job_id="44444444-4444-4444-4444-444444444444",
        job_name="Events Job", status="completed",
        execution_profile="standard", priority="normal", created_at=_now_iso(),
    )
    db.add(job)
    db.commit()
    return job.job_id


def _add_event(db, job_id, **kw):
    defaults = dict(
        event_id=str(uuid.uuid4()), job_id=job_id, event_type="connection",
        timestamp=_now_iso(), source_type="pcap", evidence_status="observed",
    )
    defaults.update(kw)
    db.add(NormalizedEvent(**defaults))
    db.commit()


def _seed(db, job_id):
    _add_event(db, job_id, event_type="dns", src_ip="10.0.0.1", dest_ip="8.8.8.8",
               dest_port=53, proto="udp", hostname="WS1",
               data_json=json.dumps({"query": "evil.example.com"}))
    _add_event(db, job_id, event_type="http", src_ip="10.0.0.1", dest_ip="93.184.216.34",
               dest_port=80, proto="tcp", hostname="WS1",
               data_json=json.dumps({"host": "good.example.com"}))
    _add_event(db, job_id, event_type="http", src_ip="10.0.0.2", dest_ip="93.184.216.34",
               dest_port=443, proto="tcp", hostname="WS2",
               data_json=json.dumps({"host": "evil.example.com"}))


class TestEventSearch:
    def test_list_all(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _seed(db, job_id)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert len(body["items"]) == 3

    def test_filter_by_event_type(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _seed(db, job_id)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events?event_type=http", headers=AUTH_HEADER)
        assert r.json()["total"] == 2

    def test_substring_search(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _seed(db, job_id)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events?q=evil.example.com", headers=AUTH_HEADER)
        assert r.json()["total"] == 2

    def test_pagination(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _seed(db, job_id)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events?limit=1&offset=0", headers=AUTH_HEADER)
        body = r.json()
        assert body["total"] == 3
        assert len(body["items"]) == 1


class TestEventAggregate:
    def test_aggregate_event_type(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _seed(db, job_id)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events/aggregate?field=event_type",
                       headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        counts = {b["value"]: b["count"] for b in body["buckets"]}
        assert counts == {"http": 2, "dns": 1}
        assert body["total_events"] == 3

    def test_aggregate_invalid_field(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events/aggregate?field=data_json",
                       headers=AUTH_HEADER)
        assert r.status_code == 400


class TestEventFlow:
    def test_flow_sankey(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _seed(db, job_id)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events/flow", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["flows_considered"] == 3
        node_ids = {n["id"] for n in body["nodes"]}
        assert "src:10.0.0.1" in node_ids
        assert "host:93.184.216.34" in node_ids
        assert "port:443" in node_ids
        # Every link references valid node indices.
        for link in body["links"]:
            assert 0 <= link["source"] < len(body["nodes"])
            assert 0 <= link["target"] < len(body["nodes"])
            assert link["value"] >= 1


class TestEventAuthAndErrors:
    def test_requires_auth(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        r = client.get(f"/api/v1/jobs/{job_id}/raw-events")
        assert r.status_code == 401

    def test_job_not_found(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/missing/raw-events", headers=AUTH_HEADER)
        assert r.status_code == 404
