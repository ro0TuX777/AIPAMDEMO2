"""Sigma engine + API tests (Phase 3)."""

import json
from datetime import datetime, timezone

from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.sigma import load_rule, match_event, run_rules

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}

ENCODED_PS_RULE = """
title: Encoded PowerShell
id: test-enc-ps
level: high
detection:
  sel_img:
    Image|endswith: '\\powershell.exe'
  sel_flag:
    CommandLine|contains:
      - ' -enc '
      - 'FromBase64String'
  condition: sel_img and sel_flag
tags:
  - attack.t1059.001
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TestEngine:
    def test_match_positive(self):
        rule = load_rule(ENCODED_PS_RULE)
        ev = {"Image": r"C:\Windows\System32\powershell.exe",
              "CommandLine": "powershell.exe -enc ZQBjAGgAbw=="}
        assert match_event(rule, ev) is True

    def test_no_match_missing_flag(self):
        rule = load_rule(ENCODED_PS_RULE)
        ev = {"Image": r"C:\Windows\powershell.exe", "CommandLine": "powershell.exe -Help"}
        assert match_event(rule, ev) is False

    def test_no_match_wrong_image(self):
        rule = load_rule(ENCODED_PS_RULE)
        ev = {"Image": r"C:\Windows\cmd.exe", "CommandLine": "cmd -enc x"}
        assert match_event(rule, ev) is False

    def test_condition_not(self):
        rule = load_rule("""
title: t
id: t
level: low
detection:
  sel:
    EventID: 1
  filt:
    User: 'SYSTEM'
  condition: sel and not filt
""")
        assert match_event(rule, {"EventID": 1, "User": "alice"}) is True
        assert match_event(rule, {"EventID": 1, "User": "SYSTEM"}) is False

    def test_one_of_them(self):
        rule = load_rule("""
title: t
id: t
level: low
detection:
  sel_a:
    A: '1'
  sel_b:
    B: '2'
  condition: 1 of them
""")
        assert match_event(rule, {"A": "1"}) is True
        assert match_event(rule, {"B": "2"}) is True
        assert match_event(rule, {"C": "3"}) is False

    def test_run_rules(self):
        rule = load_rule(ENCODED_PS_RULE)
        events = [
            {"Image": r"x\powershell.exe", "CommandLine": "powershell -enc abc"},
            {"Image": r"x\cmd.exe", "CommandLine": "nothing"},
        ]
        matches = run_rules([rule], events)
        assert len(matches) == 1
        assert matches[0].rule_id == "test-enc-ps"


def _make_job(db) -> str:
    job = Job(
        job_id="22222222-2222-2222-2222-222222222222",
        job_name="Sigma Job", status="completed",
        execution_profile="standard", priority="normal", created_at=_now_iso(),
    )
    db.add(job)
    db.commit()
    return job.job_id


def _add_event(db, job_id, data: dict, event_id: str):
    db.add(NormalizedEvent(
        event_id=event_id, job_id=job_id, event_type="process",
        timestamp=_now_iso(), source_type="log_bundle", hostname="WIN-1",
        data_json=json.dumps(data),
    ))
    db.commit()


class TestSigmaApi:
    def test_analyze_and_list(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        _add_event(db, job_id, {
            "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell -enc ZQBjAA==",
        }, "evt-1")
        _add_event(db, job_id, {"Image": r"C:\cmd.exe", "CommandLine": "dir"}, "evt-2")

        r = client.post(f"/api/v1/jobs/{job_id}/sigma/analyze", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["events_scanned"] == 2
        assert body["detections_created"] >= 1
        assert body["rules_evaluated"] >= 1

        # Idempotent: re-running creates no duplicates
        r2 = client.post(f"/api/v1/jobs/{job_id}/sigma/analyze", headers=AUTH_HEADER)
        assert r2.json()["detections_created"] == 0

        lr = client.get(f"/api/v1/jobs/{job_id}/sigma", headers=AUTH_HEADER)
        assert lr.status_code == 200
        assert lr.json()["total"] == body["detections_total"]

    def test_list_requires_auth(self, app_client):
        client, db = app_client
        job_id = _make_job(db)
        r = client.get(f"/api/v1/jobs/{job_id}/sigma")
        assert r.status_code == 401

    def test_job_not_found(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/missing/sigma", headers=AUTH_HEADER)
        assert r.status_code == 404
