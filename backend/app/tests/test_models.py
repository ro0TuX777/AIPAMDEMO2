from datetime import datetime

from app.models import FlowRecord


def test_flowrecord_basic():
    now = datetime.utcnow()
    fr = FlowRecord(
        id="1",
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        transport_proto="TCP",
        app_proto="HTTP",
        start_time=now,
        end_time=now,
        duration_sec=0.0,
        bytes_from_src=10,
        bytes_from_dst=20,
        packets_from_src=1,
        packets_from_dst=2,
    )
    assert fr.src_ip == "10.0.0.1"




from app.models import AnalysisSummary, HostFinding, JobResult


def test_jobresult_round_trip_with_raw_alerts_and_llm_summary():
    summary = AnalysisSummary(
        severity="high",
        key_findings=["Suspicious lateral movement detected"],
        mitre_techniques=[{"id": "T1021", "name": "Remote Services"}],
    )

    hosts = [
        HostFinding(
            ip="10.0.0.5",
            role="victim",
            findings=[
                "Host experienced suspicious RDP connections.",
                "Multiple failed logins",
                "Unusual outbound traffic",
            ],
        )
    ]

    raw = {
        "alerts": [
            {
                "id": "a1",
                "alert_source": "suricata",
                "severity": "high",
                "signature": "ET POLICY Suspicious RDP Activity",
            }
        ],
        "llm_analysis_raw": {
            "chunks": [
                {
                    "overall_severity": "high",
                    "attack_chain": [],
                    "host_findings": [],
                    "anomalies": [],
                    "mitre_techniques_overall": [],
                }
            ],
            "summary": summary.model_dump(),
        },
    }

    report_urls = {
        "html": "/reports/job-123.html",
        "markdown": "/reports/job-123.md",
    }

    j1 = JobResult(
        job_id="job-123",
        status="completed",
        summary=summary,
        hosts=hosts,
        raw=raw,
        report_urls=report_urls,
    )

    data = j1.model_dump()
    j2 = JobResult(**data)

    assert j2 == j1
