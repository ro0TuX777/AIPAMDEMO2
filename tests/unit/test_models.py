"""Smoke tests for V2 ORM models and fixtures."""

from backend.app.models import Job, Host, Upload


def test_job_creation(sample_job):
    """Verify sample_job fixture creates a valid Job."""
    assert sample_job.job_id is not None
    assert sample_job.status == "queued"
    assert sample_job.execution_profile == "standard"


def test_upload_creation(sample_upload):
    """Verify sample_upload fixture creates a valid Upload."""
    assert sample_upload.upload_id is not None
    assert sample_upload.filename == "test.pcap"
    assert sample_upload.size_bytes == 1024


def test_host_linked_to_job(sample_host, sample_job):
    """Verify host is linked to its parent job."""
    assert sample_host.job_id == sample_job.job_id
    assert sample_host.ip == "10.0.0.5"
    assert sample_host.role == "internal"


def test_all_tables_created(db_engine):
    """Verify all 13 V2 tables exist."""
    from sqlalchemy import inspect
    inspector = inspect(db_engine)
    tables = set(inspector.get_table_names())
    expected = {
        "jobs", "job_sensors", "hosts", "connections", "dns_queries",
        "tls_sessions", "alerts", "files", "findings", "iocs",
        "timeline_events", "artifacts", "uploads",
    }
    assert expected.issubset(tables), f"Missing tables: {expected - tables}"


def test_cascade_delete(db_session, sample_host, sample_job):
    """Verify ON DELETE CASCADE works — deleting job removes host."""
    db_session.delete(sample_job)
    db_session.commit()
    remaining = db_session.query(Host).filter_by(job_id=sample_job.job_id).all()
    assert remaining == []

