import shutil
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from backend.app.database_v2 import get_session_factory, init_v2_db
from backend.app.models.job import Job
from backend.app.config_v2 import get_settings
from backend.app.worker import prune_old_jobs

def test_prune_old_jobs(monkeypatch, tmp_path):
    # 1. Setup
    # Use a temporary DB file for isolation
    db_file = tmp_path / "test_aipam.db"
    job_root = tmp_path / "jobs"
    job_root.mkdir()
    
    settings = get_settings()
    monkeypatch.setattr(settings, "aipam_db_path", db_file)
    monkeypatch.setattr(settings, "aipam_job_root", job_root)
    monkeypatch.setattr(settings, "aipam_job_retention_days", 1)
    
    init_v2_db()
    session_factory = get_session_factory()
    db = session_factory()
    
    # Create an old job (2 days old)
    old_job_id = "test-old-job"
    old_date = datetime.now(timezone.utc) - timedelta(days=2)
    old_job = Job(
        job_id=old_job_id,
        status="completed",
        execution_profile="test",
        created_at=old_date.isoformat()
    )
    
    # Create a new job (today)
    new_job_id = "test-new-job"
    new_job = Job(
        job_id=new_job_id,
        status="completed",
        execution_profile="test",
        created_at=datetime.now(timezone.utc).isoformat()
    )
    
    db.add(old_job)
    db.add(new_job)
    db.commit()
    
    # Create disk directories
    old_path = settings.aipam_job_root / old_job_id
    new_path = settings.aipam_job_root / new_job_id
    old_path.mkdir(parents=True, exist_ok=True)
    new_path.mkdir(parents=True, exist_ok=True)
    (old_path / "test.pcap").touch()
    (new_path / "test.pcap").touch()
    
    try:
        # 2. Run Prune
        result = prune_old_jobs()
        
        # 3. Verify
        assert result["status"] == "success"
        assert result["pruned_count"] >= 1
        
        # Check DB
        stmt = select(Job).where(Job.job_id == old_job_id)
        assert db.execute(stmt).scalar_one_or_none() is None
        
        stmt = select(Job).where(Job.job_id == new_job_id)
        assert db.execute(stmt).scalar_one_or_none() is not None
        
        # Check Disk
        assert not old_path.exists()
        assert new_path.exists()
        
    finally:
        # Cleanup
        if old_path.exists():
            shutil.rmtree(old_path)
        if new_path.exists():
            shutil.rmtree(new_path)
        db.close()
