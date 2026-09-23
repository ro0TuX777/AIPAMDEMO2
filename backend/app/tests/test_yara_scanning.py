import pytest
pytest.importorskip("yara", reason="Native YARA validation requires the Task 10 Linux app image")
import json
from backend.app.pipeline.sensor_handlers import handle_file_triage
from backend.app.normalize.correlate import correlate_job
from backend.app.models.file import File
from backend.app.database_v2 import create_test_schema, get_session_factory, reset_engine
from backend.app.config_v2 import get_settings
from sqlalchemy import select

def test_yara_scanning_logic(tmp_path, monkeypatch):
    # 0. Setup required env vars for Settings validation
    monkeypatch.setenv("AIPAM_API_TOKEN", "test-token")
    
    # 1. Setup isolated environment
    db_file = tmp_path / "test_yara.db"
    job_root = tmp_path / "jobs"
    yara_dir = tmp_path / "yara_rules"
    
    job_root.mkdir()
    yara_dir.mkdir()
    monkeypatch.setenv("AIPAM_YARA_RULES_DIR", str(yara_dir))
    
    settings = get_settings()
    monkeypatch.setattr(settings, "aipam_db_path", db_file)
    monkeypatch.setattr(settings, "aipam_job_root", job_root)
    monkeypatch.setattr(settings, "aipam_yara_rules_dir", yara_dir)
    
    # Initialize DB
    reset_engine()
    create_test_schema()
    session_factory = get_session_factory()
    db = session_factory()
    
    # Create the job record to satisfy foreign key constraints
    from backend.app.models.job import Job
    job_id = "test_yara_job"
    db.add(Job(
        job_id=job_id,
        status="running",
        execution_profile="standard",
        created_at="2024-01-01T12:00:00Z"
    ))
    db.commit()
    
    # 2. Setup YARA rule
    rule_content = """
rule TestRule {
    strings:
        $a = "MALWARE_SIGNATURE"
    condition:
        $a
}
"""
    (yara_dir / "test.yar").write_text(rule_content)
    
    # 3. Setup job directory and extracted files
    job_id = "test_yara_job"
    job_dir = job_root / job_id
    extracted_dir = job_dir / "extracted_files" / "files"
    extracted_dir.mkdir(parents=True)
    
    # Create a matching file
    malicious_file = extracted_dir / "malware.exe"
    malicious_file.write_text("Some prefix MALWARE_SIGNATURE some suffix")
    
    # Create a non-matching file
    clean_file = extracted_dir / "clean.txt"
    clean_file.write_text("Hello World")
    
    # 4. Run handle_file_triage
    sensor_out = job_dir / "sensors" / "file_triage"
    sensor_out.mkdir(parents=True)
    
    handle_file_triage(job_dir, sensor_out, job_id, "standard", run_output_dir=job_dir)
    
    # 5. Verify sensor output
    results_file = sensor_out / "sensor.results.jsonl"
    assert results_file.exists()
    
    results = []
    with open(results_file, "r") as f:
        for line in f:
            if line.strip():
                results.append(json.loads(line))
    
    # Filter for extracted_file events
    file_events = [it["data"] for it in results if it.get("type") == "extracted_file"]
    
    malware_evt = next(it for it in file_events if it["filename"] == "malware.exe")
    assert "TestRule" in malware_evt["yara_matches"]
    
    clean_evt = next(it for it in file_events if it["filename"] == "clean.txt")
    assert len(clean_evt["yara_matches"]) == 0
    
    # 6. Run correlator and verify DB
    correlate_job(job_id, job_dir, db)
    
    # Query the File model
    files = db.execute(select(File).where(File.job_id == job_id)).scalars().all()
    assert len(files) == 2
    
    db_malware = next(f for f in files if f.filename == "malware.exe")
    assert "TestRule" in db_malware.yara_matches
    assert db_malware.sha256 is not None
    assert db_malware.size_bytes > 0
    
    db_clean = next(f for f in files if f.filename == "clean.txt")
    assert db_clean.yara_matches == []
    
    db.close()
