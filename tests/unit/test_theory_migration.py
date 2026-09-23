"""Populated semantic identity migration against the actual runtime head."""
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.exc import IntegrityError

ROOT = Path(__file__).parents[2]
PREDECESSOR = "ac4e7b9d2103"
REVISION = "9c7e5a3b2d10"


def test_theory_migration_preserves_reviewed_legacy_row_and_round_trip(tmp_path, monkeypatch):
    config = Config()
    config.set_main_option("script_location", str(ROOT / "backend/alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'theory.db'}")
    monkeypatch.delenv("AIPAM_DB_PATH", raising=False)
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_revision(REVISION) is not None
    assert scripts.get_revision(REVISION).down_revision == PREDECESSOR
    command.upgrade(config, PREDECESSOR)
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    metadata = MetaData()
    metadata.reflect(engine)
    jobs, theories = metadata.tables["jobs"], metadata.tables["theories"]
    with engine.begin() as conn:
        conn.execute(jobs.insert().values(job_id="legacy", status="completed",
            execution_profile="standard", priority="normal", source_type="pcap",
            created_at="2026-01-01", execution_attempt=3,
            run_token="test-run", executor_session_id=1234, executor_group_nonce="test-nonce",
            queued_at="2026-01-02", accepted_run_manifest_json='{"test": true}'))
        common = dict(job_id="legacy", scope_type="job", scope_id=None,
            label="Legacy C2", hypothesis_type="c2", score=0.8, confidence="high", rank=1,
            supporting_evidence_json='["F-1"]', contradicting_evidence_json='["F-2"]',
            score_breakdown_json='{"findings": 0.8}', explanation="keep explanation",
            next_steps_json='["keep step"]', created_at="2026-01-01")
        conn.execute(theories.insert(), [
            dict(common, id=1, theory_id="TH-unreviewed", analyst_status="unreviewed",
                 analyst_notes=None, reviewed_at=None, reviewer_id=None),
            dict(common, id=2, theory_id="TH-legacy-random", analyst_status="confirmed",
                 analyst_notes="original", reviewed_at="2026-01-02", reviewer_id="reviewer-a"),
            dict(common, id=3, theory_id="TH-newer-review", analyst_status="false_positive",
                 analyst_notes="newest notes", reviewed_at="2026-01-03", reviewer_id=None),
        ])
        conn.execute(theories.insert().values(**dict(common, id=4, theory_id="TH-phase",
            pcap_label="after", analyst_status="unreviewed")))
        job_before = dict(conn.execute(select(jobs)).mappings().one())
    command.upgrade(config, REVISION)
    metadata = MetaData()
    theories = Table("theories", metadata, autoload_with=engine)
    with engine.connect() as conn:
        rows = list(conn.execute(select(theories).order_by(theories.c.id)).mappings())
        assert len(rows) == 2
        survivor = dict(rows[0])
        assert survivor["id"] == 2
        assert survivor["theory_id"] == "TH-legacy-random"
        assert (survivor["phase_key"], survivor["scope_id_key"], survivor["theory_key"]) == ("", "", "c2")
        assert (survivor["analyst_status"], survivor["analyst_notes"], survivor["reviewed_at"], survivor["reviewer_id"]) == (
            "false_positive", "newest notes", "2026-01-03", "reviewer-a")
        for field in ("label", "score", "confidence", "rank", "supporting_evidence_json",
                      "contradicting_evidence_json", "score_breakdown_json", "explanation", "next_steps_json", "created_at"):
            assert survivor[field] == common[field]
    assert all(not c["nullable"] for c in inspect(engine).get_columns("theories")
               if c["name"] in ("phase_key", "scope_id_key", "theory_key"))
    with engine.begin() as conn:
        duplicate = dict(survivor, id=99, theory_id="TH-duplicate")
        with pytest.raises(IntegrityError):
            conn.execute(theories.insert().values(**duplicate))
    command.downgrade(config, PREDECESSOR)
    command.upgrade(config, REVISION)
    with engine.connect() as conn:
        assert [dict(row) for row in conn.execute(select(theories).order_by(theories.c.id)).mappings()] == [dict(row) for row in rows]
        assert dict(conn.execute(select(jobs)).mappings().one()) == job_before
    engine.dispose()
