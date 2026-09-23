"""Move V2 progressive snapshots without changing legacy-owned records."""
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, create_engine, inspect, select


@pytest.mark.parametrize('legacy_table', [True, False])
@pytest.mark.parametrize('precreated', [None, 'valid', 'invalid'])
def test_partial_result_migration_preserves_legacy_and_cascades_v2(tmp_path, monkeypatch, legacy_table, precreated):
    config = Config()
    config.set_main_option('script_location', str(Path(__file__).parents[2] / 'backend/alembic'))
    config.set_main_option('sqlalchemy.url', f"sqlite:///{tmp_path / 'migration.db'}")
    monkeypatch.delenv('AIPAM_DB_PATH', raising=False)
    command.upgrade(config, '9c7e5a3b2d10')
    engine = create_engine(config.get_main_option('sqlalchemy.url'))
    metadata = MetaData()
    metadata.reflect(engine)
    jobs = metadata.tables['jobs']
    legacy = metadata.tables['partialjobresultdb']
    with engine.begin() as conn:
        conn.execute(jobs.insert().values(job_id='v2-job', status='failed',
                                         execution_profile='standard', priority='normal',
                                         source_type='pcap', created_at='2026-01-01'))
        if legacy_table:
            from datetime import datetime
            # Historical V2 snapshots have no jobdb parent: the legacy writer
            # used a connection without FK enforcement before this runtime.
            conn.execute(legacy.insert(), [
                dict(job_id='v2-job', result={'stage': 'parse'}, updated_at=datetime(2026, 1, 1)),
                dict(job_id='legacy-job', result={'keep': True}, updated_at=datetime(2026, 1, 2)),
            ])
        else:
            legacy.drop(conn)
        if precreated == 'valid':
            from datetime import datetime
            from backend.app.models.partial_result import PartialResult
            PartialResult.__table__.create(conn)
            conn.execute(PartialResult.__table__.insert().values(
                job_id='v2-job', result={'stage': 'current'}, updated_at=datetime(2026, 2, 1)))
        elif precreated == 'invalid':
            conn.exec_driver_sql('CREATE TABLE partial_results (job_id VARCHAR PRIMARY KEY, result JSON, updated_at TEXT)')
    if precreated == 'invalid':
        with pytest.raises(RuntimeError, match='Unsupported partial_results schema'):
            command.upgrade(config, 'bd5f8c0e3214')
        engine.dispose()
        return
    command.upgrade(config, 'bd5f8c0e3214')
    partial = Table('partial_results', MetaData(), autoload_with=engine)
    with engine.connect() as conn:
        rows = conn.execute(select(partial)).mappings().all()
        assert len(rows) == int(legacy_table or precreated == 'valid')
        if rows:
            assert rows[0]['job_id'] == 'v2-job'
            assert rows[0]['result'] == {'stage': 'current' if precreated == 'valid' else 'parse'}
        if legacy_table:
            assert len(conn.execute(select(legacy)).all()) == 2
        conn.exec_driver_sql('PRAGMA foreign_keys=ON')
        conn.execute(jobs.delete().where(jobs.c.job_id == 'v2-job'))
        conn.commit()
        assert conn.execute(select(partial)).all() == []
        if legacy_table:
            assert len(conn.execute(select(legacy)).all()) == 2
    command.downgrade(config, '9c7e5a3b2d10')
    assert 'partial_results' not in inspect(engine).get_table_names()
    command.upgrade(config, 'bd5f8c0e3214')
    with engine.connect() as conn:
        assert conn.execute(select(partial)).all() == []
    engine.dispose()
