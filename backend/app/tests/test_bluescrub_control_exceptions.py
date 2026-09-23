"""Real BlueScrub inner catches, gated by its Unix-only isolation dependency."""
import pytest
pytest.importorskip('resource', reason='BlueScrub isolation requires Unix resource; no runtime shim')

from sqlalchemy.exc import IntegrityError
from backend.app.tests.test_bluescrub_pipeline import db, job_dir, stub_registry
from backend.app.bluescrub import service
from backend.app.pipeline.outcomes import PipelineCanceled, OwnershipLost


@pytest.mark.parametrize('boundary', ['scanner', 're_signals', 'wordlist'])
@pytest.mark.parametrize('kind', ['cancel', 'ownership', 'database'])
def test_bluescrub_inner_catches_propagate_control_and_database(db, job_dir, stub_registry, monkeypatch, boundary, kind):
    error = {'cancel': PipelineCanceled('stop'), 'ownership': OwnershipLost('stop'),
             'database': IntegrityError('INSERT', {}, RuntimeError('database failed'))}[kind]
    def fail(*a, **kw):
        raise error
    if boundary == 'scanner':
        from dataclasses import replace
        specs = service.scanners_for('triage')
        monkeypatch.setattr(service, 'scanners_for', lambda _: [replace(specs[0], run=fail)])
    elif boundary == 're_signals':
        monkeypatch.setattr(service.re_signals, 'compute', fail)
    else:
        monkeypatch.setattr(service.wordlists, 'active_terms', fail)
    with pytest.raises(type(error)) as caught:
        service.analyze_and_persist(db, 'job-1', job_dir, profile='triage', run_output_dir=job_dir)
    assert caught.value is error
