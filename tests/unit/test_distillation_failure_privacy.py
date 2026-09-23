"""Teacher HTTP/config/validation failures must not disclose provider payloads."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from backend.app import distillation

SECRET = 'synthetic-private-provider-payload'


@pytest.mark.parametrize('mode', ['http_error', 'exception'])
def test_teacher_http_failures_have_safe_logs(monkeypatch, caplog, mode):
    response = SimpleNamespace(status_code=500, json=lambda: {'error': SECRET}, text=SECRET)
    client = SimpleNamespace(post=AsyncMock(return_value=response))
    if mode == 'exception':
        client.post.side_effect = RuntimeError(SECRET)
    class Context:
        async def __aenter__(self):
            return client
        async def __aexit__(self, *args):
            return False
    monkeypatch.setattr(distillation.httpx, 'AsyncClient', lambda **kw: Context())
    teacher = distillation.TeacherConfig(endpoint='https://example.invalid', model='teacher', api_key='synthetic')
    assert asyncio.run(distillation.distill_chunk('system', 'user', teacher)) is None
    assert SECRET not in caplog.text


def test_teacher_schema_failure_has_safe_reason():
    def fail(data):
        raise ValueError(SECRET)
    spec = SimpleNamespace(output_schema=SimpleNamespace(model_validate=fail))
    result = distillation._validate_teacher_response('{}', spec)
    assert not result['valid']
    assert SECRET not in result['reason']


def test_teacher_config_failure_has_safe_logs(tmp_path, monkeypatch, caplog):
    config = tmp_path/'teacher.json'
    config.write_text(json.dumps({'temperature': SECRET}))
    monkeypatch.setattr(distillation, '_CONFIG_FILE', config)
    distillation._load_config_from_file()
    assert SECRET not in caplog.text
