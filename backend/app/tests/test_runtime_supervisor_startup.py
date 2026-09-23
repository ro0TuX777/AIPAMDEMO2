from contextlib import contextmanager
from types import SimpleNamespace
import sys

from backend.app import config_v2, database_v2, runtime_supervisor
from backend.app import schema_bootstrap


def test_main_uses_configured_database_path_under_schema_lock(monkeypatch, tmp_path):
    database_path = tmp_path / "aipam.db"
    settings = SimpleNamespace(
        aipam_job_root=tmp_path,
        aipam_reconcile_seconds=1,
        aipam_cancel_poll_seconds=1,
        aipam_stale_seconds=1,
        aipam_undispatched_grace_seconds=1,
    )
    observed = {}

    @contextmanager
    def schema_lock(path, *, exclusive):
        observed["locked_path"] = path
        observed["exclusive"] = exclusive
        yield

    class Supervisor:
        def __init__(self, *_args, **_kwargs):
            pass

        def run(self):
            observed["ran"] = True

    monkeypatch.setenv("AIPAM_DB_PATH", str(database_path))
    monkeypatch.setattr(sys, "argv", ["runtime_supervisor"])
    monkeypatch.setattr(config_v2, "get_settings", lambda: settings)
    monkeypatch.setattr(database_v2, "get_session_factory", lambda: object())
    monkeypatch.setattr(schema_bootstrap, "schema_lock", schema_lock)
    monkeypatch.setattr(schema_bootstrap, "assert_schema_current", lambda path: None)
    monkeypatch.setattr(runtime_supervisor, "RuntimeSupervisor", Supervisor)

    runtime_supervisor.main()

    assert observed == {
        "locked_path": database_path,
        "exclusive": False,
        "ran": True,
    }
