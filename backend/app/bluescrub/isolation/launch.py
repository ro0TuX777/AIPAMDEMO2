"""Receipt-gated session launch; no task work runs before publication.

The parent publishes an intent before Popen can create a new session. The child
atomically replaces it with its own exact identity before exec/privilege drop.
An interrupted launch leaves an intent and makes escalation fail closed.
"""
from __future__ import annotations
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4


def publish(path, payload):
    temporary = path.with_suffix(f'.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(payload), encoding='utf-8')
    temporary.replace(path)


def launch_process(argv, *, record, name, env, limits=None, uid=None, gid=None, **kwargs):
    from backend.app.bluescrub.isolation.runner import ProcessSession, ProcessCleanupIncomplete
    record = Path(record).resolve()
    record.parent.mkdir(parents=True, exist_ok=True)
    if record.exists():
        raise ProcessCleanupIncomplete('Unresolved process launch receipt')
    nonce = uuid4().hex
    publish(record, dict(state='launching', group_nonce=nonce, handler=name))
    child_env = {**env, 'AIPAM_PROCESS_GROUP_NONCE': nonce,
                 'AIPAM_RUN_CONTROL_DIR': str(record.parent)}
    payload = dict(argv=argv, record=str(record), name=name, nonce=nonce,
                   limits=asdict(limits) if limits else None, uid=uid, gid=gid)
    # This child runs only the receipt bootstrap until its identity is durable.
    # Use an absolute script path: analyzer cwd need not be the application root.
    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), json.dumps(payload)] if os.name != 'nt' else argv,
        env=child_env, start_new_session=os.name != 'nt',
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0, **kwargs)
    if os.name == 'nt':
        publish(record, dict(pid=proc.pid, pgid=proc.pid, sid=proc.pid, start_ticks=None,
                             boot_id=None, group_nonce=nonce, handler=name))
        return proc
    until = time.monotonic()+10
    while time.monotonic() < until:
        item = json.loads(record.read_text())
        if item.get('state') != 'launching':
            if item.get('pid') != proc.pid or item.get('group_nonce') != nonce:
                raise ProcessCleanupIncomplete('Launch receipt identity mismatch')
            proc.aipam_group = ProcessSession(item, nonce)
            return proc
        if proc.poll() is not None:
            break
        time.sleep(.01)
    # No work was authorized without a receipt. Preserve the intent even when
    # launch failed: absence needs separate containment proof, not a guess.
    raise ProcessCleanupIncomplete('Launch receipt unavailable')


def main(payload):
    # Direct-script bootstrap must work for both module and external analyzers.
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
    from backend.app.bluescrub.isolation.runner import read_process_identity
    record = Path(payload['record'])
    intent = json.loads(record.read_text())
    if intent.get('state') != 'launching' or intent.get('group_nonce') != payload['nonce']:
        raise RuntimeError('Launch intent changed')
    identity = read_process_identity(os.getpid())
    if identity is None or identity['pid'] != identity['pgid'] or identity['pid'] != identity['sid']:
        raise RuntimeError('Unique process session unavailable')
    publish(record, {**identity, 'group_nonce': payload['nonce'], 'handler': payload['name']})
    if (record.parent/'cancel.requested').exists():
        return 71
    if payload.get('limits'):
        from backend.app.bluescrub.isolation.limits import ResourceLimits, build_preexec
        build_preexec(ResourceLimits(**payload['limits']), payload['uid'], payload['gid'],
                      create_session=False)()
    os.execvpe(payload['argv'][0], payload['argv'], os.environ)
    return 1


if __name__ == '__main__':
    raise SystemExit(main(json.loads(sys.argv[1])))
