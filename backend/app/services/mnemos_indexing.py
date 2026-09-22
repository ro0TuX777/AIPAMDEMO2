"""Canonical post-commit finding upserts; reconciliation is the durable retry path.

Collect changed persisted findings in the analyst transaction, then publish only
after its outer commit. Content edits use the same path as confirmations. No
remote failure can undo committed feedback; CLI reconciliation can safely repeat
every upsert after a process interruption or exhausted retry.
"""
import asyncio
import logging

from sqlalchemy import event
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)
_tasks: set[asyncio.Task] = set()


def index_documents(documents: list[dict], *, client=None) -> int:
    from backend.app.mnemos_boundary import get_mnemos_client
    for _ in range(3):
        try:
            current_client = client or get_mnemos_client()
            if current_client is None:
                break
            count = current_client.index(documents)
            if count == len(documents):
                return count
        except Exception:
            pass  # Service exceptions may contain authentication headers/URLs.
    logger.warning("MNEMOS indexing incomplete; retry with reconcile-mnemos-findings")
    return 0


@event.listens_for(Session, "before_flush")
def _collect_changed_findings(db, _context, _instances):
    from backend.app.forensic_memory import mnemos_document_for_finding
    from backend.app.models.finding import Finding
    from backend.app.models.job import Job
    from backend.app.models.bluescrub import BlueScrubJobLineage
    pending = db.info.setdefault("mnemos_documents", {})
    new_objects = list(db.new)
    new_jobs = {item.job_id: item for item in new_objects if isinstance(item, Job)}
    new_lineage = {item.job_id: item for item in new_objects if isinstance(item, BlueScrubJobLineage)}
    seen: set[int] = set()
    for finding in [*new_objects, *list(db.dirty)]:
        if not isinstance(finding, Finding) or id(finding) in seen:
            continue
        seen.add(id(finding))
        if finding not in db.new and not db.is_modified(finding, include_collections=False):
            continue
        key = (finding.job_id, finding.finding_id)
        job = new_jobs.get(finding.job_id) or db.get(Job, finding.job_id)
        if finding.analyst_status != "confirmed" or job is None or job.status == "deleted":
            pending.pop(key, None)
            continue
        lineage = new_lineage.get(finding.job_id) or db.get(BlueScrubJobLineage, finding.job_id)
        pending[key] = mnemos_document_for_finding(finding, project_id=lineage.project_id if lineage else None)


@event.listens_for(Session, "after_commit")
def _publish_committed_findings(db):
    if db.in_nested_transaction():
        return
    documents = list(db.info.pop("mnemos_documents", {}).values())
    if not documents:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        index_documents(documents)
    else:
        task = loop.create_task(asyncio.to_thread(index_documents, documents))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        db.info.setdefault("mnemos_index_tasks", []).append(task)


@event.listens_for(Session, "after_rollback")
def _discard_rolled_back_findings(db):
    db.info.pop("mnemos_documents", None)


async def finish_committed_indexing(db: Session) -> None:
    tasks = db.info.pop("mnemos_index_tasks", [])
    if tasks:
        await asyncio.gather(*(asyncio.shield(task) for task in tasks))
