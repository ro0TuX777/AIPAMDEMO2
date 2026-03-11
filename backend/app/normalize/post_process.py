"""Post-processing logic to update global host statistics."""

import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import select
from backend.app.models.host import Host
from backend.app.models.global_host import GlobalHost

logger = logging.getLogger("aipam.post_process")

def update_global_host_stats(db: Session, job_id: str) -> None:
    """Read all hosts for a job and update the GlobalHost registry."""
    logger.info("Updating global host stats for job %s", job_id)
    
    # 1. Fetch all hosts for this job
    stmt = select(Host).where(Host.job_id == job_id)
    job_hosts = db.execute(stmt).scalars().all()
    
    for jh in job_hosts:
        # 2. Try to find existing GlobalHost
        gh = db.get(GlobalHost, jh.ip)
        
        if not gh:
            # Create new entry
            gh = GlobalHost(
                ip=jh.ip,
                first_seen=jh.first_seen,
                last_seen=jh.last_seen,
                job_count=1,
                total_alerts=jh.alert_count,
                total_findings=jh.finding_count,
                seen_as_internal=(jh.role == "internal"),
                roles_json=json.dumps([jh.role]) if jh.role else "[]",
                history_json=json.dumps([{
                    "job_id": job_id,
                    "ts": jh.first_seen or jh.last_seen,
                    "role": jh.role,
                    "alert_count": jh.alert_count,
                    "finding_count": jh.finding_count
                }])
            )
            db.add(gh)
        else:
            # Update existing entry
            gh.job_count += 1
            gh.total_alerts += jh.alert_count
            gh.total_findings += jh.finding_count
            
            if jh.role == "internal":
                gh.seen_as_internal = True
            
            # Update seen timestamps
            if jh.first_seen and (not gh.first_seen or jh.first_seen < gh.first_seen):
                gh.first_seen = jh.first_seen
            if jh.last_seen and (not gh.last_seen or jh.last_seen > gh.last_seen):
                gh.last_seen = jh.last_seen
                
            # Update roles
            roles = json.loads(gh.roles_json or "[]")
            if jh.role and jh.role not in roles:
                roles.append(jh.role)
                gh.roles_json = json.dumps(roles)
                
            # Update history
            history = json.loads(gh.history_json or "[]")
            history.append({
                "job_id": job_id,
                "ts": jh.first_seen or jh.last_seen,
                "role": jh.role,
                "alert_count": jh.alert_count,
                "finding_count": jh.finding_count
            })
            # Sort history by TS descending (keep it fresh)
            history.sort(key=lambda x: x.get("ts") or "", reverse=True)
            gh.history_json = json.dumps(history[:20]) # Keep last 20 jobs for context
            
    db.commit()
    logger.info("Global host stats update complete for job %s", job_id)
