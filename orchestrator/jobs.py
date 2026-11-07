"""Postgres tabanli kalici is kuyrugu (master_prompt.md 3.4):
`SELECT ... FOR UPDATE SKIP LOCKED`, attempts, idempotency_key,
locked_until, priority. Celery/Redis yok ama cokmeye dayanikli, yeniden
denenebilir, idempotent.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.models import Job

LOG = logging.getLogger(__name__)


def build_idempotency_key(job_type: str, repo_id: Optional[int], discriminator: str) -> str:
    """Is anahtari: (tip, repo, sha/blob_sha, scanner_version) (master_prompt.md 3.4)."""
    repo_part = str(repo_id) if repo_id is not None else "-"
    return f"{job_type}:{repo_part}:{discriminator}"


def enqueue_job(
    session: Session,
    job_type: str,
    idempotency_key: str,
    repo_id: Optional[int] = None,
    payload: Optional[Dict[str, Any]] = None,
    priority: int = 100,
) -> Optional[int]:
    """Kuyruga ekler; ayni idempotency_key zaten varsa YENI SATIR EKLEMEZ
    (ON CONFLICT DO NOTHING) -> donen deger None olur (ayni is iki kez islenmez)."""
    stmt = (
        pg_insert(Job)
        .values(
            job_type=job_type,
            repo_id=repo_id,
            payload=payload or {},
            idempotency_key=idempotency_key,
            priority=priority,
        )
        .on_conflict_do_nothing(index_elements=[Job.idempotency_key])
        .returning(Job.id)
    )
    result = session.execute(stmt)
    row = result.first()
    return row[0] if row else None


def claim_next_job(
    session: Session,
    job_types: List[str],
    lock_duration_seconds: int,
    locked_by: str,
) -> Optional[Job]:
    """SKIP LOCKED ile tek bir is claim eder.

    `status IN ('pending','running','failed')` + `locked_until` suresi
    gecmis olani da kapsar: orchestrator bir isi claim ettikten sonra
    cokerse (status='running' kalir), kilit suresi dolunca BASKA bir
    surec onu yeniden claim edebilir (crash-recovery). `attempts <
    max_attempts` sonsuz retry dongusunu engeller.
    """
    now = dt.datetime.now(dt.timezone.utc)
    rows = session.execute(
        text(
            """
            SELECT id FROM jobs
            WHERE job_type = ANY(:job_types)
              AND status IN ('pending', 'running', 'failed')
              AND attempts < max_attempts
              AND (locked_until IS NULL OR locked_until < :now)
            ORDER BY priority ASC, created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        ),
        {"job_types": job_types, "now": now},
    )
    row = rows.first()
    if row is None:
        return None
    job_id = row[0]
    locked_until = now + dt.timedelta(seconds=lock_duration_seconds)
    session.execute(
        text(
            """
            UPDATE jobs
            SET status = 'running', locked_until = :locked_until, locked_by = :locked_by,
                attempts = attempts + 1, updated_at = now()
            WHERE id = :id
            """
        ),
        {"locked_until": locked_until, "locked_by": locked_by, "id": job_id},
    )
    return session.get(Job, job_id)


def complete_job(session: Session, job_id: int) -> None:
    session.execute(
        text("UPDATE jobs SET status='done', locked_until=NULL, updated_at=now() WHERE id=:id"),
        {"id": job_id},
    )


def fail_job(session: Session, job_id: int, error: str) -> None:
    session.execute(
        text(
            "UPDATE jobs SET status='failed', locked_until=NULL, last_error=:error, updated_at=now() WHERE id=:id"
        ),
        {"id": job_id, "error": error[:2000]},
    )


def count_pending_jobs(session: Session, job_type: str) -> int:
    row = session.execute(
        text("SELECT count(*) FROM jobs WHERE job_type=:job_type AND status IN ('pending','failed')"),
        {"job_type": job_type},
    ).first()
    return int(row[0]) if row else 0
