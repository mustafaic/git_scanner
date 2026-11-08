"""Ana sayfa: ozet sayilar + sistem sagligi (master_prompt.md 3.4
"Gozlemlenebilirlik"). `app` servisi orchestrator modullerini import
ETMEZ (bkz. deploy/Dockerfile.app -- sadece core/+app/ kopyalanir); bu
yuzden heartbeat/kuyruk durumu burada core.models uzerinden DOGRUDAN
okunur, is mantigi tekrarlanmaz (sadece salt-okunur sorgu)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.deps import get_db, render_page, require_user
from core.models import AdvisoryMirrorSync, Job, Repository, SecretFinding, SystemHeartbeat, User, Finding

router = APIRouter()


@router.get("/")
def dashboard(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    open_findings = db.execute(
        select(func.count()).select_from(Finding).where(Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    ).scalar_one()
    kev_findings = db.execute(
        select(func.count()).select_from(Finding).where(Finding.kev.is_(True), Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    ).scalar_one()
    needs_review = db.execute(
        select(func.count()).select_from(Finding).where(Finding.verification_status == "NEEDS_REVIEW", Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    ).scalar_one()
    open_secrets = db.execute(
        select(func.count()).select_from(SecretFinding).where(SecretFinding.lifecycle_status == "OPEN")
    ).scalar_one()
    active_repos = db.execute(select(func.count()).select_from(Repository).where(Repository.is_active.is_(True))).scalar_one()
    pending_jobs = db.execute(select(func.count()).select_from(Job).where(Job.status == "pending")).scalar_one()

    now = dt.datetime.now(dt.timezone.utc)
    heartbeats = db.execute(select(SystemHeartbeat)).scalars().all()
    heartbeat_rows = [
        {"component": h.component, "age_seconds": int((now - h.last_success_at).total_seconds())} for h in heartbeats
    ]

    mirror_rows = db.execute(
        select(AdvisoryMirrorSync.source, func.max(AdvisoryMirrorSync.synced_at)).where(AdvisoryMirrorSync.succeeded.is_(True)).group_by(AdvisoryMirrorSync.source)
    ).all()
    mirror_sync_rows = [{"source": r[0], "age_seconds": int((now - r[1]).total_seconds())} for r in mirror_rows]

    return render_page(
        request, "dashboard.html",
        {
            "open_findings": open_findings, "kev_findings": kev_findings, "needs_review": needs_review,
            "open_secrets": open_secrets, "active_repos": active_repos, "pending_jobs": pending_jobs,
            "heartbeat_rows": heartbeat_rows, "mirror_sync_rows": mirror_sync_rows,
        },
        user=user,
    )
