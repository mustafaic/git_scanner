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
from core.settings_store import SLA_DAYS_KEY, get_setting
from core.sla import compute_due_date, is_overdue, merged_sla_days

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

    # A8 SLA (master_prompt.md 6): "gecikenler listesi". due_date saklanan
    # bir kolon DEGIL, ayarlanabilir sla_days'e gore HER ISTEKTE hesaplanir
    # (bkz. core/sla.py) -- acik bulgu sayisi tipik olarak kucuk oldugu
    # icin Python'da filtrelemek SQL'de surum/tarih aritmetigi yazmaktan
    # daha basit (kural 11).
    sla_days = merged_sla_days(get_setting(db, SLA_DAYS_KEY))
    open_finding_rows = db.execute(
        select(Finding.kev, Finding.severity_cvss_score, Finding.first_seen_at)
        .where(Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    ).all()
    overdue_findings = sum(
        1 for kev, cvss, first_seen_at in open_finding_rows
        if is_overdue(compute_due_date(
            kev=kev, cvss_score=float(cvss) if cvss is not None else None, first_seen_at=first_seen_at, sla_days=sla_days,
        ))
    )

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
            "overdue_findings": overdue_findings,
            "heartbeat_rows": heartbeat_rows, "mirror_sync_rows": mirror_sync_rows,
        },
        user=user,
    )
