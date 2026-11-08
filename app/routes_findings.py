"""SCA bulgu listesi/detayi + manuel durum degisikligi (master_prompt.md
4.2/4.3/4.5, 5-RBAC). Viewer SADECE okur; admin durumu degistirebilir
(RESOLVED HARIC -- o SADECE eslestirme motorunun karari, bkz.
orchestrator/matching.py; panelden manuel RESOLVED yapilamaz)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, get_repo_names, render_page, require_admin, require_user
from core.models import Finding, FindingEvent, FindingSource, ScanRun, User
from core.settings_store import SLA_DAYS_KEY, get_setting
from core.sla import compute_due_date, days_remaining, is_overdue, merged_sla_days

router = APIRouter()


def _sla_info(finding: Finding, sla_days: dict) -> dict:
    due = compute_due_date(
        kev=finding.kev, cvss_score=float(finding.severity_cvss_score) if finding.severity_cvss_score is not None else None,
        first_seen_at=finding.first_seen_at, sla_days=sla_days,
    )
    return {"due_date": due, "overdue": is_overdue(due), "days_remaining": days_remaining(due)}

# master_prompt.md 4.3: RESOLVED sadece eslestirme motorunun (sanity-gate
# gecmis, taze advisory DB ile) karari -- panelden elle set EDILEMEZ.
_MANUAL_ALLOWED_STATUSES = {
    "OPEN", "IN_PROGRESS", "REOPENED", "FALSE_POSITIVE", "NOT_AFFECTED", "ACCEPTED_RISK",
}


@router.get("/findings")
def list_findings(request: Request, status: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    query = select(Finding)
    if status:
        query = query.where(Finding.lifecycle_status == status)
    else:
        # Varsayilan gorunum: sadece acik/aktif olanlar.
        query = query.where(Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    query = query.order_by(Finding.kev.desc(), Finding.severity_cvss_score.desc().nullslast(), Finding.first_seen_at.desc())
    findings = db.execute(query.limit(500)).scalars().all()
    repo_names = get_repo_names(db, [f.repo_id for f in findings])
    sla_days = merged_sla_days(get_setting(db, SLA_DAYS_KEY))
    sla_by_id = {
        f.id: _sla_info(f, sla_days) for f in findings if f.lifecycle_status in ("OPEN", "IN_PROGRESS", "REOPENED")
    }
    return render_page(
        request, "findings.html",
        {"findings": findings, "repo_names": repo_names, "status_filter": status,
         "allowed_statuses": sorted(_MANUAL_ALLOWED_STATUSES | {"RESOLVED"}), "sla_by_id": sla_by_id},
        user=user,
    )


@router.get("/findings/{finding_id}")
def finding_detail(request: Request, finding_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="bulgu bulunamadi")
    repo_names = get_repo_names(db, [finding.repo_id])
    events = db.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id).order_by(FindingEvent.created_at.desc())
    ).scalars().all()
    sla_days = merged_sla_days(get_setting(db, SLA_DAYS_KEY))
    sla = _sla_info(finding, sla_days) if finding.lifecycle_status in ("OPEN", "IN_PROGRESS", "REOPENED") else None

    # A4 kanit paneli (master_prompt.md 6): "hangi tarama/eslestirme
    # run'indan" -- bir bulgu BIRDEN COK scan_run'dan kanit alabilir
    # (finding_sources, master_prompt.md 4.5).
    source_runs = db.execute(
        select(ScanRun).join(FindingSource, FindingSource.scan_run_id == ScanRun.id)
        .where(FindingSource.finding_id == finding_id).order_by(ScanRun.started_at.desc())
    ).scalars().all()

    return render_page(
        request, "finding_detail.html",
        {"finding": finding, "repo_name": repo_names.get(finding.repo_id, str(finding.repo_id)),
         "events": events, "manual_statuses": sorted(_MANUAL_ALLOWED_STATUSES), "sla": sla,
         "source_runs": source_runs},
        user=user,
    )


@router.post("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    new_status: str = Form(...),
    reason: str = Form(""),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if new_status not in _MANUAL_ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="bu durum panelden elle ayarlanamaz")
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="bulgu bulunamadi")

    old_status = finding.lifecycle_status
    finding.lifecycle_status = new_status
    finding.updated_at = dt.datetime.now(dt.timezone.utc)
    db.add(
        FindingEvent(
            finding_id=finding.id, event_type="status_changed_manual",
            from_status=old_status, to_status=new_status, actor=user.username, reason=reason or None,
        )
    )
    record_audit(
        db, user, "finding_status_changed", "finding", str(finding.id),
        {"from": old_status, "to": new_status, "reason": reason or None},
    )
    return RedirectResponse(f"/findings/{finding_id}", status_code=303)
