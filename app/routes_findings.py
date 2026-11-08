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
from app.deps import get_db, render_page, require_admin, require_user
from core.models import Finding, FindingEvent, Repository, User

router = APIRouter()

# master_prompt.md 4.3: RESOLVED sadece eslestirme motorunun (sanity-gate
# gecmis, taze advisory DB ile) karari -- panelden elle set EDILEMEZ.
_MANUAL_ALLOWED_STATUSES = {
    "OPEN", "IN_PROGRESS", "REOPENED", "FALSE_POSITIVE", "NOT_AFFECTED", "ACCEPTED_RISK",
}


def _repo_name_map(db: DbSession, repo_ids: list[int]) -> dict[int, str]:
    if not repo_ids:
        return {}
    rows = db.execute(select(Repository.github_repo_id, Repository.full_name).where(Repository.github_repo_id.in_(repo_ids))).all()
    return {row[0]: row[1] for row in rows}


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
    repo_names = _repo_name_map(db, [f.repo_id for f in findings])
    return render_page(
        request, "findings.html",
        {"findings": findings, "repo_names": repo_names, "status_filter": status, "allowed_statuses": sorted(_MANUAL_ALLOWED_STATUSES | {"RESOLVED"})},
        user=user,
    )


@router.get("/findings/{finding_id}")
def finding_detail(request: Request, finding_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="bulgu bulunamadi")
    repo_names = _repo_name_map(db, [finding.repo_id])
    events = db.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id).order_by(FindingEvent.created_at.desc())
    ).scalars().all()
    return render_page(
        request, "finding_detail.html",
        {"finding": finding, "repo_name": repo_names.get(finding.repo_id, str(finding.repo_id)),
         "events": events, "manual_statuses": sorted(_MANUAL_ALLOWED_STATUSES)},
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
