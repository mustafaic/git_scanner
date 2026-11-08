"""Secret bulgu listesi/detayi + rotasyon onayi (master_prompt.md 4.4,
5-RBAC). KRITIK: koddan silinmis olmak (present_in_current_code=False)
bulguyu KAPATMAZ -- sadece admin'in "rotate edildi" onayi ROTATED'e
cevirir (bkz. core/models.py SecretFinding docstring'i, docs/ASSUMPTIONS.md
#3). Ham secret degeri hicbir yerde TUTULMAZ/GOSTERILMEZ, sadece hash."""

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
from core.models import Repository, SecretFinding, SecretFindingEvent, User

router = APIRouter()

_MANUAL_ALLOWED_STATUSES = {"OPEN", "ROTATED", "FALSE_POSITIVE", "ACCEPTED_RISK"}


def _repo_name_map(db: DbSession, repo_ids: list[int]) -> dict[int, str]:
    if not repo_ids:
        return {}
    rows = db.execute(
        select(Repository.github_repo_id, Repository.full_name).where(Repository.github_repo_id.in_(repo_ids))
    ).all()
    return {row[0]: row[1] for row in rows}


@router.get("/secrets")
def list_secrets(request: Request, status: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    query = select(SecretFinding)
    if status:
        query = query.where(SecretFinding.lifecycle_status == status)
    else:
        query = query.where(SecretFinding.lifecycle_status == "OPEN")
    query = query.order_by(SecretFinding.present_in_current_code.desc(), SecretFinding.first_seen_at.desc())
    secrets_list = db.execute(query.limit(500)).scalars().all()
    repo_names = _repo_name_map(db, [s.repo_id for s in secrets_list])
    return render_page(
        request, "secret_findings.html",
        {"secrets": secrets_list, "repo_names": repo_names, "status_filter": status,
         "allowed_statuses": sorted(_MANUAL_ALLOWED_STATUSES)},
        user=user,
    )


@router.get("/secrets/{secret_id}")
def secret_detail(request: Request, secret_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    secret = db.get(SecretFinding, secret_id)
    if secret is None:
        raise HTTPException(status_code=404, detail="secret bulgusu bulunamadi")
    repo_names = _repo_name_map(db, [secret.repo_id])
    events = db.execute(
        select(SecretFindingEvent).where(SecretFindingEvent.secret_finding_id == secret_id)
        .order_by(SecretFindingEvent.created_at.desc())
    ).scalars().all()
    return render_page(
        request, "secret_finding_detail.html",
        {"secret": secret, "repo_name": repo_names.get(secret.repo_id, str(secret.repo_id)),
         "events": events, "manual_statuses": sorted(_MANUAL_ALLOWED_STATUSES)},
        user=user,
    )


@router.post("/secrets/{secret_id}/status")
def update_secret_status(
    secret_id: int,
    new_status: str = Form(...),
    note: str = Form(""),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if new_status not in _MANUAL_ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="gecersiz durum")
    secret = db.get(SecretFinding, secret_id)
    if secret is None:
        raise HTTPException(status_code=404, detail="secret bulgusu bulunamadi")

    old_status = secret.lifecycle_status
    secret.lifecycle_status = new_status
    secret.updated_at = dt.datetime.now(dt.timezone.utc)
    secret.rotation_note = note or secret.rotation_note
    if new_status == "ROTATED":
        secret.rotated_at = dt.datetime.now(dt.timezone.utc)
        secret.rotated_by_user_id = user.id

    db.add(
        SecretFindingEvent(
            secret_finding_id=secret.id, event_type="status_changed_manual",
            from_status=old_status, to_status=new_status, actor=user.username, reason=note or None,
        )
    )
    record_audit(
        db, user, "secret_finding_status_changed", "secret_finding", str(secret.id),
        {"from": old_status, "to": new_status, "note": note or None},
    )
    return RedirectResponse(f"/secrets/{secret_id}", status_code=303)
