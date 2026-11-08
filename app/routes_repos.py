"""Repo listesi + elle tetikleme + tarama dahil/haric politikasi
(master_prompt.md 3.5.2, 6 A3/A10). `app` servisi orchestrator'a HTTP/
import ile BAGLI DEGIL -- elle tetikleme, orchestrator'in kendisinin de
yaptigi (orchestrator/triggers.py record_trigger) tek satirlik INSERT'in
BIREBIR AYNISI (core.models.ScanTrigger); orchestrator'in claim loop'u
bunu kendi debounce/consume mantigiyla bir sonraki dongude isler.

RBAC: tarama dahil/haric SADECE admin (audit'li, gerekceli -- madde 6).
Elle tetikleme varsayilan admin-only; viewer'a ayarlardan (A10) hiz-limitli
izin verilebilir (madde 6: "viewer'lara elle tetikleme izni, varsayilan
kapali, hiz limitli")."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin, require_user
from core.models import Repository, ScanTrigger, User
from core.settings_store import DEFAULT_VIEWER_TRIGGER, VIEWER_TRIGGER_KEY, get_setting

router = APIRouter()


@router.get("/repositories")
def list_repositories(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    repos = db.execute(select(Repository).order_by(Repository.full_name)).scalars().all()
    viewer_trigger = {**DEFAULT_VIEWER_TRIGGER, **(get_setting(db, VIEWER_TRIGGER_KEY) or {})}
    can_trigger = user.role == "admin" or viewer_trigger.get("enabled", False)
    return render_page(request, "repositories.html", {"repos": repos, "can_trigger": can_trigger}, user=user)


@router.post("/repositories/{repo_id}/trigger")
def trigger_repository(
    repo_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_user),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    if repo.scan_excluded:
        raise HTTPException(status_code=400, detail="bu repo tarama politikasiyla haric tutulmus")

    if user.role != "admin":
        viewer_trigger = {**DEFAULT_VIEWER_TRIGGER, **(get_setting(db, VIEWER_TRIGGER_KEY) or {})}
        if not viewer_trigger.get("enabled", False):
            raise HTTPException(status_code=403, detail="viewer icin elle tetikleme kapali")
        window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        recent_count = db.execute(
            select(func.count()).select_from(ScanTrigger).where(
                ScanTrigger.note == f"panel:{user.username}", ScanTrigger.created_at >= window_start,
            )
        ).scalar_one()
        if recent_count >= viewer_trigger.get("max_per_hour", DEFAULT_VIEWER_TRIGGER["max_per_hour"]):
            raise HTTPException(status_code=429, detail="saatlik elle tetikleme limitine ulasildi")

    db.add(ScanTrigger(repo_id=repo_id, source="manual", note=f"panel:{user.username}"))
    record_audit(db, user, "repo_manual_trigger", "repository", str(repo_id))
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/{repo_id}/exclude")
def exclude_repository(
    repo_id: int,
    reason: str = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    if not reason.strip():
        raise HTTPException(status_code=400, detail="gerekce zorunlu")
    repo.scan_excluded = True
    repo.scan_exclude_reason = reason.strip()
    record_audit(db, user, "repo_scan_excluded", "repository", str(repo_id), {"reason": reason.strip()})
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/{repo_id}/unexclude")
def unexclude_repository(
    repo_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    repo.scan_excluded = False
    repo.scan_exclude_reason = None
    record_audit(db, user, "repo_scan_included", "repository", str(repo_id))
    return RedirectResponse("/repositories", status_code=303)
