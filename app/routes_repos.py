"""Repo listesi + elle tetikleme (master_prompt.md 3.5.2). `app` servisi
orchestrator'a HTTP/import ile BAGLI DEGIL -- elle tetikleme, orchestrator'in
kendisinin de yaptigi (orchestrator/triggers.py record_trigger) tek
satirlik INSERT'in BIREBIR AYNISI (core.models.ScanTrigger); orchestrator'in
claim loop'u bunu kendi debounce/consume mantigiyla bir sonraki dongude
isler. Sadece admin'e acik (master_prompt.md madde 20: "viewer izni
kapaliyken reddedilmeli")."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin, require_user
from core.models import Repository, ScanTrigger, User

router = APIRouter()


@router.get("/repositories")
def list_repositories(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    repos = db.execute(select(Repository).order_by(Repository.full_name)).scalars().all()
    return render_page(request, "repositories.html", {"repos": repos}, user=user)


@router.post("/repositories/{repo_id}/trigger")
def trigger_repository(
    repo_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    db.add(ScanTrigger(repo_id=repo_id, source="manual", note=f"panel:{user.username}"))
    record_audit(db, user, "repo_manual_trigger", "repository", str(repo_id))
    return RedirectResponse("/repositories", status_code=303)
