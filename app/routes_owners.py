"""A5 Sahip yonlendirme -- CSV import (master_prompt.md 6). SADECE admin.
CODEOWNERS otomatik tespiti HENUZ YOK (bkz. docs/ASSUMPTIONS.md)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin
from core.models import Repository, RepoOwner, User
from core.owners import import_owners_csv, parse_owners_csv

router = APIRouter()


@router.get("/owners")
def list_owners(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.execute(
        select(RepoOwner.repo_id, RepoOwner.owner_identifier, RepoOwner.source, Repository.full_name)
        .join(Repository, Repository.github_repo_id == RepoOwner.repo_id, isouter=True)
        .order_by(Repository.full_name)
    ).all()
    mappings = [
        {"repo_name": full_name or repo_id, "owner": owner, "source": source}
        for repo_id, owner, source, full_name in rows
    ]
    return render_page(request, "owners.html", {"mappings": mappings, "result": None}, user=user)


@router.post("/owners/import")
async def import_owners(
    request: Request,
    file: UploadFile = File(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    raw = await file.read()
    parsed = parse_owners_csv(raw.decode("utf-8", errors="replace"))
    stats = import_owners_csv(db, parsed.rows)
    record_audit(
        db, user, "owners_csv_imported", "repo_owners", None,
        {**stats, "parse_errors": len(parsed.errors)},
    )

    rows = db.execute(
        select(RepoOwner.repo_id, RepoOwner.owner_identifier, RepoOwner.source, Repository.full_name)
        .join(Repository, Repository.github_repo_id == RepoOwner.repo_id, isouter=True)
        .order_by(Repository.full_name)
    ).all()
    mappings = [
        {"repo_name": full_name or repo_id, "owner": owner, "source": source}
        for repo_id, owner, source, full_name in rows
    ]
    return render_page(
        request, "owners.html",
        {"mappings": mappings, "result": stats, "parse_errors": parsed.errors},
        user=user,
    )
