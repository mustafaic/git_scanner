"""Audit log goruntuleyici -- SADECE admin (master_prompt.md 5: "giris,
durum degisikligi, suppression, kullanici/rol/ayar/API-token degisikligi,
export audit'lenir"). Append-only, panelden SILINEMEZ/duzenlenemez."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.deps import get_db, render_page, require_admin
from core.models import AuditLog, User

router = APIRouter()

PAGE_SIZE = 100


@router.get("/audit-log")
def audit_log(request: Request, page: int = 1, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    page = max(page, 1)
    offset = (page - 1) * PAGE_SIZE
    entries = db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(PAGE_SIZE)
    ).scalars().all()
    return render_page(
        request, "audit_log.html",
        {"entries": entries, "page": page, "has_more": len(entries) == PAGE_SIZE},
        user=user,
    )
