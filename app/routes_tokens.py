"""API token self-servis yonetimi (master_prompt.md 5: "Read-only API
token'lari (hash'li saklanir, scope'lu, sureli, audit'li)"). Her kullanici
SADECE KENDI token'larini gorur/olusturur/iptal eder -- token sahipligi
user_id ile sinirlidir, admin'in bile baskasinin token'ini gormesi icin
ayri bir ekran YOK (kapsam disi, audit log zaten tum olusturma/iptalleri
kayit altina alir)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_user
from core import auth
from core.models import ApiToken, User

router = APIRouter()


@router.get("/tokens")
def list_tokens(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    tokens = db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    ).scalars().all()
    return render_page(request, "api_tokens.html", {"tokens": tokens, "new_raw_token": None}, user=user)


@router.post("/tokens")
def create_token(
    request: Request,
    name: str = Form(...),
    expires_in_days: str = Form(""),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_user),
    _csrf: None = Depends(require_csrf),
):
    expires_at = None
    if expires_in_days.strip():
        try:
            days = int(expires_in_days.strip())
        except ValueError:
            raise HTTPException(status_code=400, detail="gecersiz sure")
        if days > 0:
            expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)

    raw_token, token_hash = auth.generate_api_token()
    token = ApiToken(user_id=user.id, name=name, token_hash=token_hash, scope="read", expires_at=expires_at)
    db.add(token)
    db.flush()
    record_audit(db, user, "api_token_created", "api_token", str(token.id), {"name": name, "expires_at": str(expires_at) if expires_at else None})

    tokens = db.execute(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc())
    ).scalars().all()
    return render_page(request, "api_tokens.html", {"tokens": tokens, "new_raw_token": raw_token}, user=user)


@router.post("/tokens/{token_id}/revoke")
def revoke_token(
    token_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_user),
    _csrf: None = Depends(require_csrf),
):
    token = db.get(ApiToken, token_id)
    if token is None or token.user_id != user.id:
        raise HTTPException(status_code=404, detail="token bulunamadi")
    token.revoked_at = dt.datetime.now(dt.timezone.utc)
    record_audit(db, user, "api_token_revoked", "api_token", str(token.id))
    return RedirectResponse("/tokens", status_code=303)
