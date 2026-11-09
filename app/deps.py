"""FastAPI dependency'leri: DB oturumu, oturum-cerezi tabanli kimlik
dogrulama, RBAC, Jinja2 template ortami (master_prompt.md 5 "Uygulama
guvenligi"). `app` servisi GitHub key'ini gormez, hicbir orchestrator
modulune import BAGIMLILIGI yoktur (sadece core.* ve kendi modelleri)."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

from fastapi import Depends, HTTPException, Request, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.auth_service import get_session_user
from app.csrf import ensure_csrf_token, set_csrf_cookie
from core.config import load_settings
from core.db import session_scope
from core.lockfile_parser import display_vulnerability_id
from core.models import Repository, User

SESSION_COOKIE_NAME = "session_id"

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["cve_id"] = display_vulnerability_id

_settings = load_settings()


def get_db() -> Iterator[DbSession]:
    with session_scope() as session:
        yield session


def get_current_user(request: Request, db: DbSession = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    return get_session_user(db, token)


def require_user(user: Optional[User] = Depends(get_current_user)) -> User:
    """Girisi zorunlu kilar. 401 -- app/main.py'deki exception handler
    HTML isteklerinde /login'e yonlendirir, API/JSON isteklerinde duz 401
    doner."""
    if user is None:
        raise HTTPException(status_code=401, detail="login_required")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """master_prompt.md 5 RBAC: durum degisikligi/token/secret rotasyonu
    gibi islemler SADECE admin'e acik."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin_required")
    return user


def get_repo_names(db: DbSession, repo_ids: list[int]) -> dict[int, str]:
    if not repo_ids:
        return {}
    rows = db.execute(
        select(Repository.github_repo_id, Repository.full_name).where(Repository.github_repo_id.in_(repo_ids))
    ).all()
    return {row[0]: row[1] for row in rows}


def render_page(
    request: Request, name: str, context: dict, *, user: Optional[User] = None, status_code: int = 200
) -> Response:
    """Her HTML sayfasi icin ortak render yolu: csrf cookie/token'i
    garanti eder (base.html'deki logout formu dahil HER form bunu
    kullanir) ve `user`'i context'e ekler (nav/RBAC gorunurlugu icin)."""
    csrf_token, is_new = ensure_csrf_token(request)
    full_context = {"user": user, "csrf_token": csrf_token, **context}
    response = templates.TemplateResponse(request, name, full_context, status_code=status_code)
    if is_new:
        set_csrf_cookie(response, csrf_token, cookie_secure=_settings.session_cookie_secure)
    return response
