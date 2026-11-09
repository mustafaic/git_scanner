"""A10 kullanıcı yönetimi -- SADECE admin (master_prompt.md 6 A10).
Oluşturma/aktif-pasif/parola sıfırlama rol farkı olmadan panelden yapılır
(TOTP (2FA) kaldırıldığı için admin oluşturmanın bir "sır paylaşma
seremonisi" gerektirmesi SON BULDU, bkz. docs/ASSUMPTIONS.md #14) --
`tools/create_admin.py` artık SADECE ilk bootstrap (henuz panelde giris
yapabilecek hicbir kullanici yokken) icin gereklidir."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin
from core import auth
from core.models import User

router = APIRouter()


@router.get("/users")
def list_users(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    return render_page(request, "users.html", {"users": users, "error": None}, user=user)


@router.post("/users")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if role not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="gecersiz rol")

    existing = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if existing is not None:
        users = db.execute(select(User).order_by(User.username)).scalars().all()
        return render_page(
            request, "users.html", {"users": users, "error": f"'{username}' zaten mevcut."}, user=user, status_code=400
        )

    ok, reason = auth.check_password_policy(password)
    if not ok:
        users = db.execute(select(User).order_by(User.username)).scalars().all()
        return render_page(request, "users.html", {"users": users, "error": reason}, user=user, status_code=400)

    new_user = User(username=username, password_hash=auth.hash_password(password), role=role)
    db.add(new_user)
    db.flush()
    record_audit(db, user, "user_created", "user", str(new_user.id), {"username": username, "role": role})
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/toggle-active")
def toggle_active(
    user_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="kullanici bulunamadi")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="kendi hesabinizi devre disi birakamazsiniz")
    target.is_active = not target.is_active
    record_audit(db, user, "user_active_toggled", "user", str(target.id), {"is_active": target.is_active})
    return RedirectResponse("/users", status_code=303)


@router.post("/users/{user_id}/reset-password")
def reset_password(
    request: Request,
    user_id: int,
    new_password: str = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="kullanici bulunamadi")
    ok, reason = auth.check_password_policy(new_password)
    if not ok:
        users = db.execute(select(User).order_by(User.username)).scalars().all()
        return render_page(request, "users.html", {"users": users, "error": reason}, user=user, status_code=400)

    target.password_hash = auth.hash_password(new_password)
    target.failed_login_attempts = 0
    target.locked_until = None
    record_audit(db, user, "user_password_reset", "user", str(target.id))
    return RedirectResponse("/users", status_code=303)
