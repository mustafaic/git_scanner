"""Giris/cikis (master_prompt.md 5 "Uygulama guvenligi"). Oturum cerezi
HttpOnly + (konfigure edilebilir) Secure + SameSite=Lax; bosta zaman
asimi ve TTL app/auth_service.py'de (SESSION_TTL_SECONDS/IDLE)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session as DbSession

from app.auth_service import SESSION_TTL_SECONDS, authenticate, create_session, record_audit, revoke_session
from app.csrf import require_csrf
from app.deps import SESSION_COOKIE_NAME, get_current_user, get_db, render_page
from core.config import load_settings

router = APIRouter()
_settings = load_settings()

_ERROR_MESSAGES = {
    "invalid_credentials": "Kullanıcı adı veya parola hatalı.",
    "account_locked": "Hesap çok sayıda hatalı girişten dolayı geçici olarak kilitli, lütfen sonra tekrar deneyin.",
}


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, user=Depends(get_current_user)):
    if user is not None:
        return RedirectResponse("/", status_code=303)
    return render_page(request, "login.html", {"error": None, "username": None})


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: DbSession = Depends(get_db),
    _csrf: None = Depends(require_csrf),
):
    user, error = authenticate(db, username, password)
    if error is not None:
        return render_page(
            request,
            "login.html",
            {"error": _ERROR_MESSAGES.get(error, "Giriş başarısız."), "username": username},
            status_code=401,
        )

    token = create_session(db, user)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME, token, httponly=True, secure=_settings.session_cookie_secure,
        samesite="lax", path="/", max_age=SESSION_TTL_SECONDS,
    )
    return response


@router.post("/logout")
def logout(request: Request, db: DbSession = Depends(get_db), _csrf: None = Depends(require_csrf)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    user = get_current_user(request, db)
    if token:
        revoke_session(db, token)
    if user is not None:
        record_audit(db, user, "logout", "user", str(user.id))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
