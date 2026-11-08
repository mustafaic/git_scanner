"""CSRF korumasi -- double-submit cookie deseni (master_prompt.md 5
"CSRF/CSP"). Sunucu tarafi oturum (core/models.Session) zaten var, ama
ayrica bir synchronizer-token tablosu acmamak icin basit/kanitlanmis
double-submit deseni secildi (kural 11: olcup karmasiklastirmadan basit
baslanir):

  1. Bir form render eden GET route'u `issue_csrf_cookie()` cagirir: cevapta
     `csrf_token` cookie'si YOKSA rastgele bir token uretilip HttpOnly
     cookie olarak yazilir, AYNI deger template'e `csrf_token` olarak
     gecirilip gizli input olarak gömülur.
  2. POST/PUT/DELETE route'lari `Depends(require_csrf)` kullanir: cookie'deki
     deger ile form alanindaki (veya HTMX icin `X-CSRF-Token` header'indaki)
     deger secrets.compare_digest ile karsilastirilir, uyusmazsa 403.

BILINCLI TASARIM: bir ASGI middleware DEGIL, FastAPI dependency olarak
yazildi -- govdeyi (body) middleware seviyesinde okuyup route'a yeniden
oynatmaya calismak (Starlette'in bilinen bir tuzagi) gereksiz karmasiklik
ekliyordu; Starlette `Request.form()` sonucu zaten cache'ler, dependency
ile route'un kendi `Form(...)` parametreleri govdeyi guvenle paylasir.

Saldirgan cross-origin bir form uzerinden cookie'yi OKUYAMAZ/degerini
BILEMEZ (SOP), dolayisiyla gecerli bir hidden-field/header degeri
gonderemez.
"""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, Response

CSRF_COOKIE_NAME = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def ensure_csrf_token(request: Request) -> tuple[str, bool]:
    """Istekte gecerli bir csrf cookie varsa (deger, False) doner; yoksa
    yeni uretilmis (deger, True) doner. Degeri cookie'ye yazmak cagiranin
    sorumlulugudur (bkz. set_csrf_cookie) -- cunku token'in TemplateResponse
    govdesine (form'a) gecirilmesi, Response nesnesi olusturulmadan ONCE
    bilinmesi gereken bir degerdir."""
    existing = request.cookies.get(CSRF_COOKIE_NAME)
    if existing:
        return existing, False
    return generate_csrf_token(), True


def set_csrf_cookie(response: Response, token: str, *, cookie_secure: bool) -> None:
    response.set_cookie(
        CSRF_COOKIE_NAME, token, httponly=True, secure=cookie_secure, samesite="lax", path="/",
    )


def issue_csrf_cookie(request: Request, response: Response, *, cookie_secure: bool) -> str:
    """Form render eden bir GET handler'i, template context'ine koyacagi
    `csrf_token` degerini Response govdesi olusturulmadan ONCE bu
    fonksiyonla DEGIL -- `ensure_csrf_token()` ile alir; bu fonksiyon
    (zaten olusturulmus bir Response uzerinde) sadece cookie'yi YOKSA
    yazmak icin kullanilir (route govdesi context'e bagimli degilse,
    ör. partial/HTMX fragment'larinda, kullanisli)."""
    token, is_new = ensure_csrf_token(request)
    if is_new:
        set_csrf_cookie(response, token, cookie_secure=cookie_secure)
    return token


async def require_csrf(request: Request) -> None:
    """State-degistiren (POST/PUT/DELETE/PATCH) route'larda
    `Depends(require_csrf)` olarak kullanilir."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    submitted = request.headers.get(CSRF_HEADER_NAME)
    if not submitted:
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            value = form.get(CSRF_FORM_FIELD)
            submitted = value if isinstance(value, str) else None
    if not cookie_token or not submitted or not secrets.compare_digest(cookie_token, submitted):
        raise HTTPException(status_code=403, detail="CSRF dogrulamasi basarisiz")
