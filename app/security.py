"""Guvenlik response header'lari (master_prompt.md 5 "CSRF/CSP").

Sadece YANIT header'i ekler, istek govdesine dokunmaz -- CSRF'teki
(app/csrf.py) govde-yeniden-oynatma sorunuyla karsilasilmaz.

CSP `script-src 'self'`: htmx yerel olarak vendor edilir
(app/static/vendor/htmx.min.js), hicbir CDN'e bagimlilik yok (kural 5/6:
dis bagimliligi aciklanmis/konfigure edilebilir tut). Inline <script>
KULLANILMAZ (nonce gerektirmeden 'self' yeterli)."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response
