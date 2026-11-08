"""FastAPI panel servisi (master_prompt.md 3.4, 5): Jinja2+HTMX panel,
oturum-cerezi tabanli yerel auth + RBAC, audit log, read-only API token'lari,
CSRF (double-submit cookie) + CSP/guvenlik header'lari.

`app` servisi GitHub App key'ini GORMEZ, orchestrator modullerini import
ETMEZ (bkz. deploy/Dockerfile.app: sadece core/+app/ kopyalanir) -- repo
durumu/bulgular SADECE ortak Postgres uzerinden okunur/yazilir, elle
tetikleme de ayni sekilde core.models.ScanTrigger'a dogrudan INSERT ile
yapilir (orchestrator'in claim loop'u kendi dongusunde isler)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import (
    api,
    routes_actions,
    routes_audit,
    routes_auth,
    routes_coverage,
    routes_dashboard,
    routes_export,
    routes_findings,
    routes_repos,
    routes_secrets,
    routes_tokens,
    routes_users,
)
from app.security import SecurityHeadersMiddleware
from core.config import load_settings
from core.db import init_engine, session_scope
from core.logging_setup import configure_logging

settings = load_settings()
configure_logging("app", settings.log_level)
init_engine(settings.database_url)

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)

_STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

app.include_router(routes_auth.router)
app.include_router(routes_dashboard.router)
app.include_router(routes_repos.router)
# NOT: export router'i {finding_id}/{secret_id} path-parametreli router'lardan
# ONCE register edilmeli -- Starlette rotalari eklenme sirasina gore dener,
# "/findings/export.csv" "/findings/{finding_id}"'den SONRA gelirse "export.csv"
# finding_id'ye int donusturme hatasiyla (422) eslesmeye calisilirdi.
app.include_router(routes_export.router)
app.include_router(routes_findings.router)
app.include_router(routes_secrets.router)
app.include_router(routes_audit.router)
app.include_router(routes_tokens.router)
app.include_router(routes_actions.router)
app.include_router(routes_coverage.router)
app.include_router(routes_users.router)
app.include_router(api.router)


@app.exception_handler(StarletteHTTPException)
async def _auth_redirect_handler(request: Request, exc: StarletteHTTPException):
    """HTML panel sayfalarinda 401 -> /login'e yonlendirir (kullanici
    deneyimi); /api/* ve zaten-JSON bekleyen istekler duz JSON hata alir."""
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="db unavailable") from exc
    return {"status": "ok"}
