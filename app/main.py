"""FastAPI panel servisi - Asama 1'de sadece iskelet/healthcheck.

master_prompt.md 3.4: app, GitHub key'i gormez, dis ag erisimi yoktur.
Panel/auth/RBAC Asama 3'te eklenecek.
"""

from __future__ import annotations

from typing import Dict

from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from core.config import load_settings
from core.db import init_engine, session_scope
from core.logging_setup import configure_logging

settings = load_settings()
configure_logging("app", settings.log_level)
init_engine(settings.database_url)

app = FastAPI()


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="db unavailable") from exc
    return {"status": "ok"}
