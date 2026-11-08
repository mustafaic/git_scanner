"""A10 Ayarlar (kismi -- master_prompt.md 6): SLA hedef sureleri + ic SMTP
bildirim kanali ac/kapat + alici listesi + viewer'a hiz-limitli elle
tetikleme izni. SADECE admin. Teams webhook + CODEOWNERS otomatik tespiti
BURADA YOK (kapsam disi birakildi, bkz. docs/ASSUMPTIONS.md)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin
from core.models import User
from core.settings_store import (
    DEFAULT_NOTIFICATIONS,
    DEFAULT_VIEWER_TRIGGER,
    NOTIFICATIONS_KEY,
    SLA_DAYS_KEY,
    VIEWER_TRIGGER_KEY,
    get_setting,
    set_setting,
)
from core.sla import DEFAULT_SLA_DAYS, merged_sla_days

router = APIRouter()


def _settings_context(db: DbSession) -> dict:
    return {
        "sla_days": merged_sla_days(get_setting(db, SLA_DAYS_KEY)),
        "notifications": {**DEFAULT_NOTIFICATIONS, **(get_setting(db, NOTIFICATIONS_KEY) or {})},
        "viewer_trigger": {**DEFAULT_VIEWER_TRIGGER, **(get_setting(db, VIEWER_TRIGGER_KEY) or {})},
        "default_sla_days": DEFAULT_SLA_DAYS,
    }


@router.get("/settings")
def settings_page(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    return render_page(request, "settings.html", _settings_context(db), user=user)


@router.post("/settings/sla")
def update_sla(
    request: Request,
    kev: int = Form(...),
    cvss_9: int = Form(...),
    cvss_7: int = Form(...),
    cvss_4: int = Form(...),
    default: int = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    values = {"kev": kev, "cvss_9": cvss_9, "cvss_7": cvss_7, "cvss_4": cvss_4, "default": default}
    for tier, days in values.items():
        if days <= 0:
            return render_page(
                request, "settings.html",
                {**_settings_context(db), "error": f"'{tier}' icin sure pozitif bir tam sayi olmali."},
                user=user, status_code=400,
            )
    set_setting(db, SLA_DAYS_KEY, values, updated_by_user_id=user.id)
    record_audit(db, user, "settings_sla_updated", "settings", SLA_DAYS_KEY, values)
    return render_page(
        request, "settings.html",
        {**_settings_context(db), "sla_days": merged_sla_days(values), "flash_ok": "SLA ayarlari kaydedildi."},
        user=user,
    )


@router.post("/settings/notifications")
def update_notifications(
    request: Request,
    email_enabled: bool = Form(False),
    recipients: str = Form(""),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    recipient_list = [r.strip() for r in recipients.replace("\n", ",").split(",") if r.strip()]
    value = {"email_enabled": email_enabled, "recipients": recipient_list}
    set_setting(db, NOTIFICATIONS_KEY, value, updated_by_user_id=user.id)
    record_audit(db, user, "settings_notifications_updated", "settings", NOTIFICATIONS_KEY, {"email_enabled": email_enabled, "recipient_count": len(recipient_list)})
    return render_page(
        request, "settings.html",
        {**_settings_context(db), "notifications": value, "flash_ok": "Bildirim ayarlari kaydedildi."},
        user=user,
    )


@router.post("/settings/viewer-trigger")
def update_viewer_trigger(
    request: Request,
    enabled: bool = Form(False),
    max_per_hour: int = Form(DEFAULT_VIEWER_TRIGGER["max_per_hour"]),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if max_per_hour <= 0:
        return render_page(
            request, "settings.html",
            {**_settings_context(db), "error": "saatlik limit pozitif bir tam sayi olmali."},
            user=user, status_code=400,
        )
    value = {"enabled": enabled, "max_per_hour": max_per_hour}
    set_setting(db, VIEWER_TRIGGER_KEY, value, updated_by_user_id=user.id)
    record_audit(db, user, "settings_viewer_trigger_updated", "settings", VIEWER_TRIGGER_KEY, value)
    return render_page(
        request, "settings.html",
        {**_settings_context(db), "viewer_trigger": value, "flash_ok": "Viewer tetikleme ayarı kaydedildi."},
        user=user,
    )
