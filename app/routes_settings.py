"""A10 Ayarlar (kismi -- master_prompt.md 6): SLA hedef sureleri + ic SMTP
bildirim kanali ac/kapat + alici listesi + Teams webhook bildirim kanali +
viewer'a hiz-limitli elle tetikleme izni. SADECE admin. CODEOWNERS otomatik
tespiti BURADA YOK (kapsam disi birakildi, bkz. docs/ASSUMPTIONS.md)."""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, Form
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin
from core.backup_crypto import InvalidToken, decrypt_bytes, encrypt_bytes, load_fernet_key
from core.config import load_settings
from core.models import User
from core.notifications import send_teams_message
from core.settings_store import (
    DEFAULT_NOTIFICATIONS,
    DEFAULT_TEAMS,
    DEFAULT_VIEWER_TRIGGER,
    NOTIFICATIONS_KEY,
    SLA_DAYS_KEY,
    TEAMS_KEY,
    VIEWER_TRIGGER_KEY,
    get_setting,
    set_setting,
)
from core.sla import DEFAULT_SLA_DAYS, merged_sla_days

LOG = logging.getLogger(__name__)
router = APIRouter()

_settings = load_settings()

# docs/THREAT_MODEL.md madde 9/10: webhook URL'si admin panelden girilir
# (SSRF: sunucu bu URL'ye POST atar) -- sadece resmi MS Teams/Power Automate
# webhook host'larina izin vererek ele gecirilmis-olmayan bir admin'in
# yanlislikla/kötü niyetle sunucuyu ic aga yonlendirmesi engellenir.
# - .webhook.office.com: klasik Office 365 Connector (Incoming Webhook).
# - .logic.azure.com: klasik Azure Logic Apps HTTP trigger.
# - .environment.api.powerplatform.com: guncel Power Automate "Instant
#   cloud flow" HTTP tetikleyicisi (Microsoft'un Office 365 Connector'lari
#   kullanimdan kaldirmasinin yerine gecen format, bkz. Microsoft duyurusu).
_ALLOWED_WEBHOOK_HOST_SUFFIXES = (
    ".webhook.office.com",
    ".logic.azure.com",
    ".environment.api.powerplatform.com",
)


def _teams_fernet_key() -> Optional[bytes]:
    if not _settings.teams_encryption_key_path:
        return None
    try:
        return load_fernet_key(_settings.teams_encryption_key_path)
    except OSError:
        LOG.error("TEAMS_ENCRYPTION_KEY_PATH okunamadi: %s", _settings.teams_encryption_key_path)
        return None


def _encrypt_webhook_url(url: str) -> str:
    key = _teams_fernet_key()
    if key is None:
        raise RuntimeError("teams_encryption_key_path yapilandirilmamis")
    return encrypt_bytes(url.encode("utf-8"), key).decode("ascii")


def _decrypt_webhook_url(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    key = _teams_fernet_key()
    if key is None:
        return None
    try:
        return decrypt_bytes(token.encode("ascii"), key).decode("utf-8")
    except InvalidToken:
        LOG.error("Teams webhook URL'si cozulemedi (anahtar degismis olabilir)")
        return None


def _validate_webhook_url(url: str) -> Optional[str]:
    """Gecersizse kullaniciya gosterilecek hata metnini, gecerliyse None doner."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return "Webhook URL'si https:// ile baslamali."
    if not any(parts.hostname.endswith(suffix) for suffix in _ALLOWED_WEBHOOK_HOST_SUFFIXES):
        return "Webhook URL'si resmi bir Microsoft Teams/Power Automate adresi olmali (*.webhook.office.com veya *.logic.azure.com)."
    return None


def _settings_context(db: DbSession) -> dict:
    teams = {**DEFAULT_TEAMS, **(get_setting(db, TEAMS_KEY) or {})}
    return {
        "sla_days": merged_sla_days(get_setting(db, SLA_DAYS_KEY)),
        "notifications": {**DEFAULT_NOTIFICATIONS, **(get_setting(db, NOTIFICATIONS_KEY) or {})},
        "viewer_trigger": {**DEFAULT_VIEWER_TRIGGER, **(get_setting(db, VIEWER_TRIGGER_KEY) or {})},
        "default_sla_days": DEFAULT_SLA_DAYS,
        "teams": {**teams, "webhook_configured": bool(teams.get("webhook_url_encrypted"))},
        "teams_crypto_ready": _settings.teams_encryption_key_path is not None,
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


@router.post("/settings/teams")
def update_teams(
    request: Request,
    enabled: bool = Form(False),
    webhook_url: str = Form(""),
    event_critical_sca: bool = Form(False),
    event_new_secret: bool = Form(False),
    event_daily_digest: bool = Form(False),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    existing = {**DEFAULT_TEAMS, **(get_setting(db, TEAMS_KEY) or {})}
    webhook_url = webhook_url.strip()
    webhook_url_encrypted = existing.get("webhook_url_encrypted")

    if webhook_url:
        error = _validate_webhook_url(webhook_url)
        if error is None and _settings.teams_encryption_key_path is None:
            error = "Sunucuda TEAMS_ENCRYPTION_KEY_PATH yapilandirilmamis -- RUNBOOK.md'ye bakin."
        if error:
            return render_page(
                request, "settings.html", {**_settings_context(db), "error": error}, user=user, status_code=400,
            )
        webhook_url_encrypted = _encrypt_webhook_url(webhook_url)

    events = {
        "critical_sca_finding": event_critical_sca,
        "new_secret_finding": event_new_secret,
        "daily_digest": event_daily_digest,
    }
    value = {"enabled": enabled, "webhook_url_encrypted": webhook_url_encrypted, "events": events}
    set_setting(db, TEAMS_KEY, value, updated_by_user_id=user.id)
    record_audit(
        db, user, "settings_teams_updated", "settings", TEAMS_KEY,
        {"enabled": enabled, "webhook_configured": bool(webhook_url_encrypted), "events": events},
    )
    return render_page(
        request, "settings.html",
        {**_settings_context(db), "flash_ok": "Teams ayarları kaydedildi."},
        user=user,
    )


@router.post("/settings/teams/test")
def test_teams(
    request: Request,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    teams = {**DEFAULT_TEAMS, **(get_setting(db, TEAMS_KEY) or {})}
    webhook_url = _decrypt_webhook_url(teams.get("webhook_url_encrypted"))
    if not webhook_url:
        return render_page(
            request, "settings.html",
            {**_settings_context(db), "error": "Once gecerli bir webhook URL'si kaydedin."},
            user=user, status_code=400,
        )
    try:
        send_teams_message(
            webhook_url, "Scanner Panel bağlantı testi",
            "Bu mesajı görüyorsanız Teams entegrasyonu doğru çalışıyor.",
        )
    except httpx.HTTPError:
        LOG.exception("Teams test mesaji gonderilemedi")
        return render_page(
            request, "settings.html",
            {**_settings_context(db), "error": "Teams'e test mesajı gönderilemedi (sunucu loglarına bakın)."},
            user=user, status_code=502,
        )
    record_audit(db, user, "settings_teams_test_sent", "settings", TEAMS_KEY, {})
    return render_page(
        request, "settings.html",
        {**_settings_context(db), "flash_ok": "Test mesajı Teams'e gönderildi."},
        user=user,
    )
