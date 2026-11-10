"""A6 Iletisim modeli (master_prompt.md 6): bildirim karar kurallari +
idempotent kayit + ic SMTP gonderimi. "Varsayilan sessizlik" ve "Baseline
bulgulari hicbir zaman bildirim uretmez" kurallari BURADA (karar
fonksiyonlarinda) uygulanir; caglıran taraf (orchestrator) sadece bu
fonksiyonlarin sonucuna gore hareket eder.

GUVENLIK: SMTP sifresi core/config.py'den (env/Docker secret) okunur,
DB'ye ASLA yazilmaz; register_secret ile loglama maskeleme listesine
eklenir (core/auth.py ile ayni desen)."""

from __future__ import annotations

import datetime as dt
import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.logging_setup import register_secret
from core.models import NotificationLog

LOG = logging.getLogger(__name__)

CHANNEL_EMAIL = "email"
CHANNEL_TEAMS = "teams"
# Teams'in tek bir hedefi var (kanal webhook'u, kullanici listesi degil) --
# NotificationLog'un (dedup_key, channel, recipient) UNIQUE kisitini
# degistirmeden idempotent dedup icin sabit bir "recipient" degeri kullanilir.
TEAMS_RECIPIENT = "teams-webhook"

EVENT_CRITICAL_SCA_FINDING = "critical_sca_finding"
EVENT_NEW_SECRET_FINDING = "new_secret_finding"
EVENT_SCAN_FAILED = "scan_failed"
EVENT_DAILY_DIGEST = "daily_digest"


@dataclass
class SmtpSettings:
    host: str
    port: int
    use_tls: bool
    from_address: str
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class TeamsSettings:
    """docs/THREAT_MODEL.md madde 9: webhook URL'si DB'de sifreli saklanir
    (core/backup_crypto.py ile ayni Fernet mekanizmasi, ayri bir anahtarla),
    sadece caginan tarafta (app/orchestrator) cozulup bellekte bu dataclass'a
    konur -- diske/loga asla duz metin yazilmaz (register_secret ile
    maskeleme listesine eklenir, core/auth.py ile ayni desen)."""

    webhook_url: str
    events: Dict[str, bool]


def should_notify_new_secret(is_baseline: bool) -> bool:
    """master_prompt.md 6: 'yeni secret ... (baseline degil)' -> ANINDA.
    Baseline (ilk tarama) bulgulari HICBIR ZAMAN bildirim uretmez (kural 5)."""
    return not is_baseline


def should_notify_critical_sca(
    *, kev: bool, cvss_score: Optional[float], is_baseline: bool, critical_cvss_threshold: float = 9.0
) -> bool:
    """master_prompt.md 6: 'KEV'de olan veya CVSS >= 9 (config) SCA
    bulgusu (baseline degil)' -> ANINDA."""
    if is_baseline:
        return False
    if kev:
        return True
    return cvss_score is not None and cvss_score >= critical_cvss_threshold


def send_email(smtp_settings: SmtpSettings, to_address: str, subject: str, body: str) -> None:
    """Gercek SMTP gonderimi -- testlerde smtplib.SMTP mock'lanir (gercek
    bir SMTP sunucusu olmadan dogrulama, kullanici karari: bkz. konusma
    gecmisi/ASSUMPTIONS.md)."""
    register_secret(smtp_settings.password)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_settings.from_address
    message["To"] = to_address
    message.set_content(body)

    with smtplib.SMTP(smtp_settings.host, smtp_settings.port, timeout=15) as client:
        if smtp_settings.use_tls:
            client.starttls()
        if smtp_settings.username and smtp_settings.password:
            client.login(smtp_settings.username, smtp_settings.password)
        client.send_message(message)


def send_teams_message(webhook_url: str, title: str, text: str) -> None:
    """Office 365 Connector "MessageCard" semasi -- Teams Incoming Webhook /
    Power Automate workflow baglantilarinin kabul ettigi standart format.
    Testlerde httpx.Client mock'lanir (gercek bir Teams kanali bu oturumda
    kurulmadi, send_email ile ayni desen).

    GUVENLIK (ampirik olarak bulundu, bkz. tests): register_secret'teki
    metin-eslemeli redaksiyona GUVENILMEZ -- httpx, URL'yi loglarken
    yeniden serilestirir (ör. varsayilan :443 portunu DUSURUR), bu yuzden
    orijinal ham dizeyle TAM eslesmeyebilir ve webhook imzasi (sig=...)
    log'a DUZ METIN sizabilir. Asil kontrol -- core/logging_setup.py'nin
    kendi felsefesiyle ayni ("secret'i hic log cagrisina yazma") -- bu
    cagri SIRASINDA httpx/httpcore'un kendi istek logunu komple
    SUSTURMAKTIR."""
    register_secret(webhook_url)
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "title": title,
        "text": text,
    }
    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")
    prev_levels = (httpx_logger.level, httpcore_logger.level)
    httpx_logger.setLevel(logging.WARNING)
    httpcore_logger.setLevel(logging.WARNING)
    try:
        with httpx.Client(timeout=15) as client:
            response = client.post(webhook_url, json=payload)
            response.raise_for_status()
    finally:
        httpx_logger.setLevel(prev_levels[0])
        httpcore_logger.setLevel(prev_levels[1])


def build_minimal_teams_text(event_type: str, *, panel_base_url: Optional[str] = None) -> Dict[str, str]:
    """docs/THREAT_MODEL.md madde 9: Teams icerigi SADECE minimal (sayilar +
    panel linki) -- repo/paket/CVE/secret detayi ASLA buraya girmez (email
    gövdesinin aksine, bkz. core/notifications.py send_email cagrilari).
    Bu yuzden `finding`/`secret` nesnesi PARAMETRE OLARAK BILE ALINMAZ --
    cagiran tarafin yanlislikla detay sizdirmasi yapisal olarak engellenir."""
    titles = {
        EVENT_CRITICAL_SCA_FINDING: "Kritik SCA bulgusu",
        EVENT_NEW_SECRET_FINDING: "Yeni secret bulgusu",
    }
    link_targets = {
        EVENT_CRITICAL_SCA_FINDING: "/findings",
        EVENT_NEW_SECRET_FINDING: "/secrets",
    }
    title = titles.get(event_type, "Scanner Panel bildirimi")
    text = "Detaylar icin panele bakin."
    if panel_base_url:
        text = f"Detaylar icin panele bakin: {panel_base_url.rstrip('/')}{link_targets.get(event_type, '')}"
    return {"title": title, "text": text}


def record_and_maybe_send_teams(
    session: Session,
    *,
    event_type: str,
    dedup_key: str,
    title: str,
    text: str,
    teams_settings: Optional[TeamsSettings],
) -> int:
    """`record_and_maybe_send`in Teams karsiligi -- ayni idempotent
    (dedup_key, channel, recipient) UNIQUE deseni, tek farki Teams'in tek
    bir "alicisi" (kanal webhook'u) olmasi (bkz. TEAMS_RECIPIENT).
    `teams_settings` None, webhook_url bos VEYA event_type bu Teams
    konfigurasyonunda kapaliysa (events[event_type] is False) NO-OP doner."""
    if teams_settings is None or not teams_settings.webhook_url:
        return 0
    if not teams_settings.events.get(event_type, False):
        return 0

    result = session.execute(
        pg_insert(NotificationLog)
        .values(event_type=event_type, dedup_key=dedup_key, channel=CHANNEL_TEAMS, recipient=TEAMS_RECIPIENT, subject=title)
        .on_conflict_do_nothing(index_elements=["dedup_key", "channel", "recipient"])
        .returning(NotificationLog.id)
    )
    if result.first() is None:
        return 0  # zaten gonderilmis (idempotent atlama)
    try:
        send_teams_message(teams_settings.webhook_url, title, text)
    except Exception:  # noqa: BLE001 - Teams hatasi diger kanallari/islemi durdurmamali
        LOG.exception("Teams bildirimi gonderilemedi: event=%s", event_type)
        return 0
    return 1


def record_and_maybe_send(
    session: Session,
    *,
    event_type: str,
    dedup_key: str,
    channel: str,
    recipients: List[str],
    subject: str,
    body: str,
    smtp_settings: Optional[SmtpSettings],
) -> int:
    """master_prompt.md 6 'Gurultu kontrolleri': ayni olay/alici/kanal
    uclusu BIR KEZ gonderilir -- bu DB UNIQUE kisitiyla (ON CONFLICT DO
    NOTHING) garanti edilir; sadece GERCEKTEN yeni eklenen satirlar icin
    gonderim yapilir (idempotent -- is kuyrugundaki idempotency_key deseniyle
    ayni, bkz. orchestrator/jobs.py).

    `smtp_settings` None ise (kanal kapali/konfigure edilmemis) kayit
    YAPILMAZ -- cagiran taraf once bunu cagirmamali, ama savunmaci olarak
    burada da 0 doner (hicbir seffaf olmayan yan etki yok)."""
    if smtp_settings is None or not recipients:
        return 0

    sent_count = 0
    for recipient in recipients:
        result = session.execute(
            pg_insert(NotificationLog)
            .values(event_type=event_type, dedup_key=dedup_key, channel=channel, recipient=recipient, subject=subject)
            .on_conflict_do_nothing(index_elements=["dedup_key", "channel", "recipient"])
            .returning(NotificationLog.id)
        )
        if result.first() is None:
            continue  # zaten gonderilmis (idempotent atlama)
        try:
            send_email(smtp_settings, recipient, subject, body)
            sent_count += 1
        except Exception:  # noqa: BLE001 - bir alicinin SMTP hatasi digerlerini durdurmamali
            LOG.exception("Bildirim gonderilemedi: event=%s recipient=%s", event_type, recipient)
    return sent_count


def build_daily_digest_summary(counts: Dict[str, int], as_of: Optional[dt.date] = None) -> Dict[str, Any]:
    """Saf metin uretimi -- sayilari DB'den CAGIRAN taraf toplar (bkz.
    orchestrator/main.py), bu fonksiyon sadece konsolide ozet metnini
    kurar (master_prompt.md 6: 'Bulgu basina mesaj yok, konsolide')."""
    as_of = as_of or dt.datetime.now(dt.timezone.utc).date()
    subject = f"Günlük özet ({as_of.isoformat()})"
    lines = [
        f"Yeni bulgu: {counts.get('new', 0)}",
        f"Kapanan: {counts.get('resolved', 0)}",
        f"Yeniden açılan: {counts.get('reopened', 0)}",
        f"Başarısız tarama: {counts.get('failed_scans', 0)}",
        f"KEV'e yeni giren: {counts.get('new_kev', 0)}",
    ]
    return {"subject": subject, "body": "\n".join(lines)}
