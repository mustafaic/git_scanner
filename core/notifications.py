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

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.logging_setup import register_secret
from core.models import NotificationLog

LOG = logging.getLogger(__name__)

CHANNEL_EMAIL = "email"

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
