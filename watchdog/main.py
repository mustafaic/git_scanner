"""Watchdog iskeleti + heartbeat (master_prompt.md 6 "Dead man's switch").

system_heartbeats tablosundaki 'orchestrator' bileseninin son basarili
zaman damgasini izler; bayatlarsa loglar (yuksek sesle soyler, kural:
sessiz bozulma en buyuk dusman); konfigure edilmisse sirket ici bir
heartbeat izleyicisine (SaaS DEGIL) ping atar.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from typing import Optional

import httpx
from sqlalchemy import text

from core.config import Settings, load_settings
from core.db import init_engine, session_scope
from core.logging_setup import configure_logging

LOG = logging.getLogger(__name__)


def _last_orchestrator_success(session) -> Optional[dt.datetime]:
    row = session.execute(
        text("SELECT last_success_at FROM system_heartbeats WHERE component = 'orchestrator'")
    ).first()
    return row[0] if row else None


def check_and_ping(settings: Settings, http_client: Optional[httpx.Client] = None) -> bool:
    """Bir kontrol dongusu calistirir. Donen deger: saglikli mi (True/False)."""
    with session_scope() as session:
        last_success_at = _last_orchestrator_success(session)

    if last_success_at is None:
        LOG.warning("Henuz orchestrator heartbeat kaydi yok (ilk baslatma olabilir)")
        return False

    age_seconds = (dt.datetime.now(dt.timezone.utc) - last_success_at).total_seconds()
    if age_seconds > settings.heartbeat_stale_threshold_seconds:
        LOG.error(
            "Orchestrator heartbeat BAYAT: %.0f saniye once (esik=%ss)",
            age_seconds,
            settings.heartbeat_stale_threshold_seconds,
        )
        return False

    LOG.info("Orchestrator heartbeat taze (%.0f saniye once)", age_seconds)
    if settings.heartbeat_url:
        client = http_client or httpx.Client(timeout=10.0)
        try:
            client.get(settings.heartbeat_url)
        except Exception:  # noqa: BLE001
            LOG.exception("Heartbeat ping basarisiz")
    return True


def main() -> None:
    settings = load_settings()
    configure_logging("watchdog", settings.log_level)
    init_engine(settings.database_url)
    LOG.info(
        "Watchdog basladi (check_interval=%ss, heartbeat=%s)",
        settings.watchdog_check_interval_seconds,
        "configured" if settings.heartbeat_url else "disabled",
    )
    while True:
        try:
            check_and_ping(settings)
        except Exception:  # noqa: BLE001
            LOG.exception("Watchdog kontrol dongusunde beklenmeyen hata")
        time.sleep(settings.watchdog_check_interval_seconds)


if __name__ == "__main__":
    main()
