"""Paylaşılan ortam değişkeni tabanlı config (master_prompt.md kural 6:
bilinmeyenleri varsayma, konfigürasyona çevir).

Tüm servisler (orchestrator/app/watchdog) bu modülü kullanır. Hiçbir alan
koda gömülü sabit değer taşımaz; test/gelistirme varsayilanlari acikca
isaretlenmistir.
"""

from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    service_name: str = "service"

    database_url: str

    github_api_base_url: str = "https://api.github.com"
    github_app_id: Optional[str] = None
    github_app_installation_id: Optional[str] = None
    # Docker secret/dosya yolu (master_prompt.md 5. Guvenlik: private key
    # yalnizca orchestrator'da, 0400). Gercek key degeri ASLA burada/env'de
    # duz metin olarak tutulmaz, sadece dosya yolu tutulur.
    github_app_private_key_path: Optional[str] = None

    poll_interval_seconds: int = 60
    claim_loop_interval_seconds: float = 2.0
    job_lock_duration_seconds: int = 120
    job_max_attempts: int = 5
    debounce_window_seconds: int = 20

    # Asama 2: Hat A/B + worker staging (master_prompt.md 3.2, 3.3).
    staging_dir: str = "/staging"
    db_cache_dir: str = "/dbs"
    daily_jobs_interval_hours: int = 24
    # master_prompt.md 3.3/4.6: taze olmayan DB hicbir bulguyu kapatamaz.
    advisory_max_age_seconds: int = 48 * 3600

    log_level: str = "INFO"

    # Bos ise devre disi (varsayilan): heartbeat sadece acikca konfigure
    # edilen, sirket ici bir izleyiciye gider (kural 12/18).
    heartbeat_url: Optional[str] = None
    heartbeat_stale_threshold_seconds: int = 1800
    watchdog_check_interval_seconds: int = 60

    metrics_enabled: bool = True


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # pydantic-settings env'den doldurur
