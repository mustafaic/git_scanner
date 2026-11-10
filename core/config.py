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

    # Asama 4: ic SMTP (master_prompt.md 5 "SMTP sunucu parametreleri
    # sunucu config'inde kalir" -- DB'deki Setting tablosunda SADECE
    # kanal ac/kapat + alici listesi tutulur, sunucu adresi/kimlik
    # bilgisi BURADA, env/Docker secret'tan okunur). Bos ise (varsayilan)
    # e-posta gonderimi devre disi kalir (orchestrator/app bunu kontrol eder).
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_address: Optional[str] = None

    # Asama 3: panel oturum cerezi (master_prompt.md 5 "Oturum cerezi
    # HttpOnly + Secure + SameSite"). `Secure` HTTPS gerektirir -- yerel
    # docker-compose dev ortami duz HTTP sundugu icin KAPATILABILIR
    # (bilinen/belgelenmis sinirlama, bkz. deploy/docker-compose.yml app
    # servisi; prod'da TLS terminasyonunun onunde bu DAIMA true olmali).
    session_cookie_secure: bool = True

    # Asama 5: sifreli yedekleme (master_prompt.md 5: "Yedekler sifreli ve
    # sunucu disinda"). Anahtar Docker secret/dosya yolundan okunur (ayni
    # desen: github_app_private_key_path) -- DB'ye veya env'e duz metin
    # YAZILMAZ. Bos ise backup script'i acik bir hata ile durur (sessizce
    # sifresiz yedek ALMAZ).
    backup_encryption_key_path: Optional[str] = None
    backup_dir: str = "/backups"
    backup_retention_days: int = 14

    # Teams webhook bildirimleri (docs/THREAT_MODEL.md madde 9,
    # docs/LIMITATIONS.md madde 3: "webhook URL'si DB'de sifreli saklanmali").
    # URL'nin KENDISI admin panelden (DB, core.models.Setting) girilir --
    # SMTP host'un aksine burada env'de tutulmaz, cunku kullanici karari
    # URL'nin panelden kolayca degistirilebilir olmasi. Sadece SIFRELEME
    # ANAHTARI (Fernet, core/backup_crypto.py ile ayni mekanizma) burada,
    # Docker secret/dosya yolundan okunur -- DB'ye asla duz metin yazilmaz.
    teams_encryption_key_path: Optional[str] = None

    # Panelden GitHub token ile repo ekleme (hibrit model, 2026-11-10
    # kullanici karari). Teams webhook anahtariyla AYNI mekanizma
    # (Fernet, core/backup_crypto.py), AYRI bir anahtar dosyasi -- admin'in
    # /repositories sayfasindan girdigi PAT'ler bununla sifrelenir/cozulur.
    # Bos ise onboarding formu token kaydetmeyi reddeder.
    repo_token_encryption_key_path: Optional[str] = None

    # Teams/panel baglantilari icin "detaylar icin panele bakin: <url>"
    # seklinde minimal baglanti eklemek icin (THREAT_MODEL.md 9: "icerik
    # SADECE minimal -- sayilar + panel linki"). Bos ise link eklenmez.
    panel_base_url: Optional[str] = None


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # pydantic-settings env'den doldurur
