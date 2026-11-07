"""GitHub App JWT uretimi + installation access token degisimi/cache'i.

master_prompt.md 5. Guvenlik: private key yalnizca orchestrator'da (Docker
secret/dosya, 0400); kisa omurlu installation token orchestrator uretir,
log'a yazilmaz. Dogrulanmis API detaylari: docs/VERIFIED_FACTS.md
"GitHub App auth / discovery" (2026-11-08).
"""

from __future__ import annotations

import datetime as _dt
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import jwt

from core.logging_setup import register_secret

LOG = logging.getLogger(__name__)

# VERIFIED_FACTS.md: maksimum exp penceresi "su andan 10 dakika ileri";
# saat kaymasi icin onerilen: iat'i 60 saniye gecmise ayarla.
JWT_CLOCK_DRIFT_BACKOFF_SECONDS = 60
JWT_LIFETIME_SECONDS = 540  # 9 dakika: 10 dakikalik tavanin altinda guvenli pay
API_VERSION_HEADER = "2022-11-28"


def generate_app_jwt(app_id: str, private_key_pem: str, now: Optional[int] = None) -> str:
    """RS256 ile GitHub App JWT'si uretir. Saf fonksiyon (ag cagrisi yapmaz)."""
    now = int(time.time()) if now is None else now
    payload = {
        "iat": now - JWT_CLOCK_DRIFT_BACKOFF_SECONDS,
        "exp": now + JWT_LIFETIME_SECONDS,
        "iss": app_id,
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


@dataclass
class InstallationToken:
    token: str
    expires_at: float  # unix epoch saniye


def _parse_github_timestamp(value: str) -> float:
    dt = _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    return dt.timestamp()


class GitHubAppAuth:
    """Installation access token'i cache'ler, suresi dolmadan yeniler.

    Token hicbir zaman loglanmaz; elde edilir edilmez
    core.logging_setup.register_secret ile maskeleme listesine eklenir
    (ikinci guvence katmani; birincil kontrol token'i hic log cagrisina
    yazmamaktir).
    """

    def __init__(
        self,
        api_base_url: str,
        app_id: str,
        installation_id: str,
        private_key_pem: str,
        http_client: Optional[httpx.Client] = None,
        refresh_margin_seconds: int = 300,
    ) -> None:
        self._api_base_url = api_base_url.rstrip("/")
        self._app_id = app_id
        self._installation_id = installation_id
        self._private_key_pem = private_key_pem
        self._client = http_client or httpx.Client(timeout=30.0)
        self._refresh_margin_seconds = refresh_margin_seconds
        self._cached: Optional[InstallationToken] = None

    def get_token(self, now: Optional[float] = None) -> str:
        now = time.time() if now is None else now
        if self._cached is None or now >= (self._cached.expires_at - self._refresh_margin_seconds):
            self._cached = self._fetch_installation_token()
        return self._cached.token

    def _fetch_installation_token(self) -> InstallationToken:
        app_jwt = generate_app_jwt(self._app_id, self._private_key_pem)
        url = f"{self._api_base_url}/app/installations/{self._installation_id}/access_tokens"
        response = self._client.post(
            url,
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION_HEADER,
            },
        )
        if response.status_code != 201:
            # Yanit govdesi (icinde token olabilecek hata detayi) ASLA loglanmaz,
            # sadece durum kodu.
            raise RuntimeError(f"Installation token alinamadi: HTTP {response.status_code}")
        data = response.json()
        token = data["token"]
        register_secret(token)
        expires_at = _parse_github_timestamp(data["expires_at"])
        LOG.info("Installation token yenilendi (expires_at=%s)", data["expires_at"])
        return InstallationToken(token=token, expires_at=expires_at)


def load_private_key(path: str) -> str:
    content = Path(path).read_text(encoding="utf-8")
    register_secret(content)
    return content
