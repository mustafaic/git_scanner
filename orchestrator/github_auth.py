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
from sqlalchemy.orm import Session

from core.backup_crypto import InvalidToken, decrypt_bytes
from core.logging_setup import register_secret
from core.models import Repository, RepoCredential

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


class StaticTokenAuth:
    """GitHubAppAuth ile AYNI arayuz (sadece `get_token()`) -- JWT/installation
    token degisimi YOK, panelden girilen sabit bir PAT'i doner. Faz 1
    (panelden GitHub token ile repo ekleme, hibrit model): boylece
    orchestrator/sync.py, orchestrator/extraction.py, orchestrator/secret_scan.py
    gibi TUM `auth.get_token()` cagri yerleri HICBIR DEGISIKLIK gerektirmeden
    hem GitHub App hem manuel-PAT repolarla calisir (duck typing)."""

    def __init__(self, token: str) -> None:
        self._token = token
        register_secret(token)

    def get_token(self, now: Optional[float] = None) -> str:
        return self._token


def resolve_auth_for_repo(
    session: Session,
    repo: Repository,
    app_auth: Optional[GitHubAppAuth],
    repo_token_key: Optional[bytes],
) -> "GitHubAppAuth | StaticTokenAuth":
    """Faz 1 (panelden GitHub token ile repo ekleme, hibrit model): her repo
    icin dogru kimlik bilgisini doner -- `discovered_via='github_app'`
    (varsayilan) ise mevcut App installation token'i (DEGISMEDEN), 'manual_pat'
    ise `repo_credentials`'tan cozulen kendi PAT'i. Cagiran taraf
    (orchestrator/main.py `_process_repo_check_job`) `.get_token()` DISINDA
    hicbir seyi bilmesine gerek kalmadan ayni kodu kullanir."""
    if repo.discovered_via != "manual_pat":
        if app_auth is None:
            raise RuntimeError("GitHub App kimligi yapilandirilmamis, repo_check islenemez")
        return app_auth
    if repo_token_key is None:
        raise RuntimeError("REPO_TOKEN_ENCRYPTION_KEY_PATH yapilandirilmamis, manuel eklenen repo taranamaz")
    cred = session.get(RepoCredential, repo.github_repo_id)
    if cred is None:
        raise RuntimeError(f"{repo.full_name} icin kayitli bir token yok (repo_credentials)")
    try:
        token = decrypt_bytes(cred.encrypted_token.encode("ascii"), repo_token_key).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(f"{repo.full_name} icin token cozulemedi (sifreleme anahtari degismis olabilir)") from exc
    return StaticTokenAuth(token)
