"""orchestrator/github_auth.py testleri.

Gercek GitHub App key'i KULLANILMAZ: her test kendi atilabilir (throwaway)
RSA anahtar ciftini uretir. Ag cagrisi yapilmaz (httpx.MockTransport).
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.fernet import Fernet  # noqa: E402

from core import logging_setup  # noqa: E402
from core.backup_crypto import encrypt_bytes  # noqa: E402
from core.models import Repository, RepoCredential  # noqa: E402
from orchestrator.github_auth import (  # noqa: E402
    GitHubAppAuth,
    JWT_CLOCK_DRIFT_BACKOFF_SECONDS,
    JWT_LIFETIME_SECONDS,
    StaticTokenAuth,
    generate_app_jwt,
    load_private_key,
    resolve_auth_for_repo,
)


@pytest.fixture()
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def test_generate_app_jwt_claims_and_algorithm(rsa_keypair):
    private_pem, public_pem = rsa_keypair
    now = 1_700_000_000
    token = generate_app_jwt("app-123", private_pem, now=now)

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"

    payload = jwt.decode(token, public_pem, algorithms=["RS256"], options={"verify_exp": False})
    assert payload["iss"] == "app-123"
    assert payload["iat"] == now - JWT_CLOCK_DRIFT_BACKOFF_SECONDS
    assert payload["exp"] == now + JWT_LIFETIME_SECONDS


def test_generate_app_jwt_window_under_github_10_minute_max(rsa_keypair):
    private_pem, _ = rsa_keypair
    now = 1_700_000_000
    token = generate_app_jwt("app-123", private_pem, now=now)
    payload = jwt.decode(token, options={"verify_signature": False})
    # VERIFIED_FACTS.md: GitHub exp'i "su andan 10 dakika ileri"yi asamaz.
    assert payload["exp"] - now <= 600
    assert payload["exp"] - payload["iat"] <= 600


def test_installation_token_cached_until_refresh_margin(rsa_keypair):
    private_pem, _ = rsa_keypair
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(201, json={"token": f"ghs_fake_{call_count['n']}", "expires_at": "2026-11-08T01:00:00Z"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth = GitHubAppAuth(
        api_base_url="https://api.github.com",
        app_id="app-123",
        installation_id="inst-456",
        private_key_pem=private_pem,
        http_client=client,
        refresh_margin_seconds=300,
    )

    import datetime as dt

    expires_at_ts = dt.datetime(2026, 11, 8, 1, 0, 0, tzinfo=dt.timezone.utc).timestamp()

    token1 = auth.get_token(now=expires_at_ts - 3600)
    token2 = auth.get_token(now=expires_at_ts - 3500)  # hala cache gecerli
    assert token1 == token2
    assert call_count["n"] == 1

    token3 = auth.get_token(now=expires_at_ts - 200)  # refresh_margin (300s) icinde -> yenile
    assert token3 != token1
    assert call_count["n"] == 2


def test_installation_token_error_does_not_leak_response_body(rsa_keypair):
    private_pem, _ = rsa_keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="SECRET_LOOKING_BODY_abc123")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth = GitHubAppAuth(
        api_base_url="https://api.github.com",
        app_id="app-123",
        installation_id="inst-456",
        private_key_pem=private_pem,
        http_client=client,
    )

    with pytest.raises(RuntimeError) as excinfo:
        auth.get_token(now=1_700_000_000)
    assert "SECRET_LOOKING_BODY_abc123" not in str(excinfo.value)
    assert "404" in str(excinfo.value)


def test_installation_token_registered_for_log_redaction(rsa_keypair):
    private_pem, _ = rsa_keypair

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"token": "ghs_super_secret_token_xyz", "expires_at": "2026-11-08T01:00:00Z"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth = GitHubAppAuth(
        api_base_url="https://api.github.com",
        app_id="app-123",
        installation_id="inst-456",
        private_key_pem=private_pem,
        http_client=client,
    )
    auth.get_token(now=1_700_000_000)

    redacted = logging_setup._redact("token=ghs_super_secret_token_xyz in request")
    assert "ghs_super_secret_token_xyz" not in redacted
    assert "***REDACTED***" in redacted


def test_static_token_auth_returns_fixed_token_and_registers_for_redaction():
    auth = StaticTokenAuth("ghp_fixed_pat_value")
    assert auth.get_token() == "ghp_fixed_pat_value"
    assert auth.get_token(now=123.0) == "ghp_fixed_pat_value"  # GitHubAppAuth ile ayni imza (now kwarg'i kabul eder, yoksayar)

    redacted = logging_setup._redact("token=ghp_fixed_pat_value in request")
    assert "ghp_fixed_pat_value" not in redacted


class _FakeSession:
    """resolve_auth_for_repo SADECE `session.get(RepoCredential, id)` cagirir
    -- gercek bir Postgres oturumuna gerek yok (bu, Postgres'e ozel JSONB/
    ON CONFLICT kullanmayan okuma-SADECE bir yol)."""

    def __init__(self, credential: RepoCredential | None = None) -> None:
        self._credential = credential

    def get(self, model, pk):
        if model is RepoCredential and self._credential is not None and pk == self._credential.github_repo_id:
            return self._credential
        return None


def _make_repo(discovered_via: str, github_repo_id: int = 1) -> Repository:
    return Repository(
        github_repo_id=github_repo_id, full_name="acme/x", owner="acme", name="x",
        default_branch="main", visibility="private", discovered_via=discovered_via,
    )


def test_resolve_auth_for_repo_returns_app_auth_for_github_app_repo():
    repo = _make_repo("github_app")
    app_auth = object()  # kimlik dogrulama detayina girmeden, sadece AYNI nesnenin dondugunu test eder
    result = resolve_auth_for_repo(_FakeSession(), repo, app_auth, repo_token_key=None)
    assert result is app_auth


def test_resolve_auth_for_repo_raises_when_app_auth_missing_for_github_app_repo():
    repo = _make_repo("github_app")
    with pytest.raises(RuntimeError, match="GitHub App kimligi yapilandirilmamis"):
        resolve_auth_for_repo(_FakeSession(), repo, app_auth=None, repo_token_key=None)


def test_resolve_auth_for_repo_decrypts_stored_token_for_manual_pat_repo():
    key = Fernet.generate_key()
    token = "ghp_super_secret_manual_pat"
    repo = _make_repo("manual_pat", github_repo_id=42)
    cred = RepoCredential(
        github_repo_id=42, encrypted_token=encrypt_bytes(token.encode("utf-8"), key).decode("ascii"),
        added_by_user_id=1,
    )
    result = resolve_auth_for_repo(_FakeSession(cred), repo, app_auth=None, repo_token_key=key)
    assert isinstance(result, StaticTokenAuth)
    assert result.get_token() == token


def test_resolve_auth_for_repo_raises_when_encryption_key_missing():
    repo = _make_repo("manual_pat", github_repo_id=42)
    with pytest.raises(RuntimeError, match="REPO_TOKEN_ENCRYPTION_KEY_PATH"):
        resolve_auth_for_repo(_FakeSession(), repo, app_auth=None, repo_token_key=None)


def test_resolve_auth_for_repo_raises_when_credential_row_missing():
    repo = _make_repo("manual_pat", github_repo_id=42)
    with pytest.raises(RuntimeError, match="kayitli bir token yok"):
        resolve_auth_for_repo(_FakeSession(), repo, app_auth=None, repo_token_key=Fernet.generate_key())


def test_resolve_auth_for_repo_raises_clear_error_when_key_rotated():
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()
    repo = _make_repo("manual_pat", github_repo_id=42)
    cred = RepoCredential(
        github_repo_id=42, encrypted_token=encrypt_bytes(b"token", old_key).decode("ascii"), added_by_user_id=1,
    )
    with pytest.raises(RuntimeError, match="cozulemedi"):
        resolve_auth_for_repo(_FakeSession(cred), repo, app_auth=None, repo_token_key=new_key)


def test_load_private_key_reads_file_and_registers_secret(tmp_path):
    key_file = tmp_path / "app.pem"
    key_file.write_text("-----BEGIN FAKE KEY-----\nabc\n-----END FAKE KEY-----\n", encoding="utf-8")

    content = load_private_key(str(key_file))
    assert "BEGIN FAKE KEY" in content

    redacted = logging_setup._redact(f"loaded key: {content}")
    assert content not in redacted
    assert "***REDACTED***" in redacted
