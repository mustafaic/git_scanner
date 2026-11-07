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

from core import logging_setup  # noqa: E402
from orchestrator.github_auth import (  # noqa: E402
    GitHubAppAuth,
    JWT_CLOCK_DRIFT_BACKOFF_SECONDS,
    JWT_LIFETIME_SECONDS,
    generate_app_jwt,
    load_private_key,
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


def test_load_private_key_reads_file_and_registers_secret(tmp_path):
    key_file = tmp_path / "app.pem"
    key_file.write_text("-----BEGIN FAKE KEY-----\nabc\n-----END FAKE KEY-----\n", encoding="utf-8")

    content = load_private_key(str(key_file))
    assert "BEGIN FAKE KEY" in content

    redacted = logging_setup._redact(f"loaded key: {content}")
    assert content not in redacted
    assert "***REDACTED***" in redacted
