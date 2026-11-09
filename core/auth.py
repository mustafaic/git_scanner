"""Yerel hesap + oturum yonetimi (master_prompt.md 5 "Uygulama guvenligi").
Harici IdP yok. Parolalar argon2id.

NOT: TOTP (2FA) kullanici karariyla KALDIRILDI (2026-11-09, bkz.
docs/ASSUMPTIONS.md #14) -- bu modul artik SADECE parola/oturum/API-token
mantigini icerir.
"""

from __future__ import annotations

import datetime as dt
import re
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from core.logging_setup import register_secret

_hasher = PasswordHasher()

SESSION_TOKEN_BYTES = 32
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 15 * 60

# master_prompt.md 5: "minimum uzunluk/karmasiklik politikasi".
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def check_password_policy(password: str) -> Tuple[bool, Optional[str]]:
    """master_prompt.md 5: minimum uzunluk + karmasiklik. Basit ama somut
    bir politika (kural 11: olcup karmasiklastirmadan basit baslanir)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Parola en az {MIN_PASSWORD_LENGTH} karakter olmali"
    categories = [
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^a-zA-Z0-9]", password)),
    ]
    if sum(categories) < 3:
        return False, "Parola en az 3 karakter sinifi icermeli (kucuk/buyuk harf, rakam, sembol)"
    return True, None


def generate_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_api_token(raw_token: str) -> str:
    import hashlib

    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_api_token() -> Tuple[str, str]:
    """Donen: (ham_token -- SADECE olusturma aninda gosterilir, hash).
    DB'ye SADECE hash yazilir (master_prompt.md 5)."""
    raw = "sptk_" + secrets.token_urlsafe(32)
    register_secret(raw)
    return raw, hash_api_token(raw)


@dataclass
class LoginAttemptResult:
    allowed: bool
    reason: Optional[str] = None


def check_lockout(locked_until: Optional[dt.datetime]) -> LoginAttemptResult:
    if locked_until is None:
        return LoginAttemptResult(allowed=True)
    now = dt.datetime.now(dt.timezone.utc)
    if locked_until > now:
        return LoginAttemptResult(allowed=False, reason="account_locked")
    return LoginAttemptResult(allowed=True)


def compute_lockout_after_failure(failed_attempts: int) -> Tuple[int, Optional[dt.datetime]]:
    """Basarisiz giris sonrasi yeni (failed_attempts, locked_until) hesaplar.
    master_prompt.md 5: 'giris rate-limit + gecici kilitleme'."""
    new_count = failed_attempts + 1
    if new_count >= MAX_FAILED_LOGIN_ATTEMPTS:
        locked_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=LOCKOUT_DURATION_SECONDS)
        return new_count, locked_until
    return new_count, None
