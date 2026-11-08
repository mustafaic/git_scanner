"""Yerel hesap + TOTP + oturum yonetimi (master_prompt.md 5 "Uygulama
guvenligi"). Harici IdP yok. Parolalar argon2id, TOTP RFC 6238 (pyotp).

GUVENLIK: TOTP sirri ve kurtarma kodlari HASSAS -- core.logging_setup
register_secret() ile maskeleme listesine eklenir, asla loglanmaz/donulmez
(kurtarma kodlari SADECE olusturulduklari anda duz metin olarak gosterilir).
"""

from __future__ import annotations

import datetime as dt
import re
import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from core.logging_setup import register_secret

_hasher = PasswordHasher()

SESSION_TOKEN_BYTES = 32
RECOVERY_CODE_COUNT = 10
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


def generate_totp_secret() -> str:
    secret = pyotp.random_base32()
    register_secret(secret)
    return secret


def totp_provisioning_uri(secret: str, username: str, issuer: str = "Scanner Platform") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> List[str]:
    """Donen degerler DUZ METIN -- SADECE olusturma aninda kullaniciya bir
    kez gosterilir, DB'ye sadece hash'leri yazilir (bkz. hash_recovery_codes)."""
    codes = [secrets.token_hex(5) for _ in range(count)]
    for code in codes:
        register_secret(code)
    return codes


def hash_recovery_codes(codes: List[str]) -> List[str]:
    return [hash_password(code) for code in codes]


def verify_and_consume_recovery_code(raw_code: str, code_hashes: List[str]) -> Optional[int]:
    """Eslesirse hash listesindeki INDEKSI doner (cagiran taraf o indeksi
    listeden cikarip DB'yi guncellemeli -- tek kullanimlik)."""
    for i, h in enumerate(code_hashes):
        if verify_password(raw_code, h):
            return i
    return None


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
