import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core import auth  # noqa: E402


def test_password_hash_and_verify_roundtrip():
    h = auth.hash_password("S3cur3Passw0rd!123")
    assert auth.verify_password("S3cur3Passw0rd!123", h) is True
    assert auth.verify_password("wrong-password", h) is False


def test_password_hash_never_contains_plaintext():
    pw = "S3cur3Passw0rd!123"
    h = auth.hash_password(pw)
    assert pw not in h


def test_password_policy_rejects_short_password():
    ok, reason = auth.check_password_policy("Ab1!")
    assert ok is False
    assert "karakter" in reason


def test_password_policy_rejects_low_complexity():
    ok, reason = auth.check_password_policy("aaaaaaaaaaaa")  # 12+ char ama tek sinif
    assert ok is False


def test_password_policy_accepts_strong_password():
    ok, reason = auth.check_password_policy("Str0ng!Passw0rd#2026")
    assert ok is True
    assert reason is None


def test_generate_session_token_is_random_and_long():
    t1 = auth.generate_session_token()
    t2 = auth.generate_session_token()
    assert t1 != t2
    assert len(t1) >= 32


def test_api_token_generation_and_hash_verification():
    raw, token_hash = auth.generate_api_token()
    assert raw.startswith("sptk_")
    assert auth.hash_api_token(raw) == token_hash
    assert raw not in token_hash


def test_lockout_not_locked_when_none():
    result = auth.check_lockout(None)
    assert result.allowed is True


def test_lockout_locked_when_future():
    import datetime as dt

    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    result = auth.check_lockout(future)
    assert result.allowed is False
    assert result.reason == "account_locked"


def test_lockout_allowed_when_past():
    import datetime as dt

    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    result = auth.check_lockout(past)
    assert result.allowed is True


def test_compute_lockout_after_failure_increments_without_locking():
    count, locked_until = auth.compute_lockout_after_failure(0)
    assert count == 1
    assert locked_until is None


def test_compute_lockout_after_failure_locks_at_threshold():
    count, locked_until = auth.compute_lockout_after_failure(auth.MAX_FAILED_LOGIN_ATTEMPTS - 1)
    assert count == auth.MAX_FAILED_LOGIN_ATTEMPTS
    assert locked_until is not None
