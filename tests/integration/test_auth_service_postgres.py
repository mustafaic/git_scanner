"""app/auth_service.py testleri -- gercek Postgres gerektirir."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.auth_service import authenticate, create_session, get_session_user, revoke_session  # noqa: E402
from core import auth  # noqa: E402
from core.models import AuditLog, User  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_log"))
        conn.execute(text("DELETE FROM sessions"))
        conn.execute(text("DELETE FROM users"))
    yield


def _make_admin(session, username="admin", password="Str0ng!Passw0rd#2026", totp_enabled=True):
    secret = auth.generate_totp_secret() if totp_enabled else None
    user = User(
        username=username, password_hash=auth.hash_password(password), role="admin",
        totp_secret=secret, totp_enabled=totp_enabled,
    )
    session.add(user)
    session.flush()
    return user, secret


def test_authenticate_success_with_correct_password_and_totp(engine):
    import pyotp

    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        user, secret = _make_admin(session)
        session.commit()
        user_id = user.id

    with session_factory() as session:
        code = pyotp.TOTP(secret).now()
        result_user, error = authenticate(session, "admin", "Str0ng!Passw0rd#2026", code)
        session.commit()
    assert error is None
    assert result_user is not None
    assert result_user.id == user_id


def test_authenticate_fails_with_wrong_password_no_user_leak(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_admin(session)
        session.commit()

    with session_factory() as session:
        user, error = authenticate(session, "admin", "wrong-password", "123456")
        session.commit()
    assert user is None
    assert error == "invalid_credentials"


def test_authenticate_unknown_username_same_error_as_wrong_password(engine):
    """Kullanici var/yok bilgisi SIZDIRILMAMALI (enumeration onlenir)."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        user, error = authenticate(session, "ghost-user", "whatever", None)
        session.commit()
    assert user is None
    assert error == "invalid_credentials"


def test_authenticate_admin_without_totp_setup_is_rejected(engine):
    """master_prompt.md 5: Admin icin TOTP ZORUNLU."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_admin(session, totp_enabled=False)
        session.commit()

    with session_factory() as session:
        user, error = authenticate(session, "admin", "Str0ng!Passw0rd#2026", None)
        session.commit()
    assert user is None
    assert error == "totp_setup_required"


def test_authenticate_locks_account_after_max_failed_attempts(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_admin(session)
        session.commit()

    for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
        with session_factory() as session:
            authenticate(session, "admin", "wrong-password", None)
            session.commit()

    with session_factory() as session:
        user, error = authenticate(session, "admin", "Str0ng!Passw0rd#2026", "123456")
        session.commit()
    assert user is None
    assert error == "account_locked"


def test_authenticate_logs_audit_entries(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_admin(session)
        session.commit()
    with session_factory() as session:
        authenticate(session, "admin", "wrong-password", None)
        session.commit()
    with session_factory() as session:
        entry = session.query(AuditLog).filter_by(action="login_failed").one()
        assert entry.actor_username == "admin"


def test_session_create_and_validate_roundtrip(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        user, _ = _make_admin(session)
        token = create_session(session, user)
        session.commit()

    with session_factory() as session:
        validated = get_session_user(session, token)
        session.commit()
    assert validated is not None
    assert validated.username == "admin"


def test_session_invalid_token_returns_none(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        assert get_session_user(session, "not-a-real-token") is None


def test_revoked_session_is_rejected(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        user, _ = _make_admin(session)
        token = create_session(session, user)
        session.commit()

    with session_factory() as session:
        revoke_session(session, token)
        session.commit()

    with session_factory() as session:
        assert get_session_user(session, token) is None
