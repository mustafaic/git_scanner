"""DB'ye dokunan auth islemleri (core/auth.py SAF kripto/politika katmanidir,
bu modul onu User/Session modelleriyle birlestirir). Sadece `app` servisi
kullanir (master_prompt.md 3.4: app GitHub key'i gormez; simetrik olarak
orchestrator da kullanici/sifre/TOTP gormez)."""

from __future__ import annotations

import datetime as dt
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from core import auth
from core.models import AuditLog, Session as SessionModel, User

SESSION_TTL_SECONDS = 8 * 3600
SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60


def get_user_by_username(db: DbSession, username: str) -> Optional[User]:
    return db.execute(select(User).where(User.username == username)).scalar_one_or_none()


def record_audit(
    db: DbSession, actor_user: Optional[User], action: str,
    target_type: Optional[str] = None, target_id: Optional[str] = None, detail: Optional[dict] = None,
) -> None:
    """master_prompt.md 5: "giris, durum degisikligi, ... export" audit'lenir."""
    db.add(
        AuditLog(
            actor_user_id=actor_user.id if actor_user else None,
            actor_username=actor_user.username if actor_user else None,
            action=action, target_type=target_type, target_id=target_id, detail=detail,
        )
    )


def authenticate(db: DbSession, username: str, password: str, totp_code: Optional[str]) -> Tuple[Optional[User], Optional[str]]:
    """Donen: (user_or_None, hata_kodu_or_None). Basarisizsa user HER ZAMAN
    None'dir (kullanici var/yok bilgisi disariya sizdirilmaz)."""
    user = get_user_by_username(db, username)
    if user is None or not user.is_active:
        return None, "invalid_credentials"

    lockout = auth.check_lockout(user.locked_until)
    if not lockout.allowed:
        return None, "account_locked"

    if not auth.verify_password(password, user.password_hash):
        user.failed_login_attempts, user.locked_until = auth.compute_lockout_after_failure(user.failed_login_attempts)
        record_audit(db, user, "login_failed", "user", str(user.id))
        return None, "invalid_credentials"

    if user.totp_enabled:
        if not totp_code:
            return None, "totp_required"
        totp_ok = auth.verify_totp(user.totp_secret, totp_code)
        if not totp_ok:
            # Kurtarma kodu olabilir.
            idx = auth.verify_and_consume_recovery_code(totp_code, user.recovery_code_hashes)
            if idx is None:
                user.failed_login_attempts, user.locked_until = auth.compute_lockout_after_failure(user.failed_login_attempts)
                record_audit(db, user, "login_failed_totp", "user", str(user.id))
                return None, "invalid_totp"
            remaining = list(user.recovery_code_hashes)
            del remaining[idx]
            user.recovery_code_hashes = remaining
            record_audit(db, user, "login_recovery_code_used", "user", str(user.id))
    elif user.role == "admin":
        # master_prompt.md 5: "Admin icin TOTP (2FA) zorunlu".
        return None, "totp_setup_required"

    user.failed_login_attempts = 0
    user.locked_until = None
    record_audit(db, user, "login_success", "user", str(user.id))
    return user, None


def create_session(db: DbSession, user: User) -> str:
    token = auth.generate_session_token()
    now = dt.datetime.now(dt.timezone.utc)
    db.add(
        SessionModel(
            id=token, user_id=user.id, created_at=now, last_seen_at=now,
            expires_at=now + dt.timedelta(seconds=SESSION_TTL_SECONDS),
        )
    )
    return token


def get_session_user(db: DbSession, session_token: Optional[str]) -> Optional[User]:
    """Gecerliyse oturumun last_seen_at'ini guncelleyip kullaniciyi doner.
    master_prompt.md 5: "bosta zaman asimi"."""
    if not session_token:
        return None
    sess = db.get(SessionModel, session_token)
    now = dt.datetime.now(dt.timezone.utc)
    if sess is None or sess.revoked_at is not None or sess.expires_at < now:
        return None
    if (now - sess.last_seen_at).total_seconds() > SESSION_IDLE_TIMEOUT_SECONDS:
        sess.revoked_at = now
        return None
    sess.last_seen_at = now
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        return None
    return user


def revoke_session(db: DbSession, session_token: str) -> None:
    sess = db.get(SessionModel, session_token)
    if sess is not None:
        sess.revoked_at = dt.datetime.now(dt.timezone.utc)
