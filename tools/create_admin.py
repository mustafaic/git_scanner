#!/usr/bin/env python3
"""Ilk admin hesabini (veya parola/TOTP sifirlamayi) sunucuda CLI ile
olusturur (master_prompt.md 5: "Ilk admin sunucuda CLI ile olusturulur;
admin parolasi unutulursa yine sunucuda CLI ile sifirlanir").

Kullanim (app container'i icinde):
    python tools/create_admin.py --username admin --role admin
    python tools/create_admin.py --username admin --reset-password
    python tools/create_admin.py --username admin --reset-totp

Parola TERMINALDE interaktif olarak (getpass ile) istenir -- ASLA komut
satiri argumani olarak VERILMEZ (process listesinde gorunur)."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import auth  # noqa: E402
from core.config import load_settings  # noqa: E402
from core.db import init_engine, session_scope  # noqa: E402
from core.models import User  # noqa: E402


def _prompt_password() -> str:
    while True:
        pw1 = getpass.getpass("Parola: ")
        ok, reason = auth.check_password_policy(pw1)
        if not ok:
            print(f"Gecersiz parola: {reason}", file=sys.stderr)
            continue
        pw2 = getpass.getpass("Parola (tekrar): ")
        if pw1 != pw2:
            print("Parolalar eslesmedi, tekrar deneyin.", file=sys.stderr)
            continue
        return pw1


def _prompt_totp_verification(secret: str, username: str) -> None:
    """Admin'in authenticate() akisinda kilitlenmemesi icin (totp_enabled
    False iken giris HER ZAMAN reddedilir, bkz. app/auth_service.py),
    TOTP burada -- CLI'da, ilk kurulum aninda -- dogrulanir."""
    print(f"TOTP sirri: {secret}")
    print(f"Provisioning URI (QR kod uretmek icin, ör. qrencode ile): {auth.totp_provisioning_uri(secret, username)}")
    while True:
        code = input("TOTP uygulamanizdaki GUNCEL 6 haneli kodu girin (dogrulamak icin): ").strip()
        if auth.verify_totp(secret, code):
            print("TOTP dogrulandi.")
            return
        print("Kod hatali/suresi gecmis, tekrar deneyin.", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", choices=["admin", "viewer"], default="admin")
    parser.add_argument("--reset-password", action="store_true", help="Mevcut kullanicinin parolasini sifirla")
    parser.add_argument("--reset-totp", action="store_true", help="Mevcut kullanicinin TOTP'sini sifirla (yeni QR gosterilir)")
    args = parser.parse_args()

    settings = load_settings()
    init_engine(settings.database_url)

    with session_scope() as session:
        from sqlalchemy import select

        existing = session.execute(select(User).where(User.username == args.username)).scalar_one_or_none()

        if args.reset_password:
            if existing is None:
                print(f"Kullanici bulunamadi: {args.username}", file=sys.stderr)
                return 1
            password = _prompt_password()
            existing.password_hash = auth.hash_password(password)
            existing.failed_login_attempts = 0
            existing.locked_until = None
            print(f"'{args.username}' parolasi sifirlandi.")
            return 0

        if args.reset_totp:
            if existing is None:
                print(f"Kullanici bulunamadi: {args.username}", file=sys.stderr)
                return 1
            secret = auth.generate_totp_secret()
            _prompt_totp_verification(secret, args.username)
            existing.totp_secret = secret
            existing.totp_enabled = True
            codes = auth.generate_recovery_codes()
            existing.recovery_code_hashes = auth.hash_recovery_codes(codes)
            print("Kurtarma kodlari (SADECE SIMDI gosteriliyor, guvenli bir yerde saklayin):")
            for code in codes:
                print(f"  {code}")
            return 0

        if existing is not None:
            print(f"Kullanici zaten mevcut: {args.username}", file=sys.stderr)
            return 1

        password = _prompt_password()
        user = User(username=args.username, password_hash=auth.hash_password(password), role=args.role)

        if args.role == "admin":
            # master_prompt.md 5: Admin icin TOTP ZORUNLU -- CLI'da HEMEN
            # dogrulanir (aksi halde authenticate() admin'i hic icine almaz).
            secret = auth.generate_totp_secret()
            _prompt_totp_verification(secret, args.username)
            user.totp_secret = secret
            user.totp_enabled = True
            codes = auth.generate_recovery_codes()
            user.recovery_code_hashes = auth.hash_recovery_codes(codes)
            session.add(user)
            session.flush()
            print(f"Admin olusturuldu: {args.username}")
            print("Kurtarma kodlari (SADECE SIMDI gosteriliyor, guvenli bir yerde saklayin):")
            for code in codes:
                print(f"  {code}")
        else:
            session.add(user)
            print(f"Viewer olusturuldu: {args.username}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
