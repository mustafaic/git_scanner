#!/usr/bin/env python3
"""Ilk admin hesabini (veya parola sifirlamayi) sunucuda CLI ile olusturur
(master_prompt.md 5: "Ilk admin sunucuda CLI ile olusturulur; admin
parolasi unutulursa yine sunucuda CLI ile sifirlanir"). Sonraki admin/
viewer hesaplari panelden (/users) de olusturulabilir -- bu script SADECE
ilk bootstrap (henuz panelde giris yapabilecek hicbir kullanici yokken)
veya parola sifirlama icindir.

Kullanim (app container'i icinde):
    python tools/create_admin.py --username admin --role admin
    python tools/create_admin.py --username admin --reset-password

Parola TERMINALDE interaktif olarak (getpass ile) istenir -- ASLA komut
satiri argumani olarak VERILMEZ (process listesinde gorunur).

NOT: TOTP (2FA) kullanici karariyla KALDIRILDI (2026-11-09, bkz.
docs/ASSUMPTIONS.md #14) -- bu script artik sadece parola yonetir."""

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", choices=["admin", "viewer"], default="admin")
    parser.add_argument("--reset-password", action="store_true", help="Mevcut kullanicinin parolasini sifirla")
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

        if existing is not None:
            print(f"Kullanici zaten mevcut: {args.username}", file=sys.stderr)
            return 1

        password = _prompt_password()
        user = User(username=args.username, password_hash=auth.hash_password(password), role=args.role)
        session.add(user)
        print(f"{args.role.capitalize()} olusturuldu: {args.username}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
