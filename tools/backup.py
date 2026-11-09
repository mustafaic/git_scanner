#!/usr/bin/env python3
"""Sifreli gunluk yedek (master_prompt.md 5: "Yedekler sifreli ve sunucu
disinda"). `pg_dump --format=custom` ile dump alinir, Fernet ile
sifrelenir, `backup_dir`'e zaman damgali dosya olarak yazilir, retention
politikasina gore eski yedekler silinir.

Kullanim (orchestrator container'i icinde):
    python tools/backup.py
    python tools/backup.py --retention-days 30

NOT: Bu script DATABASE_URL'in gosterdigi veritabanini OKUR (dump alir),
hicbir sekilde YAZMAZ/DEGISTIRMEZ -- restore icin bkz. tools/restore.py."""

from __future__ import annotations

import argparse
import datetime as dt
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.backup_crypto import encrypt_bytes, load_fernet_key  # noqa: E402
from core.config import load_settings  # noqa: E402

BACKUP_FILENAME_PATTERN = "scanner_backup_%Y%m%dT%H%M%SZ.sql.enc"


def _pg_dump_uri(database_url: str) -> str:
    """SQLAlchemy stili `postgresql+psycopg://` URL'ini pg_dump'in
    anladigi `postgresql://` seklinde yeniden yazar (surucu adi pg_dump
    icin anlamsiz, sadece SQLAlchemy'nin dialect secimi icin var)."""
    parts = urlsplit(database_url)
    scheme = parts.scheme.split("+")[0]
    return f"{scheme}://{parts.netloc}{parts.path}"


def run_pg_dump(database_url: str) -> bytes:
    uri = _pg_dump_uri(database_url)
    result = subprocess.run(
        ["pg_dump", "--format=custom", "--no-owner", "--no-privileges", uri],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pg_dump basarisiz (exit={result.returncode}): {result.stderr.decode(errors='replace')}")
    return result.stdout


def apply_retention(backup_dir: Path, retention_days: int) -> int:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=retention_days)
    deleted = 0
    for path in backup_dir.glob("scanner_backup_*.sql.enc"):
        mtime = dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)
        if mtime < cutoff:
            path.unlink()
            deleted += 1
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--retention-days", type=int, default=None)
    args = parser.parse_args()

    settings = load_settings()
    if not settings.backup_encryption_key_path:
        print("HATA: BACKUP_ENCRYPTION_KEY_PATH ayarlanmamis -- sifresiz yedek alinmaz.", file=sys.stderr)
        return 1

    key = load_fernet_key(settings.backup_encryption_key_path)
    backup_dir = Path(settings.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    print("pg_dump calistiriliyor...")
    dump_bytes = run_pg_dump(settings.database_url)
    print(f"Dump alindi: {len(dump_bytes)} bayt. Sifreleniyor...")
    encrypted = encrypt_bytes(dump_bytes, key)

    filename = dt.datetime.now(dt.timezone.utc).strftime(BACKUP_FILENAME_PATTERN)
    out_path = backup_dir / filename
    out_path.write_bytes(encrypted)
    print(f"Yedek yazildi: {out_path} ({len(encrypted)} bayt, sifreli).")

    retention_days = args.retention_days if args.retention_days is not None else settings.backup_retention_days
    deleted = apply_retention(backup_dir, retention_days)
    if deleted:
        print(f"Retention: {deleted} eski yedek silindi (>{retention_days} gun).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
