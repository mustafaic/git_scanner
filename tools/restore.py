#!/usr/bin/env python3
"""Sifreli yedegi GERI YUKLER (master_prompt.md 5 "restore testi"). Bir
yedek dosyasini cozup `pg_restore` ile HEDEF bir veritabanina yazar.

GUVENLIK (bilinen bir canli veri kaybi olayindan sonra eklendi -- bkz.
deploy/docker-compose.yml postgres-test yorumu): bu script, hedef DB URL'i
CALISMA ORTAMININ KENDI DATABASE_URL'iyle (canli DB) AYNIYSA ACIKCA
REDDEDER -- restore SADECE ayri/izole bir hedefe (ör. postgres-test veya
tek seferlik bir konteyner) yapilabilir, --force ile bile bu kontrol
ATLANAMAZ (kasitli, yanlislikla canli veriyi ezmeyi engellemek icin).

Kullanim:
    python tools/restore.py --backup /backups/scanner_backup_....sql.enc \
        --target-database-url postgresql+psycopg://user:pass@host:5432/restore_test_db
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.backup_crypto import InvalidToken, decrypt_bytes, load_fernet_key  # noqa: E402
from core.config import load_settings  # noqa: E402


def _pg_restore_uri(database_url: str) -> str:
    parts = urlsplit(database_url)
    scheme = parts.scheme.split("+")[0]
    return f"{scheme}://{parts.netloc}{parts.path}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backup", required=True, help="Sifreli yedek dosyasi (.sql.enc)")
    parser.add_argument("--target-database-url", required=True, help="Restore EDILECEK (izole/test) veritabani URL'i")
    args = parser.parse_args()

    settings = load_settings()
    if not settings.backup_encryption_key_path:
        print("HATA: BACKUP_ENCRYPTION_KEY_PATH ayarlanmamis.", file=sys.stderr)
        return 1

    if args.target_database_url == settings.database_url:
        print(
            "HATA: Hedef, calisma ortaminin CANLI DATABASE_URL'iyle AYNI -- "
            "restore SADECE izole bir hedefe yapilabilir (guvenlik kontrolu, atlanamaz).",
            file=sys.stderr,
        )
        return 1

    key = load_fernet_key(settings.backup_encryption_key_path)
    encrypted = Path(args.backup).read_bytes()
    try:
        dump_bytes = decrypt_bytes(encrypted, key)
    except InvalidToken:
        print("HATA: Yedek cozulemedi -- yanlis anahtar veya bozuk dosya.", file=sys.stderr)
        return 1
    print(f"Yedek cozuldu: {len(dump_bytes)} bayt.")

    uri = _pg_restore_uri(args.target_database_url)
    result = subprocess.run(
        ["pg_restore", "--clean", "--if-exists", "--no-owner", "--no-privileges", "--dbname", uri],
        input=dump_bytes, capture_output=True, check=False,
    )
    if result.returncode != 0:
        print(f"HATA: pg_restore basarisiz (exit={result.returncode}): {result.stderr.decode(errors='replace')}", file=sys.stderr)
        return 1
    print(f"Restore tamamlandi -> {args.target_database_url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
