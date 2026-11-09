"""core/backup_crypto.py + tools/backup.py,restore.py URL donusumu testleri
(master_prompt.md 5 "Yedekler sifreli") -- DB gerektirmez."""

import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.backup_crypto import decrypt_bytes, encrypt_bytes, load_fernet_key  # noqa: E402
from tools.backup import _pg_dump_uri  # noqa: E402
from tools.restore import _pg_restore_uri  # noqa: E402


def test_encrypt_decrypt_roundtrip():
    key = Fernet.generate_key()
    data = b"-- fake pg_dump bytes --"
    encrypted = encrypt_bytes(data, key)
    assert encrypted != data
    assert decrypt_bytes(encrypted, key) == data


def test_decrypt_with_wrong_key_raises_invalid_token():
    key1 = Fernet.generate_key()
    key2 = Fernet.generate_key()
    encrypted = encrypt_bytes(b"secret-dump-content", key1)
    with pytest.raises(InvalidToken):
        decrypt_bytes(encrypted, key2)


def test_load_fernet_key_strips_whitespace(tmp_path):
    key = Fernet.generate_key()
    key_file = tmp_path / "key.txt"
    key_file.write_bytes(key + b"\n")
    loaded = load_fernet_key(str(key_file))
    assert loaded == key
    # Yuklenen anahtar GERCEKTEN kullanilabilir olmali (whitespace kirpilmis).
    Fernet(loaded)


def test_pg_dump_uri_strips_sqlalchemy_driver_suffix():
    assert _pg_dump_uri("postgresql+psycopg://user:pass@host:5432/db") == "postgresql://user:pass@host:5432/db"


def test_pg_restore_uri_strips_sqlalchemy_driver_suffix():
    assert _pg_restore_uri("postgresql+psycopg://user:pass@host:5432/db") == "postgresql://user:pass@host:5432/db"
