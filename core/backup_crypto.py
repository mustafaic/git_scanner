"""Yedek sifreleme (master_prompt.md 5: "Yedekler sifreli (örn. age/gpg) ve
sunucu dısında"). Fernet (AES-128-CBC + HMAC-SHA256, `cryptography`
kutuphanesi -- zaten PyJWT[crypto] uzerinden kurulu, yeni bagimlilik
EKLENMEDI) kullanilir; "age/gpg" sadece ORNEK, gereksinim semboldeki arac
degil "sifreli ve guvenli anahtar yonetimi" ozelligidir.

BILINEN SINIRLAMA (bkz. docs/LIMITATIONS.md): Fernet TUM veriyi TEK bir
token icinde sifreler (streaming/chunked degil) -- cok buyuk (GB'larca)
dump'larda bellek kullanimi artar. Bu projenin olcegi icin (bkz. PERF.md)
sorun degil; gercekten buyuk bir veritabaninda chunked sifreleme (ör.
AES-GCM + dosya bazli parcalama) degerlendirilmeli.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["Fernet", "InvalidToken", "load_fernet_key", "encrypt_bytes", "decrypt_bytes"]


def load_fernet_key(key_path: str) -> bytes:
    """Docker secret/dosyadan okur (ayni desen: github_app_private_key_path).
    Anahtar DUZ METIN olarak ENV'DE TUTULMAZ, sadece dosya yolu config'te."""
    raw = Path(key_path).read_bytes().strip()
    return raw


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)
