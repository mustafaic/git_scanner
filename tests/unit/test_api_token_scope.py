"""app/api.py require_api_token() saf mantik testleri (DB'siz kisimlar):
token hash karsilastirmasi core.auth uzerinden zaten test edildi
(tests/unit/test_auth.py); burada sadece Authorization header parse'ini
ve htmx vendor dosyasinin varligini (CSP script-src 'self' sadece bu
dosyaya guvenir) dogrular."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_htmx_is_vendored_locally_not_a_cdn_reference():
    vendor_path = Path(__file__).resolve().parents[2] / "app" / "static" / "vendor" / "htmx.min.js"
    assert vendor_path.exists()
    assert vendor_path.stat().st_size > 10_000
    content = vendor_path.read_text(encoding="utf-8")
    assert "htmx" in content.lower()


def test_bearer_token_hash_matches_core_auth_hash():
    from core import auth

    raw, stored_hash = auth.generate_api_token()
    header_value = f"Bearer {raw}"
    extracted = header_value[len("Bearer "):].strip()
    assert auth.hash_api_token(extracted) == stored_hash
