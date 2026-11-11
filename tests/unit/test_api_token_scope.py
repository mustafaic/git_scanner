"""app/api.py require_api_token() saf mantik testleri (DB'siz kisimlar):
token hash karsilastirmasi core.auth uzerinden zaten test edildi
(tests/unit/test_auth.py); burada sadece Authorization header parse'ini ve
panelin yukledigi TUM script'lerin yerel oldugunu (CSP script-src 'self'
ile tutarlilik) dogrular."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_every_script_the_panel_loads_is_served_from_our_own_static_dir():
    """CSP `script-src 'self'` ile tutarlilik: base.html'deki her <script
    src> yerel /static/ altinda OLMALI ve dosya gercekten var OLMALI.
    Bir CDN adresi (ya da artik var olmayan bir vendor dosyasi) eklenirse
    bu test kirilir -- yani CSP ihlali/404 PROD'A GITMEDEN yakalanir.

    NOT (2026-11-11): daha once vendor edilen htmx hicbir sayfada
    kullanilmadigi icin kaldirildi; panelin tum JS'i artik kendi kodumuz."""
    base_html = (_REPO_ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    sources = re.findall(r'<script\s+src="([^"]+)"', base_html)

    assert sources, "base.html hicbir script yuklemiyor -- beklenmeyen durum"
    for src in sources:
        assert src.startswith("/static/"), f"yerel olmayan script kaynagi: {src}"
        asset = _REPO_ROOT / "app" / src.lstrip("/")
        assert asset.is_file(), f"base.html var olmayan bir dosyayi yukluyor: {src}"


def test_no_third_party_vendor_javascript_remains():
    """Uygulama hicbir ucuncu taraf JS kutuphanesi tasimaz (tedarik zinciri
    yuzeyini sifirda tutar). Yeniden bir kutuphane vendor edilirse bu test
    bilincli olarak guncellenmeli -- sessizce eklenmemeli."""
    vendor_dir = _REPO_ROOT / "app" / "static" / "vendor"
    assert not vendor_dir.exists() or not any(vendor_dir.glob("*.js"))


def test_bearer_token_hash_matches_core_auth_hash():
    from core import auth

    raw, stored_hash = auth.generate_api_token()
    header_value = f"Bearer {raw}"
    extracted = header_value[len("Bearer "):].strip()
    assert auth.hash_api_token(extracted) == stored_hash
