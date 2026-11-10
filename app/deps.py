"""FastAPI dependency'leri: DB oturumu, oturum-cerezi tabanli kimlik
dogrulama, RBAC, Jinja2 template ortami (master_prompt.md 5 "Uygulama
guvenligi"). `app` servisi GitHub key'ini gormez, hicbir orchestrator
modulune import BAGIMLILIGI yoktur (sadece core.* ve kendi modelleri)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Iterator, Optional

from fastapi import Depends, HTTPException, Request, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.auth_service import get_session_user
from app.csrf import ensure_csrf_token, set_csrf_cookie
from core.config import load_settings
from core.db import session_scope
from core.lockfile_parser import display_vulnerability_id
from core.models import Repository, User

SESSION_COOKIE_NAME = "session_id"

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["cve_id"] = display_vulnerability_id


def severity_badge(score: object) -> Markup:
    """CVSS skorunu renkli bir rozete cevirir (Critical/High/Medium/Low) --
    UI'da duz metin yerine tek bakista siddeti gosterir. Skor yoksa (None)
    notr bir "-" doner."""
    if score is None or score == "":
        return Markup('<span class="muted">-</span>')
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return Markup(f'<span class="muted">{escape(score)}</span>')
    if numeric >= 9.0:
        css_class, label = "sev-critical", "Critical"
    elif numeric >= 7.0:
        css_class, label = "sev-high", "High"
    elif numeric >= 4.0:
        css_class, label = "sev-medium", "Medium"
    else:
        css_class, label = "sev-low", "Low"
    formatted = f"{numeric:g}"
    return Markup(f'<span class="badge {css_class}" title="{label} ({formatted})">{formatted}</span>')


templates.env.filters["severity_badge"] = severity_badge

# Gelistirici-dostu yama durumu etiketleri (core.models.Finding.fix_status
# CheckConstraint ile birebir ayni altı deger). Amac: ham enum string'i
# yerine "patch var mi / henuz yayinlanmadi mi / bilinmiyor mu" sorusuna
# tek bakista cevap vermek -- bkz. plan "Faz 3: Triyaj netligi".
_FIX_STATUS_STYLE: dict[str, tuple[str, str, str]] = {
    "PATCH_AVAILABLE": ("badge-success", "✅", "Yama mevcut"),
    "NO_FIX_YET": ("badge-warning", "⚠️", "Henüz resmi yama yok"),
    "FIX_UNKNOWN": ("badge-neutral", "❓", "Yama durumu bilinmiyor"),
    "WONT_FIX": ("badge-neutral", "🚫", "Yayıncı düzeltmeyecek"),
    "CONSTRAINT_BLOCKED": ("badge-warning", "🔒", "Üst sürüm kısıtlaması"),
    "WORKAROUND": ("badge-warning", "🛠️", "Geçici çözüm var"),
}
_FIX_STATUS_TOOLTIP: dict[str, str] = {
    "PATCH_AVAILABLE": "Bu bileşen için düzeltilmiş bir sürüm yayınlanmış.",
    "NO_FIX_YET": "Yayıncı/topluluk henüz bir düzeltme yayınlamadı -- şu an güncellenecek bir sürüm yok. İzlemeye devam edin, varsa geçici bir önlem uygulayın.",
    "FIX_UNKNOWN": "Düzeltme bilgisi güvenilir şekilde belirlenemedi (ekosistem veya sürüm formatı desteklenmiyor olabilir).",
    "WONT_FIX": "Yayıncı bu zafiyeti düzeltmeyeceğini belirtmiş.",
    "CONSTRAINT_BLOCKED": "Düzeltilmiş sürüm var ama mevcut sürüm kısıtlamaları (ör. major sürüm atlaması) nedeniyle otomatik önerilemiyor.",
    "WORKAROUND": "Resmi bir yama yok ama bilinen bir geçici çözüm (workaround) var.",
}


def fix_status_label(status: object, fix_version: object = None) -> Markup:
    """fix_status enum'unu (core.models.Finding.fix_status) gelistirici icin
    anlamli, tooltip'li bir rozete cevirir. "NO_FIX_YET" ile "FIX_UNKNOWN"
    bilerek farkli renk/metinle gosterilir -- biri "henuz yayinlanmadi",
    digeri "biz bilmiyoruz" demek, ikisi ayni sey degil."""
    if not status:
        return Markup('<span class="muted">-</span>')
    key = str(status)
    css_class, icon, label = _FIX_STATUS_STYLE.get(key, ("badge-neutral", "❓", key))
    tooltip = _FIX_STATUS_TOOLTIP.get(key, "")
    text = label
    if key == "PATCH_AVAILABLE" and fix_version:
        text = f"{label}: {escape(fix_version)} sürümüne güncelleyin"
    return Markup(f'<span class="badge {css_class}" title="{escape(tooltip)}">{icon} {text}</span>')


templates.env.filters["fix_status_label"] = fix_status_label

# EPSS (Exploit Prediction Scoring System): bir CVE'nin onumuzdeki 30 gunde
# gercekten istismar edilme olasiligi tahmini. DB'de zaten toplanıyordu
# (core.models.Finding.epss_score) ama panelde hic gosterilmiyordu --
# KEV (zaten sömürülüyor) ile EPSS (sömürülme olasılığı) birlikte,
# CVSS'in (teorik şiddet) yanına, "gerçekten önemli mi" sorusuna somut bir
# sinyal daha ekliyor.
def epss_badge(score: object) -> Markup:
    if score is None or score == "":
        return Markup("")
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return Markup("")
    if numeric >= 0.10:
        css_class, label = "badge-danger", "Yüksek istismar olasılığı"
    elif numeric >= 0.01:
        css_class, label = "badge-warning", "Orta istismar olasılığı"
    else:
        css_class, label = "badge-neutral", "Düşük istismar olasılığı"
    pct = numeric * 100
    tooltip = "EPSS: önümüzdeki 30 gün içinde gerçekten istismar edilme olasılığı tahmini (first.org)."
    return Markup(f'<span class="badge {css_class}" title="{escape(tooltip)}">{label} (%{pct:.1f})</span>')


templates.env.filters["epss_badge"] = epss_badge


def timestamp(value: object) -> Markup:
    """Tarih/saat gosterimi: `2026-11-11 18:08:58`.

    Kullanici karari (2026-11-11): mikrosaniye ve saat dilimi eki
    GOSTERILMEZ -- `2026-11-11 18:08:58.390890+00:00` gibi bir deger
    tablolarda gereksiz yer kapliyor ve okumayi zorlastiriyordu. Degerler
    DB'de saat dilimi bilgili (UTC) tutulmaya DEVAM eder; kayip yasanmasin
    diye tam ISO deger `title` attribute'unda korunur (uzerine gelince
    gorunur) -- audit/denetim icin hassasiyet kaybolmaz.
    """
    if value is None or value == "":
        return Markup('<span class="muted">-</span>')
    if isinstance(value, dt.datetime):
        short, full = value.strftime("%Y-%m-%d %H:%M:%S"), value.isoformat()
    elif isinstance(value, dt.date):
        short, full = value.strftime("%Y-%m-%d"), value.isoformat()
    else:
        # Beklenmeyen bir tip (ör. zaten string'e cevrilmis bir deger) --
        # sessizce bozmak yerine oldugu gibi, escape edilerek gosterilir.
        return Markup(f'<span class="ts">{escape(str(value))}</span>')
    return Markup(f'<span class="ts" title="{escape(full)}">{escape(short)}</span>')


templates.env.filters["ts"] = timestamp

_settings = load_settings()


def get_db() -> Iterator[DbSession]:
    with session_scope() as session:
        yield session


def get_current_user(request: Request, db: DbSession = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    return get_session_user(db, token)


def require_user(user: Optional[User] = Depends(get_current_user)) -> User:
    """Girisi zorunlu kilar. 401 -- app/main.py'deki exception handler
    HTML isteklerinde /login'e yonlendirir, API/JSON isteklerinde duz 401
    doner."""
    if user is None:
        raise HTTPException(status_code=401, detail="login_required")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """master_prompt.md 5 RBAC: durum degisikligi/token/secret rotasyonu
    gibi islemler SADECE admin'e acik."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin_required")
    return user


def get_repo_names(db: DbSession, repo_ids: list[int]) -> dict[int, str]:
    if not repo_ids:
        return {}
    rows = db.execute(
        select(Repository.github_repo_id, Repository.full_name).where(Repository.github_repo_id.in_(repo_ids))
    ).all()
    return {row[0]: row[1] for row in rows}


def render_page(
    request: Request, name: str, context: dict, *, user: Optional[User] = None, status_code: int = 200
) -> Response:
    """Her HTML sayfasi icin ortak render yolu: csrf cookie/token'i
    garanti eder (base.html'deki logout formu dahil HER form bunu
    kullanir) ve `user`'i context'e ekler (nav/RBAC gorunurlugu icin)."""
    csrf_token, is_new = ensure_csrf_token(request)
    full_context = {"user": user, "csrf_token": csrf_token, **context}
    response = templates.TemplateResponse(request, name, full_context, status_code=status_code)
    if is_new:
        set_csrf_cookie(response, csrf_token, cookie_secure=_settings.session_cookie_secure)
    return response
