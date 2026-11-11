"""Analiz sayfasi: gelistiricilere/yoneticilere "gercekten onemli ne var"
sorusuna donut/trend/bar grafiklerle ozet cevap. Sadece OKUMA -- yeni bir
tablo/model gerektirmez, mevcut findings/secret_findings/repositories
verisinden agregat sorgularla uretilir (dashboard.py ile ayni desen:
veri DB'den cekilir, agregasyon Python'da yapilir -- bu olcekte SQL'de
karmasik tarih/yuzde aritmetigi yazmaktan daha basit, kural 11).

Grafikler sunucu tarafinda inline SVG olarak render edilir (app/chart_helpers.py
SADECE sayisal geometri uretir); hicbir kullanici-kontrollu metin (repo/paket/
kural adi) ham SVG'ye gömülmez, her zaman normal Jinja auto-escape ile ayri
HTML metin dugumlerinde gosterilir (bkz. docs/THREAT_MODEL.md madde 1)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.chart_helpers import bar_percentages, daily_open_counts, donut_segments, trend_polyline_points
from app.deps import get_db, get_repo_names, render_page, require_user
from core.models import Finding, RepoOwner, SecretFinding, User
from core.settings_store import SLA_DAYS_KEY, get_setting
from core.sla import compute_due_date, is_overdue, merged_sla_days

router = APIRouter()

_OPEN_LIKE = ("OPEN", "IN_PROGRESS", "REOPENED")
_TREND_WINDOW_DAYS = 90
_EPSS_HIGH_THRESHOLD = 0.10  # epss_badge ile ayni esik (app/deps.py)
_TOP_RISKY_REPO_LIMIT = 10
_TOP_ECOSYSTEM_LIMIT = 8
_TOP_SECRET_RULE_LIMIT = 8

# Donut dolgulari EVRENSEL severity tokenlarindan gelir (bkz.
# app/static/css/tokens.css): Low yesil / Medium sari / High turuncu /
# Critical kirmizi -- temadan bagimsiz, uygulamanin her yerinde ayni.
# "none" bir seviye degil, "skor yok" durumu: notr gri.
_SEVERITY_COLORS = {
    "critical": "var(--sev-critical)", "high": "var(--sev-high)",
    "medium": "var(--sev-medium)", "low": "var(--sev-low)", "none": "var(--sev-none)",
}
_SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "none": "Skor yok"}

_FIX_BUCKET_COLORS = {
    "patch_available": "var(--success-text)", "no_fix_yet": "var(--warning-text)",
    "unknown": "var(--neutral-text)", "other": "var(--sev-none)",
}
_FIX_BUCKET_LABELS = {
    "patch_available": "Yama mevcut", "no_fix_yet": "Henüz yama yok",
    "unknown": "Durum bilinmiyor", "other": "Diğer",
}
_FIX_STATUS_TO_BUCKET = {
    "PATCH_AVAILABLE": "patch_available", "NO_FIX_YET": "no_fix_yet", "FIX_UNKNOWN": "unknown",
    "WONT_FIX": "other", "CONSTRAINT_BLOCKED": "other", "WORKAROUND": "other",
}


def _owner_repo_ids(db: DbSession, owner: str) -> list[int]:
    return db.execute(select(RepoOwner.repo_id).where(RepoOwner.owner_identifier == owner)).scalars().all()


def _donut_chart(buckets: dict[str, int], colors: dict[str, str], labels: dict[str, str]) -> dict:
    keys = [k for k in colors if buckets.get(k)]
    values = [buckets[k] for k in keys]
    segments = donut_segments(values)
    rows = [
        {"label": labels[k], "value": v, "pct": seg.pct, "color": colors[k], "dash_array": seg.dash_array, "dash_offset": seg.dash_offset}
        for k, v, seg in zip(keys, values, segments)
    ]
    return {"rows": rows, "total": sum(buckets.values())}


@router.get("/analytics")
def analytics(request: Request, owner: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    finding_query = select(Finding).where(Finding.lifecycle_status.in_(_OPEN_LIKE))
    secret_query = select(SecretFinding).where(SecretFinding.lifecycle_status == "OPEN")
    owner_repo_ids: list[int] | None = None
    if owner:
        owner_repo_ids = _owner_repo_ids(db, owner)
        finding_query = finding_query.where(Finding.repo_id.in_(owner_repo_ids))
        secret_query = secret_query.where(SecretFinding.repo_id.in_(owner_repo_ids))

    open_findings = db.execute(finding_query).scalars().all()
    open_secrets = db.execute(secret_query).scalars().all()

    kev_count = sum(1 for f in open_findings if f.kev)
    epss_high_count = sum(1 for f in open_findings if f.epss_score is not None and float(f.epss_score) >= _EPSS_HIGH_THRESHOLD)

    # --- Siddet + yama durumu donut'lari (ayni open_findings'i yeniden kullanir) ---
    severity_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    fix_buckets = {"patch_available": 0, "no_fix_yet": 0, "unknown": 0, "other": 0}
    for f in open_findings:
        score = float(f.severity_cvss_score) if f.severity_cvss_score is not None else None
        if score is None:
            severity_buckets["none"] += 1
        elif score >= 9.0:
            severity_buckets["critical"] += 1
        elif score >= 7.0:
            severity_buckets["high"] += 1
        elif score >= 4.0:
            severity_buckets["medium"] += 1
        else:
            severity_buckets["low"] += 1
        fix_buckets[_FIX_STATUS_TO_BUCKET.get(f.fix_status, "unknown")] += 1
    severity_donut = _donut_chart(severity_buckets, _SEVERITY_COLORS, _SEVERITY_LABELS)
    fix_donut = _donut_chart(fix_buckets, _FIX_BUCKET_COLORS, _FIX_BUCKET_LABELS)

    # --- SLA performansi: siddet katmani basina zamaninda/gecikmis sayisi ---
    sla_days = merged_sla_days(get_setting(db, SLA_DAYS_KEY))
    sla_on_time = {k: 0 for k in severity_buckets}
    sla_overdue = {k: 0 for k in severity_buckets}
    for f in open_findings:
        score = float(f.severity_cvss_score) if f.severity_cvss_score is not None else None
        bucket = (
            "none" if score is None else "critical" if score >= 9.0 else "high" if score >= 7.0
            else "medium" if score >= 4.0 else "low"
        )
        due = compute_due_date(kev=f.kev, cvss_score=score, first_seen_at=f.first_seen_at, sla_days=sla_days)
        if is_overdue(due):
            sla_overdue[bucket] += 1
        else:
            sla_on_time[bucket] += 1
    sla_rows = []
    for key in ("critical", "high", "medium", "low", "none"):
        total = sla_on_time[key] + sla_overdue[key]
        if total == 0:
            continue
        sla_rows.append({
            "label": _SEVERITY_LABELS[key], "on_time": sla_on_time[key], "overdue": sla_overdue[key],
            "on_time_pct": round(sla_on_time[key] * 100 / total, 1), "overdue_pct": round(sla_overdue[key] * 100 / total, 1),
        })

    # --- 90 gunluk trend (yaklasik -- bkz. chart_helpers.daily_open_counts docstring) ---
    today = dt.datetime.now(dt.timezone.utc).date()
    window_start = today - dt.timedelta(days=_TREND_WINDOW_DAYS - 1)
    sca_hist_query = select(Finding.first_seen_at, Finding.resolved_at)
    secret_hist_query = select(SecretFinding.first_seen_at, SecretFinding.rotated_at)
    if owner_repo_ids is not None:
        sca_hist_query = sca_hist_query.where(Finding.repo_id.in_(owner_repo_ids))
        secret_hist_query = secret_hist_query.where(SecretFinding.repo_id.in_(owner_repo_ids))
    sca_hist_rows = [(fs.date(), ra.date() if ra else None) for fs, ra in db.execute(sca_hist_query).all()]
    secret_hist_rows = [(fs.date(), ra.date() if ra else None) for fs, ra in db.execute(secret_hist_query).all()]
    sca_series = daily_open_counts(sca_hist_rows, window_start, _TREND_WINDOW_DAYS)
    secret_series = daily_open_counts(secret_hist_rows, window_start, _TREND_WINDOW_DAYS)
    trend = {
        "sca_points": trend_polyline_points(sca_series) if sca_series else "",
        "secret_points": trend_polyline_points(secret_series) if secret_series else "",
        "start_label": window_start.isoformat(),
        "mid_label": (window_start + dt.timedelta(days=_TREND_WINDOW_DAYS // 2)).isoformat(),
        "end_label": today.isoformat(),
        "sca_latest": sca_series[-1] if sca_series else 0,
        "secret_latest": secret_series[-1] if secret_series else 0,
        "has_data": bool(sca_hist_rows or secret_hist_rows),
    }

    # --- En riskli repolar (acik critical+high sayisina gore) ---
    risk_query = (
        select(Finding.repo_id, func.count())
        .where(Finding.lifecycle_status.in_(_OPEN_LIKE), or_(Finding.kev.is_(True), Finding.severity_cvss_score >= 7))
        .group_by(Finding.repo_id).order_by(func.count().desc()).limit(_TOP_RISKY_REPO_LIMIT)
    )
    if owner_repo_ids is not None:
        risk_query = risk_query.where(Finding.repo_id.in_(owner_repo_ids))
    risk_rows = db.execute(risk_query).all()
    risk_repo_names = get_repo_names(db, [r[0] for r in risk_rows])
    risk_widths = bar_percentages([r[1] for r in risk_rows])
    top_risky_repos = [
        {"label": risk_repo_names.get(repo_id, str(repo_id)), "count": count, "width_pct": width}
        for (repo_id, count), width in zip(risk_rows, risk_widths)
    ]

    # --- Ekosistem dagilimi ---
    eco_query = (
        select(Finding.ecosystem, func.count()).where(Finding.lifecycle_status.in_(_OPEN_LIKE))
        .group_by(Finding.ecosystem).order_by(func.count().desc()).limit(_TOP_ECOSYSTEM_LIMIT)
    )
    if owner_repo_ids is not None:
        eco_query = eco_query.where(Finding.repo_id.in_(owner_repo_ids))
    eco_rows = db.execute(eco_query).all()
    eco_widths = bar_percentages([r[1] for r in eco_rows])
    ecosystem_dist = [{"label": eco, "count": count, "width_pct": width} for (eco, count), width in zip(eco_rows, eco_widths)]

    # --- Secret kural tipi dagilimi ---
    rule_query = (
        select(SecretFinding.rule_id, func.count()).where(SecretFinding.lifecycle_status == "OPEN")
        .group_by(SecretFinding.rule_id).order_by(func.count().desc()).limit(_TOP_SECRET_RULE_LIMIT)
    )
    if owner_repo_ids is not None:
        rule_query = rule_query.where(SecretFinding.repo_id.in_(owner_repo_ids))
    rule_rows = db.execute(rule_query).all()
    rule_widths = bar_percentages([r[1] for r in rule_rows])
    secret_rule_dist = [{"label": rule, "count": count, "width_pct": width} for (rule, count), width in zip(rule_rows, rule_widths)]

    all_owners = db.execute(select(RepoOwner.owner_identifier).distinct().order_by(RepoOwner.owner_identifier)).scalars().all()

    return render_page(
        request, "analytics.html",
        {
            "kev_count": kev_count, "epss_high_count": epss_high_count,
            "open_findings_count": len(open_findings), "open_secrets_count": len(open_secrets),
            "severity_donut": severity_donut, "fix_donut": fix_donut,
            "sla_rows": sla_rows, "trend": trend,
            "top_risky_repos": top_risky_repos, "ecosystem_dist": ecosystem_dist, "secret_rule_dist": secret_rule_dist,
            "all_owners": all_owners, "owner_filter": owner,
        },
        user=user,
    )
