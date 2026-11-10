"""A6 "Bugün" ekranı: aksiyon odaklı giriş sayfası (master_prompt.md 6).
Ozet sayilar + sistem sagligi + "bugun yapilacaklar" listesi (sahip/ekip
filtresi + son ziyaretten beri yeni rozeti). `app` servisi orchestrator
modullerini import ETMEZ (bkz. deploy/Dockerfile.app); heartbeat/kuyruk
durumu burada core.models uzerinden DOGRUDAN okunur, is mantigi
tekrarlanmaz (sadece salt-okunur sorgu)."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.deps import get_db, get_repo_names, render_page, require_user
from core.models import AdvisoryMirrorSync, Repository, RepoOwner, SecretFinding, SystemHeartbeat, User, Finding
from core.settings_store import SLA_DAYS_KEY, get_setting
from core.sla import compute_due_date, is_overdue, merged_sla_days

router = APIRouter()

_OPEN_LIKE = ("OPEN", "IN_PROGRESS", "REOPENED")
_ACTION_LIST_LIMIT = 20


@router.get("/")
def dashboard(
    request: Request, owner: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user),
):
    open_findings = db.execute(
        select(func.count()).select_from(Finding).where(Finding.lifecycle_status.in_(_OPEN_LIKE))
    ).scalar_one()
    kev_findings = db.execute(
        select(func.count()).select_from(Finding).where(Finding.kev.is_(True), Finding.lifecycle_status.in_(_OPEN_LIKE))
    ).scalar_one()
    needs_review = db.execute(
        select(func.count()).select_from(Finding).where(Finding.verification_status == "NEEDS_REVIEW", Finding.lifecycle_status.in_(_OPEN_LIKE))
    ).scalar_one()
    open_secrets = db.execute(
        select(func.count()).select_from(SecretFinding).where(SecretFinding.lifecycle_status == "OPEN")
    ).scalar_one()
    active_repos = db.execute(select(func.count()).select_from(Repository).where(Repository.is_active.is_(True))).scalar_one()

    # A8 SLA (master_prompt.md 6): "gecikenler listesi". due_date saklanan
    # bir kolon DEGIL, ayarlanabilir sla_days'e gore HER ISTEKTE hesaplanir
    # (bkz. core/sla.py) -- acik bulgu sayisi tipik olarak kucuk oldugu
    # icin Python'da filtrelemek SQL'de surum/tarih aritmetigi yazmaktan
    # daha basit (kural 11).
    sla_days = merged_sla_days(get_setting(db, SLA_DAYS_KEY))
    open_finding_rows = db.execute(
        select(Finding.kev, Finding.severity_cvss_score, Finding.first_seen_at)
        .where(Finding.lifecycle_status.in_(_OPEN_LIKE))
    ).all()
    overdue_findings = sum(
        1 for kev, cvss, first_seen_at in open_finding_rows
        if is_overdue(compute_due_date(
            kev=kev, cvss_score=float(cvss) if cvss is not None else None, first_seen_at=first_seen_at, sla_days=sla_days,
        ))
    )

    # Siddet dagilimi (UI: ozet cubuk grafigi) -- ayrica bir sorgu ACMAZ,
    # yukarida zaten cekilmis open_finding_rows'u yeniden kullanir.
    severity_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for _kev, cvss, _first_seen in open_finding_rows:
        score = float(cvss) if cvss is not None else None
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
    severity_total = len(open_finding_rows) or 1
    severity_pct = {k: round(v * 100 / severity_total, 1) for k, v in severity_buckets.items()}

    now = dt.datetime.now(dt.timezone.utc)
    heartbeats = db.execute(select(SystemHeartbeat)).scalars().all()
    heartbeat_rows = [
        {"component": h.component, "age_seconds": int((now - h.last_success_at).total_seconds())} for h in heartbeats
    ]

    mirror_rows = db.execute(
        select(AdvisoryMirrorSync.source, func.max(AdvisoryMirrorSync.synced_at)).where(AdvisoryMirrorSync.succeeded.is_(True)).group_by(AdvisoryMirrorSync.source)
    ).all()
    mirror_sync_rows = [{"source": r[0], "age_seconds": int((now - r[1]).total_seconds())} for r in mirror_rows]

    # A6 "Bugun" aksiyon listesi: ayni onceliklendirme master_prompt.md 4.6
    # ile AYNI (KEV > CVSS > yas). Sahip/ekip filtresi (A5, repo_owners)
    # secilirse sadece o sahibin repolarindaki bulgular gosterilir.
    previous_visit = user.last_dashboard_visit_at  # GUNCELLEMEDEN ONCE yakala
    action_query = select(Finding).where(Finding.lifecycle_status.in_(_OPEN_LIKE))
    if owner:
        owner_repo_ids = db.execute(
            select(RepoOwner.repo_id).where(RepoOwner.owner_identifier == owner)
        ).scalars().all()
        action_query = action_query.where(Finding.repo_id.in_(owner_repo_ids))
    action_query = action_query.order_by(
        Finding.kev.desc(), Finding.severity_cvss_score.desc().nullslast(), Finding.first_seen_at.desc()
    ).limit(_ACTION_LIST_LIMIT)
    action_findings = db.execute(action_query).scalars().all()
    action_repo_names = get_repo_names(db, [f.repo_id for f in action_findings])

    # Baseline bulgular zaten "yeni" sayilmaz (ayri bir kural degil --
    # first_seen_at ilk basarili taramada yazilir, baseline'da da ayni
    # sekilde set edilir; burada SADECE "son ziyaretten SONRA" kontrol edilir).
    new_ids = (
        {f.id for f in action_findings if previous_visit is not None and f.first_seen_at > previous_visit}
        if previous_visit is not None else set()
    )

    all_owners = db.execute(select(RepoOwner.owner_identifier).distinct().order_by(RepoOwner.owner_identifier)).scalars().all()

    user.last_dashboard_visit_at = now

    return render_page(
        request, "dashboard.html",
        {
            "open_findings": open_findings, "kev_findings": kev_findings, "needs_review": needs_review,
            "open_secrets": open_secrets, "active_repos": active_repos,
            "overdue_findings": overdue_findings,
            "severity_buckets": severity_buckets, "severity_pct": severity_pct,
            "heartbeat_rows": heartbeat_rows, "mirror_sync_rows": mirror_sync_rows,
            "action_findings": action_findings, "action_repo_names": action_repo_names, "new_ids": new_ids,
            "all_owners": all_owners, "owner_filter": owner,
        },
        user=user,
    )
