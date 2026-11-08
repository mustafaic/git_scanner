"""A1 Aksiyon gruplari (fix-once-close-many) + A2 Blast radius
(master_prompt.md 6). Salt-okunur agregasyon sorgulari -- yeni tablo
gerektirmez, Finding.fix_version zaten Hat B'de (core/finding_model.py
compute_fix_recommendation) hesaplanmis durumda."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.deps import get_db, render_page, require_user
from core.lockfile_parser import build_install_hint
from core.models import Finding, Repository, User
from core.owners import get_owners_map

router = APIRouter()

_OPEN_LIKE = ("OPEN", "IN_PROGRESS", "REOPENED")


@router.get("/action-groups")
def action_groups(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    rows = db.execute(
        select(
            Finding.ecosystem, Finding.package_name, Finding.fix_version,
            func.count(func.distinct(Finding.repo_id)).label("repo_count"),
            func.count(Finding.id).label("finding_count"),
            func.max(Finding.severity_cvss_score).label("max_cvss"),
            func.bool_or(Finding.kev).label("any_kev"),
        )
        .where(
            Finding.lifecycle_status.in_(_OPEN_LIKE),
            Finding.fix_status == "PATCH_AVAILABLE",
            Finding.fix_version.is_not(None),
        )
        .group_by(Finding.ecosystem, Finding.package_name, Finding.fix_version)
        .order_by(func.count(Finding.id).desc())
        .limit(200)
    ).all()

    groups = [
        {
            "ecosystem": r.ecosystem, "package_name": r.package_name, "fix_version": r.fix_version,
            "repo_count": r.repo_count, "finding_count": r.finding_count,
            "max_cvss": float(r.max_cvss) if r.max_cvss is not None else None, "any_kev": bool(r.any_kev),
            "install_hint": build_install_hint(r.ecosystem, r.package_name, r.fix_version),
        }
        for r in rows
    ]
    return render_page(request, "action_groups.html", {"groups": groups}, user=user)


@router.get("/blast-radius")
def blast_radius(
    request: Request, q: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)
):
    results = []
    if q.strip():
        term = f"%{q.strip()}%"
        rows = db.execute(
            select(Finding, Repository.full_name)
            .join(Repository, Repository.github_repo_id == Finding.repo_id, isouter=True)
            .where(
                Finding.canonical_vulnerability_id.ilike(term)
                | Finding.package_name.ilike(term)
                | cast(Finding.aliases, String).ilike(term)
            )
            .order_by(Finding.lifecycle_status, Finding.repo_id)
            .limit(500)
        ).all()
        owners_map = get_owners_map(db, [f.repo_id for f, _ in rows])
        results = [
            {"finding": f, "repo_name": name or f.repo_id, "owners": owners_map.get(f.repo_id, [])}
            for f, name in rows
        ]

    affected_repo_count = len({r["finding"].repo_id for r in results})
    return render_page(
        request, "blast_radius.html",
        {"q": q, "results": results, "affected_repo_count": affected_repo_count},
        user=user,
    )
