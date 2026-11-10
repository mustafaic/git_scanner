"""A2 Blast radius (master_prompt.md 6): bir CVE/GHSA/OSV kimligi veya paket
adi girilince etkilenen TUM repolari listeler. Salt-okunur agregasyon
sorgusu -- yeni tablo gerektirmez.

NOT (2026-11-11, kullanici karari): Bu modul onceden "A1 Aksiyon gruplari"
(`/action-groups`, fix-once-close-many + komut ipucu) sayfasini da
barindiriyordu; o sayfa TAMAMEN KALDIRILDI (dosya adi da bu yuzden
routes_actions.py -> routes_blast_radius.py olarak degisti). Komut ipucu
uretimi (core/lockfile_parser.build_install_hint ve ekosistem ad/surum
grameri dogrulamasi) da birlikte kaldirildi -- bkz. docs/THREAT_MODEL.md
madde 1: artik panel HICBIR yerde kopyala-yapistir komut ipucu uretmiyor,
dolayisiyla o saldiri yuzeyi tamamen ortadan kalkti."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.deps import get_db, render_page, require_user
from core.models import Finding, Repository, User
from core.owners import get_owners_map

router = APIRouter()


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
