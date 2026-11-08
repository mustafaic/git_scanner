"""A3 Coverage ve saglik paneli (master_prompt.md 6): taranmayan/lockfile'siz
repolar, PARTIAL/basarisiz taramalar, gecikmis tetikleyiciler, "N gundur
dogrulanmadi" repolar, arsiv/fork bilgisi, bilinen kor noktalar.

NOT (bilinen sinirlama, LIMITATIONS.md'ye tasinacak): "lockfile'siz repo"
sinyali, en son extraction scan_run'inin `details.files` listesinin BOS
olmasidir (orchestrator/extraction.py) -- bu, "repo'da hic lockfile yok"
ile "repo'nun hic bagimliligi yok" durumlarini AYIRT ETMEZ."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.deps import get_db, get_repo_names, render_page, require_user
from core.models import Repository, ScanRun, ScanTrigger, User

router = APIRouter()

STALE_DAYS_THRESHOLD = 7
STALE_TRIGGER_MINUTES = 30


@router.get("/coverage")
def coverage(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    latest_ids_subq = (
        select(ScanRun.repo_id, func.max(ScanRun.id).label("max_id"))
        .where(ScanRun.run_type == "extraction", ScanRun.repo_id.is_not(None))
        .group_by(ScanRun.repo_id)
        .subquery()
    )
    latest_runs = db.execute(
        select(ScanRun).join(latest_ids_subq, ScanRun.id == latest_ids_subq.c.max_id)
    ).scalars().all()

    repos = db.execute(select(Repository)).scalars().all()
    repo_by_id = {r.github_repo_id: r for r in repos}
    latest_by_repo = {r.repo_id: r for r in latest_runs}

    now = dt.datetime.now(dt.timezone.utc)

    lockfile_less = []
    partial_or_failed = []
    stale = []
    for run in latest_runs:
        files = (run.details or {}).get("files") or []
        if not files:
            lockfile_less.append(run)
        if run.status in ("partial", "failed", "needs_review"):
            partial_or_failed.append(run)
        reference_time = run.finished_at or run.started_at
        if reference_time and (now - reference_time).days >= STALE_DAYS_THRESHOLD:
            stale.append((run, (now - reference_time).days))

    never_scanned = [r for r in repos if r.is_active and r.github_repo_id not in latest_by_repo]

    stale_trigger_cutoff = now - dt.timedelta(minutes=STALE_TRIGGER_MINUTES)
    lagging_triggers = db.execute(
        select(ScanTrigger)
        .where(ScanTrigger.consumed_at.is_(None), ScanTrigger.created_at < stale_trigger_cutoff)
        .order_by(ScanTrigger.created_at)
        .limit(200)
    ).scalars().all()

    archived_or_fork = [r for r in repos if r.archived or r.fork]

    repo_ids = {run.repo_id for run in (lockfile_less + partial_or_failed)} | {r.github_repo_id for r in never_scanned}
    repo_ids |= {t.repo_id for t in lagging_triggers} | {r.github_repo_id for r in archived_or_fork}
    repo_names = get_repo_names(db, list(repo_ids))

    return render_page(
        request, "coverage.html",
        {
            "lockfile_less": lockfile_less, "partial_or_failed": partial_or_failed,
            "stale": stale, "never_scanned": never_scanned, "lagging_triggers": lagging_triggers,
            "archived_or_fork": archived_or_fork, "repo_names": repo_names,
            "stale_days_threshold": STALE_DAYS_THRESHOLD, "stale_trigger_minutes": STALE_TRIGGER_MINUTES,
        },
        user=user,
    )
