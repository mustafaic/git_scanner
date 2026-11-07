"""Orchestrator FastAPI uygulamasi: /healthz, /metrics ve arka planda
calisan claim-loop (jobs tablosundan is claim eder, isler).

Kapsam siniri (Asama 1): discovery + Hat A adim 1 (HEAD SHA karsilastirma).
Tree/blob diff, parse, Hat B, bildirim vb. Asama 2+ kapsamidir.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from core.config import Settings, load_settings
from core.db import init_engine, session_scope
from core.logging_setup import configure_logging
from core.metrics import (
    JOB_DURATION_SECONDS,
    JOBS_CLAIMED_TOTAL,
    JOBS_COMPLETED_TOTAL,
    LAST_SUCCESSFUL_CYCLE_TIMESTAMP,
    QUEUE_LENGTH,
)
from core.models import Job, Repository, SystemHeartbeat
from orchestrator.discovery import list_installation_repositories, upsert_repositories
from orchestrator.github_auth import GitHubAppAuth, load_private_key
from orchestrator.jobs import (
    build_idempotency_key,
    claim_next_job,
    complete_job,
    count_pending_jobs,
    enqueue_job,
    fail_job,
)
from orchestrator.sync import EmptyRepositoryError, sync_repository_head

LOG = logging.getLogger(__name__)

settings: Settings = load_settings()
configure_logging("orchestrator", settings.log_level)

_auth: Optional[GitHubAppAuth] = None
if settings.github_app_id and settings.github_app_installation_id and settings.github_app_private_key_path:
    try:
        _auth = GitHubAppAuth(
            api_base_url=settings.github_api_base_url,
            app_id=settings.github_app_id,
            installation_id=settings.github_app_installation_id,
            private_key_pem=load_private_key(settings.github_app_private_key_path),
        )
        LOG.info("GitHub App kimligi yuklendi (installation_id=%s)", settings.github_app_installation_id)
    except OSError:
        LOG.warning("GITHUB_APP_PRIVATE_KEY_PATH okunamadi; discovery/sync devre disi kalacak")
else:
    LOG.warning("GitHub App kimlik bilgileri eksik; discovery/sync devre disi (sadece iskelet/healthcheck calisir)")

_stop_event = threading.Event()


def _write_heartbeat(session: Any, component: str, detail: Optional[Dict[str, Any]] = None) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    stmt = (
        pg_insert(SystemHeartbeat)
        .values(component=component, last_success_at=now, detail=detail or {})
        .on_conflict_do_update(
            index_elements=[SystemHeartbeat.component],
            set_={"last_success_at": now, "detail": detail or {}},
        )
    )
    session.execute(stmt)


def _process_repo_sync_job(job: Job) -> None:
    if _auth is None:
        raise RuntimeError("GitHub App kimligi yapilandirilmamis, repo_sync islenemez")
    with session_scope() as session:
        repo = session.get(Repository, job.repo_id)
        if repo is None:
            raise RuntimeError(f"repositories tablosunda bulunamadi: repo_id={job.repo_id}")
        try:
            sync_repository_head(settings.github_api_base_url, _auth, repo)
        except EmptyRepositoryError:
            # Gercek bir hata degil: repo'da henuz commit yok, retry'nin
            # faydasi olmaz. last_seen_sha NULL kalir (dogru temsil).
            LOG.info("Repo %s henuz commit icermiyor, atlaniyor", repo.full_name)
        complete_job(session, job.id)


def _claim_loop_tick() -> bool:
    """Bir claim-loop adimi calistirir. Donen deger: bir is islendi mi."""
    with session_scope() as session:
        job = claim_next_job(session, ["repo_sync"], settings.job_lock_duration_seconds, locked_by="orchestrator")

    processed = job is not None
    if job is not None:
        JOBS_CLAIMED_TOTAL.labels(job_type=job.job_type).inc()
        start = time.monotonic()
        try:
            _process_repo_sync_job(job)
            JOBS_COMPLETED_TOTAL.labels(job_type=job.job_type, status="done").inc()
        except Exception as exc:  # noqa: BLE001 - bir job'un hatasi dongunun tamamini durdurmamali
            LOG.exception("Job %s basarisiz", job.id)
            with session_scope() as session:
                fail_job(session, job.id, str(exc))
            JOBS_COMPLETED_TOTAL.labels(job_type=job.job_type, status="failed").inc()
        finally:
            JOB_DURATION_SECONDS.labels(job_type=job.job_type).observe(time.monotonic() - start)

    with session_scope() as session:
        _write_heartbeat(session, "orchestrator")
        QUEUE_LENGTH.labels(job_type="repo_sync").set(count_pending_jobs(session, "repo_sync"))
    LAST_SUCCESSFUL_CYCLE_TIMESTAMP.labels(component="orchestrator").set_to_current_time()
    return processed


def _claim_loop() -> None:
    LOG.info("Claim loop basladi")
    while not _stop_event.is_set():
        try:
            processed = _claim_loop_tick()
        except Exception:  # noqa: BLE001
            LOG.exception("Claim loop dongusunde beklenmeyen hata")
            processed = False
        _stop_event.wait(0 if processed else settings.claim_loop_interval_seconds)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_engine(settings.database_url)
    thread = threading.Thread(target=_claim_loop, daemon=True, name="claim-loop")
    thread.start()
    yield
    _stop_event.set()


app = FastAPI(lifespan=lifespan)


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="db unavailable") from exc
    return {"status": "ok"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/internal/discover")
def discover() -> Dict[str, int]:
    # NOT: Bu uc nokta henuz RBAC/auth ile korunmuyor (Asama 3 kapsami).
    # Orchestrator sadece ic Docker agindan erisilebilir oldugu icin bu
    # Asama 1 iskeletinde kabul edilebilir; dis aga ASLA acilmamali.
    if _auth is None:
        raise HTTPException(status_code=503, detail="GitHub App kimligi yapilandirilmamis")
    repos_json = list_installation_repositories(settings.github_api_base_url, _auth)
    with session_scope() as session:
        count = upsert_repositories(session, repos_json)
        for repo_json in repos_json:
            key = build_idempotency_key("repo_sync", repo_json["id"], "discovery")
            enqueue_job(session, "repo_sync", key, repo_id=repo_json["id"], priority=100)
    return {"discovered": count}
