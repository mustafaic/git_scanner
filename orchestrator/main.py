"""Orchestrator FastAPI uygulamasi: /healthz, /metrics ve arka planda
calisan uc dongu (master_prompt.md 3.5, 3.2, 3.3):

1. poll loop: GraphQL batch ile tum aktif repolarin HEAD SHA'sini yoklar,
   degisenler icin tetikleyici kaydeder (hizli yoklama + gunluk uzlastirma
   ayni mekanizma: her dongu TUM repolari kapsar).
2. claim loop: tetikleyicileri debounce edip is kuyruguna ekler, isleri
   claim edip isler (repo_check: Hat A + anlik Hat B).
3. daily jobs loop: mirror sync (KEV/EPSS/OSV DB) + gunluk tam Hat B.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from core.config import Settings, load_settings
from core.db import init_engine, session_scope
from core.logging_setup import configure_logging
from core.metrics import (
    GITHUB_RATE_LIMIT_REMAINING,
    JOB_DURATION_SECONDS,
    JOBS_CLAIMED_TOTAL,
    JOBS_COMPLETED_TOTAL,
    LAST_SUCCESSFUL_CYCLE_TIMESTAMP,
    QUEUE_LENGTH,
)
from core.models import Finding, Job, Repository, ScanRun, SystemHeartbeat
from core.notifications import (
    CHANNEL_EMAIL,
    EVENT_DAILY_DIGEST,
    SmtpSettings,
    build_daily_digest_summary,
    record_and_maybe_send,
)
from core.settings_store import NOTIFICATIONS_KEY, get_setting
from orchestrator.discovery import list_installation_repositories, upsert_repositories
from orchestrator.extraction import extract_repository
from orchestrator.github_auth import GitHubAppAuth, load_private_key
from orchestrator.jobs import (
    build_idempotency_key,
    claim_next_job,
    complete_job,
    count_pending_jobs,
    enqueue_job,
    fail_job,
)
from orchestrator.matching import is_advisory_data_fresh, run_daily_match, run_immediate_match
from orchestrator.mirror import apply_mirror_result, sync_epss, sync_kev, sync_osv_ecosystem_db
from orchestrator.sync import EmptyRepositoryError, sync_repository_head
from orchestrator.triggers import consume_triggers_and_enqueue, poll_head_shas, record_trigger

LOG = logging.getLogger(__name__)

settings: Settings = load_settings()
configure_logging("orchestrator", settings.log_level)

# master_prompt.md 3.3: gunluk tam eslestirmede taranacak ekosistemler.
OSV_ECOSYSTEMS = ["npm", "PyPI", "Go", "crates.io", "Packagist", "Maven", "NuGet", "RubyGems"]

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
_osv_binary_path = "/usr/local/bin/osv-scanner"  # worker konteynerinde; orchestrator bunu CALISTIRMAZ, sadece yol bilgisini jobs.py'ye iletir


def _write_heartbeat(session: Any, component: str, detail: Optional[Dict[str, Any]] = None) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    stmt = (
        pg_insert(SystemHeartbeat)
        .values(component=component, last_success_at=now, detail=detail or {})
        .on_conflict_do_update(index_elements=[SystemHeartbeat.component], set_={"last_success_at": now, "detail": detail or {}})
    )
    session.execute(stmt)


def _get_heartbeat_age_seconds(session: Any, component: str) -> Optional[float]:
    row = session.execute(text("SELECT last_success_at FROM system_heartbeats WHERE component=:c"), {"c": component}).first()
    if row is None:
        return None
    return (dt.datetime.now(dt.timezone.utc) - row[0]).total_seconds()


def _repo_has_any_finding(session: Any, repo_id: int) -> bool:
    return session.execute(select(Finding.id).where(Finding.repo_id == repo_id).limit(1)).first() is not None


def _build_notification_config(session: Any) -> tuple[Optional[SmtpSettings], List[str]]:
    """master_prompt.md 5: 'SMTP sunucu parametreleri sunucu config'inde
    kalir' (core.config/env, BURADA) + 'kanallar admin tarafindan acilip
    kapatilir' (core.models.Setting, app/routes_settings.py'den yazilir).
    Ikisi de yoksa (varsayilan) bildirim gonderimi TAMAMEN devre disi --
    core.notifications.record_and_maybe_send zaten None/bos ile no-op."""
    notif = get_setting(session, NOTIFICATIONS_KEY, default={}) or {}
    if not notif.get("email_enabled") or not settings.smtp_host or not settings.smtp_from_address:
        return None, []
    recipients = [r for r in notif.get("recipients", []) if r]
    if not recipients:
        return None, []
    smtp_settings = SmtpSettings(
        host=settings.smtp_host, port=settings.smtp_port, use_tls=settings.smtp_use_tls,
        from_address=settings.smtp_from_address, username=settings.smtp_username, password=settings.smtp_password,
    )
    return smtp_settings, recipients


def _process_repo_check_job(job: Job) -> None:
    """Hat A (degisim tespiti + envanter) + anlik Hat B (S2) -- master_prompt.md 3.2/3.3."""
    if _auth is None:
        raise RuntimeError("GitHub App kimligi yapilandirilmamis, repo_check islenemez")
    staging_dir = Path(settings.staging_dir)

    with session_scope() as session:
        repo = session.get(Repository, job.repo_id)
        if repo is None:
            raise RuntimeError(f"repositories tablosunda bulunamadi: repo_id={job.repo_id}")

        try:
            changed = sync_repository_head(settings.github_api_base_url, _auth, repo)
        except EmptyRepositoryError:
            LOG.info("Repo %s henuz commit icermiyor, atlaniyor", repo.full_name)
            complete_job(session, job.id)
            return

        if not changed:
            complete_job(session, job.id)
            return

        is_baseline = not _repo_has_any_finding(session, repo.github_repo_id)
        scan_run, changed_contents = extract_repository(
            session, settings.github_api_base_url, _auth, staging_dir, repo
        )

        if scan_run.status in ("success", "partial") and changed_contents:
            db_fresh = is_advisory_data_fresh(session, settings.advisory_max_age_seconds)
            smtp_settings, notify_recipients = _build_notification_config(session)
            for lockfile_path, (blob_sha, content) in changed_contents.items():
                run_immediate_match(
                    session, staging_dir, _osv_binary_path, settings.db_cache_dir,
                    repo_id=repo.github_repo_id, lockfile_path=lockfile_path,
                    lockfile_blob_sha=blob_sha,
                    lockfile_content=content, db_is_fresh=db_fresh, is_baseline=is_baseline,
                    smtp_settings=smtp_settings, notify_recipients=notify_recipients,
                )

        complete_job(session, job.id)


def _claim_loop_tick() -> bool:
    with session_scope() as session:
        consume_triggers_and_enqueue(session, settings.debounce_window_seconds)
        job = claim_next_job(session, ["repo_check"], settings.job_lock_duration_seconds, locked_by="orchestrator")

    processed = job is not None
    if job is not None:
        JOBS_CLAIMED_TOTAL.labels(job_type=job.job_type).inc()
        start = time.monotonic()
        try:
            _process_repo_check_job(job)
            JOBS_COMPLETED_TOTAL.labels(job_type=job.job_type, status="done").inc()
        except Exception as exc:  # noqa: BLE001
            LOG.exception("Job %s basarisiz", job.id)
            with session_scope() as session:
                fail_job(session, job.id, str(exc))
            JOBS_COMPLETED_TOTAL.labels(job_type=job.job_type, status="failed").inc()
        finally:
            JOB_DURATION_SECONDS.labels(job_type=job.job_type).observe(time.monotonic() - start)

    with session_scope() as session:
        _write_heartbeat(session, "orchestrator")
        QUEUE_LENGTH.labels(job_type="repo_check").set(count_pending_jobs(session, "repo_check"))
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


def _poll_tick() -> None:
    if _auth is None:
        return
    with session_scope() as session:
        repos = session.execute(select(Repository).where(Repository.is_active.is_(True))).scalars().all()
    if not repos:
        return
    try:
        head_shas = poll_head_shas(settings.github_api_base_url, _auth, repos)
    except Exception:  # noqa: BLE001
        LOG.exception("Poll (GraphQL batch HEAD) basarisiz")
        return
    repo_by_id = {r.github_repo_id: r for r in repos}
    with session_scope() as session:
        for repo_id, head_sha in head_shas.items():
            repo = repo_by_id.get(repo_id)
            if repo is not None and repo.last_seen_sha != head_sha:
                record_trigger(session, repo_id, source="poll")
        _write_heartbeat(session, "poll_loop")


def _poll_loop() -> None:
    LOG.info("Poll loop basladi (interval=%ss)", settings.poll_interval_seconds)
    while not _stop_event.is_set():
        try:
            _poll_tick()
        except Exception:  # noqa: BLE001
            LOG.exception("Poll loop dongusunde beklenmeyen hata")
        _stop_event.wait(settings.poll_interval_seconds)


def _send_daily_digest(session: Any, smtp_settings: Optional[SmtpSettings], notify_recipients: List[str]) -> None:
    """master_prompt.md 6: 'Diger yeni bulgular, kapananlar, REOPENED ->
    Gunluk ozet'; 'Bulgu basina mesaj yok, konsolide'. dedup_key=gun bazli
    -> ayni gun icin ikinci bir cagri (ör. daily_jobs_loop'un erken tekrar
    tetiklenmesi) idempotent olarak ATLANIR (core.notifications)."""
    if not smtp_settings or not notify_recipients:
        return
    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=settings.daily_jobs_interval_hours)
    counts = {
        "new": session.execute(
            select(func.count()).select_from(Finding).where(Finding.first_seen_at >= window_start, Finding.baseline.is_(False))
        ).scalar_one(),
        "resolved": session.execute(
            select(func.count()).select_from(Finding).where(Finding.resolved_at >= window_start)
        ).scalar_one(),
        "reopened": session.execute(
            select(func.count()).select_from(Finding).where(Finding.lifecycle_status == "REOPENED", Finding.updated_at >= window_start)
        ).scalar_one(),
        "failed_scans": session.execute(
            select(func.count()).select_from(ScanRun).where(ScanRun.status.in_(["failed", "partial"]), ScanRun.started_at >= window_start)
        ).scalar_one(),
        "new_kev": session.execute(
            select(func.count()).select_from(Finding).where(Finding.kev.is_(True), Finding.first_seen_at >= window_start, Finding.baseline.is_(False))
        ).scalar_one(),
    }
    digest = build_daily_digest_summary(counts)
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    record_and_maybe_send(
        session, event_type=EVENT_DAILY_DIGEST, dedup_key=f"daily_digest:{today}", channel=CHANNEL_EMAIL,
        recipients=notify_recipients, subject=digest["subject"], body=digest["body"], smtp_settings=smtp_settings,
    )


def _run_daily_jobs() -> None:
    staging_dir = Path(settings.staging_dir)
    with session_scope() as session:
        for ecosystem in OSV_ECOSYSTEMS:
            result = sync_osv_ecosystem_db(Path(settings.db_cache_dir), ecosystem)
            apply_mirror_result(session, result)
        apply_mirror_result(session, sync_kev())
        apply_mirror_result(session, sync_epss())

    with session_scope() as session:
        db_fresh = is_advisory_data_fresh(session, settings.advisory_max_age_seconds)
        smtp_settings, notify_recipients = _build_notification_config(session)
        run_daily_match(
            session, staging_dir, _osv_binary_path, settings.db_cache_dir, db_is_fresh=db_fresh,
            smtp_settings=smtp_settings, notify_recipients=notify_recipients,
        )
        _send_daily_digest(session, smtp_settings, notify_recipients)
        _write_heartbeat(session, "daily_jobs")


def _daily_jobs_loop() -> None:
    LOG.info("Daily jobs loop basladi (interval=%sh)", settings.daily_jobs_interval_hours)
    interval_seconds = settings.daily_jobs_interval_hours * 3600
    while not _stop_event.is_set():
        try:
            with session_scope() as session:
                age = _get_heartbeat_age_seconds(session, "daily_jobs")
            if age is None or age >= interval_seconds:
                LOG.info("Gunluk isler calistiriliyor (mirror sync + daily match)")
                _run_daily_jobs()
        except Exception:  # noqa: BLE001
            LOG.exception("Daily jobs loop dongusunde beklenmeyen hata")
        _stop_event.wait(min(interval_seconds, 3600))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_engine(settings.database_url)
    threads = [
        threading.Thread(target=_claim_loop, daemon=True, name="claim-loop"),
        threading.Thread(target=_poll_loop, daemon=True, name="poll-loop"),
        threading.Thread(target=_daily_jobs_loop, daemon=True, name="daily-jobs-loop"),
    ]
    for t in threads:
        t.start()
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
    # iskelette kabul edilebilir; dis aga ASLA acilmamali.
    if _auth is None:
        raise HTTPException(status_code=503, detail="GitHub App kimligi yapilandirilmamis")
    repos_json = list_installation_repositories(settings.github_api_base_url, _auth)
    with session_scope() as session:
        count = upsert_repositories(session, repos_json)
        for repo_json in repos_json:
            key = build_idempotency_key("repo_check", repo_json["id"], "discovery")
            enqueue_job(session, "repo_check", key, repo_id=repo_json["id"], priority=100)
    return {"discovered": count}


@app.post("/internal/trigger/{repo_id}")
def trigger_repo(repo_id: int) -> Dict[str, str]:
    """Elle tetikleme (master_prompt.md 3.5.2): repo bazli 'Simdi kontrol et'.
    RBAC Asama 3 kapsami; su an sadece ic agdan erisilebilir."""
    with session_scope() as session:
        repo = session.get(Repository, repo_id)
        if repo is None:
            raise HTTPException(status_code=404, detail="repo bulunamadi")
        record_trigger(session, repo_id, source="manual")
    return {"status": "triggered"}
