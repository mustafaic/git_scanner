"""Repo listesi + elle tetikleme + tarama dahil/haric politikasi + panelden
GitHub token ile repo ekleme (hibrit model, 2026-11-10 kullanici karari).
`app` servisi orchestrator'a HTTP/import ile BAGLI DEGIL -- elle tetikleme,
orchestrator'in kendisinin de yaptigi (orchestrator/triggers.py
record_trigger) tek satirlik INSERT'in BIREBIR AYNISI (core.models.ScanTrigger);
orchestrator'in claim loop'u bunu kendi debounce/consume mantigiyla bir
sonraki dongude isler. Repo ekleme de AYNI desen: panel sadece admin'in
girdigi owner/repo+PAT'i SIFRELEYIP `repo_onboarding_requests`'e yazar --
token'i gercekten kullanip GitHub'a dogrulama atan taraf orchestrator'dir
(app servisi GitHub'a hic cikmaz, bkz. deploy/Dockerfile.app).

RBAC: tarama dahil/haric + repo ekleme/token kaldirma SADECE admin (audit'li,
gerekceli). Elle tetikleme varsayilan admin-only; viewer'a ayarlardan (A10)
hiz-limitli izin verilebilir."""

from __future__ import annotations

import datetime as dt
import logging
from typing import Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession
from starlette.requests import Request

from app.auth_service import record_audit
from app.csrf import require_csrf
from app.deps import get_db, render_page, require_admin, require_user
from core.backup_crypto import encrypt_bytes, load_fernet_key
from core.config import load_settings
from core.models import Job, Repository, RepoCredential, RepoOnboardingRequest, ScanTrigger, User
from core.settings_store import DEFAULT_VIEWER_TRIGGER, VIEWER_TRIGGER_KEY, get_setting

LOG = logging.getLogger(__name__)
router = APIRouter()

_settings = load_settings()
_PENDING_REQUEST_LIMIT = 20


def _trigger_status_by_repo(db: DbSession, repo_ids: list[int]) -> dict[int, dict]:
    """Her repo icin "Simdi kontrol et" butonunun sonucunu gorunur kilar --
    oncesinde sadece sessiz bir redirect vardi, admin tetiklemenin isleyip
    islemedigini anlayamiyordu. En son ScanTrigger (henuz tuketilmemisse
    "kuyrukta") + bekleyen/calisan Job (varsa "taraniyor") bilgisini birlestirir."""
    if not repo_ids:
        return {}
    status: dict[int, dict] = {}
    recent_triggers = db.execute(
        select(ScanTrigger).where(ScanTrigger.repo_id.in_(repo_ids)).order_by(ScanTrigger.created_at.desc()).limit(500)
    ).scalars().all()
    for trig in recent_triggers:
        if trig.repo_id not in status:
            status[trig.repo_id] = {
                "last_trigger_at": trig.created_at,
                "queued": trig.consumed_at is None,
            }
    active_jobs = db.execute(
        select(Job.repo_id).where(Job.repo_id.in_(repo_ids), Job.status.in_(["pending", "running"]))
    ).scalars().all()
    for repo_id in active_jobs:
        status.setdefault(repo_id, {})["scanning"] = True
    return status


def _repo_token_fernet_key() -> Optional[bytes]:
    if not _settings.repo_token_encryption_key_path:
        return None
    try:
        return load_fernet_key(_settings.repo_token_encryption_key_path)
    except OSError:
        LOG.error("REPO_TOKEN_ENCRYPTION_KEY_PATH okunamadi: %s", _settings.repo_token_encryption_key_path)
        return None


def _parse_owner_repo(raw: str) -> Optional[tuple[str, str]]:
    """"owner/repo" veya tam bir GitHub URL'si kabul eder. Gecersizse None."""
    raw = raw.strip().rstrip("/")
    if not raw:
        return None
    if raw.startswith("http://") or raw.startswith("https://"):
        path = urlsplit(raw).path.strip("/")
    else:
        path = raw
    parts = [p for p in path.split("/") if p]
    if len(parts) != 2:
        return None
    owner, repo_name = parts
    if repo_name.endswith(".git"):
        repo_name = repo_name[: -len(".git")]
    if not owner or not repo_name:
        return None
    return owner, repo_name


def _repositories_context(db: DbSession, user: User) -> dict:
    repos = db.execute(select(Repository).order_by(Repository.full_name)).scalars().all()
    viewer_trigger = {**DEFAULT_VIEWER_TRIGGER, **(get_setting(db, VIEWER_TRIGGER_KEY) or {})}
    can_trigger = user.role == "admin" or viewer_trigger.get("enabled", False)
    trigger_status = _trigger_status_by_repo(db, [r.github_repo_id for r in repos])
    pending_requests = []
    if user.role == "admin":
        pending_requests = db.execute(
            select(RepoOnboardingRequest).where(RepoOnboardingRequest.status.in_(["pending", "failed"]))
            .order_by(RepoOnboardingRequest.created_at.desc()).limit(_PENDING_REQUEST_LIMIT)
        ).scalars().all()
    manual_repo_ids = {r.github_repo_id for r in repos if r.discovered_via == "manual_pat"}
    return {
        "repos": repos, "can_trigger": can_trigger, "trigger_status": trigger_status,
        "pending_requests": pending_requests, "manual_repo_ids": manual_repo_ids,
        "repo_token_crypto_ready": _settings.repo_token_encryption_key_path is not None,
    }


@router.get("/repositories")
def list_repositories(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    return render_page(request, "repositories.html", _repositories_context(db, user), user=user)


@router.post("/repositories/add")
def add_repository(
    request: Request,
    repo: str = Form(...),
    token: str = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Admin panelden "owner/repo + PAT" girer; panel token'i SADECE
    sifreleyip kuyruga yazar -- GitHub'a karsi gercek dogrulama/kesif
    orchestrator'in bir sonraki poll dongusunde yapilir (bkz.
    orchestrator/main.py, Faz 1 "pending onboarding istekleri" adimi)."""
    parsed = _parse_owner_repo(repo)
    token = token.strip()
    error: Optional[str] = None
    if parsed is None:
        error = "Repo 'owner/repo' biçiminde olmalı (ör. octocat/hello-world) veya tam bir GitHub URL'si olmalı."
    elif not token:
        error = "GitHub token zorunlu."
    key = _repo_token_fernet_key()
    if error is None and key is None:
        error = "Sunucuda REPO_TOKEN_ENCRYPTION_KEY_PATH yapılandırılmamış -- deploy/secrets/README.md'ye bakın."
    if error:
        return render_page(
            request, "repositories.html", {**_repositories_context(db, user), "error": error}, user=user, status_code=400,
        )

    owner, repo_name = parsed
    encrypted_token = encrypt_bytes(token.encode("utf-8"), key).decode("ascii")
    db.add(
        RepoOnboardingRequest(
            owner=owner, repo_name=repo_name, encrypted_token=encrypted_token,
            requested_by_user_id=user.id, status="pending",
        )
    )
    # Token DEGERI audit log'a YAZILMAZ -- sadece hangi repo icin istek
    # yapildigi (bkz. docs/THREAT_MODEL.md yeni madde "panelden PAT ile repo ekleme").
    record_audit(db, user, "repo_onboarding_requested", "repository", f"{owner}/{repo_name}")
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/onboarding-requests/{request_id}/dismiss")
def dismiss_onboarding_request(
    request_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    req = db.get(RepoOnboardingRequest, request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="istek bulunamadi")
    record_audit(db, user, "repo_onboarding_request_dismissed", "repo_onboarding_request", str(request_id), {"owner": req.owner, "repo_name": req.repo_name})
    db.delete(req)
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/{repo_id}/remove-credential")
def remove_repository_credential(
    repo_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Panelden eklenmis (manual_pat) bir repo icin saklanan token'i siler.
    Token olmadan taranamayacagi icin repo otomatik hariç tutulur (mevcut
    scan_excluded mekanizmasi, exclude_repository ile ayni alanlar)."""
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    cred = db.get(RepoCredential, repo_id)
    if cred is not None:
        db.delete(cred)
    if repo.discovered_via == "manual_pat" and not repo.scan_excluded:
        repo.scan_excluded = True
        repo.scan_exclude_reason = "Manuel eklenen token kaldırıldı -- bu repo artık taranamıyor."
    record_audit(db, user, "repo_credential_removed", "repository", str(repo_id))
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/{repo_id}/trigger")
def trigger_repository(
    repo_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_user),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    if repo.scan_excluded:
        raise HTTPException(status_code=400, detail="bu repo tarama politikasiyla haric tutulmus")

    if user.role != "admin":
        viewer_trigger = {**DEFAULT_VIEWER_TRIGGER, **(get_setting(db, VIEWER_TRIGGER_KEY) or {})}
        if not viewer_trigger.get("enabled", False):
            raise HTTPException(status_code=403, detail="viewer icin elle tetikleme kapali")
        window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        recent_count = db.execute(
            select(func.count()).select_from(ScanTrigger).where(
                ScanTrigger.note == f"panel:{user.username}", ScanTrigger.created_at >= window_start,
            )
        ).scalar_one()
        if recent_count >= viewer_trigger.get("max_per_hour", DEFAULT_VIEWER_TRIGGER["max_per_hour"]):
            raise HTTPException(status_code=429, detail="saatlik elle tetikleme limitine ulasildi")

    db.add(ScanTrigger(repo_id=repo_id, source="manual", note=f"panel:{user.username}"))
    record_audit(db, user, "repo_manual_trigger", "repository", str(repo_id))
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/{repo_id}/exclude")
def exclude_repository(
    repo_id: int,
    reason: str = Form(...),
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    if not reason.strip():
        raise HTTPException(status_code=400, detail="gerekce zorunlu")
    repo.scan_excluded = True
    repo.scan_exclude_reason = reason.strip()
    record_audit(db, user, "repo_scan_excluded", "repository", str(repo_id), {"reason": reason.strip()})
    return RedirectResponse("/repositories", status_code=303)


@router.post("/repositories/{repo_id}/unexclude")
def unexclude_repository(
    repo_id: int,
    db: DbSession = Depends(get_db),
    user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo bulunamadi")
    repo.scan_excluded = False
    repo.scan_exclude_reason = None
    record_audit(db, user, "repo_scan_included", "repository", str(repo_id))
    return RedirectResponse("/repositories", status_code=303)
