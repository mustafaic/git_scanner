"""Secret taramasi orkestrasyonu: kalici bare mirror onbellegi, incremental/
tam-yeniden-tarama tetikleyicileri (master_prompt.md 3.4, 4.4).

GIT KIMLIK DOGRULAMASI (kural: "Git islemlerinde token'i URL'e gomme,
process listesinde/loglarda gorunur"): token URL'e VEYA `-c` CLI
argumanina DEGIL, `GIT_CONFIG_*` ORTAM DEGISKENLERINE enjekte edilir --
bu sekilde token `ps aux` cikisinda GORUNMEZ (sadece /proc/<pid>/environ'da,
daha dar bir maruziyet). Bkz. docs/VERIFIED_FACTS.md.
"""

from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from adapters.gitleaks import parse as parse_gitleaks_output
from core.models import Repository, ScanRun
from core.secret_finding_model import ingest_secret_findings
from core.worker_protocol import (
    WorkerJob,
    clear_staging,
    is_result_ready,
    read_result,
    write_job,
)
from orchestrator.github_auth import GitHubAppAuth

LOG = logging.getLogger(__name__)

GIT_TIMEOUT_SECONDS = 600
WORKER_JOB_TIMEOUT_SECONDS = 400
WORKER_POLL_INTERVAL_SECONDS = 0.3

# master_prompt.md 5 "Git sertligi": hook'lar kapali, submodule recursion
# yok, LFS smudge kapali, GIT_TERMINAL_PROMPT=0.
_GIT_SAFETY_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
}


def _mirror_dirname(repo_full_name: str) -> str:
    return repo_full_name.replace("/", "__") + ".git"


def _git_env_with_auth(auth: GitHubAppAuth) -> Dict[str, str]:
    token = auth.get_token()
    basic = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    env = dict(os.environ)
    env.update(_GIT_SAFETY_ENV)
    env["GIT_CONFIG_COUNT"] = "2"
    env["GIT_CONFIG_KEY_0"] = "http.extraHeader"
    env["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {basic}"
    env["GIT_CONFIG_KEY_1"] = "core.hooksPath"
    env["GIT_CONFIG_VALUE_1"] = "/dev/null"
    return env


def clone_url_for_repo(api_base_url: str, full_name: str) -> str:
    """github.com icin https://github.com/<full_name>.git; GHES icin
    web host'u api_base_url'den (https://<host>/api/v3) turetir.
    NOT (bkz. docs/ASSUMPTIONS.md): GHES turetimi dogrulanmadi, gercek
    GHES ortaminda test edilmeli."""
    base = api_base_url.rstrip("/")
    if base == "https://api.github.com":
        host = "https://github.com"
    elif base.endswith("/api/v3"):
        host = base[: -len("/api/v3")]
    else:
        host = base
    return f"{host}/{full_name}.git"


def ensure_mirror(mirrors_dir: Path, repo_full_name: str, clone_url: str, auth: GitHubAppAuth) -> Path:
    """Repo icin kalici bir bare mirror saglar (yoksa `clone --mirror`,
    varsa `fetch --prune`). Donen: mirror dizin yolu."""
    mirror_path = mirrors_dir / _mirror_dirname(repo_full_name)
    env = _git_env_with_auth(auth)
    if not mirror_path.exists():
        mirrors_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--mirror", "--no-local", clone_url, str(mirror_path)],
            env=env, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=True,
        )
    else:
        subprocess.run(
            ["git", "-C", str(mirror_path), "fetch", "--prune", "origin"],
            env=env, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=True,
        )
    return mirror_path


def get_mirror_head_sha(mirror_path: Path, default_branch: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(mirror_path), "rev-parse", f"refs/heads/{default_branch}"],
        capture_output=True, timeout=30, check=True,
    )
    return result.stdout.decode("utf-8").strip()


def is_force_push(mirror_path: Path, old_sha: str, new_sha: str) -> bool:
    """master_prompt.md 4.4: force-push/gecmis yeniden yazimi -> tam
    yeniden tarama. `old_sha` yeni gecmiste bir ata DEGILSE force-push'tur."""
    if not old_sha or old_sha == new_sha:
        return False
    result = subprocess.run(
        ["git", "-C", str(mirror_path), "merge-base", "--is-ancestor", old_sha, new_sha],
        capture_output=True, timeout=30,
    )
    return result.returncode != 0


def run_gitleaks_job(
    staging_dir: Path, mirror_subdir: str, log_opts: Optional[str],
    timeout_seconds: int = WORKER_JOB_TIMEOUT_SECONDS,
) -> Tuple[int, bytes]:
    """Worker'a bir 'secret_scan' isi verir, sonucu bekler. Donen:
    (exit_code, report_json_bytes)."""
    clear_staging(staging_dir)
    write_job(staging_dir, WorkerJob(job_id=str(uuid.uuid4()), job_kind="secret_scan", mirror_subdir=mirror_subdir, log_opts=log_opts))

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_result_ready(staging_dir):
            result = read_result(staging_dir)
            clear_staging(staging_dir)
            return result.exit_code, result.stdout
        time.sleep(WORKER_POLL_INTERVAL_SECONDS)
    clear_staging(staging_dir)
    raise RuntimeError(f"Worker secret_scan zaman asimi: {mirror_subdir}")


def _latest_successful_secret_scan(session: Session, repo_id: int) -> Optional[ScanRun]:
    return session.execute(
        select(ScanRun)
        .where(ScanRun.run_type == "secret_scan", ScanRun.repo_id == repo_id, ScanRun.status == "success")
        .order_by(ScanRun.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def scan_repository_secrets(
    session: Session,
    staging_dir: Path,
    mirrors_dir: Path,
    api_base_url: str,
    auth: GitHubAppAuth,
    repo: Repository,
    scanner_version: str,
) -> ScanRun:
    """Bir repo icin secret taramasini calistirir (mirror fetch + gitleaks +
    ingest). master_prompt.md 4.4: force-push, tam gecmis yeniden yazimi
    veya scanner/ruleset surumu degisimi -> TAM yeniden tarama (log_opts=None)."""
    clone_url = clone_url_for_repo(api_base_url, repo.full_name)

    try:
        mirror_path = ensure_mirror(mirrors_dir, repo.full_name, clone_url, auth)
        new_head_sha = get_mirror_head_sha(mirror_path, repo.default_branch)
    except subprocess.CalledProcessError as exc:
        scan_run = ScanRun(run_type="secret_scan", repo_id=repo.github_repo_id, scanner_name="gitleaks",
                            scanner_version=scanner_version, status="failed", error=f"git hatasi: {exc}")
        session.add(scan_run)
        session.flush()
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    old_sha = repo.last_scanned_sha
    last_run = _latest_successful_secret_scan(session, repo.github_repo_id)
    scanner_version_changed = last_run is not None and last_run.scanner_version != scanner_version
    force_push_detected = bool(old_sha) and is_force_push(mirror_path, old_sha, new_head_sha)

    full_rescan = (not old_sha) or force_push_detected or scanner_version_changed
    log_opts = None if full_rescan else f"{old_sha}..{new_head_sha}"
    is_baseline = last_run is None

    scan_run = ScanRun(
        run_type="secret_scan", repo_id=repo.github_repo_id, commit_sha=new_head_sha,
        scanner_name="gitleaks", scanner_version=scanner_version, status="success",
        details={"full_rescan": full_rescan, "force_push_detected": force_push_detected,
                  "scanner_version_changed": scanner_version_changed},
    )
    session.add(scan_run)
    session.flush()

    try:
        exit_code, report_json = run_gitleaks_job(staging_dir, _mirror_dirname(repo.full_name), log_opts)
    except Exception as exc:  # noqa: BLE001
        scan_run.status = "failed"
        scan_run.error = str(exc)
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    # Ayni mantik: exit 0 = temiz; exit 1 = bulgu VEYA hata, gecerli JSON
    # varligiyla ayirt edilir (bkz. adapters/gitleaks.py, docs/VERIFIED_FACTS.md).
    if exit_code not in (0, 1) or (exit_code == 1 and not report_json):
        scan_run.status = "failed"
        scan_run.error = f"gitleaks exit_code={exit_code}"
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    try:
        findings = parse_gitleaks_output(report_json)
    except ValueError as exc:
        scan_run.status = "failed"
        scan_run.error = str(exc)
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    stats = ingest_secret_findings(
        session, repo.github_repo_id, scan_run.id, findings, is_baseline=is_baseline, is_full_scan=full_rescan
    )
    scan_run.details = {**scan_run.details, **stats}
    repo.last_scanned_sha = new_head_sha
    scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
    return scan_run
