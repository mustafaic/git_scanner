"""Hat A: Trees/Blobs ile degisiklik tespiti + icerik-adresli onbellek +
sanity gate + component_snapshots (master_prompt.md 3.2).

Gercek lockfile PARSE islemi worker'da (izole, network_mode:none) yapilir
-- repo icerigi guvenilmeyen girdidir (3.2.6). Bu modul SADECE orchestrator
tarafini yapar: tree/blob indirme, worker'a staging, sonuc toplama, DB yazma.
"""

from __future__ import annotations

import base64
import datetime as dt
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from core.models import ComponentSnapshot, Repository, ScanRun
from core.worker_protocol import (
    WorkerJob,
    clear_staging,
    is_result_ready,
    read_result,
    stage_input_file,
    write_job,
)
from orchestrator.github_auth import API_VERSION_HEADER, GitHubAppAuth

LOG = logging.getLogger(__name__)

# master_prompt.md 3.2.5: symlink (mode 120000) ASLA takip edilmez.
SYMLINK_MODE = "120000"

# Lockfile basename -> core.lockfile_parser.PARSERS anahtari.
LOCKFILE_BASENAME_TO_PARSER_KEY: Dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "poetry.lock": "poetry",
    "Cargo.lock": "cargo",
    "Pipfile.lock": "pipenv",
    "composer.lock": "composer",
    "Gemfile.lock": "bundler",
    "go.mod": "go",
    "packages.lock.json": "nuget",
    "gradle.lockfile": "gradle",
    "buildscript-gradle.lockfile": "gradle",
}

MAX_LOCKFILE_BLOB_BYTES = 10 * 1024 * 1024
WORKER_JOB_TIMEOUT_SECONDS = 60
WORKER_POLL_INTERVAL_SECONDS = 0.3

# master_prompt.md 3.2.7: bilesen sayisi beklenmedik bicimde cokerse (esik +
# mutlak limit) sonuc otomatik kabul edilmez.
COLLAPSE_RATIO_THRESHOLD = 0.5
COLLAPSE_MIN_BASELINE_COMPONENTS = 5


def get_repo_tree(
    api_base_url: str, auth: GitHubAppAuth, owner: str, repo: str, ref: str, http_client: Optional[httpx.Client] = None
) -> Tuple[List[Dict[str, Any]], bool]:
    """VERIFIED_FACTS.md: tree_sha dogrudan branch adi kabul eder."""
    client = http_client or httpx.Client(timeout=60.0)
    response = client.get(
        f"{api_base_url.rstrip('/')}/repos/{owner}/{repo}/git/trees/{ref}",
        params={"recursive": 1},
        headers={
            "Authorization": f"Bearer {auth.get_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION_HEADER,
        },
    )
    if response.status_code != 200:
        raise RuntimeError(f"Tree alinamadi ({owner}/{repo}): HTTP {response.status_code}")
    data = response.json()
    return data.get("tree", []) or [], bool(data.get("truncated"))


def find_lockfiles(tree_entries: List[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """Donen: [(path, blob_sha, parser_key), ...]. Symlink'ler DAHIL EDILMEZ."""
    found = []
    for entry in tree_entries:
        if entry.get("type") != "blob" or entry.get("mode") == SYMLINK_MODE:
            continue
        basename = (entry.get("path") or "").rsplit("/", 1)[-1]
        parser_key = LOCKFILE_BASENAME_TO_PARSER_KEY.get(basename)
        if parser_key:
            found.append((entry["path"], entry["sha"], parser_key))
    return found


def get_blob_content(
    api_base_url: str, auth: GitHubAppAuth, owner: str, repo: str, blob_sha: str, http_client: Optional[httpx.Client] = None
) -> Optional[bytes]:
    client = http_client or httpx.Client(timeout=60.0)
    response = client.get(
        f"{api_base_url.rstrip('/')}/repos/{owner}/{repo}/git/blobs/{blob_sha}",
        headers={
            "Authorization": f"Bearer {auth.get_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION_HEADER,
        },
    )
    if response.status_code != 200:
        return None
    data = response.json()
    if data.get("encoding") != "base64" or not data.get("content"):
        return None
    return base64.b64decode(data["content"])


def run_lockfile_parse_job(
    staging_dir: Path, input_filename: str, lockfile_type: str, content: bytes,
    timeout_seconds: int = WORKER_JOB_TIMEOUT_SECONDS,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Worker'a bir 'lockfile_parse' isi verir, sonucu bekler. Donen:
    (exit_code, components_json_list). Zaman asiminda RuntimeError firlatir."""
    import json

    clear_staging(staging_dir)
    stage_input_file(staging_dir, input_filename, content)
    write_job(staging_dir, WorkerJob(job_id=str(uuid.uuid4()), job_kind="lockfile_parse", input_filename=input_filename, lockfile_type=lockfile_type))

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_result_ready(staging_dir):
            result = read_result(staging_dir)
            clear_staging(staging_dir)
            try:
                components = json.loads(result.stdout.decode("utf-8")) if result.stdout else []
            except (UnicodeDecodeError, json.JSONDecodeError):
                components = []
            return result.exit_code, components
        time.sleep(WORKER_POLL_INTERVAL_SECONDS)
    clear_staging(staging_dir)
    raise RuntimeError(f"Worker lockfile_parse zaman asimi: {input_filename}")


def _latest_cached_components(session: Session, blob_sha: str) -> Optional[List[ComponentSnapshot]]:
    """Icerik-adresli onbellek: bu blob_sha (HANGI repo/lockfile_path'tan
    gelmis olursa olsun) daha once parse edildiyse, yeniden parse ETME."""
    latest_run_id = session.execute(
        select(ComponentSnapshot.scan_run_id)
        .where(ComponentSnapshot.lockfile_blob_sha == blob_sha)
        .order_by(ComponentSnapshot.scan_run_id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if latest_run_id is None:
        return None
    rows = session.execute(
        select(ComponentSnapshot).where(
            ComponentSnapshot.lockfile_blob_sha == blob_sha, ComponentSnapshot.scan_run_id == latest_run_id
        )
    ).scalars().all()
    return list(rows) if rows else None


def _count_current_components(session: Session, repo_id: int) -> int:
    return session.execute(
        select(ComponentSnapshot).where(ComponentSnapshot.repo_id == repo_id, ComponentSnapshot.is_current.is_(True))
    ).scalars().all().__len__()


def extract_repository(
    session: Session,
    api_base_url: str,
    auth: GitHubAppAuth,
    staging_dir: Path,
    repo: Repository,
    http_client: Optional[httpx.Client] = None,
) -> Tuple[ScanRun, Dict[str, Tuple[str, bytes]]]:
    """Bir repo icin Hat A'yi calistirir. Donen ScanRun zaten session'a
    eklenmis ve flush edilmistir (id okunabilir); commit cagiran tarafta.

    Donen ikinci deger (`changed_contents`): bu calistirmada DEGISEN
    lockfile'larin HAM icerigi (path -> bytes) -- cagiran taraf (main.py)
    bunu Hat B anlik eslestirmeye (S2) dogrudan besler, tekrar indirmez."""
    scan_run = ScanRun(
        run_type="extraction", repo_id=repo.github_repo_id, commit_sha=repo.last_seen_sha,
        status="success", details={},
    )
    session.add(scan_run)
    session.flush()

    try:
        tree_entries, truncated = get_repo_tree(api_base_url, auth, repo.owner, repo.name, repo.default_branch, http_client)
    except Exception as exc:  # noqa: BLE001
        scan_run.status = "failed"
        scan_run.error = str(exc)
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run, {}

    lockfiles = find_lockfiles(tree_entries)
    file_statuses: List[Dict[str, Any]] = []
    # Pass 1: her lockfile icin YENI bilesen listesini (DB'ye DOKUNMADAN) topla.
    pending_writes: List[Tuple[str, str, List[Dict[str, Any]]]] = []  # (path, blob_sha, components)
    changed_contents: Dict[str, Tuple[str, bytes]] = {}  # path -> (blob_sha, ham icerik)
    unchanged_paths: List[str] = []
    any_failure = False

    for path, blob_sha, parser_key in lockfiles:
        prev_blob_sha = session.execute(
            select(ComponentSnapshot.lockfile_blob_sha).where(
                ComponentSnapshot.repo_id == repo.github_repo_id,
                ComponentSnapshot.lockfile_path == path,
                ComponentSnapshot.is_current.is_(True),
            ).limit(1)
        ).scalar_one_or_none()

        if prev_blob_sha == blob_sha:
            file_statuses.append({"path": path, "blob_sha": blob_sha, "status": "unchanged"})
            unchanged_paths.append(path)
            continue

        # Icerik her zaman indirilir (Hat B anlik eslestirme bunu kullanir);
        # icerik-adresli onbellek sadece PARSE adimini (worker cagrisini) atlar.
        content = get_blob_content(api_base_url, auth, repo.owner, repo.name, blob_sha, http_client)
        if content is None or len(content) > MAX_LOCKFILE_BLOB_BYTES:
            file_statuses.append({"path": path, "blob_sha": blob_sha, "status": "blob_fetch_failed"})
            any_failure = True
            continue
        changed_contents[path] = (blob_sha, content)

        cached = _latest_cached_components(session, blob_sha)
        if cached is not None:
            components = [
                {"ecosystem": c.ecosystem, "name": c.name, "version": c.version, "scope": c.scope, "relation": c.relation, "purl": c.purl}
                for c in cached
            ]
            file_statuses.append({"path": path, "blob_sha": blob_sha, "status": "cache_hit", "component_count": len(components)})
            pending_writes.append((path, blob_sha, components))
            continue

        try:
            exit_code, components = run_lockfile_parse_job(staging_dir, path.rsplit("/", 1)[-1], parser_key, content)
            if exit_code != 0:
                file_statuses.append({"path": path, "blob_sha": blob_sha, "status": "parse_failed", "exit_code": exit_code})
                any_failure = True
                continue
            file_statuses.append({"path": path, "blob_sha": blob_sha, "status": "parsed", "component_count": len(components)})
            pending_writes.append((path, blob_sha, components))
        except Exception as exc:  # noqa: BLE001 - bir lockfile'in hatasi digerlerini etkilemez (monorepo izolasyonu)
            LOG.exception("Lockfile isleme hatasi: %s", path)
            file_statuses.append({"path": path, "blob_sha": blob_sha, "status": "error", "error": str(exc)})
            any_failure = True

    # Sanity gate: toplam bilesen sayisi beklenmedik bicimde cokuyor mu?
    before_count = _count_current_components(session, repo.github_repo_id)
    after_count = sum(len(c) for _, _, c in pending_writes) + _sum_unchanged_components(session, repo.github_repo_id, unchanged_paths)
    collapsed = (
        before_count >= COLLAPSE_MIN_BASELINE_COMPONENTS
        and after_count < before_count * (1 - COLLAPSE_RATIO_THRESHOLD)
    )

    scan_run.details = {
        "files": file_statuses, "truncated": truncated,
        "component_count_before": before_count, "component_count_after": after_count,
    }

    if collapsed:
        scan_run.status = "needs_review"
        scan_run.error = "component_count_collapsed"
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run, {}  # pending_writes UYGULANMAZ: eski envanter korunur

    # Pass 2: guvenliyse yaz.
    for path, blob_sha, components in pending_writes:
        session.execute(
            update(ComponentSnapshot)
            .where(
                ComponentSnapshot.repo_id == repo.github_repo_id,
                ComponentSnapshot.lockfile_path == path,
                ComponentSnapshot.is_current.is_(True),
            )
            .values(is_current=False)
        )
        for comp in components:
            session.add(
                ComponentSnapshot(
                    repo_id=repo.github_repo_id, lockfile_path=path, lockfile_blob_sha=blob_sha,
                    scan_run_id=scan_run.id, ecosystem=comp["ecosystem"], purl=comp.get("purl"),
                    name=comp["name"], version=comp["version"], scope=comp.get("scope", "unknown"),
                    relation=comp.get("relation", "unknown"), is_current=True,
                )
            )

    scan_run.status = "partial" if any_failure else "success"
    scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
    return scan_run, changed_contents


def _sum_unchanged_components(session: Session, repo_id: int, unchanged_paths: List[str]) -> int:
    if not unchanged_paths:
        return 0
    rows = session.execute(
        select(ComponentSnapshot).where(
            ComponentSnapshot.repo_id == repo_id,
            ComponentSnapshot.lockfile_path.in_(unchanged_paths),
            ComponentSnapshot.is_current.is_(True),
        )
    ).scalars().all()
    return len(rows)
