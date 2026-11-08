"""orchestrator/extraction.py extract_repository() testleri. Gercek
Postgres gerektirir. Worker surecini taklit etmek icin arka planda bir
thread, GERCEK worker/main.py'nin process_one_job() fonksiyonunu
cagirarak ayni dosya tabanli protokolu kullanir (Docker gerektirmez;
protokolun KENDISI test edilir, sadece osv-scanner binary yok)."""

from __future__ import annotations

import base64
import os
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.models import ComponentSnapshot, Repository, ScanRun  # noqa: E402
from core.worker_protocol import is_job_ready  # noqa: E402
from orchestrator.extraction import extract_repository  # noqa: E402
from worker.main import process_one_job  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")

NPM_LOCK_CONTENT = (
    Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner" / "npm_lodash_package-lock.json"
).read_bytes()


class _FakeAuth:
    def get_token(self, now=None) -> str:
        return "fake-token"


class _FakeWorkerThread(threading.Thread):
    def __init__(self, staging_dir: Path) -> None:
        super().__init__(daemon=True)
        self.staging_dir = staging_dir
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            if is_job_ready(self.staging_dir):
                process_one_job(self.staging_dir, binary_path="/unused", db_cache_dir="/unused")
            time.sleep(0.05)

    def stop(self) -> None:
        self._stop.set()


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM component_snapshots"))
        conn.execute(text("DELETE FROM scan_runs"))
        conn.execute(text("DELETE FROM repositories"))
    yield


@pytest.fixture()
def worker_thread(tmp_path):
    thread = _FakeWorkerThread(tmp_path)
    thread.start()
    yield tmp_path
    thread.stop()


def _make_repo(session, repo_id: int = 1, full_name: str = "acme/widgets") -> Repository:
    repo = Repository(
        github_repo_id=repo_id, full_name=full_name, owner=full_name.split("/")[0], name=full_name.split("/")[1],
        default_branch="main", visibility="private", archived=False, fork=False, is_active=True,
    )
    session.add(repo)
    session.flush()
    return repo


def _mock_github_client(tree_entries, blob_contents) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/git/trees/" in path:
            return httpx.Response(200, json={"tree": tree_entries, "truncated": False})
        if "/git/blobs/" in path:
            blob_sha = path.rsplit("/", 1)[-1]
            content = blob_contents.get(blob_sha)
            if content is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(content).decode()})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_extract_repository_parses_real_npm_lockfile_via_worker_protocol(engine, worker_thread):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        repo = _make_repo(session)
        session.commit()
        repo_id = repo.github_repo_id

    tree = [{"path": "package-lock.json", "type": "blob", "mode": "100644", "sha": "blobsha1"}]
    client = _mock_github_client(tree, {"blobsha1": NPM_LOCK_CONTENT})

    with session_factory() as session:
        repo = session.get(Repository, repo_id)
        scan_run = extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo, http_client=client)
        session.commit()

    assert scan_run.status == "success"
    with session_factory() as session:
        snapshots = session.query(ComponentSnapshot).filter_by(repo_id=repo_id, is_current=True).all()
    assert len(snapshots) == 1
    assert snapshots[0].name == "lodash"
    assert snapshots[0].version == "4.17.15"


def test_extract_repository_skips_unchanged_blob(engine, worker_thread):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        repo = _make_repo(session)
        session.commit()
        repo_id = repo.github_repo_id

    tree = [{"path": "package-lock.json", "type": "blob", "mode": "100644", "sha": "blobsha1"}]
    client = _mock_github_client(tree, {"blobsha1": NPM_LOCK_CONTENT})

    with session_factory() as session:
        repo = session.get(Repository, repo_id)
        extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo, http_client=client)
        session.commit()

    with session_factory() as session:
        repo = session.get(Repository, repo_id)
        scan_run2 = extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo, http_client=client)
        session.commit()

    assert scan_run2.details["files"][0]["status"] == "unchanged"
    with session_factory() as session:
        count = session.query(ComponentSnapshot).filter_by(repo_id=repo_id).count()
    assert count == 1


def test_extract_repository_content_addressed_cache_cross_repo(engine, worker_thread):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_repo(session, repo_id=1, full_name="acme/widgets")
        _make_repo(session, repo_id=2, full_name="acme/other")
        session.commit()

    tree = [{"path": "package-lock.json", "type": "blob", "mode": "100644", "sha": "shared-blob-sha"}]
    client = _mock_github_client(tree, {"shared-blob-sha": NPM_LOCK_CONTENT})

    with session_factory() as session:
        repo1 = session.get(Repository, 1)
        extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo1, http_client=client)
        session.commit()

    with session_factory() as session:
        repo2 = session.get(Repository, 2)
        scan_run2 = extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo2, http_client=client)
        session.commit()

    assert scan_run2.details["files"][0]["status"] == "cache_hit"
    with session_factory() as session:
        snap = session.query(ComponentSnapshot).filter_by(repo_id=2, is_current=True).one()
    assert snap.name == "lodash"


def test_extract_repository_component_collapse_triggers_needs_review(engine, worker_thread):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        repo = _make_repo(session)
        repo_id = repo.github_repo_id
        run0 = ScanRun(run_type="extraction", repo_id=repo_id, status="success")
        session.add(run0)
        session.flush()
        for i in range(10):
            session.add(
                ComponentSnapshot(
                    repo_id=repo_id, lockfile_path="package-lock.json", lockfile_blob_sha="old-sha",
                    scan_run_id=run0.id, ecosystem="npm", name=f"pkg-{i}", version="1.0.0",
                    scope="prod", relation="direct", is_current=True,
                )
            )
        session.commit()

    # Yeni tarama tek bilesen donduruyor (NPM_LOCK_CONTENT=sadece lodash) -> %90 dusus.
    tree = [{"path": "package-lock.json", "type": "blob", "mode": "100644", "sha": "new-sha"}]
    client = _mock_github_client(tree, {"new-sha": NPM_LOCK_CONTENT})

    with session_factory() as session:
        repo = session.get(Repository, repo_id)
        scan_run = extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo, http_client=client)
        session.commit()

    assert scan_run.status == "needs_review"
    with session_factory() as session:
        current = session.query(ComponentSnapshot).filter_by(repo_id=repo_id, is_current=True).all()
    assert len(current) == 10  # ESKI envanter KORUNDU


def test_extract_repository_monorepo_isolation_one_lockfile_failure(engine, worker_thread):
    """master_prompt.md 3.2.8: bir lockfile parse edilemezse yalnizca onun
    bulgulari etkilenir, digerleri normal islenir."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        repo = _make_repo(session)
        session.commit()
        repo_id = repo.github_repo_id

    tree = [
        {"path": "services/api/package-lock.json", "type": "blob", "mode": "100644", "sha": "good-sha"},
        {"path": "services/broken/poetry.lock", "type": "blob", "mode": "100644", "sha": "bad-sha"},
    ]
    # bad-sha icin blob icerigi HIC verilmiyor -> blob_fetch_failed
    client = _mock_github_client(tree, {"good-sha": NPM_LOCK_CONTENT})

    with session_factory() as session:
        repo = session.get(Repository, repo_id)
        scan_run = extract_repository(session, "https://api.github.com", _FakeAuth(), worker_thread, repo, http_client=client)
        session.commit()

    assert scan_run.status == "partial"
    with session_factory() as session:
        good_snaps = session.query(ComponentSnapshot).filter_by(repo_id=repo_id, lockfile_path="services/api/package-lock.json").all()
    assert len(good_snaps) == 1
    assert good_snaps[0].name == "lodash"
