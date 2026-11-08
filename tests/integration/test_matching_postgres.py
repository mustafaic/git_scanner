"""orchestrator/matching.py testleri. Gercek Postgres gerektirir.

Worker'i taklit eden thread GERCEK osv-scanner binary'sini CAGIRMAZ
(orchestrator imajinda yok, bilerek -- binary sadece worker imajinda,
bkz. deploy/Dockerfile.worker ve docs/VERIFIED_FACTS.md'deki canli worker
izolasyon testi). Bunun yerine, GERCEK osv-scanner v2.7.0 ile uretilmis
golden fixture ciktisini dogrudan yazar -- boylece matching.py'nin
KORELASYON/INGEST mantigi gercek veriyle test edilir, binary'nin kendisi
ayri test edildi.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.models import AdvisoryMirrorSync, ComponentSnapshot, Finding, Repository, ScanRun  # noqa: E402
from core.worker_protocol import is_job_ready, read_job, write_result  # noqa: E402
from orchestrator.matching import is_advisory_data_fresh, run_daily_match, run_immediate_match  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner"
LODASH_OSV_OUTPUT = (FIXTURES / "golden_npm_lodash_output.json").read_bytes()
LODASH_LOCKFILE = (FIXTURES / "npm_lodash_package-lock.json").read_bytes()


class _StubWorkerThread(threading.Thread):
    """osv_scan isleri icin ONCEDEN BELIRLENMIS (gercek binary ile uretilmis)
    golden ciktiyi doner -- subprocess/binary'ye ihtiyac yok."""

    def __init__(self, staging_dir: Path, canned_output: bytes = LODASH_OSV_OUTPUT, exit_code: int = 1) -> None:
        super().__init__(daemon=True)
        self.staging_dir = staging_dir
        self.canned_output = canned_output
        self.exit_code = exit_code
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            if is_job_ready(self.staging_dir):
                job = read_job(self.staging_dir)
                if job.job_kind == "osv_scan":
                    write_result(self.staging_dir, exit_code=self.exit_code, stdout=self.canned_output, stderr=b"")
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
        conn.execute(text("DELETE FROM finding_sources"))
        conn.execute(text("DELETE FROM finding_events"))
        conn.execute(text("DELETE FROM findings"))
        conn.execute(text("DELETE FROM component_snapshots"))
        conn.execute(text("DELETE FROM scan_runs"))
        conn.execute(text("DELETE FROM advisory_mirror_syncs"))
        conn.execute(text("DELETE FROM repositories"))
    yield


@pytest.fixture()
def stub_worker(tmp_path):
    thread = _StubWorkerThread(tmp_path)
    thread.start()
    yield tmp_path
    thread.stop()


def _mark_fresh(session):
    for source in ("kev", "epss"):
        session.add(AdvisoryMirrorSync(source=source, succeeded=True))
    session.commit()


def _mark_stale(session):
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)
    for source in ("kev", "epss"):
        sync = AdvisoryMirrorSync(source=source, succeeded=True)
        session.add(sync)
    session.commit()
    session.execute(text("UPDATE advisory_mirror_syncs SET synced_at = :old"), {"old": old})
    session.commit()


def test_is_advisory_data_fresh_true_when_recent(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        _mark_fresh(session)
        assert is_advisory_data_fresh(session, max_age_seconds=3600) is True


def test_is_advisory_data_fresh_false_when_missing(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        assert is_advisory_data_fresh(session, max_age_seconds=3600) is False


def test_is_advisory_data_fresh_false_when_stale(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        _mark_stale(session)
        assert is_advisory_data_fresh(session, max_age_seconds=3600) is False


def _make_repo_with_lodash_snapshot(session, repo_id=1):
    repo = Repository(
        github_repo_id=repo_id, full_name=f"acme/widgets-{repo_id}", owner="acme", name=f"widgets-{repo_id}",
        default_branch="main", visibility="private", archived=False, fork=False, is_active=True,
    )
    session.add(repo)
    extraction_run = ScanRun(run_type="extraction", repo_id=repo_id, status="success")
    session.add(extraction_run)
    session.flush()
    session.add(
        ComponentSnapshot(
            repo_id=repo_id, lockfile_path="package-lock.json", lockfile_blob_sha="blob-1",
            scan_run_id=extraction_run.id, ecosystem="npm", name="lodash", version="4.17.15",
            scope="prod", relation="direct", purl="pkg:npm/lodash@4.17.15", is_current=True,
        )
    )
    session.commit()


def test_run_immediate_match_creates_findings_from_real_golden_output(engine, stub_worker):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_repo_with_lodash_snapshot(session)

    with session_factory() as session:
        scan_run = run_immediate_match(
            session, stub_worker, "/unused", "/unused", repo_id=1, lockfile_path="package-lock.json",
            lockfile_blob_sha="blob-1", lockfile_content=LODASH_LOCKFILE, db_is_fresh=True, is_baseline=True,
        )
        session.commit()

    assert scan_run.status == "success"
    assert scan_run.details["created"] == 5
    with session_factory() as session:
        findings = session.query(Finding).filter_by(repo_id=1).all()
    assert len(findings) == 5
    assert all(f.baseline for f in findings)


def test_run_immediate_match_stale_db_does_not_resolve(engine, tmp_path):
    """master_prompt.md 4.6: DB bayatsa Hat B basarili olsa da bulgu kapanmaz."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)

    fresh_worker = _StubWorkerThread(tmp_path, canned_output=LODASH_OSV_OUTPUT, exit_code=1)
    fresh_worker.start()
    try:
        with session_factory() as session:
            _make_repo_with_lodash_snapshot(session)
            run_immediate_match(
                session, tmp_path, "/x", "/x", 1, "package-lock.json", "blob-1", LODASH_LOCKFILE,
                db_is_fresh=True, is_baseline=True,
            )
            session.commit()
    finally:
        fresh_worker.stop()

    with session_factory() as session:
        findings = session.query(Finding).filter_by(repo_id=1).all()
    assert len(findings) == 5
    assert all(f.lifecycle_status == "OPEN" for f in findings)

    # Simdi: paket upgrade edildi (artik zafiyet yok) AMA DB BAYAT.
    clean_output = (FIXTURES / "golden_npm_clean_output.json").read_bytes()
    stale_worker = _StubWorkerThread(tmp_path, canned_output=clean_output, exit_code=0)
    stale_worker.start()
    try:
        with session_factory() as session:
            scan_run = run_immediate_match(
                session, tmp_path, "/x", "/x", 1, "package-lock.json", "blob-1", LODASH_LOCKFILE,
                db_is_fresh=False, is_baseline=False,
            )
            session.commit()
    finally:
        stale_worker.stop()

    assert scan_run.details["db_fresh"] is False
    with session_factory() as session:
        findings = session.query(Finding).filter_by(repo_id=1).all()
    # HICBIRI RESOLVED olmamali -- DB bayat (kural: hata senaryolarinda bulgu kapanmaz).
    assert all(f.lifecycle_status == "OPEN" for f in findings)


def test_run_daily_match_distributes_to_all_repos_sharing_component(engine, stub_worker):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        _make_repo_with_lodash_snapshot(session, repo_id=1)
        _make_repo_with_lodash_snapshot(session, repo_id=2)

    with session_factory() as session:
        scan_run = run_daily_match(session, stub_worker, "/unused", "/unused", db_is_fresh=True)
        session.commit()

    assert scan_run.status == "success"
    assert scan_run.details["unique_components"] == 1  # ayni lodash@4.17.15 iki repoda
    assert scan_run.details["created"] == 10  # 5 zafiyet x 2 repo
    with session_factory() as session:
        repo1_findings = session.query(Finding).filter_by(repo_id=1).count()
        repo2_findings = session.query(Finding).filter_by(repo_id=2).count()
    assert repo1_findings == 5
    assert repo2_findings == 5


def test_run_daily_match_no_components_is_noop(engine, stub_worker):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        scan_run = run_daily_match(session, stub_worker, "/unused", "/unused", db_is_fresh=True)
        session.commit()
    assert scan_run.status == "success"
    assert scan_run.details == {"unique_components": 0}
