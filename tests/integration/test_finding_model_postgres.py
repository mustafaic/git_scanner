"""core/finding_model.py ingest_lockfile_findings() testleri -- gercek
Postgres gerektirir (Finding/FindingEvent/FindingSource modelleri)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.finding_model import (  # noqa: E402
    STATUS_OPEN,
    STATUS_REOPENED,
    STATUS_RESOLVED,
    BuiltFinding,
    FixRecommendation,
    SeverityResult,
    ingest_lockfile_findings,
)
from core.models import Finding, ScanRun  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean_tables(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM finding_sources"))
        conn.execute(text("DELETE FROM finding_events"))
        conn.execute(text("DELETE FROM findings"))
        conn.execute(text("DELETE FROM scan_runs"))
    yield


def _make_scan_run(session, status="success") -> int:
    run = ScanRun(run_type="immediate_match", repo_id=1, status=status)
    session.add(run)
    session.flush()
    return run.id


def _bf(canonical_id="GHSA-xxxx", purl="pkg:npm/lodash@4.17.15", version="4.17.15") -> BuiltFinding:
    return BuiltFinding(
        repo_id=1,
        lockfile_path="package-lock.json",
        ecosystem="npm",
        purl=purl,
        package_name="lodash",
        version=version,
        scope="prod",
        relation="direct",
        canonical_vulnerability_id=canonical_id,
        aliases=["CVE-0000-0001"],
        severity=SeverityResult(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_score=9.8, source="cvss_v3"),
        fix=FixRecommendation(status="PATCH_AVAILABLE", version="4.17.19"),
        verification_status="VERIFIED",
        needs_review_reason=None,
    )


def test_new_finding_is_created_as_open_and_baseline(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run_id = _make_scan_run(session)
        stats = ingest_lockfile_findings(
            session, repo_id=1, lockfile_path="package-lock.json", scan_run_id=run_id,
            scan_run_status="success", built_findings=[_bf()], is_baseline=True,
        )
        session.commit()
    assert stats == {"created": 1, "updated": 0, "resolved": 0, "reopened": 0}

    with session_factory() as session:
        finding = session.query(Finding).one()
        assert finding.lifecycle_status == STATUS_OPEN
        assert finding.baseline is True


def test_unchanged_finding_is_updated_not_duplicated(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run1, "success", [_bf()], is_baseline=True)
        session.commit()
    with session_factory() as session:
        run2 = _make_scan_run(session)
        stats = ingest_lockfile_findings(session, 1, "package-lock.json", run2, "success", [_bf()], is_baseline=False)
        session.commit()
    assert stats == {"created": 0, "updated": 1, "resolved": 0, "reopened": 0}
    with session_factory() as session:
        assert session.query(Finding).count() == 1


def test_finding_resolved_when_absent_on_successful_scan(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run1, "success", [_bf()], is_baseline=True)
        session.commit()

    with session_factory() as session:
        run2 = _make_scan_run(session, status="success")
        # Ayni lockfile icin yeni basarili tarama, ama bu sefer ZAFIYET YOK (upgrade edilmis).
        stats = ingest_lockfile_findings(session, 1, "package-lock.json", run2, "success", [], is_baseline=False)
        session.commit()
    assert stats["resolved"] == 1
    with session_factory() as session:
        finding = session.query(Finding).one()
        assert finding.lifecycle_status == STATUS_RESOLVED
        assert finding.resolved_at is not None


def test_finding_not_resolved_on_partial_or_failed_scan(engine):
    """master_prompt.md 4.3: hata senaryolarinda HICBIR bulgu kapanmaz."""
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run1, "success", [_bf()], is_baseline=True)
        session.commit()

    for bad_status in ("partial", "failed", "needs_review"):
        with session_factory() as session:
            run2 = _make_scan_run(session, status=bad_status)
            stats = ingest_lockfile_findings(session, 1, "package-lock.json", run2, bad_status, [], is_baseline=False)
            session.commit()
        assert stats["resolved"] == 0, f"status={bad_status} ile bulgu kapanmamali"

    with session_factory() as session:
        finding = session.query(Finding).one()
        assert finding.lifecycle_status == STATUS_OPEN  # hala acik


def test_resolved_finding_reopens_when_seen_again(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run1, "success", [_bf()], is_baseline=True)
        session.commit()
    with session_factory() as session:
        run2 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run2, "success", [], is_baseline=False)
        session.commit()

    with session_factory() as session:
        finding = session.query(Finding).one()
        assert finding.lifecycle_status == STATUS_RESOLVED

    # Ayni zafiyet tekrar ortaya cikti (ornegin downgrade edildi).
    with session_factory() as session:
        run3 = _make_scan_run(session)
        stats = ingest_lockfile_findings(session, 1, "package-lock.json", run3, "success", [_bf()], is_baseline=False)
        session.commit()
    assert stats["reopened"] == 1
    with session_factory() as session:
        finding = session.query(Finding).one()
        assert finding.lifecycle_status == STATUS_REOPENED
        assert finding.resolved_at is None


def test_finding_events_are_append_only_audit_trail(engine):
    from core.models import FindingEvent

    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run1, "success", [_bf()], is_baseline=True)
        session.commit()
    with session_factory() as session:
        run2 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run2, "success", [], is_baseline=False)
        session.commit()

    with session_factory() as session:
        events = session.query(FindingEvent).order_by(FindingEvent.id).all()
    assert [e.event_type for e in events] == ["CREATED", "RESOLVED"]


def test_different_repos_do_not_resolve_each_others_findings(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_lockfile_findings(session, 1, "package-lock.json", run1, "success", [_bf()], is_baseline=True)
        session.commit()

    # repo_id=2 icin ayri bir bulgu, farkli lockfile_path/repo -- reconciliation
    # sadece (repo_id, lockfile_path) kombinasyonuna bakmali.
    with session_factory() as session:
        run2 = ScanRun(run_type="immediate_match", repo_id=2, status="success")
        session.add(run2)
        session.flush()
        stats = ingest_lockfile_findings(session, 2, "other/package-lock.json", run2.id, "success", [], is_baseline=False)
        session.commit()
    assert stats["resolved"] == 0  # repo 1'in bulgusuna dokunulmamali

    with session_factory() as session:
        finding = session.query(Finding).filter_by(repo_id=1).one()
        assert finding.lifecycle_status == STATUS_OPEN
