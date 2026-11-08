"""core/secret_finding_model.py testleri -- gercek Postgres gerektirir."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.gitleaks import NormalizedSecretFinding  # noqa: E402
from core.models import ScanRun, SecretFinding  # noqa: E402
from core.secret_finding_model import (  # noqa: E402
    STATUS_OPEN,
    STATUS_ROTATED,
    confirm_rotation,
    ingest_secret_findings,
    suppress_finding,
)

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM secret_finding_events"))
        conn.execute(text("DELETE FROM secret_findings"))
        conn.execute(text("DELETE FROM scan_runs"))
    yield


def _nf(rule_id="aws-key", file_path="config.ini", secret="fake-secret-1", commit="sha1", line=5) -> NormalizedSecretFinding:
    import hashlib

    h = hashlib.sha256(secret.encode()).hexdigest()
    fp = hashlib.sha256(f"{rule_id}:{file_path}:{h}".encode()).hexdigest()
    return NormalizedSecretFinding(
        rule_id=rule_id, file_path=file_path, commit_sha=commit, line_number=line,
        entropy=4.5, tags=[], gitleaks_fingerprint=f"{commit}:{file_path}:{rule_id}:{line}",
        custom_fingerprint=fp, secret_content_hash=h,
    )


def _make_scan_run(session, repo_id=1) -> int:
    run = ScanRun(run_type="secret_scan", repo_id=repo_id, scanner_name="gitleaks", status="success")
    session.add(run)
    session.flush()
    return run.id


def test_new_secret_finding_created_as_open(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        run_id = _make_scan_run(session)
        stats, _created = ingest_secret_findings(session, 1, run_id, [_nf()], is_baseline=True, is_full_scan=False)
        session.commit()
    assert stats == {"created": 1, "updated": 0, "marked_absent": 0}
    with session_factory() as session:
        finding = session.query(SecretFinding).one()
        assert finding.lifecycle_status == STATUS_OPEN
        assert finding.present_in_current_code is True
        assert finding.baseline is True


def test_incremental_scan_does_not_mark_absent_findings_not_seen(engine):
    """master_prompt.md 4.4: incremental tarama eski commit'leri yeniden
    gormez -- 'bu turda yok' demek 'koddan kalkti' DEMEK DEGILDIR."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run1, [_nf()], is_baseline=True, is_full_scan=False)
        session.commit()

    with session_factory() as session:
        run2 = _make_scan_run(session)
        # Ikinci (incremental) taramada bu secret GORUNMUYOR (yeni commit'lerde yok).
        stats, _created = ingest_secret_findings(session, 1, run2, [], is_baseline=False, is_full_scan=False)
        session.commit()
    assert stats["marked_absent"] == 0
    with session_factory() as session:
        finding = session.query(SecretFinding).one()
        assert finding.present_in_current_code is True  # DEGISMEDI


def test_full_scan_marks_absent_but_does_not_resolve(engine):
    """master_prompt.md 4.4: koddan silinince RESOLVED OLMAZ -- present_in_current_code
    False olur ama lifecycle_status OPEN kalir."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run1, [_nf()], is_baseline=True, is_full_scan=False)
        session.commit()

    with session_factory() as session:
        run2 = _make_scan_run(session)
        # Secret koddan kaldirildi, TAM tarama bunu tespit ediyor.
        stats, _created = ingest_secret_findings(session, 1, run2, [], is_baseline=False, is_full_scan=True)
        session.commit()
    assert stats["marked_absent"] == 1
    with session_factory() as session:
        finding = session.query(SecretFinding).one()
        assert finding.present_in_current_code is False
        assert finding.lifecycle_status == STATUS_OPEN  # HALA ACIK -- kural budur


def test_confirm_rotation_requires_note(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run1, [_nf()], is_baseline=True, is_full_scan=False)
        session.commit()
        finding_id = session.query(SecretFinding).one().id

    with session_factory() as session:
        with pytest.raises(ValueError):
            confirm_rotation(session, finding_id, actor_username="admin", note="")
        session.rollback()


def test_confirm_rotation_closes_finding_with_reason(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run1, [_nf()], is_baseline=True, is_full_scan=False)
        session.commit()
        finding_id = session.query(SecretFinding).one().id

    with session_factory() as session:
        confirm_rotation(session, finding_id, actor_username="admin", note="AWS key rotated 2026-11-08")
        session.commit()

    with session_factory() as session:
        finding = session.get(SecretFinding, finding_id)
        assert finding.lifecycle_status == STATUS_ROTATED
        assert finding.rotated_at is not None
        assert finding.rotation_note == "AWS key rotated 2026-11-08"

    from core.models import SecretFindingEvent
    with session_factory() as session:
        events = session.query(SecretFindingEvent).filter_by(secret_finding_id=finding_id).all()
    event_types = [e.event_type for e in events]
    assert "CREATED" in event_types
    assert "ROTATED" in event_types


def test_reappearing_secret_logs_event_but_still_open(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    with session_factory() as session:
        run1 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run1, [_nf()], is_baseline=True, is_full_scan=False)
        session.commit()
    with session_factory() as session:
        run2 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run2, [], is_baseline=False, is_full_scan=True)
        session.commit()
    with session_factory() as session:
        finding_id = session.query(SecretFinding).one().id
        assert session.get(SecretFinding, finding_id).present_in_current_code is False

    with session_factory() as session:
        run3 = _make_scan_run(session)
        ingest_secret_findings(session, 1, run3, [_nf()], is_baseline=False, is_full_scan=False)
        session.commit()
    with session_factory() as session:
        finding = session.get(SecretFinding, finding_id)
        assert finding.present_in_current_code is True
