from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.models import Job, ScanTrigger  # noqa: E402
from orchestrator.triggers import consume_triggers_and_enqueue, record_trigger  # noqa: E402

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
        conn.execute(text("DELETE FROM jobs"))
        conn.execute(text("DELETE FROM scan_triggers"))
    yield


def test_multiple_triggers_same_repo_debounce_to_one_job(engine):
    """master_prompt.md 3.5: 'ayni repo icin kisa pencerede gelen
    tetikleyiciler tek ise birlesir'."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    now = dt.datetime.now(dt.timezone.utc)
    with session_factory() as session:
        for _ in range(5):  # ardi ardina 5 push
            record_trigger(session, repo_id=42, source="poll")
        session.commit()

        enqueued = consume_triggers_and_enqueue(session, debounce_window_seconds=20, now=now)
        session.commit()

    assert enqueued == 1
    with session_factory() as session:
        jobs = session.query(Job).filter_by(job_type="repo_check", repo_id=42).all()
    assert len(jobs) == 1


def test_different_repos_get_separate_jobs(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    now = dt.datetime.now(dt.timezone.utc)
    with session_factory() as session:
        record_trigger(session, repo_id=1, source="poll")
        record_trigger(session, repo_id=2, source="manual")
        session.commit()
        enqueued = consume_triggers_and_enqueue(session, debounce_window_seconds=20, now=now)
        session.commit()

    assert enqueued == 2
    with session_factory() as session:
        repo_ids = {j.repo_id for j in session.query(Job).all()}
    assert repo_ids == {1, 2}


def test_triggers_marked_consumed_not_reprocessed(engine):
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    now = dt.datetime.now(dt.timezone.utc)
    with session_factory() as session:
        record_trigger(session, repo_id=1, source="poll")
        session.commit()
        consume_triggers_and_enqueue(session, debounce_window_seconds=20, now=now)
        session.commit()

    with session_factory() as session:
        unconsumed = session.query(ScanTrigger).filter(ScanTrigger.consumed_at.is_(None)).count()
    assert unconsumed == 0

    # Ikinci cagri: yeni tetikleyici yok -> yeni is eklenmemeli.
    with session_factory() as session:
        enqueued_again = consume_triggers_and_enqueue(session, debounce_window_seconds=20, now=now)
        session.commit()
    assert enqueued_again == 0


def test_new_trigger_after_debounce_window_creates_new_job(engine):
    """Ayni repo icin FARKLI debounce penceresinde gelen tetikleyici YENI
    bir is uretmeli (idempotency_key pencere numarasini icerir)."""
    session_factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    t0 = dt.datetime.now(dt.timezone.utc)
    t1 = t0 + dt.timedelta(seconds=25)  # farkli 20s pencere

    with session_factory() as session:
        record_trigger(session, repo_id=1, source="poll")
        session.commit()
        consume_triggers_and_enqueue(session, debounce_window_seconds=20, now=t0)
        session.commit()

    with session_factory() as session:
        record_trigger(session, repo_id=1, source="poll")
        session.commit()
        enqueued = consume_triggers_and_enqueue(session, debounce_window_seconds=20, now=t1)
        session.commit()

    assert enqueued == 1
    with session_factory() as session:
        count = session.query(Job).filter_by(job_type="repo_check", repo_id=1).count()
    assert count == 2
