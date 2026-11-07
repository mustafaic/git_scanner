"""Gercek Postgres'e karsi is kuyrugu testleri (master_prompt.md Asama 1
kabul kriteri: "orchestrator kill edilip yeniden baslayinca job'lar
kaybolmaz/cift islenmez").

Calistirmadan once sema migrate edilmis olmali (alembic upgrade head).
DATABASE_URL ortam degiskeni gercek bir Postgres'e isaret etmeli; yoksa
testler atlanir (host'ta calistirilmaya calisildiginda CI/Docker disinda
patlamasin).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.jobs import build_idempotency_key, claim_next_job, complete_job, enqueue_job  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean_jobs_table(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM jobs"))
    yield


def test_enqueue_job_is_idempotent(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    key = build_idempotency_key("repo_sync", 1, "sha-a")
    with session_factory() as session:
        first_id = enqueue_job(session, "repo_sync", key, repo_id=1)
        session.commit()
    with session_factory() as session:
        second_id = enqueue_job(session, "repo_sync", key, repo_id=1)
        session.commit()

    assert first_id is not None
    assert second_id is None

    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM jobs WHERE idempotency_key=:key"), {"key": key}
        ).scalar_one()
    assert count == 1


def test_concurrent_claim_gives_each_job_to_exactly_one_worker(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        for i in range(20):
            key = build_idempotency_key("repo_sync", i, "sha")
            enqueue_job(session, "repo_sync", key, repo_id=i)
        session.commit()

    claimed_by: dict[int, str] = {}
    lock = threading.Lock()
    errors: list[str] = []

    def worker(worker_name: str) -> None:
        local_engine = create_engine(DATABASE_URL, future=True)
        local_session_factory = sessionmaker(bind=local_engine, future=True)
        try:
            while True:
                with local_session_factory() as session:
                    job = claim_next_job(session, ["repo_sync"], lock_duration_seconds=60, locked_by=worker_name)
                    job_id = job.id if job is not None else None
                    session.commit()
                if job_id is None:
                    break
                with lock:
                    if job_id in claimed_by:
                        errors.append(f"job {job_id} iki kez claim edildi: {claimed_by[job_id]} ve {worker_name}")
                    claimed_by[job_id] = worker_name
                with local_session_factory() as session:
                    complete_job(session, job_id)
                    session.commit()
        finally:
            local_engine.dispose()

    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(claimed_by) == 20


def test_crash_recovery_requeues_after_lock_expires(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    key = build_idempotency_key("repo_sync", 999, "sha-crash")

    with session_factory() as session:
        enqueue_job(session, "repo_sync", key, repo_id=999)
        session.commit()

    # worker-1 isi claim eder ama "coker" (hic complete_job cagirmaz).
    with session_factory() as session:
        job = claim_next_job(session, ["repo_sync"], lock_duration_seconds=1, locked_by="worker-1")
        assert job is not None
        first_job_id = job.id
        session.commit()

    # Kilit suresi dolmadan: baska worker ayni isi ALAMAMALI.
    with session_factory() as session:
        immediate = claim_next_job(session, ["repo_sync"], lock_duration_seconds=1, locked_by="worker-2")
        session.commit()
    assert immediate is None

    time.sleep(1.2)  # locked_until suresi gecsin (crash-recovery penceresi)

    # Simdi worker-2 (orchestrator "yeniden baslatildi" gibi) isi yeniden claim edebilmeli.
    with session_factory() as session:
        recovered = claim_next_job(session, ["repo_sync"], lock_duration_seconds=60, locked_by="worker-2")
        assert recovered is not None
        assert recovered.id == first_job_id
        assert recovered.attempts == 2  # ilk claim + crash-recovery claim
        session.commit()
