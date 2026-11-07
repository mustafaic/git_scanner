from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.mirror import MirrorSyncResult, apply_mirror_result  # noqa: E402

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
        conn.execute(text("DELETE FROM kev_entries"))
        conn.execute(text("DELETE FROM epss_scores"))
        conn.execute(text("DELETE FROM advisory_mirror_syncs"))
    yield


def test_successful_kev_sync_upserts_entries_and_records_sync(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    result = MirrorSyncResult(
        "kev", True, item_count=2, checksum="abc",
        payload=[
            {"cve_id": "CVE-2021-44228", "date_added": "2021-12-10", "vulnerability_name": "Log4Shell"},
            {"cve_id": "CVE-2020-1234", "date_added": "2020-05-01", "vulnerability_name": "Widget Overflow"},
        ],
    )
    with session_factory() as session:
        apply_mirror_result(session, result)
        session.commit()

    with engine.connect() as conn:
        kev_count = conn.execute(text("SELECT count(*) FROM kev_entries")).scalar_one()
        sync_count = conn.execute(text("SELECT count(*) FROM advisory_mirror_syncs WHERE source='kev'")).scalar_one()
    assert kev_count == 2
    assert sync_count == 1


def test_kev_upsert_updates_existing_entry(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        apply_mirror_result(
            session,
            MirrorSyncResult("kev", True, payload=[{"cve_id": "CVE-X", "date_added": "2020-01-01", "vulnerability_name": "Old name"}]),
        )
        session.commit()
    with session_factory() as session:
        apply_mirror_result(
            session,
            MirrorSyncResult("kev", True, payload=[{"cve_id": "CVE-X", "date_added": "2020-01-01", "vulnerability_name": "New name"}]),
        )
        session.commit()

    with engine.connect() as conn:
        count = conn.execute(text("SELECT count(*) FROM kev_entries")).scalar_one()
        name = conn.execute(text("SELECT vulnerability_name FROM kev_entries WHERE cve_id='CVE-X'")).scalar_one()
    assert count == 1
    assert name == "New name"


def test_epss_sync_upserts_scores(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    result = MirrorSyncResult(
        "epss", True, payload=[{"cve_id": "CVE-2021-44228", "score": 0.9452, "percentile": 0.9999}]
    )
    with session_factory() as session:
        apply_mirror_result(session, result)
        session.commit()

    with engine.connect() as conn:
        score = conn.execute(text("SELECT score FROM epss_scores WHERE cve_id='CVE-2021-44228'")).scalar_one()
    assert float(score) == pytest.approx(0.9452)


def test_failed_sync_records_failure_but_touches_no_data_tables(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    result = MirrorSyncResult("kev", False, error="HTTP 403")
    with session_factory() as session:
        apply_mirror_result(session, result)
        session.commit()

    with engine.connect() as conn:
        kev_count = conn.execute(text("SELECT count(*) FROM kev_entries")).scalar_one()
        sync_row = conn.execute(text("SELECT succeeded, error FROM advisory_mirror_syncs WHERE source='kev'")).one()
    assert kev_count == 0
    assert sync_row[0] is False
    assert sync_row[1] == "HTTP 403"
