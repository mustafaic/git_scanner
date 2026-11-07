from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core import db as core_db  # noqa: E402
from core.config import Settings  # noqa: E402
from watchdog.main import check_and_ping  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


@pytest.fixture(autouse=True)
def _init_core_db_and_clean():
    engine = create_engine(DATABASE_URL, future=True)
    core_db.init_engine(DATABASE_URL)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM system_heartbeats"))
    yield
    engine.dispose()


def _insert_heartbeat(age_seconds: float) -> None:
    engine = create_engine(DATABASE_URL, future=True)
    last_success_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=age_seconds)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO system_heartbeats (component, last_success_at, detail) "
                "VALUES ('orchestrator', :ts, '{}'::jsonb)"
            ),
            {"ts": last_success_at},
        )
    engine.dispose()


def _settings(heartbeat_url=None) -> Settings:
    return Settings(database_url=DATABASE_URL, heartbeat_stale_threshold_seconds=60, heartbeat_url=heartbeat_url)


def test_no_heartbeat_row_is_unhealthy():
    healthy = check_and_ping(_settings())
    assert healthy is False


def test_fresh_heartbeat_is_healthy():
    _insert_heartbeat(age_seconds=5)
    healthy = check_and_ping(_settings())
    assert healthy is True


def test_stale_heartbeat_is_unhealthy():
    _insert_heartbeat(age_seconds=600)
    healthy = check_and_ping(_settings())
    assert healthy is False


def test_healthy_with_heartbeat_url_pings_it():
    _insert_heartbeat(age_seconds=5)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    healthy = check_and_ping(_settings(heartbeat_url="http://heartbeat.internal/ping"), http_client=client)
    assert healthy is True
    assert calls == ["http://heartbeat.internal/ping"]
