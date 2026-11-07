"""orchestrator/discovery.py upsert_repositories testleri (PostgreSQL JSONB +
ON CONFLICT kullanir, gercek Postgres gerekir)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.discovery import upsert_repositories  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


def _repo(repo_id: int, archived: bool = False) -> dict:
    return {
        "id": repo_id,
        "full_name": f"acme/repo-{repo_id}",
        "owner": {"login": "acme"},
        "name": f"repo-{repo_id}",
        "default_branch": "main",
        "visibility": "private",
        "private": True,
        "archived": archived,
        "fork": False,
    }


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean_repositories_table(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM repositories"))
    yield


def test_upsert_inserts_new_repos(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        count = upsert_repositories(session, [_repo(1), _repo(2)])
        session.commit()
    assert count == 2

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT github_repo_id, is_active FROM repositories ORDER BY github_repo_id")).all()
    assert [r[0] for r in rows] == [1, 2]
    assert all(r[1] for r in rows)


def test_upsert_marks_disappeared_repos_inactive_not_deleted(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        upsert_repositories(session, [_repo(1), _repo(2)])
        session.commit()

    # Ikinci discovery turunda repo 2 installation'dan kayboldu (erisim kaldirildi).
    with session_factory() as session:
        upsert_repositories(session, [_repo(1)])
        session.commit()

    with engine.connect() as conn:
        rows = {r[0]: r[1] for r in conn.execute(text("SELECT github_repo_id, is_active FROM repositories")).all()}
    assert rows == {1: True, 2: False}  # silinmedi, sadece pasif


def test_upsert_updates_changed_fields(engine):
    session_factory = sessionmaker(bind=engine, future=True)
    with session_factory() as session:
        upsert_repositories(session, [_repo(1, archived=False)])
        session.commit()
    with session_factory() as session:
        upsert_repositories(session, [_repo(1, archived=True)])
        session.commit()

    with engine.connect() as conn:
        archived = conn.execute(text("SELECT archived FROM repositories WHERE github_repo_id=1")).scalar_one()
    assert archived is True
