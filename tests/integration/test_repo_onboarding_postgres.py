"""Faz 1 (2026-11-10, panelden GitHub token ile repo ekleme -- hibrit model)
icin orchestrator-seviyesi entegrasyon testleri: upsert_single_repository
(PostgreSQL JSONB/ON CONFLICT kullanir, gercek Postgres gerekir) +
resolve_auth_for_repo'nun repo_credentials tablosundan gercek bir token
cozmesi. HTTP/panel katmani ayrica tests/integration/test_app_panel_postgres.py'de
(RBAC + girdi dogrulama) test edilir -- bu dosya SADECE DB'ye dokunan kismi
kapsar."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.backup_crypto import encrypt_bytes  # noqa: E402
from core.models import Repository, RepoCredential  # noqa: E402
from orchestrator.discovery import upsert_single_repository  # noqa: E402
from orchestrator.github_auth import StaticTokenAuth, resolve_auth_for_repo  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")


def _repo_json(repo_id: int, full_name: str = "acme/manual-repo") -> dict:
    owner, name = full_name.split("/")
    return {
        "id": repo_id, "full_name": full_name, "owner": {"login": owner}, "name": name,
        "default_branch": "main", "visibility": "private", "private": True, "archived": False, "fork": False,
    }


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean(engine):
    with engine.begin() as conn:
        for table in ("repo_credentials", "repo_onboarding_requests", "repositories"):
            conn.execute(text(f"DELETE FROM {table}"))
    yield


def test_upsert_single_repository_does_not_deactivate_other_repos(engine):
    """upsert_repositories'in (App'in TOPLU kesfi) TERSINE: bu fonksiyon
    DIGER repolarin is_active durumuna DOKUNMAMALI -- tek bir repo panelden
    eklendiginde App'ten gelen hicbir repo yanlislikla pasife dusmemeli."""
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=200, full_name="acme/app-discovered", owner="acme", name="app-discovered",
            default_branch="main", visibility="private",
        ))
        session.commit()

    with Session() as session:
        github_repo_id = upsert_single_repository(session, _repo_json(201), discovered_via="manual_pat")
        session.commit()
    assert github_repo_id == 201

    with engine.connect() as conn:
        rows = {
            r[0]: (r[1], r[2])
            for r in conn.execute(text("SELECT github_repo_id, is_active, discovered_via FROM repositories")).all()
        }
    assert rows[200] == (True, "github_app")  # App'ten gelen etkilenmedi, varsayilan korunuyor
    assert rows[201] == (True, "manual_pat")


def test_upsert_single_repository_is_idempotent_on_conflict(engine):
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        upsert_single_repository(session, _repo_json(210, "acme/repo-a"), discovered_via="manual_pat")
        session.commit()
    with Session() as session:
        upsert_single_repository(session, _repo_json(210, "acme/repo-a-renamed"), discovered_via="manual_pat")
        session.commit()

    with engine.connect() as conn:
        full_name = conn.execute(text("SELECT full_name FROM repositories WHERE github_repo_id=210")).scalar_one()
    assert full_name == "acme/repo-a-renamed"


def test_resolve_auth_for_repo_decrypts_stored_token_for_manual_repo(engine):
    key = Fernet.generate_key()
    token = "ghp_super_secret_pat_value"
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        repo_id = upsert_single_repository(session, _repo_json(202), discovered_via="manual_pat")
        encrypted = encrypt_bytes(token.encode("utf-8"), key).decode("ascii")
        session.add(RepoCredential(github_repo_id=repo_id, encrypted_token=encrypted, added_by_user_id=1))
        session.commit()

    with Session() as session:
        repo = session.get(Repository, repo_id)
        auth = resolve_auth_for_repo(session, repo, app_auth=None, repo_token_key=key)
    assert isinstance(auth, StaticTokenAuth)
    assert auth.get_token() == token


def test_resolve_auth_for_repo_raises_clear_error_when_credential_missing(engine):
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        repo_id = upsert_single_repository(session, _repo_json(204), discovered_via="manual_pat")
        session.commit()

    with Session() as session:
        repo = session.get(Repository, repo_id)
        with pytest.raises(RuntimeError, match="kayitli bir token yok"):
            resolve_auth_for_repo(session, repo, app_auth=None, repo_token_key=Fernet.generate_key())


def test_resolve_auth_for_repo_uses_app_auth_unchanged_for_github_app_repo(engine):
    """discovered_via='github_app' (varsayilan) repolarda davranis BIT-BIT
    AYNI kalmali -- repo_credentials'a hic bakilmamali."""
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add(Repository(
            github_repo_id=205, full_name="acme/app-repo", owner="acme", name="app-repo",
            default_branch="main", visibility="private",
        ))
        session.commit()

    app_auth = object()
    with Session() as session:
        repo = session.get(Repository, 205)
        result = resolve_auth_for_repo(session, repo, app_auth=app_auth, repo_token_key=None)
    assert result is app_auth
