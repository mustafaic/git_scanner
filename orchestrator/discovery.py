"""Repo discovery: GitHub App installation'inin gorebildigi repolari
listeler ve `repositories` tablosuna upsert eder.

VERIFIED_FACTS.md: GET /installation/repositories installation access
token ile cagrilir (JWT ile DEGIL), yanit {total_count, repositories[],
repository_selection}, per_page max 100.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Set

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.models import Repository
from orchestrator.github_auth import API_VERSION_HEADER, GitHubAppAuth

LOG = logging.getLogger(__name__)


def list_installation_repositories(
    api_base_url: str,
    auth: GitHubAppAuth,
    http_client: Optional[httpx.Client] = None,
) -> List[Dict[str, Any]]:
    client = http_client or httpx.Client(timeout=30.0)
    repos: List[Dict[str, Any]] = []
    page = 1
    while True:
        response = client.get(
            f"{api_base_url.rstrip('/')}/installation/repositories",
            params={"per_page": 100, "page": page},
            headers={
                "Authorization": f"Bearer {auth.get_token()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION_HEADER,
            },
        )
        if response.status_code != 200:
            raise RuntimeError(f"Installation repo listesi alinamadi: HTTP {response.status_code}")
        data = response.json()
        page_repos = data.get("repositories", [])
        repos.extend(page_repos)
        if len(page_repos) < 100:
            break
        page += 1
    return repos


def _repo_fields(repo: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "full_name": repo["full_name"],
        "owner": repo["owner"]["login"],
        "name": repo["name"],
        "default_branch": repo.get("default_branch") or "main",
        "visibility": repo.get("visibility") or ("private" if repo.get("private") else "public"),
        "archived": bool(repo.get("archived")),
        "fork": bool(repo.get("fork")),
        "is_active": True,
    }


def upsert_repositories(session: Session, repos_json: Iterable[Dict[str, Any]]) -> int:
    """Gelen repo JSON'larini `repositories`'e upsert eder; installation'dan
    kaybolan (silinen/erisimi kaldirilan) repolari SESSIZCE SILMEZ, sadece
    is_active=False isaretler (master_prompt.md 3.2.9).

    Donen deger: islenen (upsert edilen) repo sayisi.
    """
    count = 0
    seen_ids: Set[int] = set()
    for repo in repos_json:
        github_repo_id = repo["id"]
        seen_ids.add(github_repo_id)
        fields = _repo_fields(repo)
        stmt = (
            pg_insert(Repository)
            .values(github_repo_id=github_repo_id, **fields)
            .on_conflict_do_update(index_elements=[Repository.github_repo_id], set_=fields)
        )
        session.execute(stmt)
        count += 1

    if seen_ids:
        session.execute(
            Repository.__table__.update()
            .where(Repository.github_repo_id.not_in(seen_ids))
            .values(is_active=False)
        )
    else:
        session.execute(Repository.__table__.update().values(is_active=False))
    return count
