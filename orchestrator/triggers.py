"""Degisiklik algilama ve tetikleme (master_prompt.md 3.5): hizli yoklama
(GraphQL batch HEAD SHA), elle tetikleme, debounce, oncelikli kuyruk.

Tetikleyici YALNIZCA "bu repoyu simdi kontrol et" der; gercek durum HER
ZAMAN GitHub API'den okunur (bkz. orchestrator/sync.py), tetikleyicinin
tasidigi veriye GUVENILMEZ (sahte tetikleyici en kotu ihtimalle zararsiz
bir fazladan kontrol uretir).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from typing import Dict, List, Optional

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from core.models import Repository, ScanTrigger
from orchestrator.github_auth import GitHubAppAuth
from orchestrator.jobs import build_idempotency_key, enqueue_job

LOG = logging.getLogger(__name__)


def _graphql_endpoint(api_base_url: str) -> str:
    """VERIFIED_FACTS.md: github.com -> api.github.com/graphql;
    GHES -> https://<host>/api/graphql (REST taban yolu /api/v3'u degistirir)."""
    base = api_base_url.rstrip("/")
    if base == "https://api.github.com":
        return "https://api.github.com/graphql"
    if base.endswith("/api/v3"):
        return base[: -len("/api/v3")] + "/api/graphql"
    return base + "/graphql"


def poll_head_shas(
    api_base_url: str, auth: GitHubAppAuth, repos: List[Repository], http_client: Optional[httpx.Client] = None
) -> Dict[int, str]:
    """GraphQL batch sorgu: cok sayida reponun HEAD SHA'sini TEK istekte
    alir (master_prompt.md 3.5.1 "tek sorguda cok repo"). Donen:
    {github_repo_id: head_sha} (sadece basariyla okunabilenler)."""
    if not repos:
        return {}
    client = http_client or httpx.Client(timeout=30.0)
    aliases = [f"r{i}" for i in range(len(repos))]
    parts = [
        f'{alias}: repository(owner: {json.dumps(repo.owner)}, name: {json.dumps(repo.name)}) '
        f'{{ defaultBranchRef {{ target {{ oid }} }} }}'
        for alias, repo in zip(aliases, repos)
    ]
    query = "query { " + " ".join(parts) + " }"

    response = client.post(
        _graphql_endpoint(api_base_url),
        json={"query": query},
        headers={"Authorization": f"Bearer {auth.get_token()}", "Accept": "application/vnd.github+json"},
    )
    if response.status_code != 200:
        raise RuntimeError(f"GraphQL batch HEAD sorgusu basarisiz: HTTP {response.status_code}")
    data = response.json().get("data") or {}

    result: Dict[int, str] = {}
    for alias, repo in zip(aliases, repos):
        node = data.get(alias)
        if node and node.get("defaultBranchRef"):
            result[repo.github_repo_id] = node["defaultBranchRef"]["target"]["oid"]
    return result


def record_trigger(session: Session, repo_id: int, source: str, note: Optional[str] = None) -> None:
    """source: 'poll' | 'manual' | 'webhook' | 'reconcile'."""
    session.add(ScanTrigger(repo_id=repo_id, source=source, note=note))


def consume_triggers_and_enqueue(
    session: Session, debounce_window_seconds: int, now: Optional[dt.datetime] = None
) -> int:
    """Bekleyen (consumed_at IS NULL) tetikleyicileri repo bazinda gruplayip
    HER REPO icin EN FAZLA BIR 'repo_check' isi kuyruga ekler (debounce,
    master_prompt.md 3.5 "Debounce ve birlesme"). idempotency_key, isin
    DEBOUNCE PENCERESI bazinda tekilligini saglar -- ayni pencerede tekrar
    cagrilirsa ON CONFLICT DO NOTHING ile sessizce atlanir.

    Donen: kuyruga eklenen is sayisi.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    bucket = int(now.timestamp() // debounce_window_seconds)

    pending = session.execute(
        select(ScanTrigger.repo_id).where(ScanTrigger.consumed_at.is_(None)).distinct()
    ).scalars().all()

    enqueued = 0
    for repo_id in pending:
        key = build_idempotency_key("repo_check", repo_id, str(bucket))
        job_id = enqueue_job(session, "repo_check", key, repo_id=repo_id, priority=10)
        if job_id is not None:
            enqueued += 1
        session.execute(
            update(ScanTrigger).where(ScanTrigger.repo_id == repo_id, ScanTrigger.consumed_at.is_(None)).values(consumed_at=now)
        )
    return enqueued
