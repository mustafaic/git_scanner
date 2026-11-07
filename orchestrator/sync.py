"""Hat A - adim 1 (master_prompt.md 3.2.1): default branch HEAD SHA'sini
GitHub API'den okur, `repositories.last_seen_sha` ile karsilastirir.

NOT - kapsam siniri (kural 4): Bu modul SADECE adim 1'i yapar (HEAD SHA
okuma + karsilastirma). Tree/blob diff, lockfile parse, sanity gate vb.
(adim 2+) Asama 2'nin kapsamidir, burada UYGULANMAZ.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from core.models import Repository
from orchestrator.github_auth import GitHubAppAuth

LOG = logging.getLogger(__name__)

# VERIFIED (docs/VERIFIED_FACTS.md referansli arastirma, docs.github.com/en/rest/commits/commits):
# bu media type GET /repos/{owner}/{repo}/commits/{ref} yanitini duz metin SHA olarak dondurur.
SHA_MEDIA_TYPE = "application/vnd.github.sha"
API_VERSION_HEADER = "2022-11-28"


def fetch_default_branch_head_sha(
    api_base_url: str,
    auth: GitHubAppAuth,
    owner: str,
    repo: str,
    default_branch: str,
    http_client: Optional[httpx.Client] = None,
) -> str:
    """Tetikleyicinin tasidigi veriye GUVENILMEZ; SHA her zaman burada,
    kendi App token'imizla GitHub'dan okunur (master_prompt.md 3.5)."""
    client = http_client or httpx.Client(timeout=30.0)
    # Resmi doküman formatı: "heads/BRANCH_NAME" (bkz. docstring referansı).
    ref = f"heads/{default_branch}"
    response = client.get(
        f"{api_base_url.rstrip('/')}/repos/{owner}/{repo}/commits/{ref}",
        headers={
            "Authorization": f"Bearer {auth.get_token()}",
            "Accept": SHA_MEDIA_TYPE,
            "X-GitHub-Api-Version": API_VERSION_HEADER,
        },
    )
    if response.status_code != 200:
        raise RuntimeError(f"HEAD SHA alinamadi ({owner}/{repo}): HTTP {response.status_code}")
    return response.text.strip()


def sync_repository_head(
    api_base_url: str,
    auth: GitHubAppAuth,
    repo: Repository,
    http_client: Optional[httpx.Client] = None,
) -> bool:
    """`repo.last_seen_sha`'yi guncel HEAD SHA ile karsilastirir/gunceller.

    Donen deger: SHA degisti mi (True/False). Cagiran taraf (orchestrator
    main.py) degistiyse Asama 2'de tree/blob diff isini kuyruga eklecek;
    Asama 1'de bu fonksiyon sadece karsilastirma+guncellemeyi yapar.
    """
    head_sha = fetch_default_branch_head_sha(
        api_base_url, auth, repo.owner, repo.name, repo.default_branch, http_client=http_client
    )
    changed = head_sha != repo.last_seen_sha
    if changed:
        LOG.info("Repo %s HEAD degisti: %s -> %s", repo.full_name, repo.last_seen_sha, head_sha)
        repo.last_seen_sha = head_sha
    else:
        LOG.info("Repo %s HEAD degismedi (%s)", repo.full_name, head_sha)
    return changed
