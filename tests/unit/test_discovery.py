"""orchestrator/discovery.py - list_installation_repositories testleri.

upsert_repositories PostgreSQL'e ozel (JSONB + ON CONFLICT) oldugu icin
gercek Postgres gerektirir; onun testi tests/integration/'dadir.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.discovery import fetch_repository_by_name, list_installation_repositories  # noqa: E402
from orchestrator.github_auth import GitHubAppAuth  # noqa: E402


class _FakeAuth:
    def get_token(self, now=None) -> str:
        return "fake-installation-token"


def _make_repo(repo_id: int) -> dict:
    return {
        "id": repo_id,
        "full_name": f"acme/repo-{repo_id}",
        "owner": {"login": "acme"},
        "name": f"repo-{repo_id}",
        "default_branch": "main",
        "visibility": "private",
        "private": True,
        "archived": False,
        "fork": False,
    }


def test_single_page_stops_without_second_request():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        assert request.headers["Authorization"] == "Bearer fake-installation-token"
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
        return httpx.Response(
            200,
            json={"total_count": 2, "repository_selection": "selected", "repositories": [_make_repo(1), _make_repo(2)]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    repos = list_installation_repositories("https://api.github.com", _FakeAuth(), http_client=client)

    assert len(calls) == 1
    assert [r["id"] for r in repos] == [1, 2]


def test_pagination_follows_full_pages():
    page1 = [_make_repo(i) for i in range(1, 101)]  # tam 100 -> ikinci sayfa gelmeli
    page2 = [_make_repo(101)]

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        body = page1 if page == 1 else page2
        return httpx.Response(200, json={"total_count": 101, "repository_selection": "all", "repositories": body})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    repos = list_installation_repositories("https://api.github.com", _FakeAuth(), http_client=client)

    assert len(repos) == 101
    assert repos[-1]["id"] == 101


def test_non_200_raises_without_leaking_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="installation suspended - secret detail xyz")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError) as excinfo:
        list_installation_repositories("https://api.github.com", _FakeAuth(), http_client=client)
    assert "secret detail xyz" not in str(excinfo.value)
    assert "403" in str(excinfo.value)


# --- Faz 1 (2026-11-10): panelden GitHub token ile repo ekleme -- fetch_repository_by_name ---


def test_fetch_repository_by_name_sends_pat_as_bearer_token():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers["Authorization"]
        captured["path"] = request.url.path
        return httpx.Response(200, json=_make_repo(999))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    repo_json = fetch_repository_by_name("https://api.github.com", "ghp_admin_pat", "acme", "repo-999", http_client=client)

    assert captured["authorization"] == "Bearer ghp_admin_pat"
    assert captured["path"] == "/repos/acme/repo-999"
    assert repo_json["id"] == 999


def test_fetch_repository_by_name_raises_http_status_error_on_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        fetch_repository_by_name("https://api.github.com", "ghp_x", "acme", "missing-repo", http_client=client)
    assert excinfo.value.response.status_code == 404


def test_fetch_repository_by_name_raises_http_status_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Forbidden"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        fetch_repository_by_name("https://api.github.com", "ghp_x", "acme", "forbidden-repo", http_client=client)
    assert excinfo.value.response.status_code == 403
