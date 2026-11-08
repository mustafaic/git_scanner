import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.models import Repository  # noqa: E402
from orchestrator.triggers import _graphql_endpoint, poll_head_shas  # noqa: E402


class _FakeAuth:
    def get_token(self, now=None) -> str:
        return "fake-token"


def _repo(repo_id, owner, name) -> Repository:
    return Repository(
        github_repo_id=repo_id, full_name=f"{owner}/{name}", owner=owner, name=name,
        default_branch="main", visibility="private", archived=False, fork=False, is_active=True,
    )


def test_graphql_endpoint_for_github_com():
    assert _graphql_endpoint("https://api.github.com") == "https://api.github.com/graphql"


def test_graphql_endpoint_for_ghes():
    assert _graphql_endpoint("https://ghes.acme.internal/api/v3") == "https://ghes.acme.internal/api/graphql"


def test_poll_head_shas_empty_repo_list_no_request():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"data": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = poll_head_shas("https://api.github.com", _FakeAuth(), [], http_client=client)
    assert result == {}
    assert calls == []


def test_poll_head_shas_batches_multiple_repos_in_one_request():
    repos = [_repo(1, "acme", "widgets"), _repo(2, "acme", "gadgets")]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        body = request.content.decode("utf-8")
        assert "widgets" in body and "gadgets" in body
        return httpx.Response(
            200,
            json={
                "data": {
                    "r0": {"defaultBranchRef": {"target": {"oid": "sha-widgets"}}},
                    "r1": {"defaultBranchRef": {"target": {"oid": "sha-gadgets"}}},
                }
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = poll_head_shas("https://api.github.com", _FakeAuth(), repos, http_client=client)

    assert len(calls) == 1  # TEK istek, N repo icin
    assert result == {1: "sha-widgets", 2: "sha-gadgets"}


def test_poll_head_shas_skips_repo_with_missing_default_branch_ref():
    repos = [_repo(1, "acme", "widgets"), _repo(2, "acme", "empty-repo")]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"r0": {"defaultBranchRef": {"target": {"oid": "sha-1"}}}, "r1": {"defaultBranchRef": None}}},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = poll_head_shas("https://api.github.com", _FakeAuth(), repos, http_client=client)
    assert result == {1: "sha-1"}


def test_poll_head_shas_raises_on_non_200():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="rate limited")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    import pytest

    with pytest.raises(RuntimeError):
        poll_head_shas("https://api.github.com", _FakeAuth(), [_repo(1, "a", "b")], http_client=client)
