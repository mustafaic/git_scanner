from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.sync import EmptyRepositoryError, fetch_default_branch_head_sha  # noqa: E402


class _FakeAuth:
    def get_token(self, now=None) -> str:
        return "fake-token"


def test_fetch_head_sha_uses_heads_prefix_and_sha_media_type():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["accept"] = request.headers["Accept"]
        return httpx.Response(200, text="deadbeef1234567890deadbeef1234567890abcd\n")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sha = fetch_default_branch_head_sha(
        "https://api.github.com", _FakeAuth(), "acme", "widgets", "main", http_client=client
    )

    assert captured["path"] == "/repos/acme/widgets/commits/heads/main"
    assert captured["accept"] == "application/vnd.github.sha"
    assert sha == "deadbeef1234567890deadbeef1234567890abcd"


def test_fetch_head_sha_non_200_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="Not Found")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError):
        fetch_default_branch_head_sha(
            "https://api.github.com", _FakeAuth(), "acme", "widgets", "main", http_client=client
        )


def test_fetch_head_sha_409_raises_empty_repository_error():
    # Gercek test org'unda gozlendi (bkz. docs/VERIFIED_FACTS.md): commit
    # icermeyen repo'larda GitHub bu endpoint'te 409 doner.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"message": "Git Repository is empty."})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(EmptyRepositoryError):
        fetch_default_branch_head_sha(
            "https://api.github.com", _FakeAuth(), "acme", "widgets", "main", http_client=client
        )
