import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.jobs import build_idempotency_key  # noqa: E402


def test_build_idempotency_key_with_repo_id():
    key = build_idempotency_key("repo_sync", 12345, "abc123sha")
    assert key == "repo_sync:12345:abc123sha"


def test_build_idempotency_key_without_repo_id():
    key = build_idempotency_key("mirror_sync", None, "2026-11-08")
    assert key == "mirror_sync:-:2026-11-08"


def test_build_idempotency_key_is_deterministic():
    a = build_idempotency_key("repo_sync", 1, "sha1")
    b = build_idempotency_key("repo_sync", 1, "sha1")
    c = build_idempotency_key("repo_sync", 1, "sha2")
    assert a == b
    assert a != c
