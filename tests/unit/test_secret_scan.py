import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.secret_scan import _mirror_dirname, clone_url_for_repo  # noqa: E402


def test_clone_url_for_github_com():
    assert clone_url_for_repo("https://api.github.com", "acme/widgets") == "https://github.com/acme/widgets.git"


def test_clone_url_for_ghes():
    assert (
        clone_url_for_repo("https://ghes.acme.internal/api/v3", "acme/widgets")
        == "https://ghes.acme.internal/acme/widgets.git"
    )


def test_mirror_dirname_replaces_slash():
    assert _mirror_dirname("acme/widgets") == "acme__widgets.git"
