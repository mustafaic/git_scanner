import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.extraction import find_lockfiles  # noqa: E402


def test_find_lockfiles_detects_known_basenames():
    tree = [
        {"path": "package.json", "type": "blob", "mode": "100644", "sha": "a"},
        {"path": "package-lock.json", "type": "blob", "mode": "100644", "sha": "b"},
        {"path": "src/go.mod", "type": "blob", "mode": "100644", "sha": "c"},
        {"path": "node_modules", "type": "tree", "mode": "040000", "sha": "d"},
    ]
    found = find_lockfiles(tree)
    assert ("package-lock.json", "b", "npm") in found
    assert ("src/go.mod", "c", "go") in found
    assert len(found) == 2


def test_find_lockfiles_excludes_symlinks():
    tree = [
        {"path": "evil-link/package-lock.json", "type": "blob", "mode": "120000", "sha": "deadbeef"},
        {"path": "real/package-lock.json", "type": "blob", "mode": "100644", "sha": "cafef00d"},
    ]
    found = find_lockfiles(tree)
    assert len(found) == 1
    assert found[0][0] == "real/package-lock.json"


def test_find_lockfiles_monorepo_multiple_paths():
    tree = [
        {"path": "services/api/package-lock.json", "type": "blob", "mode": "100644", "sha": "a"},
        {"path": "services/worker/poetry.lock", "type": "blob", "mode": "100644", "sha": "b"},
    ]
    found = find_lockfiles(tree)
    paths = {f[0] for f in found}
    assert paths == {"services/api/package-lock.json", "services/worker/poetry.lock"}


def test_find_lockfiles_empty_tree_is_empty():
    assert find_lockfiles([]) == []
