import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.matching import build_synthetic_sbom  # noqa: E402


def test_build_synthetic_sbom_shape():
    sbom = build_synthetic_sbom([("npm", "lodash", "4.17.15", "pkg:npm/lodash@4.17.15")])
    doc = json.loads(sbom)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["components"] == [{"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}]


def test_build_synthetic_sbom_without_purl_omits_field():
    sbom = build_synthetic_sbom([("Go", "example.com/foo", "1.2.3", None)])
    doc = json.loads(sbom)
    assert "purl" not in doc["components"][0]


def test_build_synthetic_sbom_empty_list():
    sbom = build_synthetic_sbom([])
    doc = json.loads(sbom)
    assert doc["components"] == []
