"""adapters/osv_scanner.py parse() golden-file testleri.

Golden dosyalar gercek osv-scanner v2.7.0 binary'si ile uretildi (Asama 0b/2
spike, bkz. docs/MATCHING_SPIKE.md) -- sentetik/el yazimi JSON degil.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.osv_scanner import ScanExecutionResult, parse  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner"


def test_parse_golden_npm_lodash_output_has_expected_vulnerabilities():
    raw = (FIXTURES / "golden_npm_lodash_output.json").read_bytes()
    matches = parse(raw)
    assert len(matches) == 1
    match = matches[0]
    assert match.ecosystem == "npm"
    assert match.name == "lodash"
    assert match.version == "4.17.15"
    vuln_ids = {v.canonical_id for v in match.vulnerabilities}
    assert "GHSA-p6mc-m468-83gw" in vuln_ids  # Prototype Pollution

    proto_pollution = next(v for v in match.vulnerabilities if v.canonical_id == "GHSA-p6mc-m468-83gw")
    assert "CVE-2020-8203" in proto_pollution.aliases
    assert proto_pollution.severity_cvss_vector is not None
    assert proto_pollution.severity_cvss_vector.startswith("CVSS:3.1/")
    assert "4.17.19" in proto_pollution.fixed_versions


def test_parse_golden_go_gin_output_has_expected_vulnerabilities():
    raw = (FIXTURES / "golden_go_gin_output.json").read_bytes()
    matches = parse(raw)
    assert len(matches) >= 1
    gin_match = next(m for m in matches if m.name == "github.com/gin-gonic/gin")
    assert gin_match.ecosystem == "Go"
    # ONEMLI: OSV-Scanner Go surumlerini "v" ONEKI OLMADAN raporlar ("1.6.3"),
    # ama core/lockfile_parser.py (go.mod'dan) "v1.6.3" tutar. Hat A/B
    # korelasyonunda bu normalize edilmeli (bkz. core/finding_model.py).
    assert gin_match.version == "1.6.3"
    assert len(gin_match.vulnerabilities) >= 1


def test_parse_golden_clean_output_is_empty():
    raw = (FIXTURES / "golden_npm_clean_output.json").read_bytes()
    matches = parse(raw)
    assert matches == []


def test_parse_empty_stdout_is_empty_list():
    assert parse(b"") == []


def test_parse_invalid_json_raises_value_error():
    import pytest

    with pytest.raises(ValueError):
        parse(b"{not valid json")


def test_scan_execution_result_succeeded_property():
    assert ScanExecutionResult(exit_code=0, stdout=b"", stderr=b"").succeeded is True
    assert ScanExecutionResult(exit_code=1, stdout=b"", stderr=b"").succeeded is True
    assert ScanExecutionResult(exit_code=127, stdout=b"", stderr=b"").succeeded is False
    assert ScanExecutionResult(exit_code=-1, stdout=b"", stderr=b"").succeeded is False
