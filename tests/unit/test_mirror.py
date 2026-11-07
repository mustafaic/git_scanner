"""orchestrator/mirror.py saf fonksiyon testleri (KEV/EPSS parse).
Gercek ag cagrisi YAPMAZ -- embedded fixture icerigi kullanir."""

import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from orchestrator.mirror import parse_epss_csv, parse_kev_json  # noqa: E402


def test_parse_kev_json_extracts_expected_fields():
    raw = json.dumps(
        {
            "catalogVersion": "2026.11.07",
            "dateReleased": "2026-11-07T00:00:00.000Z",
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j2",
                    "vulnerabilityName": "Apache Log4j2 RCE",
                    "dateAdded": "2021-12-10",
                },
                {
                    "cveID": "CVE-2020-1234",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Acme Widget Overflow",
                    "dateAdded": "2020-05-01",
                },
            ],
        }
    ).encode("utf-8")

    entries = parse_kev_json(raw)
    assert len(entries) == 2
    log4j = next(e for e in entries if e["cve_id"] == "CVE-2021-44228")
    assert log4j["date_added"] == "2021-12-10"
    assert log4j["vulnerability_name"] == "Apache Log4j2 RCE"


def test_parse_kev_json_skips_entries_without_cve_id():
    raw = json.dumps({"vulnerabilities": [{"vendorProject": "X"}, {"cveID": "CVE-2021-1"}]}).encode("utf-8")
    entries = parse_kev_json(raw)
    assert len(entries) == 1
    assert entries[0]["cve_id"] == "CVE-2021-1"


def test_parse_epss_csv_skips_comment_header_line():
    csv_text = (
        "#model_version:v2025.03.14,score_date:2026-11-07T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.94520,0.99991\n"
        "CVE-2020-1234,0.00123,0.45000\n"
    )
    raw_gzip = gzip.compress(csv_text.encode("utf-8"))
    entries = parse_epss_csv(raw_gzip)
    assert len(entries) == 2
    log4j = next(e for e in entries if e["cve_id"] == "CVE-2021-44228")
    assert log4j["score"] == 0.94520
    assert log4j["percentile"] == 0.99991


def test_parse_epss_csv_empty_after_comments_is_empty_list():
    raw_gzip = gzip.compress(b"#just a comment\n")
    assert parse_epss_csv(raw_gzip) == []


def test_parse_epss_csv_malformed_row_is_skipped():
    csv_text = "cve,epss,percentile\nCVE-1,notanumber,0.5\nCVE-2,0.1,0.2\n"
    raw_gzip = gzip.compress(csv_text.encode("utf-8"))
    entries = parse_epss_csv(raw_gzip)
    assert len(entries) == 1
    assert entries[0]["cve_id"] == "CVE-2"
