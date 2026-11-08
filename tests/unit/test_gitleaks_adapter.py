"""adapters/gitleaks.py parse() golden-file testleri.

Golden dosyalar gercek gitleaks v8.30.1 binary'si ile, GERCEK (ama sahte/
test amacli) secret pattern'leriyle uretildi (bkz. docs/VERIFIED_FACTS.md).
Kritik test: NormalizedSecretFinding'in hicbir alaninda ham secret degeri
YER ALMAMALI.
"""

import dataclasses
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.gitleaks import NormalizedSecretFinding, ScanExecutionResult, parse  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "gitleaks"

RAW_GITHUB_PAT = "ghp_1234567890abcdefghij1234567890ABCDEF"
RAW_STRIPE_KEY = "NOT_A_REAL_SECRET_FAKE_VALUE_FOR_TESTING_ONLY_1234567890ABCDEFGHIJ"


def test_parse_golden_clean_output_is_empty():
    raw = (FIXTURES / "golden_clean_output.json").read_bytes()
    assert parse(raw) == []


def test_parse_empty_bytes_is_empty_list():
    assert parse(b"") == []
    assert parse(b"  ") == []


def test_parse_golden_findings_extracts_expected_fields():
    raw = (FIXTURES / "golden_findings_output.json").read_bytes()
    findings = parse(raw)
    assert len(findings) == 2
    by_rule = {f.rule_id: f for f in findings}
    assert "github-pat" in by_rule
    assert "stripe-access-token" in by_rule

    pat = by_rule["github-pat"]
    assert pat.file_path == "settings.py"
    assert pat.line_number == 2
    assert pat.gitleaks_fingerprint == "eb0d84f3f0d3ffdd6a808fe89cd51dffd0a435a2:settings.py:github-pat:2"
    assert pat.commit_sha == "eb0d84f3f0d3ffdd6a808fe89cd51dffd0a435a2"


def test_parse_computes_correct_secret_content_hash():
    raw = (FIXTURES / "golden_findings_output.json").read_bytes()
    findings = parse(raw)
    pat = next(f for f in findings if f.rule_id == "github-pat")
    expected_hash = hashlib.sha256(RAW_GITHUB_PAT.encode("utf-8")).hexdigest()
    assert pat.secret_content_hash == expected_hash


def test_parse_custom_fingerprint_is_stable_and_line_independent():
    """master_prompt.md 4.4 + docs/ASSUMPTIONS.md #3: ozel fingerprint
    SATIRDAN BAGIMSIZ olmali (gitleaks'in kendi fingerprint'inin aksine)."""
    raw = json.dumps(
        [
            {"RuleID": "github-pat", "File": "a.py", "Secret": RAW_GITHUB_PAT, "StartLine": 5,
             "Commit": "sha1", "Fingerprint": "sha1:a.py:github-pat:5"},
            {"RuleID": "github-pat", "File": "a.py", "Secret": RAW_GITHUB_PAT, "StartLine": 42,
             "Commit": "sha2", "Fingerprint": "sha2:a.py:github-pat:42"},
        ]
    ).encode("utf-8")
    findings = parse(raw)
    assert findings[0].custom_fingerprint == findings[1].custom_fingerprint
    assert findings[0].gitleaks_fingerprint != findings[1].gitleaks_fingerprint


def test_parse_different_secrets_same_rule_file_get_different_fingerprints():
    raw = json.dumps(
        [
            {"RuleID": "github-pat", "File": "a.py", "Secret": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "StartLine": 1},
            {"RuleID": "github-pat", "File": "a.py", "Secret": "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "StartLine": 1},
        ]
    ).encode("utf-8")
    findings = parse(raw)
    assert findings[0].custom_fingerprint != findings[1].custom_fingerprint


def test_raw_secret_value_never_appears_in_normalized_finding():
    """KRITIK GUVENLIK TESTI: ham secret degeri, parse() SONRASI hicbir
    alanda/repr'de gorunmemeli (master_prompt.md 4.4)."""
    raw = (FIXTURES / "golden_findings_output.json").read_bytes()
    findings = parse(raw)
    dump = repr([dataclasses.asdict(f) for f in findings])
    assert RAW_GITHUB_PAT not in dump
    assert RAW_STRIPE_KEY not in dump
    for f in findings:
        for value in dataclasses.asdict(f).values():
            assert value != RAW_GITHUB_PAT
            assert value != RAW_STRIPE_KEY


def test_parse_author_and_email_are_never_captured():
    """KVKK (master_prompt.md 5): commit yazari adi/e-postasi saklanmaz."""
    raw = (FIXTURES / "golden_findings_output.json").read_bytes()
    findings = parse(raw)
    for f in findings:
        field_names = {field.name for field in dataclasses.fields(f)}
        assert "author" not in field_names
        assert "email" not in field_names


def test_parse_invalid_json_raises_value_error():
    import pytest

    with pytest.raises(ValueError):
        parse(b"{not valid json")


def test_scan_execution_result_succeeded_clean():
    assert ScanExecutionResult(exit_code=0, report_json=b"[]", stderr=b"").succeeded is True


def test_scan_execution_result_succeeded_with_findings():
    assert ScanExecutionResult(exit_code=1, report_json=b"[{}]", stderr=b"").succeeded is True


def test_scan_execution_result_failed_when_no_report_file():
    """Gercek hatada (ornegin bozuk repo yolu) rapor dosyasi HIC yazilmaz --
    exit_code=1 olsa bile report_json=None ise basarisiz sayilmali."""
    assert ScanExecutionResult(exit_code=1, report_json=None, stderr=b"fatal error").succeeded is False
