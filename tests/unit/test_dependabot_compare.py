"""core/dependabot_compare.py testleri (master_prompt.md 8) -- DB/HTTP
gerektirmez. Ekosistem eslemesi docs/VERIFIED_FACTS.md'de resmi
dokumandan dogrulanan degerlerle test edilir (Rust -> 'rust', 'cargo' DEGIL)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.dependabot_compare import (  # noqa: E402
    FindingLite,
    alert_vulnerability_ids,
    compare_alerts_to_findings,
    map_dependabot_ecosystem,
)
from core.lockfile_parser import ECOSYSTEM_CARGO, ECOSYSTEM_NPM, ECOSYSTEM_PYPI  # noqa: E402


def _alert(number, ecosystem, ghsa_id=None, cve_id=None, state="open"):
    return {
        "number": number, "state": state,
        "dependency": {"package": {"ecosystem": ecosystem, "name": "pkg"}},
        "security_advisory": {"ghsa_id": ghsa_id, "cve_id": cve_id, "identifiers": []},
    }


def test_map_dependabot_ecosystem_rust_is_cargo_not_literally_rust_string():
    """KRITIK: Dependabot 'rust' der, biz 'crates.io' (ECOSYSTEM_CARGO)
    kullaniriz -- ilk (yanlis) varsayim 'cargo' idi, resmi dokumandan
    duzeltildi (bkz. core/dependabot_compare.py docstring)."""
    assert map_dependabot_ecosystem("rust") == ECOSYSTEM_CARGO
    assert map_dependabot_ecosystem("cargo") is None  # Dependabot'ta bu deger YOK


def test_map_dependabot_ecosystem_known_values():
    assert map_dependabot_ecosystem("npm") == ECOSYSTEM_NPM
    assert map_dependabot_ecosystem("pip") == ECOSYSTEM_PYPI


def test_map_dependabot_ecosystem_unsupported_returns_none():
    assert map_dependabot_ecosystem("pub") is None
    assert map_dependabot_ecosystem("totally-unknown") is None


def test_alert_vulnerability_ids_collects_ghsa_and_cve():
    alert = _alert(1, "npm", ghsa_id="GHSA-xxxx", cve_id="CVE-2024-0001")
    assert alert_vulnerability_ids(alert) == {"GHSA-xxxx", "CVE-2024-0001"}


def test_compare_matches_when_ghsa_overlaps():
    alerts = [_alert(1, "npm", ghsa_id="GHSA-aaaa")]
    findings = [FindingLite(package_name="lodash", ecosystem=ECOSYSTEM_NPM, canonical_vulnerability_id="GHSA-aaaa")]
    result = compare_alerts_to_findings("acme/repo", alerts, findings)
    assert result.matched_alert_numbers == [1]
    assert result.missed_alert_numbers == []


def test_compare_matches_via_alias_not_canonical_id():
    """Dependabot CVE kullanirken biz GHSA'yi canonical secmis olabiliriz
    -- alias listesi uzerinden eslesmeli (master_prompt.md 4.5)."""
    alerts = [_alert(1, "npm", cve_id="CVE-2024-0001")]
    findings = [FindingLite(
        package_name="lodash", ecosystem=ECOSYSTEM_NPM,
        canonical_vulnerability_id="GHSA-aaaa", aliases=["CVE-2024-0001"],
    )]
    result = compare_alerts_to_findings("acme/repo", alerts, findings)
    assert result.matched_alert_numbers == [1]


def test_compare_reports_missed_alert_as_recall_gap():
    alerts = [_alert(1, "npm", ghsa_id="GHSA-missed")]
    findings = []
    result = compare_alerts_to_findings("acme/repo", alerts, findings)
    assert result.missed_alert_numbers == [1]
    assert result.matched_alert_numbers == []


def test_compare_wrong_ecosystem_does_not_match():
    alerts = [_alert(1, "npm", ghsa_id="GHSA-aaaa")]
    findings = [FindingLite(package_name="somepkg", ecosystem=ECOSYSTEM_PYPI, canonical_vulnerability_id="GHSA-aaaa")]
    result = compare_alerts_to_findings("acme/repo", alerts, findings)
    assert result.missed_alert_numbers == [1]


def test_compare_unsupported_ecosystem_is_skipped_not_reported_as_missed():
    alerts = [_alert(1, "pub", ghsa_id="GHSA-dart")]
    result = compare_alerts_to_findings("acme/repo", alerts, [])
    assert result.unsupported_ecosystem_alert_numbers == [1]
    assert result.missed_alert_numbers == []


def test_compare_extra_finding_without_matching_alert_is_informational():
    alerts = []
    findings = [FindingLite(package_name="lodash", ecosystem=ECOSYSTEM_NPM, canonical_vulnerability_id="GHSA-only-ours")]
    result = compare_alerts_to_findings("acme/repo", alerts, findings)
    assert result.extra_findings_without_alert == ["GHSA-only-ours"]
