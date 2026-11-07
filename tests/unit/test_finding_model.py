"""core/finding_model.py testleri. Gercek golden fixture'lar (lodash/gin)
ile adapters.osv_scanner.parse() cikisindan NormalizedPackageMatch'ler
alinip finding_model fonksiyonlarina verilir -- ucten uca gercek veri."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from adapters.osv_scanner import parse  # noqa: E402
from core.finding_model import (  # noqa: E402
    FIX_NO_FIX_YET,
    FIX_PATCH_AVAILABLE,
    FIX_UNKNOWN,
    NEEDS_REVIEW,
    VERIFIED,
    build_findings_for_component,
    compute_fix_recommendation,
    compute_severity,
    determine_verification,
    normalize_version_for_ecosystem,
)
from core.lockfile_parser import ParsedComponent

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner"


def _lodash_match():
    raw = (FIXTURES / "golden_npm_lodash_output.json").read_bytes()
    return parse(raw)[0]


def _gin_match():
    raw = (FIXTURES / "golden_go_gin_output.json").read_bytes()
    matches = parse(raw)
    return next(m for m in matches if m.name == "github.com/gin-gonic/gin")


# --- severity -----------------------------------------------------------------

def test_compute_severity_real_cvss_vector_gives_numeric_score():
    match = _lodash_match()
    proto_pollution = next(v for v in match.vulnerabilities if v.canonical_id == "GHSA-p6mc-m468-83gw")
    severity = compute_severity(proto_pollution)
    assert severity.source == "cvss_v3"
    assert severity.cvss_score is not None
    assert 7.0 <= severity.cvss_score <= 8.0  # bilinen HIGH araligi
    assert severity.conflict is None


def test_compute_severity_missing_everything_is_empty():
    from adapters.osv_scanner import NormalizedVulnerability

    vuln = NormalizedVulnerability(canonical_id="FAKE-1", raw={})
    severity = compute_severity(vuln)
    assert severity.cvss_score is None
    assert severity.source is None


def test_compute_severity_conflicting_cvss_entries_flagged():
    from adapters.osv_scanner import NormalizedVulnerability

    vuln = NormalizedVulnerability(
        canonical_id="FAKE-2",
        raw={"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                           {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"}]},
    )
    severity = compute_severity(vuln)
    assert severity.conflict is not None


# --- verification ---------------------------------------------------------

def test_determine_verification_verified_when_score_present():
    match = _lodash_match()
    vuln = next(v for v in match.vulnerabilities if v.canonical_id == "GHSA-p6mc-m468-83gw")
    severity = compute_severity(vuln)
    status, reason = determine_verification(severity)
    assert status == VERIFIED
    assert reason is None


def test_determine_verification_needs_review_when_no_severity():
    from core.finding_model import SeverityResult

    status, reason = determine_verification(SeverityResult())
    assert status == NEEDS_REVIEW
    assert reason == "no_severity_data"


def test_determine_verification_needs_review_on_conflict():
    from core.finding_model import SeverityResult

    status, reason = determine_verification(SeverityResult(conflict={"x": 1}))
    assert status == NEEDS_REVIEW
    assert reason == "severity_conflict"


# --- fix recommendation -----------------------------------------------------

def test_compute_fix_recommendation_picks_max_of_fixed_versions_npm():
    rec = compute_fix_recommendation("npm", "3.7.0", ["4.17.19", "4.17.21", "4.17.11"])
    assert rec.status == FIX_PATCH_AVAILABLE
    assert rec.version == "4.17.21"


def test_compute_fix_recommendation_no_candidates_is_no_fix_yet():
    rec = compute_fix_recommendation("npm", "1.0.0", [])
    assert rec.status == FIX_NO_FIX_YET
    assert rec.version is None


def test_compute_fix_recommendation_unsupported_ecosystem_is_unknown():
    rec = compute_fix_recommendation("SomeWeirdEcosystem", "1.0.0", ["2.0.0"])
    assert rec.status == FIX_UNKNOWN


def test_compute_fix_recommendation_detects_major_bump():
    rec = compute_fix_recommendation("npm", "3.9.0", ["4.0.0"])
    assert rec.status == FIX_PATCH_AVAILABLE
    assert rec.is_major_bump is True


def test_compute_fix_recommendation_minor_bump_not_flagged_major():
    rec = compute_fix_recommendation("npm", "4.17.11", ["4.17.21"])
    assert rec.is_major_bump is False


def test_compute_fix_recommendation_real_lodash_vulnerability():
    match = _lodash_match()
    proto_pollution = next(v for v in match.vulnerabilities if v.canonical_id == "GHSA-p6mc-m468-83gw")
    rec = compute_fix_recommendation(match.ecosystem, match.version, proto_pollution.fixed_versions)
    assert rec.status == FIX_PATCH_AVAILABLE
    assert rec.version == "4.17.19"


# --- Go version normalization -------------------------------------------

def test_normalize_version_for_ecosystem_strips_go_v_prefix():
    assert normalize_version_for_ecosystem("Go", "v1.2.3") == "1.2.3"
    assert normalize_version_for_ecosystem("npm", "1.2.3") == "1.2.3"


def test_gin_component_and_match_correlate_after_go_normalization():
    match = _gin_match()
    hat_a_version = "v1.6.3"  # core/lockfile_parser.py'nin go.mod'dan okudugu hal
    assert normalize_version_for_ecosystem("Go", hat_a_version) == match.version


# --- build_findings_for_component (ucten uca) -------------------------------

def test_build_findings_for_component_real_lodash():
    match = _lodash_match()
    component = ParsedComponent(
        ecosystem="npm", name="lodash", version="4.17.15", scope="prod", relation="direct",
        purl="pkg:npm/lodash@4.17.15",
    )
    findings = build_findings_for_component(repo_id=1, component=component, match=match)
    assert len(findings) == 5
    ids = {f.canonical_vulnerability_id for f in findings}
    assert "GHSA-p6mc-m468-83gw" in ids
    proto = next(f for f in findings if f.canonical_vulnerability_id == "GHSA-p6mc-m468-83gw")
    assert proto.verification_status == VERIFIED
    assert proto.fix.status == FIX_PATCH_AVAILABLE
    assert proto.fix.version == "4.17.19"
    assert proto.package_name == "lodash"
    assert proto.repo_id == 1


def test_build_findings_for_component_no_vulnerabilities_is_empty():
    from adapters.osv_scanner import NormalizedPackageMatch

    component = ParsedComponent(ecosystem="npm", name="left-pad", version="1.3.0")
    match = NormalizedPackageMatch(ecosystem="npm", name="left-pad", version="1.3.0", purl=None, vulnerabilities=[])
    findings = build_findings_for_component(repo_id=1, component=component, match=match)
    assert findings == []
