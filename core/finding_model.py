"""Finding modeli: normalizasyon, dedup, Verified/Needs Review,
patchability + yukseltme onerisi, lifecycle (master_prompt.md 4.1-4.5).

Bu modul SAF FONKSIYONLARDAN olusur (DB baglantisi yok) -> agir birim
testli. DB'ye yazma islemi orchestrator/matching.py'de (Hat B) yapilir.

ONEMLI (kural 3): Surum ARALIK eslestirmesini (affected mi degil mi) BIZ
YAPMAYIZ -- OSV-Scanner zaten bu kararı verip bize sadece "bu paket@surum
icin BU ID'li zafiyet var" olarak bildirir, guveniriz. Burada SADECE
"bunlari kapatan en kucuk surum nedir" (fix_version) hesaplamasi icin
univers (olgun kutuphane) ile SIRALAMA yapilir -- aralik YORUMLAMASI yok.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from cvss import CVSS3
from sqlalchemy import select
from sqlalchemy.orm import Session
from univers.versions import (
    ComposerVersion,
    GolangVersion,
    MavenVersion,
    NugetVersion,
    PypiVersion,
    RubygemsVersion,
    SemverVersion,
)

from adapters.osv_scanner import NormalizedPackageMatch, NormalizedVulnerability
from core.models import Finding, FindingEvent, FindingSource
from core.lockfile_parser import (
    ECOSYSTEM_CARGO,
    ECOSYSTEM_GO,
    ECOSYSTEM_MAVEN,
    ECOSYSTEM_NPM,
    ECOSYSTEM_NUGET,
    ECOSYSTEM_PACKAGIST,
    ECOSYSTEM_PYPI,
    ECOSYSTEM_RUBYGEMS,
    ParsedComponent,
)

VERIFIED = "VERIFIED"
NEEDS_REVIEW = "NEEDS_REVIEW"

FIX_PATCH_AVAILABLE = "PATCH_AVAILABLE"
FIX_NO_FIX_YET = "NO_FIX_YET"
FIX_UNKNOWN = "FIX_UNKNOWN"

STATUS_OPEN = "OPEN"
STATUS_REOPENED = "REOPENED"
STATUS_RESOLVED = "RESOLVED"

# univers'ta Cargo'ya ozel sinif yok (bkz. docs/ASSUMPTIONS.md #10) ->
# Rust standart semver kullandigi icin SemverVersion fallback.
ECOSYSTEM_VERSION_CLASS: Dict[str, Any] = {
    ECOSYSTEM_NPM: SemverVersion,
    ECOSYSTEM_PYPI: PypiVersion,
    ECOSYSTEM_GO: GolangVersion,
    ECOSYSTEM_CARGO: SemverVersion,
    ECOSYSTEM_PACKAGIST: ComposerVersion,
    ECOSYSTEM_MAVEN: MavenVersion,
    ECOSYSTEM_NUGET: NugetVersion,
    ECOSYSTEM_RUBYGEMS: RubygemsVersion,
}


def normalize_version_for_ecosystem(ecosystem: str, version: str) -> str:
    """Hat A (lockfile_parser) ve Hat B (OSV-Scanner) ayni bilesen icin
    FARKLI string temsilleri uretebilir (bkz. docs/VERIFIED_FACTS.md madde 8:
    Go'da 'v1.2.3' vs '1.2.3'). Korelasyon oncesi normalize edilir."""
    if ecosystem == ECOSYSTEM_GO and version.startswith("v"):
        return version[1:]
    return version


# --- Severity / CVSS --------------------------------------------------------

@dataclass
class SeverityResult:
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    source: Optional[str] = None  # 'cvss_v3' | 'database_specific_label' | None
    conflict: Optional[Dict[str, Any]] = None


def compute_severity(vuln: NormalizedVulnerability) -> SeverityResult:
    cvss_entries = [s for s in (vuln.raw.get("severity") or []) if s.get("type") == "CVSS_V3"]
    if len(cvss_entries) > 1:
        distinct_scores = {s.get("score") for s in cvss_entries}
        if len(distinct_scores) > 1:
            return SeverityResult(conflict={"cvss_v3_entries": cvss_entries})

    if vuln.severity_cvss_vector:
        try:
            score = CVSS3(vuln.severity_cvss_vector).scores()[0]
            return SeverityResult(cvss_vector=vuln.severity_cvss_vector, cvss_score=round(score, 1), source="cvss_v3")
        except Exception:
            pass  # noqa: S110 - parse edilemeyen vektor -> etikete dus

    if vuln.database_specific_severity:
        return SeverityResult(source="database_specific_label")

    return SeverityResult()


# --- Dogrulama (Verified vs Needs Review) ----------------------------------

def determine_verification(severity: SeverityResult) -> Tuple[str, Optional[str]]:
    """master_prompt.md 4.2: skor yok veya kaynaklar celisiyor -> Needs Review.

    NOT: Paket kimligi/cozulmus tam surum/affected araligi sorulari burada
    sorulmaz -- Hat A zaten gercek bir LOCKFILE'dan geldigi icin (manifest-only
    asla bu noktaya ulasmaz, bkz. orchestrator/extraction.py) ve OSV-Scanner
    affected karari zaten verdigi icin bu kosullar yapi geregi saglanir.
    """
    if severity.conflict is not None:
        return NEEDS_REVIEW, "severity_conflict"
    if severity.cvss_score is None and severity.source is None:
        return NEEDS_REVIEW, "no_severity_data"
    return VERIFIED, None


# --- Patchability / yukseltme onerisi ---------------------------------------

_LEADING_DIGITS_RE = re.compile(r"^\D*(\d+)")


def _major_component(version: str) -> Optional[str]:
    match = _LEADING_DIGITS_RE.match(version)
    return match.group(1) if match else None


@dataclass
class FixRecommendation:
    status: str
    version: Optional[str] = None
    is_major_bump: bool = False


def compute_fix_recommendation(
    ecosystem: str, current_version: str, fixed_version_candidates: List[str]
) -> FixRecommendation:
    """master_prompt.md 4.1: birden fazla zafiyet varsa onerilen surum,
    HEPSINI kapatan EN KUCUK surumdur = tum 'fixed' esiklerinin EN
    BUYUGU (cunku her esigin altinda kalan, o zafiyeti acik birakir).
    Guvenilir hesaplanamiyorsa (ekosistem desteklenmiyor, parse hatasi)
    FIX_UNKNOWN doner, oneri uretilmez."""
    if not fixed_version_candidates:
        return FixRecommendation(FIX_NO_FIX_YET)

    version_cls = ECOSYSTEM_VERSION_CLASS.get(ecosystem)
    if version_cls is None:
        return FixRecommendation(FIX_UNKNOWN)

    try:
        current = version_cls(current_version)
    except Exception:
        return FixRecommendation(FIX_UNKNOWN)

    parsed_candidates = []
    for raw in fixed_version_candidates:
        try:
            parsed_candidates.append(version_cls(raw))
        except Exception:
            continue
    if not parsed_candidates:
        return FixRecommendation(FIX_UNKNOWN)

    best = max(parsed_candidates)
    best_str = str(best)
    if best <= current:
        # Nadir durum: OSV verisi mevcut surumun zaten fix icerdigini soyluyor.
        return FixRecommendation(FIX_PATCH_AVAILABLE, best_str, False)

    is_major_bump = _major_component(best_str) != _major_component(current_version)
    return FixRecommendation(FIX_PATCH_AVAILABLE, best_str, is_major_bump)


# --- Finding alanlarinin insasi (saf, DB'siz) --------------------------------

@dataclass
class BuiltFinding:
    repo_id: int
    lockfile_path: str
    ecosystem: str
    purl: Optional[str]
    package_name: str
    version: str
    scope: str
    relation: str
    canonical_vulnerability_id: str
    aliases: List[str]
    severity: SeverityResult
    fix: FixRecommendation
    verification_status: str
    needs_review_reason: Optional[str]
    raw_vulnerability: Dict[str, Any] = field(default_factory=dict)


STATUS_IN_PROGRESS = "IN_PROGRESS"
_OPEN_LIKE_STATUSES = (STATUS_OPEN, STATUS_REOPENED, STATUS_IN_PROGRESS)


def ingest_lockfile_findings(
    session: Session,
    repo_id: int,
    lockfile_path: str,
    scan_run_id: int,
    scan_run_status: str,
    built_findings: List["BuiltFinding"],
    is_baseline: bool,
) -> Tuple[Dict[str, int], List[Finding]]:
    """Bir lockfile'in TUM bilesenlerinden uretilen BuiltFinding listesini
    upsert eder ve RESOLVED/REOPENED reconciliation'ini yapar.

    master_prompt.md 4.3 RESOLVED kurali: sadece `scan_run_status == 'success'`
    ise eski acik bulgular (artik mevcut taramada gorunmeyenler) RESOLVED
    olur. PARTIAL/failed/needs_review taramalarda HICBIR bulgu kapanmaz.

    Donen ikinci deger (`created_findings`): BU cagirmada YENI olusturulan
    Finding'ler -- orchestrator/matching.py bunu A6 "kritik bulgu" aninda
    bildirim kararina (core/notifications.py) girdi olarak kullanir
    (master_prompt.md 6: 'Baseline bulgulari hicbir zaman bildirim uretmez',
    `is_baseline` zaten her Finding'in `baseline` alaninda tasiniyor).
    """
    now = dt.datetime.now(dt.timezone.utc)
    stats = {"created": 0, "updated": 0, "resolved": 0, "reopened": 0}
    created_findings: List[Finding] = []
    current_keys: Set[Tuple[Optional[str], str, str]] = set()

    for bf in built_findings:
        key = (bf.purl, bf.version, bf.canonical_vulnerability_id)
        current_keys.add(key)
        existing = session.execute(
            select(Finding).where(
                Finding.repo_id == repo_id,
                Finding.lockfile_path == lockfile_path,
                Finding.purl == bf.purl,
                Finding.version == bf.version,
                Finding.canonical_vulnerability_id == bf.canonical_vulnerability_id,
            )
        ).scalar_one_or_none()

        if existing is None:
            finding = Finding(
                repo_id=repo_id,
                lockfile_path=lockfile_path,
                ecosystem=bf.ecosystem,
                purl=bf.purl,
                package_name=bf.package_name,
                version=bf.version,
                scope=bf.scope,
                relation=bf.relation,
                canonical_vulnerability_id=bf.canonical_vulnerability_id,
                aliases=bf.aliases,
                severity_cvss_vector=bf.severity.cvss_vector,
                severity_cvss_score=bf.severity.cvss_score,
                severity_source=bf.severity.source,
                severity_conflict=bf.severity.conflict,
                fix_status=bf.fix.status,
                fix_version=bf.fix.version,
                fix_version_is_major_bump=bf.fix.is_major_bump,
                verification_status=bf.verification_status,
                needs_review_reason=bf.needs_review_reason,
                lifecycle_status=STATUS_OPEN,
                baseline=is_baseline,
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(finding)
            session.flush()
            session.add(
                FindingEvent(
                    finding_id=finding.id,
                    event_type="CREATED",
                    to_status=STATUS_OPEN,
                    reason="baseline" if is_baseline else "new_finding",
                )
            )
            session.add(
                FindingSource(
                    finding_id=finding.id, scan_run_id=scan_run_id, raw_vulnerability_id=bf.canonical_vulnerability_id
                )
            )
            stats["created"] += 1
            created_findings.append(finding)
        else:
            from_status = existing.lifecycle_status
            existing.last_seen_at = now
            existing.severity_cvss_vector = bf.severity.cvss_vector
            existing.severity_cvss_score = bf.severity.cvss_score
            existing.severity_source = bf.severity.source
            existing.severity_conflict = bf.severity.conflict
            existing.fix_status = bf.fix.status
            existing.fix_version = bf.fix.version
            existing.fix_version_is_major_bump = bf.fix.is_major_bump
            existing.verification_status = bf.verification_status
            existing.needs_review_reason = bf.needs_review_reason
            if from_status == STATUS_RESOLVED:
                existing.lifecycle_status = STATUS_REOPENED
                existing.resolved_at = None
                existing.resolved_scan_run_id = None
                session.add(
                    FindingEvent(
                        finding_id=existing.id, event_type="REOPENED", from_status=from_status, to_status=STATUS_REOPENED,
                        reason="component_vulnerability_seen_again",
                    )
                )
                stats["reopened"] += 1
            else:
                stats["updated"] += 1
            existing_source = session.execute(
                select(FindingSource).where(
                    FindingSource.finding_id == existing.id, FindingSource.scan_run_id == scan_run_id
                )
            ).scalar_one_or_none()
            if existing_source is None:
                session.add(
                    FindingSource(
                        finding_id=existing.id, scan_run_id=scan_run_id,
                        raw_vulnerability_id=bf.canonical_vulnerability_id,
                    )
                )

    if scan_run_status == "success":
        stale_findings = session.execute(
            select(Finding).where(
                Finding.repo_id == repo_id,
                Finding.lockfile_path == lockfile_path,
                Finding.lifecycle_status.in_(_OPEN_LIKE_STATUSES),
            )
        ).scalars().all()
        for existing in stale_findings:
            key = (existing.purl, existing.version, existing.canonical_vulnerability_id)
            if key in current_keys:
                continue
            from_status = existing.lifecycle_status
            existing.lifecycle_status = STATUS_RESOLVED
            existing.resolved_at = now
            existing.resolved_scan_run_id = scan_run_id
            session.add(
                FindingEvent(
                    finding_id=existing.id, event_type="RESOLVED", from_status=from_status, to_status=STATUS_RESOLVED,
                    reason="not_present_in_latest_successful_scan",
                )
            )
            stats["resolved"] += 1

    return stats, created_findings


def build_findings_for_component(
    repo_id: int, component: ParsedComponent, match: NormalizedPackageMatch
) -> List[BuiltFinding]:
    """Bir bilesen + onun Hat B eslesme sonucundan (0..N) BuiltFinding uretir.
    `match.vulnerabilities` bossa liste bos doner (zafiyet yok)."""
    built: List[BuiltFinding] = []
    for vuln in match.vulnerabilities:
        severity = compute_severity(vuln)
        verification_status, reason = determine_verification(severity)
        fix = compute_fix_recommendation(component.ecosystem, component.version, vuln.fixed_versions)
        built.append(
            BuiltFinding(
                repo_id=repo_id,
                lockfile_path="",  # cagiran taraf (orchestrator) doldurur
                ecosystem=component.ecosystem,
                purl=component.purl,
                package_name=component.name,
                version=component.version,
                scope=component.scope,
                relation=component.relation,
                canonical_vulnerability_id=vuln.canonical_id,
                aliases=vuln.aliases,
                severity=severity,
                fix=fix,
                verification_status=verification_status,
                needs_review_reason=reason,
                raw_vulnerability=vuln.raw,
            )
        )
    return built
