"""Hat B: eslestirme -- anlik (commit sonrasi) ve gunluk tam
(master_prompt.md 3.3).

Anlik: bir repo'nun degisen lockfile blob'u DOGRUDAN worker'a verilir
(S2 stratejisi, bkz. docs/MATCHING_SPIKE.md), sonuc o repo'nun
bulgularina islenir -- dakikalar icinde geri bildirim.

Gunluk tam: TUM repolardaki benzersiz (ecosystem,name,version) kumesi
cikarilir, sentetik bir CycloneDX SBOM olusturulur (S1), worker'a BIR KEZ
verilir (repo sayisi kadar degil); sonuc TUM ilgili (repo,lockfile)
ikilisine dagitilir. Boylece her gun N repo yerine M (<<N) benzersiz
bilesen eslestirilir (master_prompt.md 3.1).

RESOLVED kurali icin DB tazeligi sarti: bkz. is_advisory_data_fresh().
"""

from __future__ import annotations

import datetime as dt
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from adapters.osv_scanner import NormalizedPackageMatch, run as run_osv_scanner_binary
from core.finding_model import (
    STATUS_RESOLVED,
    BuiltFinding,
    build_findings_for_component,
    ingest_lockfile_findings,
    normalize_version_for_ecosystem,
)
from core.lockfile_parser import ParsedComponent
from core.models import AdvisoryMirrorSync, ComponentSnapshot, Finding, ScanRun
from core.notifications import (
    CHANNEL_EMAIL,
    EVENT_CRITICAL_SCA_FINDING,
    SmtpSettings,
    record_and_maybe_send,
    should_notify_critical_sca,
)
from core.worker_protocol import (
    WorkerJob,
    clear_staging,
    is_result_ready,
    read_result,
    stage_input_file,
    write_job,
)

WORKER_JOB_TIMEOUT_SECONDS = 180
WORKER_POLL_INTERVAL_SECONDS = 0.3

# master_prompt.md 3.3: "Bulgu kapatma icin ek kosul: ... DB taze olmali
# (maksimum yas config'de)". Hangi kaynaklarin "zorunlu taze" sayildigi.
REQUIRED_FRESH_SOURCES = ("kev", "epss")


def run_osv_scan_job(
    staging_dir: Path, binary_path: str, db_cache_dir: str, input_filename: str, content: bytes,
    timeout_seconds: int = WORKER_JOB_TIMEOUT_SECONDS,
) -> Tuple[int, List[NormalizedPackageMatch]]:
    """Worker'a bir 'osv_scan' isi verir (dosya tabanli protokol uzerinden,
    gercek calistirmada worker/main.py bunu isler). Donen: (exit_code, matches)."""
    from adapters.osv_scanner import parse as parse_osv_output

    clear_staging(staging_dir)
    stage_input_file(staging_dir, input_filename, content)
    write_job(staging_dir, WorkerJob(job_id=str(uuid.uuid4()), job_kind="osv_scan", input_filename=input_filename))

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_result_ready(staging_dir):
            result = read_result(staging_dir)
            clear_staging(staging_dir)
            matches = parse_osv_output(result.stdout) if result.exit_code in (0, 1) else []
            return result.exit_code, matches
        time.sleep(WORKER_POLL_INTERVAL_SECONDS)
    clear_staging(staging_dir)
    raise RuntimeError(f"Worker osv_scan zaman asimi: {input_filename}")


def is_advisory_data_fresh(session: Session, max_age_seconds: int) -> bool:
    """master_prompt.md 3.3/4.6: senkron basarisiz/bayatsa hicbir bulgu
    kapanmaz. Zorunlu kaynaklarin (KEV, EPSS) HER BIRI icin en son BASARILI
    senkron max_age_seconds icinde olmali."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=max_age_seconds)
    for source in REQUIRED_FRESH_SOURCES:
        latest = session.execute(
            select(func.max(AdvisoryMirrorSync.synced_at)).where(
                AdvisoryMirrorSync.source == source, AdvisoryMirrorSync.succeeded.is_(True)
            )
        ).scalar_one_or_none()
        if latest is None or latest < cutoff:
            return False
    return True


def _notify_critical_sca_findings(
    session: Session, created_findings: List[Finding], smtp_settings: Optional[SmtpSettings], notify_recipients: Optional[List[str]],
) -> None:
    """master_prompt.md 6 'Iletisim modeli': 'KEV'de olan veya CVSS >= 9
    SCA bulgusu (baseline degil) -> ANINDA'. Kanal konfigure/acik degilse
    (smtp_settings None veya alici yoksa) core.notifications zaten no-op
    doner -- burada erken cikis SADECE gereksiz dongu/sorguyu atlar."""
    if not smtp_settings or not notify_recipients:
        return
    for finding in created_findings:
        cvss = float(finding.severity_cvss_score) if finding.severity_cvss_score is not None else None
        if not should_notify_critical_sca(kev=finding.kev, cvss_score=cvss, is_baseline=finding.baseline):
            continue
        subject = f"[Kritik] {finding.package_name} {finding.version} -- {finding.canonical_vulnerability_id}"
        body = (
            f"Repo ID: {finding.repo_id}\nLockfile: {finding.lockfile_path}\n"
            f"Paket: {finding.package_name}@{finding.version}\nZafiyet: {finding.canonical_vulnerability_id}\n"
            f"CVSS: {cvss if cvss is not None else '-'}\nKEV: {finding.kev}\n"
        )
        record_and_maybe_send(
            session, event_type=EVENT_CRITICAL_SCA_FINDING, dedup_key=f"finding:{finding.id}",
            channel=CHANNEL_EMAIL, recipients=notify_recipients, subject=subject, body=body, smtp_settings=smtp_settings,
        )


def run_immediate_match(
    session: Session,
    staging_dir: Path,
    osv_binary_path: str,
    db_cache_dir: str,
    repo_id: int,
    lockfile_path: str,
    lockfile_blob_sha: str,
    lockfile_content: bytes,
    db_is_fresh: bool,
    is_baseline: bool = False,
    smtp_settings: Optional[SmtpSettings] = None,
    notify_recipients: Optional[List[str]] = None,
) -> ScanRun:
    """Bir repo'nun TEK bir degisen lockfile'i icin anlik eslestirme
    (master_prompt.md 3.3: "commit sonrasi aninda eslestirme")."""
    scan_run = ScanRun(
        run_type="immediate_match", repo_id=repo_id, lockfile_path=lockfile_path,
        lockfile_blob_sha=lockfile_blob_sha, scanner_name="osv-scanner", status="success",
    )
    session.add(scan_run)
    session.flush()

    try:
        exit_code, matches = run_osv_scan_job(
            staging_dir, osv_binary_path, db_cache_dir, lockfile_path.rsplit("/", 1)[-1], lockfile_content
        )
    except Exception as exc:  # noqa: BLE001
        scan_run.status = "failed"
        scan_run.error = str(exc)
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    if exit_code not in (0, 1):
        scan_run.status = "failed"
        scan_run.error = f"osv-scanner exit_code={exit_code}"
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    components = session.execute(
        select(ComponentSnapshot).where(
            ComponentSnapshot.repo_id == repo_id, ComponentSnapshot.lockfile_path == lockfile_path,
            ComponentSnapshot.is_current.is_(True),
        )
    ).scalars().all()

    matches_by_key = {
        (m.ecosystem, m.name, normalize_version_for_ecosystem(m.ecosystem, m.version)): m for m in matches
    }

    built: List[BuiltFinding] = []
    for comp in components:
        key = (comp.ecosystem, comp.name, normalize_version_for_ecosystem(comp.ecosystem, comp.version))
        match = matches_by_key.get(key)
        if match is None or not match.vulnerabilities:
            continue
        parsed = ParsedComponent(comp.ecosystem, comp.name, comp.version, comp.scope, comp.relation, comp.purl)
        built.extend(build_findings_for_component(repo_id, parsed, match))
    for bf in built:
        bf.lockfile_path = lockfile_path

    # DB bayatsa Hat B basariyla calismis olsa da bulgu KAPATILAMAZ (4.6);
    # ingest_lockfile_findings'e "success" DISINDA bir durum veririz.
    ingest_status = "success" if db_is_fresh else "needs_review"
    stats, created_findings = ingest_lockfile_findings(session, repo_id, lockfile_path, scan_run.id, ingest_status, built, is_baseline)
    _notify_critical_sca_findings(session, created_findings, smtp_settings, notify_recipients)
    scan_run.details = {**stats, "db_fresh": db_is_fresh}
    scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
    return scan_run


def build_synthetic_sbom(components: List[Tuple[str, str, str, Optional[str]]]) -> bytes:
    """S1 stratejisi (bkz. docs/MATCHING_SPIKE.md): gunluk tam eslestirme
    icin benzersiz bilesen kumesinden minimal bir CycloneDX 1.5 SBOM uretir."""
    cdx_components = []
    for ecosystem, name, version, purl in components:
        comp: Dict[str, Any] = {"type": "library", "name": name, "version": version}
        if purl:
            comp["purl"] = purl
        cdx_components.append(comp)
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": cdx_components}
    return json.dumps(doc).encode("utf-8")


def run_daily_match(
    session: Session, staging_dir: Path, osv_binary_path: str, db_cache_dir: str, db_is_fresh: bool,
    smtp_settings: Optional[SmtpSettings] = None, notify_recipients: Optional[List[str]] = None,
) -> ScanRun:
    """Gunluk tam eslestirme: benzersiz bilesen kumesi -> sentetik SBOM ->
    TEK worker cagrisi -> tum (repo,lockfile) ikililerine dagitim."""
    scan_run = ScanRun(run_type="daily_match", status="success", scanner_name="osv-scanner")
    session.add(scan_run)
    session.flush()

    all_current = session.execute(
        select(ComponentSnapshot).where(ComponentSnapshot.is_current.is_(True))
    ).scalars().all()

    unique_components: Dict[Tuple[str, str, str], Optional[str]] = {}
    groups: Dict[Tuple[int, str], List[ComponentSnapshot]] = {}
    for comp in all_current:
        norm_version = normalize_version_for_ecosystem(comp.ecosystem, comp.version)
        key = (comp.ecosystem, comp.name, norm_version)
        unique_components.setdefault(key, comp.purl)
        groups.setdefault((comp.repo_id, comp.lockfile_path), []).append(comp)

    if not unique_components:
        scan_run.details = {"unique_components": 0}
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    sbom_bytes = build_synthetic_sbom([(eco, name, ver, purl) for (eco, name, ver), purl in unique_components.items()])

    try:
        exit_code, matches = run_osv_scan_job(staging_dir, osv_binary_path, db_cache_dir, "bom.json", sbom_bytes)
    except Exception as exc:  # noqa: BLE001
        scan_run.status = "failed"
        scan_run.error = str(exc)
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    if exit_code not in (0, 1):
        scan_run.status = "failed"
        scan_run.error = f"osv-scanner exit_code={exit_code}"
        scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
        return scan_run

    matches_by_key = {
        (m.ecosystem, m.name, normalize_version_for_ecosystem(m.ecosystem, m.version)): m for m in matches
    }

    totals = {"created": 0, "updated": 0, "resolved": 0, "reopened": 0}
    ingest_status = "success" if db_is_fresh else "needs_review"
    for (repo_id, lockfile_path), comps in groups.items():
        built: List[BuiltFinding] = []
        for comp in comps:
            key = (comp.ecosystem, comp.name, normalize_version_for_ecosystem(comp.ecosystem, comp.version))
            match = matches_by_key.get(key)
            if match is None or not match.vulnerabilities:
                continue
            parsed = ParsedComponent(comp.ecosystem, comp.name, comp.version, comp.scope, comp.relation, comp.purl)
            built.extend(build_findings_for_component(repo_id, parsed, match))
        for bf in built:
            bf.lockfile_path = lockfile_path
        stats, created_findings = ingest_lockfile_findings(session, repo_id, lockfile_path, scan_run.id, ingest_status, built, is_baseline=False)
        _notify_critical_sca_findings(session, created_findings, smtp_settings, notify_recipients)
        for key in totals:
            totals[key] += stats[key]

    scan_run.details = {"unique_components": len(unique_components), "db_fresh": db_is_fresh, **totals}
    scan_run.finished_at = dt.datetime.now(dt.timezone.utc)
    return scan_run
