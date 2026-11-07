"""OSV-Scanner adaptoru (master_prompt.md 3.4 adaptor sozlesmesi):
run(job_dir) -> ham cikti, parse(ham cikti) -> normalize edilmis liste.

Hat B (eslestirme) icin kullanilir. worker/main.py tarafindan cagrilir
(network_mode: none container icinde). --offline ZORUNLU (bkz.
docs/VERIFIED_FACTS.md: OSV-Scanner varsayilan modda CEVRIMICIDIR).

ONEMLI (bkz. core/lockfile_parser.py docstring'i): Bu adaptor Hat A'nin
envanter kaynagi DEGILDIR -- OSV-Scanner zafiyetsiz paketler icin BOS
cikti doner. Sadece Hat B'nin "bu paket@surum zafiyetli mi" sorusunu
cevaplamak icin kullanilir.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCANNER_NAME = "osv-scanner"

# Ampirik olarak dogrulandi (Asama 0b/2 spike, bkz. docs/VERIFIED_FACTS.md):
# 0 = basarili calisma, zafiyet YOK. 1 = basarili calisma, zafiyet BULUNDU.
# Baska bir kod (ör. 127) = calisma/parse HATASI (sanity gate -> PARTIAL/failed).
EXIT_CODE_SUCCESS_NO_FINDINGS = 0
EXIT_CODE_SUCCESS_WITH_FINDINGS = 1


@dataclass
class ScanExecutionResult:
    exit_code: int
    stdout: bytes
    stderr: bytes

    @property
    def succeeded(self) -> bool:
        return self.exit_code in (EXIT_CODE_SUCCESS_NO_FINDINGS, EXIT_CODE_SUCCESS_WITH_FINDINGS)


def run(
    binary_path: str,
    target_path: str,
    db_cache_dir: str,
    timeout_seconds: int = 120,
) -> ScanExecutionResult:
    """target_path bir lockfile dosyasi VEYA bir SBOM (CycloneDX) dosyasi
    olabilir (ikisi de ayni JSON seklini uretir, bkz. docs/MATCHING_SPIKE.md)."""
    env = dict(os.environ)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = db_cache_dir
    try:
        proc = subprocess.run(
            [
                binary_path, "scan", "source",
                "--offline", "--offline-vulnerabilities",
                "--format", "json",
                target_path,
            ],
            capture_output=True,
            timeout=timeout_seconds,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return ScanExecutionResult(exit_code=-1, stdout=b"", stderr=str(exc).encode("utf-8"))
    return ScanExecutionResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


@dataclass
class NormalizedVulnerability:
    canonical_id: str
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    severity_cvss_vector: Optional[str] = None
    database_specific_severity: Optional[str] = None
    # Bu paket+ekosistem icin OSV'nin bildirdigi TUM "fixed" surumleri (ham,
    # siralanmamis). Hangisinin "onerilen yukseltme" oldugunu secmek
    # core/finding_model.py'nin isi (univers ile, ekosistem-farkli siralama).
    fixed_versions: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedPackageMatch:
    ecosystem: str
    name: str
    version: str
    purl: Optional[str]
    vulnerabilities: List[NormalizedVulnerability] = field(default_factory=list)


def parse(raw_stdout: bytes) -> List[NormalizedPackageMatch]:
    try:
        data = json.loads(raw_stdout.decode("utf-8")) if raw_stdout.strip() else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"OSV-Scanner ciktisi parse edilemedi: {exc}") from exc

    matches: List[NormalizedPackageMatch] = []
    for result in data.get("results", []) or []:
        for pkg_entry in result.get("packages", []) or []:
            pkg = pkg_entry.get("package", {}) or {}
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            vulns: List[NormalizedVulnerability] = []
            for v in pkg_entry.get("vulnerabilities", []) or []:
                severity_vector = None
                for sev in v.get("severity", []) or []:
                    if sev.get("type") == "CVSS_V3":
                        severity_vector = sev.get("score")
                        break
                db_specific = v.get("database_specific", {}) or {}
                vulns.append(
                    NormalizedVulnerability(
                        canonical_id=v.get("id", ""),
                        aliases=list(v.get("aliases", []) or []),
                        summary=v.get("summary", ""),
                        severity_cvss_vector=severity_vector,
                        database_specific_severity=db_specific.get("severity"),
                        fixed_versions=_extract_fixed_versions(v, ecosystem, name),
                        raw=v,
                    )
                )
            matches.append(
                NormalizedPackageMatch(
                    ecosystem=ecosystem, name=name, version=pkg.get("version", ""), purl=pkg.get("purl"),
                    vulnerabilities=vulns,
                )
            )
    return matches


def _extract_fixed_versions(vuln: Dict[str, Any], ecosystem: str, name: str) -> List[str]:
    fixed: List[str] = []
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        if ecosystem and pkg.get("ecosystem") != ecosystem:
            continue
        if name and pkg.get("name") != name:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                fixed_version = event.get("fixed")
                if fixed_version:
                    fixed.append(fixed_version)
    return fixed
