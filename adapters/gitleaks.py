"""Gitleaks adaptoru (master_prompt.md 3.4 adaptor sozlesmesi):
run(job_dir) -> ham cikti, parse(ham cikti) -> normalize edilmis liste.

GUVENLIK TASARIMI (kural 8, master_prompt.md 4.4 "Ham secret degeri DB'ye,
loglara, API yanitina, panele, bildirimlere ASLA yazilmaz"): run() gitleaks'i
redaksiyon OLMADAN calistirir (rapor dosyasinda ham deger gecici olarak
bulunur, SADECE worker'in izole, ag'siz surecinde), ama parse() bu degeri
HEMEN sha256 ile hash'ler ve sonuctan SILER. NormalizedSecretFinding
nesnesinde ham secret ASLA yer almaz -- sadece hash'i.

KVKK (master_prompt.md 5 "Veri minimizasyonu"): Gitleaks'in Author/Email
alanlari BILEREK okunmuyor/parse edilmiyor (commit yazari bilgisi saklanmaz).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# VERIFIED (docs/VERIFIED_FACTS.md, 2026-11-08): 0 = bulgu yok (temiz).
# 1 = bulgu VAR **veya** calisma hatasi -- Gitleaks bu ikisini AYNI exit
# koduyla doner. Ayirmak icin rapor dosyasinin GECERLI JSON olup olmadigina
# bakiyoruz (gercek hatada dosya yazilmaz/bozuk olur).
EXIT_CODE_CLEAN = 0
EXIT_CODE_FINDINGS_OR_ERROR = 1


@dataclass
class ScanExecutionResult:
    exit_code: int
    report_json: Optional[bytes]  # None: rapor dosyasi yok/gecersiz -> gercek hata
    stderr: bytes

    @property
    def succeeded(self) -> bool:
        if self.exit_code == EXIT_CODE_CLEAN:
            return True
        if self.exit_code == EXIT_CODE_FINDINGS_OR_ERROR:
            return self.report_json is not None
        return False


def run(
    binary_path: str,
    repo_mirror_path: str,
    report_path: str,
    log_opts: Optional[str] = None,
    timeout_seconds: int = 300,
) -> ScanExecutionResult:
    """`gitleaks git` ile commit GECMISINI tarar (master_prompt.md 4.4:
    koddan silinmis ama gecmiste var olan secret'lar da bulunmali -- bkz.
    docs/VERIFIED_FACTS.md: `gitleaks dir` SADECE diskteki guncel dosyalara
    bakar, bu yuzden KULLANILMAZ).

    `log_opts` verilmezse TUM gecmis taranir (ilk/tam tarama); verilirse
    (ör. "last_sha..HEAD") sadece o commit araligi taranir (incremental,
    master_prompt.md 4.4).
    """
    # VERIFIED (canli test, 2026-11-08): repo yolu POZITIF ARGUMAN'dir,
    # --repo-path diye bir flag YOKTUR ("unknown flag" + exit 126 ile dogrulandi).
    args = [
        binary_path, "git", repo_mirror_path,
        "--report-format=json",
        f"--report-path={report_path}",
        "--no-banner",
    ]
    if log_opts:
        args.append(f"--log-opts={log_opts}")
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return ScanExecutionResult(exit_code=-1, report_json=None, stderr=str(exc).encode("utf-8"))

    report_json: Optional[bytes] = None
    report_file = Path(report_path)
    if report_file.is_file():
        try:
            raw = report_file.read_bytes()
            json.loads(raw.decode("utf-8"))  # sadece gecerlilik kontrolu
            report_json = raw
        except (UnicodeDecodeError, json.JSONDecodeError, OSError):
            report_json = None
    return ScanExecutionResult(exit_code=proc.returncode, report_json=report_json, stderr=proc.stderr)


@dataclass
class NormalizedSecretFinding:
    rule_id: str
    file_path: str
    commit_sha: Optional[str] = None
    line_number: Optional[int] = None
    entropy: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    gitleaks_fingerprint: Optional[str] = None  # satira bagli, sadece kanit/referans
    custom_fingerprint: str = ""  # rule_id+file+secret_hash, SATIRDAN BAGIMSIZ
    secret_content_hash: str = ""


def parse(report_json: bytes) -> List[NormalizedSecretFinding]:
    """UYARI: Bu fonksiyon ham secret degerini (`entry["Secret"]`) SADECE
    hash hesaplamak icin okur; donen NormalizedSecretFinding nesnesinde
    ham deger HICBIR ZAMAN tutulmaz, sadece sha256 hash'i tutulur."""
    if not report_json or not report_json.strip():
        return []
    try:
        data = json.loads(report_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Gitleaks ciktisi parse edilemedi: {exc}") from exc
    if not isinstance(data, list):
        return []

    findings: List[NormalizedSecretFinding] = []
    for entry in data:
        rule_id = entry.get("RuleID", "")
        file_path = entry.get("File", "")
        raw_secret = entry.get("Secret") or ""
        secret_content_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
        custom_fingerprint = hashlib.sha256(
            f"{rule_id}:{file_path}:{secret_content_hash}".encode("utf-8")
        ).hexdigest()
        findings.append(
            NormalizedSecretFinding(
                rule_id=rule_id,
                file_path=file_path,
                commit_sha=entry.get("Commit") or None,
                line_number=entry.get("StartLine"),
                entropy=entry.get("Entropy"),
                tags=list(entry.get("Tags") or []),
                gitleaks_fingerprint=entry.get("Fingerprint"),
                custom_fingerprint=custom_fingerprint,
                secret_content_hash=secret_content_hash,
            )
        )
    return findings
