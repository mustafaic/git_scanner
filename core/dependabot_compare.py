"""Dependabot karsilastirmasi (master_prompt.md 8): "tools/dependabot_compare.py
... Dependabot alert'lerini aracimizin bulgularıyla karşılaştırıp kaçırdığımız
bulguları (recall) ve çelişkileri raporlar; Dependabot burada yalnızca
bağımsız doğrulama kaynağıdır, ürün akışına girmez."

Bu modul SAF FONKSIYONLARDAN olusur (core/finding_model.py ile ayni desen):
HTTP/DB baglantisi yok, sadece ilkel veri alir -- tools/dependabot_compare.py
I/O'yu (GitHub API, Postgres) yapip bu fonksiyonlara besler.

EKOSISTEM ESLEMESI (2026-11-09, resmi dokumandan dogrulandi -- bkz.
docs/VERIFIED_FACTS.md): Dependabot'un `ecosystem` degerleri OSV/bizim
ECOSYSTEM_* sabitlerimizden FARKLI string'ler kullanir. KRITIK: Rust icin
Dependabot "rust" der, "cargo" DEMEZ (ilk tahminin tersi, resmi dokumandan
duzeltildi)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.lockfile_parser import (
    ECOSYSTEM_CARGO,
    ECOSYSTEM_GO,
    ECOSYSTEM_MAVEN,
    ECOSYSTEM_NPM,
    ECOSYSTEM_NUGET,
    ECOSYSTEM_PACKAGIST,
    ECOSYSTEM_PYPI,
    ECOSYSTEM_RUBYGEMS,
)

# Dependabot ecosystem string -> bizim ECOSYSTEM_* sabitimiz. "pub" (Dart/
# Flutter) icin karsiligimiz yok (core/lockfile_parser.py desteklemiyor).
DEPENDABOT_ECOSYSTEM_MAP: Dict[str, str] = {
    "npm": ECOSYSTEM_NPM,
    "pip": ECOSYSTEM_PYPI,
    "go": ECOSYSTEM_GO,
    "rust": ECOSYSTEM_CARGO,
    "composer": ECOSYSTEM_PACKAGIST,
    "maven": ECOSYSTEM_MAVEN,
    "nuget": ECOSYSTEM_NUGET,
    "rubygems": ECOSYSTEM_RUBYGEMS,
}


def map_dependabot_ecosystem(ecosystem: str) -> Optional[str]:
    """None donerse bu ekosistem bizim tarafimizda desteklenmiyor --
    karsilastirma YAPILAMAZ (yanlis-pozitif 'kacirdik' raporu URETILMEMELI)."""
    return DEPENDABOT_ECOSYSTEM_MAP.get(ecosystem)


def alert_vulnerability_ids(alert: Dict[str, Any]) -> Set[str]:
    """Bir Dependabot alert'inin GHSA/CVE kimliklerini (karsilastirma icin
    kullanilacak TUM ad varyantlarini) doner."""
    advisory = alert.get("security_advisory") or {}
    ids: Set[str] = set()
    if advisory.get("ghsa_id"):
        ids.add(advisory["ghsa_id"])
    if advisory.get("cve_id"):
        ids.add(advisory["cve_id"])
    for identifier in advisory.get("identifiers") or []:
        value = identifier.get("value")
        if value:
            ids.add(value)
    return ids


def finding_vulnerability_ids(canonical_vulnerability_id: str, aliases: List[str]) -> Set[str]:
    return {canonical_vulnerability_id, *aliases}


@dataclass
class FindingLite:
    """Karsilastirma icin Finding modelinin minimal izdusumu -- core/
    bu dosya ORM'e bagli olmasin diye (test edilebilirlik, kural: finding_model.py
    ile ayni felsefe)."""

    package_name: str
    ecosystem: str
    canonical_vulnerability_id: str
    aliases: List[str] = field(default_factory=list)


@dataclass
class AlertComparisonResult:
    repo_full_name: str
    matched_alert_numbers: List[int] = field(default_factory=list)
    missed_alert_numbers: List[int] = field(default_factory=list)  # RECALL GAP -- kritik metrik
    unsupported_ecosystem_alert_numbers: List[int] = field(default_factory=list)
    extra_findings_without_alert: List[str] = field(default_factory=list)  # bilgi amacli, FP ANLAMINA GELMEZ


def compare_alerts_to_findings(
    repo_full_name: str, alerts: List[Dict[str, Any]], findings: List[FindingLite],
) -> AlertComparisonResult:
    """`alerts` SADECE `state == "open"` olanlari icermeli (cagiran taraf
    filtreler, bkz. tools/dependabot_compare.py). Eslesme kurali: AYNI
    ekosistem + (GHSA/CVE kimlik kesisimi bos degil). Paket adi/surum
    KARSILASTIRMADA KULLANILMAZ -- Dependabot "fixed" oldugunu dusundugu
    bir surumle bizden farkli bir an'da ayni zafiyeti raporlayabilir,
    asil onemli olan "bu zafiyeti biliyor muyuz" sorusu (recall)."""
    result = AlertComparisonResult(repo_full_name=repo_full_name)

    finding_id_sets = [finding_vulnerability_ids(f.canonical_vulnerability_id, f.aliases) for f in findings]
    finding_ecosystems = [f.ecosystem for f in findings]
    matched_finding_indices: Set[int] = set()

    for alert in alerts:
        number = alert.get("number")
        dependabot_ecosystem = ((alert.get("dependency") or {}).get("package") or {}).get("ecosystem", "")
        our_ecosystem = map_dependabot_ecosystem(dependabot_ecosystem)
        if our_ecosystem is None:
            result.unsupported_ecosystem_alert_numbers.append(number)
            continue

        alert_ids = alert_vulnerability_ids(alert)
        found = False
        for i, (ids, eco) in enumerate(zip(finding_id_sets, finding_ecosystems)):
            if eco == our_ecosystem and ids & alert_ids:
                found = True
                matched_finding_indices.add(i)
        if found:
            result.matched_alert_numbers.append(number)
        else:
            result.missed_alert_numbers.append(number)

    for i, f in enumerate(findings):
        if i not in matched_finding_indices:
            result.extra_findings_without_alert.append(f.canonical_vulnerability_id)

    return result
