"""Advisory (OSV offline DB) + KEV + EPSS mirror senkronu (master_prompt.md
3.3 Hat B adim 1-2, 5 "Veri cikisi politikasi"). SADECE toplu PUBLIC dosya
indirme -- bilesen/paket bazinda cevrimici sorgu YASAK (kural 12/kapsam).

Bu modul orchestrator'da calisir (ag erisimi var); worker DB'yi READ-ONLY
mount olarak kullanir, kendisi hic indirme yapmaz (master_prompt.md 5).
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.models import AdvisoryMirrorSync, EpssScore, KevEntry

LOG = logging.getLogger(__name__)

# VERIFIED (docs/VERIFIED_FACTS.md, 2026-11-08): OSV-Scanner'in offline DB
# dizin yapisi tam olarak budur (osv-db-cache/osv-scalibr/<Ecosystem>/all.zip).
OSV_DB_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# VERIFIED: resmi cisa.gov URL'si programatik istekleri 403 ile reddediyor
# (WAF/bot korumasi, gercek tarayici UA ile de denendi, sonuc degismedi).
# Ayni veri CISA'nin kendi resmi GitHub mirror'inda (cisagov/kev-data) 200
# donuyor -- bu yuzden PRIMARY kaynak olarak mirror kullaniliyor.
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

# VERIFIED: sabit URL, 302 ile o gunun dosyasina yonlendiriyor (follow_redirects gerekir).
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

DEFAULT_HEADERS = {"User-Agent": "scanner-platform-mirror/1.0 (+internal)"}


class MirrorSyncResult:
    def __init__(self, source: str, succeeded: bool, item_count: Optional[int] = None,
                 checksum: Optional[str] = None, error: Optional[str] = None,
                 payload: Optional[Any] = None) -> None:
        self.source = source
        self.succeeded = succeeded
        self.item_count = item_count
        self.checksum = checksum
        self.error = error
        self.payload = payload


def sync_osv_ecosystem_db(
    db_cache_dir: Path, ecosystem: str, http_client: Optional[httpx.Client] = None
) -> MirrorSyncResult:
    client = http_client or httpx.Client(timeout=180.0, follow_redirects=True, headers=DEFAULT_HEADERS)
    url = f"{OSV_DB_BASE_URL}/{ecosystem}/all.zip"
    source = f"osv-{ecosystem}"
    try:
        response = client.get(url)
    except httpx.HTTPError as exc:
        return MirrorSyncResult(source, False, error=str(exc))
    if response.status_code != 200:
        return MirrorSyncResult(source, False, error=f"HTTP {response.status_code}")

    target_dir = db_cache_dir / "osv-scalibr" / ecosystem
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "all.zip").write_bytes(response.content)
    checksum = hashlib.sha256(response.content).hexdigest()
    return MirrorSyncResult(source, True, item_count=len(response.content), checksum=checksum)


def parse_kev_json(raw: bytes) -> List[Dict[str, Any]]:
    import json

    data = json.loads(raw.decode("utf-8"))
    entries = []
    for item in data.get("vulnerabilities", []) or []:
        entries.append(
            {
                "cve_id": item.get("cveID"),
                "date_added": item.get("dateAdded"),
                "vulnerability_name": item.get("vulnerabilityName"),
            }
        )
    return [e for e in entries if e["cve_id"]]


def sync_kev(http_client: Optional[httpx.Client] = None) -> MirrorSyncResult:
    client = http_client or httpx.Client(timeout=60.0, follow_redirects=True, headers=DEFAULT_HEADERS)
    try:
        response = client.get(KEV_URL)
    except httpx.HTTPError as exc:
        return MirrorSyncResult("kev", False, error=str(exc))
    if response.status_code != 200:
        return MirrorSyncResult("kev", False, error=f"HTTP {response.status_code}")
    try:
        entries = parse_kev_json(response.content)
    except Exception as exc:  # noqa: BLE001
        return MirrorSyncResult("kev", False, error=f"parse_error: {exc}")
    checksum = hashlib.sha256(response.content).hexdigest()
    return MirrorSyncResult("kev", True, item_count=len(entries), checksum=checksum, payload=entries)


def parse_epss_csv(raw_gzip_bytes: bytes) -> List[Dict[str, Any]]:
    raw = gzip.decompress(raw_gzip_bytes)
    text = raw.decode("utf-8")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not lines:
        return []
    reader = csv.DictReader(lines)
    entries = []
    for row in reader:
        try:
            entries.append(
                {
                    "cve_id": row["cve"],
                    "score": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
            )
        except (KeyError, ValueError):
            continue
    return entries


def sync_epss(http_client: Optional[httpx.Client] = None) -> MirrorSyncResult:
    client = http_client or httpx.Client(timeout=60.0, follow_redirects=True, headers=DEFAULT_HEADERS)
    try:
        response = client.get(EPSS_URL)
    except httpx.HTTPError as exc:
        return MirrorSyncResult("epss", False, error=str(exc))
    if response.status_code != 200:
        return MirrorSyncResult("epss", False, error=f"HTTP {response.status_code}")
    try:
        entries = parse_epss_csv(response.content)
    except Exception as exc:  # noqa: BLE001
        return MirrorSyncResult("epss", False, error=f"parse_error: {exc}")
    checksum = hashlib.sha256(response.content).hexdigest()
    return MirrorSyncResult("epss", True, item_count=len(entries), checksum=checksum, payload=entries)


def apply_mirror_result(session: Session, result: MirrorSyncResult) -> None:
    """Senkron sonucunu DB'ye yazar: her zaman `advisory_mirror_syncs`'e bir
    kayit (basarili/basarisiz), basariliysa ayrica kev_entries/epss_scores'u
    upsert eder. Basarisiz senkron hicbir bulguyu etkilemez (sadece eski
    veri "bayat" kalir -- master_prompt.md 4.6)."""
    session.add(
        AdvisoryMirrorSync(
            source=result.source, succeeded=result.succeeded, item_count=result.item_count,
            checksum=result.checksum, error=result.error,
        )
    )
    if not result.succeeded or result.payload is None:
        return

    if result.source == "kev":
        for entry in result.payload:
            stmt = (
                pg_insert(KevEntry)
                .values(cve_id=entry["cve_id"], date_added=entry.get("date_added"), vulnerability_name=entry.get("vulnerability_name"))
                .on_conflict_do_update(
                    index_elements=[KevEntry.cve_id],
                    set_={"date_added": entry.get("date_added"), "vulnerability_name": entry.get("vulnerability_name")},
                )
            )
            session.execute(stmt)
    elif result.source == "epss":
        import datetime as dt

        as_of = dt.date.today()
        for entry in result.payload:
            stmt = (
                pg_insert(EpssScore)
                .values(cve_id=entry["cve_id"], score=entry["score"], percentile=entry["percentile"], as_of_date=as_of)
                .on_conflict_do_update(
                    index_elements=[EpssScore.cve_id],
                    set_={"score": entry["score"], "percentile": entry["percentile"], "as_of_date": as_of},
                )
            )
            session.execute(stmt)
