#!/usr/bin/env python3
"""Dependabot karsilastirmasi (master_prompt.md 8) -- INSAN TARAFINDAN
calistirilir, urun akisina GIRMEZ. Dependabot alert'lerini bizim
`findings` tablomuzla karsilastirip KACIRDIGIMIZ zafiyetleri (recall gap)
ve ekosistem kapsama farklarini raporlar.

Kullanim:
    DEPENDABOT_COMPARE_TOKEN=ghp_... python tools/dependabot_compare.py

Token: okuma yetkili bir PAT, `security_events` kapsamiyla (ozel repolar
icin) veya genel repolarda `public_repo` (resmi dokuman, 2026-11-09
dogrulandi). GitHub App'in KENDI izin kumesine HICBIR SEY EKLENMEZ --
bu script App'ten TAMAMEN BAGIMSIZ, kendi ayri token'ini kullanir
(master_prompt.md 8: "App'e ek izin gerektirmez").

TOKEN ASLA LOGLANMAZ (core.logging_setup.register_secret)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import httpx
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.config import load_settings  # noqa: E402
from core.db import init_engine, session_scope  # noqa: E402
from core.dependabot_compare import FindingLite, compare_alerts_to_findings  # noqa: E402
from core.logging_setup import register_secret  # noqa: E402
from core.models import Finding, Repository  # noqa: E402

_OPEN_LIKE = ("OPEN", "IN_PROGRESS", "REOPENED")


def fetch_open_alerts(client: httpx.Client, api_base_url: str, full_name: str) -> List[Dict[str, Any]]:
    """Cursor tabanli sayfalama (Link header, `rel="next"`) -- bu uc nokta
    klasik `page=N` KULLANMAZ (2026-11-09 resmi dokumandan dogrulandi)."""
    alerts: List[Dict[str, Any]] = []
    url = f"{api_base_url}/repos/{full_name}/dependabot/alerts"
    params = {"state": "open", "per_page": 100}
    while url:
        resp = client.get(url, params=params)
        if resp.status_code == 404:
            return []  # Dependabot kapali/erisim yok -- sessizce atla
        resp.raise_for_status()
        alerts.extend(resp.json())
        next_link = resp.links.get("next")
        url = next_link["url"] if next_link else None
        params = None  # sonraki URL zaten tum query string'i icerir
    return alerts


def main() -> int:
    token = os.environ.get("DEPENDABOT_COMPARE_TOKEN")
    if not token:
        print("HATA: DEPENDABOT_COMPARE_TOKEN ortam degiskeni ayarlanmamis.", file=sys.stderr)
        return 1
    register_secret(token)

    settings = load_settings()
    init_engine(settings.database_url)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    with session_scope() as session:
        repos = session.execute(
            select(Repository).where(Repository.is_active.is_(True), Repository.scan_excluded.is_(False))
        ).scalars().all()
        repo_rows = [(r.github_repo_id, r.full_name) for r in repos]

    total_matched = total_missed = total_unsupported = 0
    missed_details = []

    with httpx.Client(timeout=30.0, headers=headers) as client:
        for repo_id, full_name in repo_rows:
            alerts = fetch_open_alerts(client, settings.github_api_base_url, full_name)
            if not alerts:
                continue

            with session_scope() as session:
                finding_rows = session.execute(
                    select(Finding).where(Finding.repo_id == repo_id, Finding.lifecycle_status.in_(_OPEN_LIKE))
                ).scalars().all()
            findings = [
                FindingLite(package_name=f.package_name, ecosystem=f.ecosystem,
                            canonical_vulnerability_id=f.canonical_vulnerability_id, aliases=f.aliases)
                for f in finding_rows
            ]

            result = compare_alerts_to_findings(full_name, alerts, findings)
            total_matched += len(result.matched_alert_numbers)
            total_missed += len(result.missed_alert_numbers)
            total_unsupported += len(result.unsupported_ecosystem_alert_numbers)
            if result.missed_alert_numbers:
                missed_details.append((full_name, result.missed_alert_numbers))

            print(
                f"{full_name}: {len(alerts)} acik Dependabot alert'i -- "
                f"{len(result.matched_alert_numbers)} eslesti, "
                f"{len(result.missed_alert_numbers)} KACIRILDI, "
                f"{len(result.unsupported_ecosystem_alert_numbers)} desteklenmeyen ekosistem"
            )

    print("\n=== OZET ===")
    print(f"Eslesen: {total_matched}")
    print(f"KACIRILAN (recall gap): {total_missed}")
    print(f"Desteklenmeyen ekosistem (atlandi): {total_unsupported}")
    if total_matched + total_missed > 0:
        recall = total_matched / (total_matched + total_missed)
        print(f"Recall: {recall:.1%}")
    if missed_details:
        print("\nKacirilan alert'ler (repo: alert numaralari):")
        for full_name, numbers in missed_details:
            print(f"  {full_name}: {numbers}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
