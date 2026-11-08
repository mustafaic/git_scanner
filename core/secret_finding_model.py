"""Secret finding modeli: dedup, lifecycle (master_prompt.md 4.4 --
SCA'dan FARKLI kurallar).

KRITIK KURAL (4.4): "Koddan silinince RESOLVED OLMAZ; git gecmisinde kalir.
Kapanis kosulu: admin'in 'rotate edildi/iptal edildi' onayi." Bu modul
KODU bu kurala gore yazar: incremental/full taramadan bagimsiz olarak,
present_in_current_code=False olmasi HICBIR ZAMAN lifecycle_status'u
degistirmez -- sadece confirm_rotation() (admin eylemi) degistirir.
"""

from __future__ import annotations

import datetime as dt
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from adapters.gitleaks import NormalizedSecretFinding
from core.models import SecretFinding, SecretFindingEvent

STATUS_OPEN = "OPEN"
STATUS_ROTATED = "ROTATED"
STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
STATUS_ACCEPTED_RISK = "ACCEPTED_RISK"


def ingest_secret_findings(
    session: Session,
    repo_id: int,
    scan_run_id: int,
    findings: List[NormalizedSecretFinding],
    is_baseline: bool,
    is_full_scan: bool,
) -> Dict[str, int]:
    """Bu taramanin sonuclarini upsert eder.

    `is_full_scan=False` (incremental) ise SADECE yeni/guncellenen bulgular
    islenir -- bu taramada GORUNMEYEN eski bulgulara DOKUNULMAZ (cunku
    incremental tarama sadece YENI commit araligini kapsar, eski bir
    commit'teki secret hala kodda olabilir ama bu turda yeniden
    raporlanmaz). SADECE `is_full_scan=True` ise "artik kodda yok"
    (present_in_current_code=False) reconciliation'i yapilir -- ve bu bile
    lifecycle_status'u DEGISTIRMEZ (master_prompt.md 4.4).
    """
    now = dt.datetime.now(dt.timezone.utc)
    stats = {"created": 0, "updated": 0, "marked_absent": 0}
    seen_fingerprints = set()

    for nf in findings:
        seen_fingerprints.add(nf.custom_fingerprint)
        existing = session.execute(
            select(SecretFinding).where(
                SecretFinding.repo_id == repo_id,
                SecretFinding.custom_fingerprint == nf.custom_fingerprint,
            )
        ).scalar_one_or_none()

        if existing is None:
            finding = SecretFinding(
                repo_id=repo_id,
                rule_id=nf.rule_id,
                file_path=nf.file_path,
                custom_fingerprint=nf.custom_fingerprint,
                gitleaks_fingerprint=nf.gitleaks_fingerprint,
                secret_content_hash=nf.secret_content_hash,
                commit_sha=nf.commit_sha,
                line_number=nf.line_number,
                entropy=nf.entropy,
                tags=nf.tags,
                present_in_current_code=True,
                lifecycle_status=STATUS_OPEN,
                baseline=is_baseline,
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(finding)
            session.flush()
            session.add(
                SecretFindingEvent(
                    secret_finding_id=finding.id, event_type="CREATED", to_status=STATUS_OPEN,
                    reason="baseline" if is_baseline else "new_finding",
                )
            )
            stats["created"] += 1
        else:
            existing.last_seen_at = now
            existing.file_path = nf.file_path
            existing.line_number = nf.line_number
            existing.commit_sha = nf.commit_sha
            if not existing.present_in_current_code:
                existing.present_in_current_code = True
                session.add(
                    SecretFindingEvent(
                        secret_finding_id=existing.id, event_type="REAPPEARED_IN_CODE",
                        reason="seen_again_in_scan",
                    )
                )
            stats["updated"] += 1

    if is_full_scan:
        stale = session.execute(
            select(SecretFinding).where(
                SecretFinding.repo_id == repo_id,
                SecretFinding.present_in_current_code.is_(True),
            )
        ).scalars().all()
        for existing in stale:
            if existing.custom_fingerprint in seen_fingerprints:
                continue
            existing.present_in_current_code = False
            # master_prompt.md 4.4: lifecycle_status KASITLI OLARAK degismiyor.
            session.add(
                SecretFindingEvent(
                    secret_finding_id=existing.id, event_type="REMOVED_FROM_CODE",
                    reason="not_present_in_full_scan",
                    evidence={"note": "lifecycle_status degismedi; kapanis icin admin rotate onayi gerekir"},
                )
            )
            stats["marked_absent"] += 1

    return stats


def confirm_rotation(
    session: Session, secret_finding_id: int, actor_username: str, note: str,
) -> SecretFinding:
    """SADECE admin eylemi (master_prompt.md 4.3: suppression/FP/kapatma
    icin ZORUNLU gerekce). Bu, bir secret bulgusunu kapatan TEK yoldur."""
    finding = session.get(SecretFinding, secret_finding_id)
    if finding is None:
        raise ValueError(f"secret_finding bulunamadi: {secret_finding_id}")
    if not note or not note.strip():
        raise ValueError("Rotation onayi icin gerekce (note) ZORUNLUDUR")

    from_status = finding.lifecycle_status
    now = dt.datetime.now(dt.timezone.utc)
    finding.lifecycle_status = STATUS_ROTATED
    finding.rotated_at = now
    finding.rotation_note = note
    session.add(
        SecretFindingEvent(
            secret_finding_id=finding.id, event_type="ROTATED", from_status=from_status, to_status=STATUS_ROTATED,
            actor=actor_username, reason=note,
        )
    )
    return finding


def suppress_finding(
    session: Session, secret_finding_id: int, new_status: str, actor_username: str, reason: str,
) -> SecretFinding:
    """FALSE_POSITIVE / ACCEPTED_RISK -- admin, zorunlu gerekce (4.3)."""
    if new_status not in (STATUS_FALSE_POSITIVE, STATUS_ACCEPTED_RISK):
        raise ValueError(f"Gecersiz durum: {new_status}")
    if not reason or not reason.strip():
        raise ValueError("Suppression icin gerekce ZORUNLUDUR")

    finding = session.get(SecretFinding, secret_finding_id)
    if finding is None:
        raise ValueError(f"secret_finding bulunamadi: {secret_finding_id}")

    from_status = finding.lifecycle_status
    finding.lifecycle_status = new_status
    session.add(
        SecretFindingEvent(
            secret_finding_id=finding.id, event_type="SUPPRESSED", from_status=from_status, to_status=new_status,
            actor=actor_username, reason=reason,
        )
    )
    return finding
