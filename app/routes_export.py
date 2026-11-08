"""A9 Export ve API (master_prompt.md 6): "bulgu listesi/audit icin CSV ve
JSON export (denetim kaniti)". Ayni filtre/erisim kurallari liste
sayfalariyla BIREBIR: findings/secrets viewer+admin, audit-log SADECE admin
(panelde zaten gordugu veriyle ayni -- A2 Blast Radius paragrafiyla ayni
RBAC mantigi)."""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.deps import get_db, get_repo_names, require_admin, require_user
from core.models import AuditLog, Finding, SecretFinding, User

router = APIRouter()

_FINDING_FIELDS = [
    "id", "repo", "lockfile_path", "ecosystem", "purl", "package_name", "version",
    "canonical_vulnerability_id", "aliases", "severity_cvss_score", "kev", "epss_score",
    "fix_status", "fix_version", "verification_status", "lifecycle_status",
    "first_seen_at", "last_seen_at", "resolved_at",
]

_SECRET_FIELDS = [
    "id", "repo", "rule_id", "file_path", "present_in_current_code", "lifecycle_status",
    "tags", "first_seen_at", "last_seen_at", "rotated_at", "rotation_note",
]

_AUDIT_FIELDS = ["id", "created_at", "actor_username", "action", "target_type", "target_id", "detail"]


def _csv_response(fieldnames: list[str], rows: Iterable[dict[str, Any]], filename: str) -> Response:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
    return Response(
        buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _finding_row(f: Finding, repo_names: dict[int, str]) -> dict[str, Any]:
    return {
        "id": f.id, "repo": repo_names.get(f.repo_id, f.repo_id), "lockfile_path": f.lockfile_path,
        "ecosystem": f.ecosystem, "purl": f.purl, "package_name": f.package_name, "version": f.version,
        "canonical_vulnerability_id": f.canonical_vulnerability_id, "aliases": ",".join(f.aliases or []),
        "severity_cvss_score": f.severity_cvss_score, "kev": f.kev, "epss_score": f.epss_score,
        "fix_status": f.fix_status, "fix_version": f.fix_version,
        "verification_status": f.verification_status, "lifecycle_status": f.lifecycle_status,
        "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at, "resolved_at": f.resolved_at,
    }


def _secret_row(s: SecretFinding, repo_names: dict[int, str]) -> dict[str, Any]:
    return {
        "id": s.id, "repo": repo_names.get(s.repo_id, s.repo_id), "rule_id": s.rule_id, "file_path": s.file_path,
        "present_in_current_code": s.present_in_current_code, "lifecycle_status": s.lifecycle_status,
        "tags": ",".join(s.tags or []), "first_seen_at": s.first_seen_at, "last_seen_at": s.last_seen_at,
        "rotated_at": s.rotated_at, "rotation_note": s.rotation_note,
    }


def _audit_row(a: AuditLog) -> dict[str, Any]:
    return {
        "id": a.id, "created_at": a.created_at, "actor_username": a.actor_username, "action": a.action,
        "target_type": a.target_type, "target_id": a.target_id, "detail": a.detail,
    }


def _findings_query(status: str):
    query = select(Finding)
    if status:
        query = query.where(Finding.lifecycle_status == status)
    else:
        query = query.where(Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    return query.order_by(Finding.first_seen_at.desc()).limit(5000)


def _secrets_query(status: str):
    query = select(SecretFinding)
    if status:
        query = query.where(SecretFinding.lifecycle_status == status)
    else:
        query = query.where(SecretFinding.lifecycle_status == "OPEN")
    return query.order_by(SecretFinding.first_seen_at.desc()).limit(5000)


@router.get("/findings/export.csv")
def export_findings_csv(status: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    findings = db.execute(_findings_query(status)).scalars().all()
    repo_names = get_repo_names(db, [f.repo_id for f in findings])
    rows = [_finding_row(f, repo_names) for f in findings]
    return _csv_response(_FINDING_FIELDS, rows, "findings.csv")


@router.get("/findings/export.json")
def export_findings_json(status: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    findings = db.execute(_findings_query(status)).scalars().all()
    repo_names = get_repo_names(db, [f.repo_id for f in findings])
    rows = [_finding_row(f, repo_names) for f in findings]
    return JSONResponse([{k: (str(v) if v is not None else None) for k, v in r.items()} for r in rows])


@router.get("/secrets/export.csv")
def export_secrets_csv(status: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    secrets_list = db.execute(_secrets_query(status)).scalars().all()
    repo_names = get_repo_names(db, [s.repo_id for s in secrets_list])
    rows = [_secret_row(s, repo_names) for s in secrets_list]
    return _csv_response(_SECRET_FIELDS, rows, "secret_findings.csv")


@router.get("/secrets/export.json")
def export_secrets_json(status: str = "", db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    secrets_list = db.execute(_secrets_query(status)).scalars().all()
    repo_names = get_repo_names(db, [s.repo_id for s in secrets_list])
    rows = [_secret_row(s, repo_names) for s in secrets_list]
    return JSONResponse([{k: (str(v) if v is not None else None) for k, v in r.items()} for r in rows])


@router.get("/audit-log/export.csv")
def export_audit_log_csv(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    entries = db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(5000)).scalars().all()
    rows = [_audit_row(a) for a in entries]
    return _csv_response(_AUDIT_FIELDS, rows, "audit_log.csv")
