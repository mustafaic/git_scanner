"""Read-only, API-token korumali JSON API (master_prompt.md 5: "Read-only
API token'lari"). Oturum cerezi/CSRF ile ILGISIZ -- Authorization: Bearer
header'i tasir, tarayici cerez gondermedigi icin CSRF modeli burada
GECERSIZ (bkz. app/csrf.py, bu router'a require_csrf eklenmez)."""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from core import auth
from core.db import session_scope
from core.models import ApiToken, Finding, SecretFinding

router = APIRouter(prefix="/api")


def _get_db():
    with session_scope() as session:
        yield session


def require_api_token(request: Request, db: DbSession = Depends(_get_db)) -> ApiToken:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer <token> gerekli")
    raw_token = header[len("bearer "):].strip()
    token_hash = auth.hash_api_token(raw_token)
    token = db.execute(select(ApiToken).where(ApiToken.token_hash == token_hash)).scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=401, detail="gecersiz token")
    now = dt.datetime.now(dt.timezone.utc)
    if token.revoked_at is not None:
        raise HTTPException(status_code=401, detail="token iptal edilmis")
    if token.expires_at is not None and token.expires_at < now:
        raise HTTPException(status_code=401, detail="token suresi dolmus")
    token.last_used_at = now
    return token


def _finding_json(f: Finding) -> Dict[str, Any]:
    return {
        "id": f.id, "repo_id": f.repo_id, "lockfile_path": f.lockfile_path, "ecosystem": f.ecosystem,
        "purl": f.purl, "package_name": f.package_name, "version": f.version,
        "canonical_vulnerability_id": f.canonical_vulnerability_id, "aliases": f.aliases,
        "severity_cvss_score": float(f.severity_cvss_score) if f.severity_cvss_score is not None else None,
        "kev": f.kev, "epss_score": float(f.epss_score) if f.epss_score is not None else None,
        "fix_status": f.fix_status, "fix_version": f.fix_version,
        "verification_status": f.verification_status, "lifecycle_status": f.lifecycle_status,
        "first_seen_at": f.first_seen_at.isoformat(), "last_seen_at": f.last_seen_at.isoformat(),
    }


def _secret_finding_json(s: SecretFinding) -> Dict[str, Any]:
    # KRITIK: ham secret/ secret_content_hash API'de bile MINIMAL -- hash
    # disari sizdirilabilir bilgi degil (tek yonlu), ama yine de ihtiyac
    # olmayan alanlar (satir, dosya) burada da OLDUGU GIBI donuyor cunku
    # bunlar zaten repo'ya erisimi olan herkesin gorebilecegi bilgiler.
    return {
        "id": s.id, "repo_id": s.repo_id, "rule_id": s.rule_id, "file_path": s.file_path,
        "present_in_current_code": s.present_in_current_code, "lifecycle_status": s.lifecycle_status,
        "tags": s.tags, "first_seen_at": s.first_seen_at.isoformat(), "last_seen_at": s.last_seen_at.isoformat(),
    }


@router.get("/findings")
def api_list_findings(
    status: str = "", db: DbSession = Depends(_get_db), token: ApiToken = Depends(require_api_token)
) -> List[Dict[str, Any]]:
    query = select(Finding)
    if status:
        query = query.where(Finding.lifecycle_status == status)
    else:
        query = query.where(Finding.lifecycle_status.in_(["OPEN", "IN_PROGRESS", "REOPENED"]))
    findings = db.execute(query.order_by(Finding.first_seen_at.desc()).limit(1000)).scalars().all()
    return [_finding_json(f) for f in findings]


@router.get("/secret-findings")
def api_list_secret_findings(
    status: str = "", db: DbSession = Depends(_get_db), token: ApiToken = Depends(require_api_token)
) -> List[Dict[str, Any]]:
    query = select(SecretFinding)
    if status:
        query = query.where(SecretFinding.lifecycle_status == status)
    else:
        query = query.where(SecretFinding.lifecycle_status == "OPEN")
    secrets_list = db.execute(query.order_by(SecretFinding.first_seen_at.desc()).limit(1000)).scalars().all()
    return [_secret_finding_json(s) for s in secrets_list]
