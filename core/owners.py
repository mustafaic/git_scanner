"""A5 Sahip yonlendirme (master_prompt.md 6): "CODEOWNERS -> GitHub
team/depo eslemesi -> ice aktarilabilir (CSV) repo->ekip tablosu ->
'sahipsiz' listesi". Bu surumde SADECE CSV import uygulandi; CODEOWNERS
otomatik tespiti kapsam disi (bkz. docs/ASSUMPTIONS.md)."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.models import Repository, RepoOwner

SOURCE_CSV = "csv"


@dataclass
class ParsedOwnerRow:
    full_name: str
    owner_identifier: str


@dataclass
class CsvParseResult:
    rows: List[ParsedOwnerRow] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def parse_owners_csv(content: str) -> CsvParseResult:
    """Beklenen format: `repo_full_name,owner_identifier` (baslik satiri
    opsiyonel, ilk satir 'full_name'/'repo' iceriyorsa atlanir). Gecersiz
    satirlar (eksik alan, bos deger) ATLANIR ve hata listesine eklenir --
    tek bir bozuk satir tum import'u DURDURMAZ (kural: monorepo/coverage
    ile ayni tolerans felsefesi)."""
    result = CsvParseResult()
    reader = csv.reader(io.StringIO(content))
    for i, row in enumerate(reader, start=1):
        if not row or all(not c.strip() for c in row):
            continue
        if i == 1 and len(row) >= 2 and row[0].strip().lower() in ("full_name", "repo", "repo_full_name"):
            continue  # baslik satiri
        if len(row) < 2:
            result.errors.append(f"satir {i}: en az 2 sutun (repo_full_name, owner_identifier) gerekli")
            continue
        full_name, owner = row[0].strip(), row[1].strip()
        if not full_name or not owner:
            result.errors.append(f"satir {i}: repo_full_name veya owner_identifier bos")
            continue
        result.rows.append(ParsedOwnerRow(full_name=full_name, owner_identifier=owner))
    return result


def import_owners_csv(session: Session, rows: List[ParsedOwnerRow]) -> Dict[str, int]:
    """Her satiri Repository.full_name uzerinden coz, bulunamayanlari
    `unknown_repo` olarak sayar (import'u durdurmaz). Ayni (repo,owner,csv)
    uclusu zaten varsa ON CONFLICT DO NOTHING ile sessizce atlanir."""
    stats = {"imported": 0, "duplicate": 0, "unknown_repo": 0}
    if not rows:
        return stats

    full_names = {r.full_name for r in rows}
    repo_id_by_name: Dict[str, int] = dict(
        session.execute(
            select(Repository.full_name, Repository.github_repo_id).where(Repository.full_name.in_(full_names))
        ).all()
    )

    for row in rows:
        repo_id = repo_id_by_name.get(row.full_name)
        if repo_id is None:
            stats["unknown_repo"] += 1
            continue
        result = session.execute(
            pg_insert(RepoOwner)
            .values(repo_id=repo_id, owner_identifier=row.owner_identifier, source=SOURCE_CSV)
            .on_conflict_do_nothing(index_elements=["repo_id", "owner_identifier", "source"])
            .returning(RepoOwner.id)
        )
        if result.first() is None:
            stats["duplicate"] += 1
        else:
            stats["imported"] += 1
    return stats


def get_owners_map(session: Session, repo_ids: List[int]) -> Dict[int, List[str]]:
    if not repo_ids:
        return {}
    rows = session.execute(
        select(RepoOwner.repo_id, RepoOwner.owner_identifier).where(RepoOwner.repo_id.in_(repo_ids))
    ).all()
    owners_map: Dict[int, List[str]] = {}
    for repo_id, owner in rows:
        owners_map.setdefault(repo_id, []).append(owner)
    return owners_map


def list_unowned_repo_ids(session: Session) -> List[int]:
    """master_prompt.md 6 A5: 'sahipsiz' listesi."""
    owned_ids = session.execute(select(RepoOwner.repo_id).distinct()).scalars().all()
    rows = session.execute(
        select(Repository.github_repo_id).where(Repository.github_repo_id.notin_(owned_ids))
    ).scalars().all()
    return list(rows)
