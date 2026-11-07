"""Asama 1 SQLAlchemy modelleri: repositories, jobs, scan_triggers,
system_heartbeats (master_prompt.md 3.4, 7-Asama 1)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, Index, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"

    github_repo_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    visibility: Mapped[str] = mapped_column(String(20), nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fork: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # master_prompt.md 3.2.1: Hat A (Asama 2) bu alani HEAD SHA karsilastirmasinda kullanir.
    last_seen_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("status in ('pending','running','done','failed')", name="jobs_status_check"),
        Index("ix_jobs_claim", "status", "priority", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    repo_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # master_prompt.md 3.4: (tip, repo, sha/blob_sha, scanner_version) -> ayni is iki kez islenmez.
    idempotency_key: Mapped[str] = mapped_column(String(300), nullable=False, unique=True)
    # Dusuk sayi = yuksek oncelik (0 = en yuksek). master_prompt.md 3.5: taze commit
    # isleri toplu islerden once calisir.
    priority: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=100)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=5)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class ScanTrigger(Base):
    __tablename__ = "scan_triggers"
    __table_args__ = (
        CheckConstraint("source in ('poll','manual','webhook','reconcile')", name="scan_triggers_source_check"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    # Webhook payload'indan gelen SHA gibi GUVENILMEYEN bilgi icin serbest not;
    # gercek durum her zaman GitHub API'den okunur (master_prompt.md 3.5).
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class SystemHeartbeat(Base):
    """Watchdog'un izledigi, her bilesenin "son basarili" zaman damgasi
    (master_prompt.md 6 "Dead man's switch"). Asama 1'de sadece orchestrator
    claim-loop'u yazar; Asama 2'de hat_a_daily/hat_b_daily gibi satirlar eklenecek."""

    __tablename__ = "system_heartbeats"

    component: Mapped[str] = mapped_column(String(100), primary_key=True)
    last_success_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detail: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
