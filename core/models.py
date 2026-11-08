"""SQLAlchemy modelleri. Asama 1: repositories, jobs, scan_triggers,
system_heartbeats. Asama 2: scan_runs, advisory_mirror_syncs,
component_snapshots, kev_entries, epss_scores, findings, finding_events,
finding_sources (master_prompt.md 3.4, 4.5, 7-Asama 2). Asama 3: users,
sessions, audit_log, api_tokens, secret_findings, secret_finding_events
(master_prompt.md 4.4, 5, 7-Asama 3)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Index,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
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
    # A3/A10 (master_prompt.md 6): "Repo bazli tarama politikasi (dahil/
    # harici + gerekce, audit'li)". True ise orchestrator bu repoyu
    # yoklama/tetikleme dongulerinde ATLAR (bkz. orchestrator/main.py
    # _poll_tick, orchestrator/triggers.py consume_triggers_and_enqueue).
    scan_excluded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scan_exclude_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # master_prompt.md 3.2.1: Hat A (Asama 2) bu alani HEAD SHA karsilastirmasinda kullanir.
    last_seen_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # master_prompt.md 4.4: secret taramasi icin ayri takip -- `last_scanned_sha..HEAD`
    # araligi (Hat A'nin last_seen_sha'sindan BAGIMSIZ, Asama 3).
    last_scanned_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
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


# --- Asama 2: Hat A / Hat B / Finding modeli --------------------------------


class ScanRun(Base):
    """Her extraction/match calistirmasinin denetim kaydi (master_prompt.md
    4.5: "Her scan/match run: repo, branch, commit SHA, lockfile blob
    SHA'lari, scanner adi+surumu, advisory DB zaman damgasi, ham cikti
    referansi"). RESOLVED kurali ve sanity-gate bu tabloya bakarak karar verir."""

    __tablename__ = "scan_runs"
    __table_args__ = (
        CheckConstraint(
            "run_type in ('extraction','immediate_match','daily_match','secret_scan')", name="scan_runs_run_type_check"
        ),
        CheckConstraint(
            "status in ('success','partial','failed','needs_review')", name="scan_runs_status_check"
        ),
        Index("ix_scan_runs_repo_type", "repo_id", "run_type", "started_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_type: Mapped[str] = mapped_column(String(30), nullable=False)
    repo_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    commit_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    lockfile_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lockfile_blob_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scanner_name: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scanner_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    advisory_db_as_of: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    # Sanity-gate detayi: dosya basina {path, blob_sha, status} listesi,
    # bilesen sayisi oncesi/sonrasi vb. (master_prompt.md 3.2.7).
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    raw_output_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AdvisoryMirrorSync(Base):
    """Advisory/KEV/EPSS senkron geçmişi (zaman damgası+checksum kaydı,
    master_prompt.md 3.3/5). Bulgu kapatma kuralı bu tabloya bakar: taze
    ve başarılı bir senkron olmadan hiçbir bulgu RESOLVED olamaz."""

    __tablename__ = "advisory_mirror_syncs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # ör. 'osv-npm', 'kev', 'epss'
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    item_count: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    checksum: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ComponentSnapshot(Base):
    """Hat A ciktisi: bir lockfile'daki bilesen listesi (master_prompt.md
    3.2.6). Eslestirme stratejisinden bagimsiz sorgulanabilir (blast
    radius, coverage icin, bkz. 3.3). `is_current=False` olanlar gecmis
    (audit) icin tutulur, aktif eslestirmede kullanilmaz."""

    __tablename__ = "component_snapshots"
    __table_args__ = (
        Index("ix_component_snapshots_current_lookup", "repo_id", "lockfile_path", "is_current"),
        Index("ix_component_snapshots_unique_set", "ecosystem", "name", "version", "is_current"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    lockfile_path: Mapped[str] = mapped_column(Text, nullable=False)
    lockfile_blob_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(30), nullable=False)
    purl: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")  # prod/dev/optional/unknown
    relation: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")  # direct/transitive/unknown
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class KevEntry(Base):
    """CISA KEV katalogu (master_prompt.md 2/4.6). CVE ID anahtar."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    vulnerability_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class EpssScore(Base):
    """EPSS skorlari (master_prompt.md 4.6). CVE ID anahtar, en son senkrondan
    gelen tek skor tutulur (gecmis trend Asama 4 kapsaminda ayrica ele alinabilir)."""

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    score: Mapped[float] = mapped_column(Numeric(6, 5), nullable=False)
    percentile: Mapped[float] = mapped_column(Numeric(6, 5), nullable=False)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Finding(Base):
    """SCA bulgusu (master_prompt.md 4.2, 4.3, 4.5). Dogal anahtar: repo +
    lockfile yolu + component (purl+surum) + canonical vulnerability ID."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "repo_id", "lockfile_path", "purl", "version", "canonical_vulnerability_id",
            name="uq_findings_natural_key",
        ),
        CheckConstraint(
            "verification_status in ('VERIFIED','NEEDS_REVIEW')", name="findings_verification_status_check"
        ),
        CheckConstraint(
            "lifecycle_status in ('OPEN','IN_PROGRESS','RESOLVED','REOPENED','FALSE_POSITIVE',"
            "'NOT_AFFECTED','ACCEPTED_RISK')",
            name="findings_lifecycle_status_check",
        ),
        CheckConstraint(
            "fix_status in ('PATCH_AVAILABLE','NO_FIX_YET','FIX_UNKNOWN','WONT_FIX',"
            "'CONSTRAINT_BLOCKED','WORKAROUND')",
            name="findings_fix_status_check",
        ),
        Index("ix_findings_repo_status", "repo_id", "lifecycle_status"),
        Index("ix_findings_component", "ecosystem", "package_name", "version"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    lockfile_path: Mapped[str] = mapped_column(Text, nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(30), nullable=False)
    purl: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    package_name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    relation: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")

    canonical_vulnerability_id: Mapped[str] = mapped_column(String(100), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    severity_cvss_vector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity_cvss_score: Mapped[Optional[float]] = mapped_column(Numeric(3, 1), nullable=True)
    severity_source: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    severity_conflict: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_added_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Numeric(6, 5), nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Numeric(6, 5), nullable=True)

    fix_status: Mapped[str] = mapped_column(String(30), nullable=False, default="FIX_UNKNOWN")
    fix_version: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    fix_version_is_major_bump: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    verification_status: Mapped[str] = mapped_column(String(20), nullable=False)
    needs_review_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    lifecycle_status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_scan_run_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class FindingEvent(Base):
    """Append-only olay gecmisi (master_prompt.md 4.3: "kim/ne zaman/neden/kanit")."""

    __tablename__ = "finding_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    from_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    to_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    actor: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class FindingSource(Base):
    """Bir bulgunun hangi scan_run'lardan kanit aldigi (master_prompt.md
    4.5: "Finding birden cok kaynaktan kanit alabilir (scan_sources)")."""

    __tablename__ = "finding_sources"
    __table_args__ = (UniqueConstraint("finding_id", "scan_run_id", name="uq_finding_sources"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    scan_run_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    raw_vulnerability_id: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# --- Asama 3: auth, audit, API tokens, secret findings ----------------------


class User(Base):
    """Yerel hesap (master_prompt.md 5 "Uygulama guvenligi"). Harici IdP yok.
    Admin icin TOTP ZORUNLU (uygulama katmaninda enforce edilir, bkz.
    core/auth.py); viewer icin opsiyonel."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role in ('admin','viewer')", name="users_role_check"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    # argon2id hash (core.auth) -- DUZ METIN PAROLA ASLA TUTULMAZ.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # TOTP sirri -- hassas, ASLA loglanmaz (core.logging_setup.register_secret
    # ile maskeleme listesine eklenir, bkz. core/auth.py).
    totp_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Kurtarma kodlari TEK KULLANIMLIK ve HASH'LENMIS tutulur (duz metin degil).
    recovery_code_hashes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # A6 "Bugun" ekrani (master_prompt.md 6): "son ziyaretinden beri yeni
    # olanlar rozetle". NULL = henuz hic ziyaret yok -> hicbir sey "yeni"
    # sayilmaz (ilk ziyarette tum gecmis bulgular yanlislikla yeni gorunmesin).
    last_dashboard_visit_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Session(Base):
    """Sunucu tarafi oturum kaydi (master_prompt.md 5: "Oturum cerezi HttpOnly
    + Secure + SameSite, bosta zaman asimi"). Cerezde SADECE bu id tutulur;
    DB-destekli olmasi admin'e "oturumu zorla kapat" imkani verir."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # rastgele token (hash degil, kendisi)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """master_prompt.md 5: "giris, durum degisikligi, suppression,
    kullanici/rol/ayar/API-token degisikligi, export." Append-only."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    actor_username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    detail: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ApiToken(Base):
    """master_prompt.md 5: "Read-only API token'lari (hash'li saklanir,
    scope'lu, sureli, audit'li)". Token'in kendisi SADECE olusturulurken
    gosterilir, DB'de yalnizca hash'i tutulur."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="read")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SecretFinding(Base):
    """Secret bulgusu (master_prompt.md 4.4 -- SCA'dan FARKLI kurallar):
    koddan silinince RESOLVED OLMAZ, sadece admin "rotate edildi" onayiyla
    kapanir. Ham secret degeri hicbir sutunda TUTULMAZ -- sadece hash'i."""

    __tablename__ = "secret_findings"
    __table_args__ = (
        UniqueConstraint("repo_id", "custom_fingerprint", name="uq_secret_findings_natural_key"),
        CheckConstraint(
            "lifecycle_status in ('OPEN','ROTATED','FALSE_POSITIVE','ACCEPTED_RISK')",
            name="secret_findings_lifecycle_status_check",
        ),
        Index("ix_secret_findings_repo_status", "repo_id", "lifecycle_status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    # Kendi fingerprint'imiz: rule_id + file_path + secret-content-hash
    # (satirdan BAGIMSIZ, kararli -- bkz. docs/ASSUMPTIONS.md #3).
    custom_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    # Gitleaks'in KENDI fingerprint'i (satir numarasina bagli, sadece kanit/referans).
    gitleaks_fingerprint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    secret_content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    commit_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    entropy: Mapped[Optional[float]] = mapped_column(Numeric(6, 3), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # master_prompt.md 4.4: koddan kaldirilmis olmak RESOLVED yapmaz, sadece
    # bu bayrak False olur (FIX_PENDING benzeri ara sinyal).
    present_in_current_code: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    lifecycle_status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_by_user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    rotation_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class SecretFindingEvent(Base):
    """Append-only olay gecmisi (secret_findings icin, finding_events'in esi)."""

    __tablename__ = "secret_finding_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    secret_finding_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    from_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    to_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    actor: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# --- Asama 4: ayarlar (SLA/bildirim) + bildirim idempotency ------------------


class Setting(Base):
    """Admin'in panelden degistirdigi ayarlar (master_prompt.md 6 A10):
    SLA hedef sureleri, bildirim kanali aç/kapat + alici listesi. SMTP
    sunucu parametreleri BURADA DEGIL -- sunucu config'inde (core/config.py,
    env) kalir (master_prompt.md 5: "SMTP sunucu parametreleri sunucu
    config'inde kalir"). Secret iceren degerler (ör. Teams webhook URL'si)
    bu tabloda SADECE sifreli yazilmalidir -- su an (Asama 4 part 3) hicbir
    secret-iceren ayar burada TUTULMUYOR (Teams webhook'u kapsam disi,
    bkz. docs/ASSUMPTIONS.md)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    updated_by_user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)


class RepoOwner(Base):
    """A5 sahip yonlendirme (master_prompt.md 6): bir repo BIRDEN FAZLA
    sahibe (takim/kisi) sahip olabilir. `source`: 'csv' (admin ice aktardi),
    'manual' (panelden tek tek eklendi -- henuz UI yok), 'codeowners'
    (otomatik tespit -- henuz uygulanmadi, bkz. docs/ASSUMPTIONS.md).
    Bir repo icin repo_owners satiri YOKSA 'sahipsiz' sayilir (A3 Coverage)."""

    __tablename__ = "repo_owners"
    __table_args__ = (
        UniqueConstraint("repo_id", "owner_identifier", "source", name="uq_repo_owners_repo_identifier_source"),
        CheckConstraint("source in ('csv', 'manual', 'codeowners')", name="repo_owners_source_check"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    owner_identifier: Mapped[str] = mapped_column(String(300), nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class NotificationLog(Base):
    """master_prompt.md 6 "Gurultu kontrolleri": ayni olay/alici/kanal
    ucluzu BIR KEZ gonderilir -- uq_notification_log_dedup bunu DB
    seviyesinde garanti eder (ON CONFLICT DO NOTHING ile idempotent yazim,
    bkz. core/notifications.py)."""

    __tablename__ = "notification_log"
    __table_args__ = (
        UniqueConstraint("dedup_key", "channel", "recipient", name="uq_notification_log_dedup"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(300), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    recipient: Mapped[str] = mapped_column(String(300), nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
