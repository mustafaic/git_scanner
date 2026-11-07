"""stage 2: scan_runs, advisory_mirror_syncs, component_snapshots,
kev_entries, epss_scores, findings, finding_events, finding_sources

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("run_type", sa.String(30), nullable=False),
        sa.Column("repo_id", sa.BigInteger(), nullable=True),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("lockfile_path", sa.Text(), nullable=True),
        sa.Column("lockfile_blob_sha", sa.String(64), nullable=True),
        sa.Column("scanner_name", sa.String(50), nullable=True),
        sa.Column("scanner_version", sa.String(50), nullable=True),
        sa.Column("advisory_db_as_of", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("raw_output_ref", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "run_type in ('extraction','immediate_match','daily_match')", name="scan_runs_run_type_check"
        ),
        sa.CheckConstraint(
            "status in ('success','partial','failed','needs_review')", name="scan_runs_status_check"
        ),
    )
    op.create_index("ix_scan_runs_repo_type", "scan_runs", ["repo_id", "run_type", "started_at"])

    op.create_table(
        "advisory_mirror_syncs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column("item_count", sa.BigInteger(), nullable=True),
        sa.Column("checksum", sa.String(128), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )

    op.create_table(
        "component_snapshots",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger(), nullable=False),
        sa.Column("lockfile_path", sa.Text(), nullable=False),
        sa.Column("lockfile_blob_sha", sa.String(64), nullable=False),
        sa.Column("scan_run_id", sa.BigInteger(), nullable=False),
        sa.Column("ecosystem", sa.String(30), nullable=False),
        sa.Column("purl", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.String(200), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("relation", sa.String(20), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(
        "ix_component_snapshots_current_lookup", "component_snapshots", ["repo_id", "lockfile_path", "is_current"]
    )
    op.create_index(
        "ix_component_snapshots_unique_set", "component_snapshots", ["ecosystem", "name", "version", "is_current"]
    )

    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(30), primary_key=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("vulnerability_name", sa.Text(), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(30), primary_key=True),
        sa.Column("score", sa.Numeric(6, 5), nullable=False),
        sa.Column("percentile", sa.Numeric(6, 5), nullable=False),
        sa.Column("as_of_date", sa.Date(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger(), nullable=False),
        sa.Column("lockfile_path", sa.Text(), nullable=False),
        sa.Column("ecosystem", sa.String(30), nullable=False),
        sa.Column("purl", sa.Text(), nullable=True),
        sa.Column("package_name", sa.Text(), nullable=False),
        sa.Column("version", sa.String(200), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("relation", sa.String(20), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("canonical_vulnerability_id", sa.String(100), nullable=False),
        sa.Column("aliases", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("severity_cvss_vector", sa.Text(), nullable=True),
        sa.Column("severity_cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("severity_source", sa.String(30), nullable=True),
        sa.Column("severity_conflict", postgresql.JSONB(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_added_date", sa.Date(), nullable=True),
        sa.Column("epss_score", sa.Numeric(6, 5), nullable=True),
        sa.Column("epss_percentile", sa.Numeric(6, 5), nullable=True),
        sa.Column("fix_status", sa.String(30), nullable=False, server_default=sa.text("'FIX_UNKNOWN'")),
        sa.Column("fix_version", sa.String(200), nullable=True),
        sa.Column("fix_version_is_major_bump", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("verification_status", sa.String(20), nullable=False),
        sa.Column("needs_review_reason", sa.Text(), nullable=True),
        sa.Column("lifecycle_status", sa.String(20), nullable=False, server_default=sa.text("'OPEN'")),
        sa.Column("baseline", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_scan_run_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "repo_id", "lockfile_path", "purl", "version", "canonical_vulnerability_id",
            name="uq_findings_natural_key",
        ),
        sa.CheckConstraint(
            "verification_status in ('VERIFIED','NEEDS_REVIEW')", name="findings_verification_status_check"
        ),
        sa.CheckConstraint(
            "lifecycle_status in ('OPEN','IN_PROGRESS','RESOLVED','REOPENED','FALSE_POSITIVE',"
            "'NOT_AFFECTED','ACCEPTED_RISK')",
            name="findings_lifecycle_status_check",
        ),
        sa.CheckConstraint(
            "fix_status in ('PATCH_AVAILABLE','NO_FIX_YET','FIX_UNKNOWN','WONT_FIX',"
            "'CONSTRAINT_BLOCKED','WORKAROUND')",
            name="findings_fix_status_check",
        ),
    )
    op.create_index("ix_findings_repo_status", "findings", ["repo_id", "lifecycle_status"])
    op.create_index("ix_findings_component", "findings", ["ecosystem", "package_name", "version"])

    op.create_table(
        "finding_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("from_status", sa.String(20), nullable=True),
        sa.Column("to_status", sa.String(20), nullable=True),
        sa.Column("actor", sa.String(100), nullable=False, server_default=sa.text("'system'")),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_finding_events_finding_id", "finding_events", ["finding_id"])

    op.create_table(
        "finding_sources",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("scan_run_id", sa.BigInteger(), nullable=False),
        sa.Column("raw_vulnerability_id", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("finding_id", "scan_run_id", name="uq_finding_sources"),
    )


def downgrade() -> None:
    op.drop_table("finding_sources")
    op.drop_index("ix_finding_events_finding_id", table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index("ix_findings_component", table_name="findings")
    op.drop_index("ix_findings_repo_status", table_name="findings")
    op.drop_table("findings")
    op.drop_table("epss_scores")
    op.drop_table("kev_entries")
    op.drop_index("ix_component_snapshots_unique_set", table_name="component_snapshots")
    op.drop_index("ix_component_snapshots_current_lookup", table_name="component_snapshots")
    op.drop_table("component_snapshots")
    op.drop_table("advisory_mirror_syncs")
    op.drop_index("ix_scan_runs_repo_type", table_name="scan_runs")
    op.drop_table("scan_runs")
