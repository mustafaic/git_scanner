"""stage 3: users, sessions, audit_log, api_tokens, secret_findings,
secret_finding_events; scan_runs run_type += 'secret_scan';
repositories += last_scanned_sha

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("repositories", sa.Column("last_scanned_sha", sa.String(64), nullable=True))

    op.drop_constraint("scan_runs_run_type_check", "scan_runs", type_="check")
    op.create_check_constraint(
        "scan_runs_run_type_check", "scan_runs",
        "run_type in ('extraction','immediate_match','daily_match','secret_scan')",
    )

    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("totp_secret", sa.Text(), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("recovery_code_hashes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("failed_login_attempts", sa.SmallInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.CheckConstraint("role in ('admin','viewer')", name="users_role_check"),
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_username", sa.String(100), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=True),
        sa.Column("target_id", sa.String(100), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False, server_default=sa.text("'read'")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_api_tokens_token_hash"),
    )

    op.create_table(
        "secret_findings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger(), nullable=False),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("custom_fingerprint", sa.String(128), nullable=False),
        sa.Column("gitleaks_fingerprint", sa.Text(), nullable=True),
        sa.Column("secret_content_hash", sa.String(128), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("line_number", sa.BigInteger(), nullable=True),
        sa.Column("entropy", sa.Numeric(6, 3), nullable=True),
        sa.Column("tags", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("present_in_current_code", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("lifecycle_status", sa.String(20), nullable=False, server_default=sa.text("'OPEN'")),
        sa.Column("baseline", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_by_user_id", sa.BigInteger(), nullable=True),
        sa.Column("rotation_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("repo_id", "custom_fingerprint", name="uq_secret_findings_natural_key"),
        sa.CheckConstraint(
            "lifecycle_status in ('OPEN','ROTATED','FALSE_POSITIVE','ACCEPTED_RISK')",
            name="secret_findings_lifecycle_status_check",
        ),
    )
    op.create_index("ix_secret_findings_repo_status", "secret_findings", ["repo_id", "lifecycle_status"])

    op.create_table(
        "secret_finding_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("secret_finding_id", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("from_status", sa.String(20), nullable=True),
        sa.Column("to_status", sa.String(20), nullable=True),
        sa.Column("actor", sa.String(100), nullable=False, server_default=sa.text("'system'")),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_secret_finding_events_finding_id", "secret_finding_events", ["secret_finding_id"])


def downgrade() -> None:
    op.drop_index("ix_secret_finding_events_finding_id", table_name="secret_finding_events")
    op.drop_table("secret_finding_events")
    op.drop_index("ix_secret_findings_repo_status", table_name="secret_findings")
    op.drop_table("secret_findings")
    op.drop_table("api_tokens")
    op.drop_index("ix_audit_log_created_at", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_table("users")

    op.drop_constraint("scan_runs_run_type_check", "scan_runs", type_="check")
    op.create_check_constraint(
        "scan_runs_run_type_check", "scan_runs",
        "run_type in ('extraction','immediate_match','daily_match')",
    )
    op.drop_column("repositories", "last_scanned_sha")
