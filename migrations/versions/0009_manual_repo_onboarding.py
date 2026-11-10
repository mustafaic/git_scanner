"""Panelden GitHub token ile repo ekleme (hibrit model -- 2026-11-10 kullanici
karari: GitHub App org-wide kesfi korunur, ek olarak admin panelden tek bir
repo icin fine-grained PAT ile ekleyebilir). repositories.discovered_via +
repo_onboarding_requests + repo_credentials tablolari.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-10

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "repositories",
        sa.Column("discovered_via", sa.String(20), nullable=False, server_default="github_app"),
    )
    op.create_check_constraint(
        "repositories_discovered_via_check", "repositories", "discovered_via in ('github_app','manual_pat')",
    )

    op.create_table(
        "repo_onboarding_requests",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("repo_name", sa.String(255), nullable=False),
        sa.Column("encrypted_token", sa.Text(), nullable=False),
        sa.Column("requested_by_user_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("resolved_github_repo_id", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status in ('pending','validated','failed')", name="repo_onboarding_requests_status_check"),
    )
    op.create_index("ix_repo_onboarding_requests_status", "repo_onboarding_requests", ["status"])

    op.create_table(
        "repo_credentials",
        sa.Column("github_repo_id", sa.BigInteger(), primary_key=True),
        sa.Column("encrypted_token", sa.Text(), nullable=False),
        sa.Column("added_by_user_id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validation_error", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("repo_credentials")
    op.drop_index("ix_repo_onboarding_requests_status", table_name="repo_onboarding_requests")
    op.drop_table("repo_onboarding_requests")
    op.drop_constraint("repositories_discovered_via_check", "repositories", type_="check")
    op.drop_column("repositories", "discovered_via")
