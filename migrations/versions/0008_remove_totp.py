"""TOTP (2FA) kaldirildi -- kullanici karari (2026-11-09, bkz.
docs/ASSUMPTIONS.md #14). users.totp_secret, totp_enabled,
recovery_code_hashes sutunlari DUSURULUYOR.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-09

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("users", "totp_secret")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "recovery_code_hashes")


def downgrade() -> None:
    op.add_column("users", sa.Column("recovery_code_hashes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("totp_secret", sa.Text(), nullable=True))
