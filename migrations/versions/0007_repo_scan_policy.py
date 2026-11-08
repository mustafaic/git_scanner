"""repositories.scan_excluded + scan_exclude_reason (A3/A10 master_prompt.md
6: "Repo bazli tarama politikasi (dahil/hariç + gerekçe, audit'li)").

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-09

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("repositories", sa.Column("scan_excluded", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("repositories", sa.Column("scan_exclude_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("repositories", "scan_exclude_reason")
    op.drop_column("repositories", "scan_excluded")
