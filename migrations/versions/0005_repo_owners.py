"""repo_owners (A5 sahip yonlendirme -- master_prompt.md 6): "CODEOWNERS
-> GitHub team/depo eslemesi (kullanilabilirse) -> ice aktarilabilir (CSV)
repo->ekip tablosu -> 'sahipsiz' listesi". Bu surumde SADECE CSV/manuel
kaynak (source='csv'); CODEOWNERS otomatik tespiti sonraki bir adim
(bkz. docs/ASSUMPTIONS.md) -- sema buna gore genisleyebilir sekilde
(source sutunu) tasarlandi.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-09

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "repo_owners",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger(), nullable=False),
        sa.Column("owner_identifier", sa.String(300), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("repo_id", "owner_identifier", "source", name="uq_repo_owners_repo_identifier_source"),
        sa.CheckConstraint("source in ('csv', 'manual', 'codeowners')", name="repo_owners_source_check"),
    )
    op.create_index("ix_repo_owners_repo_id", "repo_owners", ["repo_id"])


def downgrade() -> None:
    op.drop_index("ix_repo_owners_repo_id", table_name="repo_owners")
    op.drop_table("repo_owners")
