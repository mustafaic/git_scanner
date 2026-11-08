"""settings (admin-editable key/value, SLA + bildirim kanal ayarlari),
notification_log (idempotent bildirim kaydi -- master_prompt.md 6
"Gurultu kontrolleri: ayni olay ayni aliciya ayni kanaldan BIR KEZ gider").

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_by_user_id", sa.BigInteger(), nullable=True),
    )

    op.create_table(
        "notification_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        # Ayni olay/alici/kanal ucluginu TEKRAR gondermemek icin -- master_prompt.md 6.
        sa.Column("dedup_key", sa.String(300), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("recipient", sa.String(300), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("dedup_key", "channel", "recipient", name="uq_notification_log_dedup"),
    )
    op.create_index("ix_notification_log_sent_at", "notification_log", ["sent_at"])


def downgrade() -> None:
    op.drop_index("ix_notification_log_sent_at", table_name="notification_log")
    op.drop_table("notification_log")
    op.drop_table("settings")
