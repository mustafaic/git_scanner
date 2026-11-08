"""users.last_dashboard_visit_at -- A6 "Bugün" ekrani (master_prompt.md 6):
"kullanicinin son ziyaretinden beri yeni olanlar rozetle". NULL ise
kullanici henuz hic giris yapmamis/ziyaret etmemis demektir (ilk ziyarette
hicbir sey "yeni" rozeti ALMAZ -- aksi halde TUM mevcut bulgular yanlislikla
yeni gorunur).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-09

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_dashboard_visit_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "last_dashboard_visit_at")
