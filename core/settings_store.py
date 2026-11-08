"""core.models.Setting icin paylasilan okuma/yazma yardimcilari (app VE
orchestrator kullanir -- app admin'in degistirdigi degerleri yazar,
orchestrator bildirim gonderirken okur). Upsert deseni, orchestrator/main.py
_write_heartbeat() ile AYNI (pg_insert ... on_conflict_do_update)."""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.models import Setting

SLA_DAYS_KEY = "sla_days"
NOTIFICATIONS_KEY = "notifications"

DEFAULT_NOTIFICATIONS: dict[str, Any] = {"email_enabled": False, "recipients": []}


def get_setting(session: Session, key: str, default: Optional[Any] = None) -> Any:
    row = session.get(Setting, key)
    return row.value if row is not None else default


def set_setting(session: Session, key: str, value: Any, updated_by_user_id: Optional[int] = None) -> None:
    stmt = (
        pg_insert(Setting)
        .values(key=key, value=value, updated_by_user_id=updated_by_user_id)
        .on_conflict_do_update(index_elements=["key"], set_={"value": value, "updated_by_user_id": updated_by_user_id})
    )
    session.execute(stmt)
