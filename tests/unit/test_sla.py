"""core/sla.py testleri (master_prompt.md 6 A8) -- DB gerektirmez."""

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.sla import (  # noqa: E402
    DEFAULT_SLA_DAYS,
    compute_due_date,
    days_remaining,
    is_overdue,
    merged_sla_days,
)

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def test_kev_gets_shortest_sla_regardless_of_cvss():
    due = compute_due_date(kev=True, cvss_score=2.0, first_seen_at=_NOW, sla_days=DEFAULT_SLA_DAYS)
    assert due == dt.date(2026, 1, 2)


def test_cvss_9_tier():
    due = compute_due_date(kev=False, cvss_score=9.8, first_seen_at=_NOW, sla_days=DEFAULT_SLA_DAYS)
    assert due == _NOW.date() + dt.timedelta(days=DEFAULT_SLA_DAYS["cvss_9"])


def test_cvss_7_tier():
    due = compute_due_date(kev=False, cvss_score=7.2, first_seen_at=_NOW, sla_days=DEFAULT_SLA_DAYS)
    assert due == _NOW.date() + dt.timedelta(days=DEFAULT_SLA_DAYS["cvss_7"])


def test_no_severity_data_falls_back_to_default_tier():
    due = compute_due_date(kev=False, cvss_score=None, first_seen_at=_NOW, sla_days=DEFAULT_SLA_DAYS)
    assert due == _NOW.date() + dt.timedelta(days=DEFAULT_SLA_DAYS["default"])


def test_kev_overrides_even_low_cvss_tier_boundary():
    due_kev = compute_due_date(kev=True, cvss_score=9.9, first_seen_at=_NOW, sla_days=DEFAULT_SLA_DAYS)
    due_cvss = compute_due_date(kev=False, cvss_score=9.9, first_seen_at=_NOW, sla_days=DEFAULT_SLA_DAYS)
    assert due_kev < due_cvss


def test_is_overdue_true_when_past_due_date():
    due = dt.date(2026, 1, 1)
    assert is_overdue(due, today=dt.date(2026, 1, 2)) is True
    assert is_overdue(due, today=dt.date(2026, 1, 1)) is False
    assert is_overdue(due, today=dt.date(2025, 12, 31)) is False


def test_days_remaining_negative_when_overdue():
    due = dt.date(2026, 1, 1)
    assert days_remaining(due, today=dt.date(2026, 1, 5)) == -4
    assert days_remaining(due, today=dt.date(2025, 12, 30)) == 2


def test_merged_sla_days_fills_missing_tiers_with_defaults():
    merged = merged_sla_days({"kev": 2})
    assert merged["kev"] == 2
    assert merged["cvss_9"] == DEFAULT_SLA_DAYS["cvss_9"]


def test_merged_sla_days_ignores_invalid_values():
    merged = merged_sla_days({"kev": -5, "cvss_9": "not-an-int", "unknown_key": 1})
    assert merged["kev"] == DEFAULT_SLA_DAYS["kev"]
    assert merged["cvss_9"] == DEFAULT_SLA_DAYS["cvss_9"]
    assert "unknown_key" not in merged


def test_merged_sla_days_with_none_returns_defaults():
    assert merged_sla_days(None) == dict(DEFAULT_SLA_DAYS)
