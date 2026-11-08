"""core/notifications.py idempotency (gercek Postgres UNIQUE kisiti) +
orchestrator critical-event notification kancalari testleri. Gercek bir
SMTP sunucusu kurulmadi (kullanici karari) -- core.notifications.send_email
mock'lanir, sadece DB-seviyesindeki idempotent kayit/karar mantigi gercek
Postgres'e karsi dogrulanir."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.models import Finding, NotificationLog, SecretFinding  # noqa: E402
from core.notifications import (  # noqa: E402
    CHANNEL_EMAIL,
    EVENT_CRITICAL_SCA_FINDING,
    SmtpSettings,
    record_and_maybe_send,
)
from orchestrator.matching import _notify_critical_sca_findings  # noqa: E402
from orchestrator.secret_scan import _notify_new_secret_findings  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL ayarli degil (gercek Postgres gerekir)")

_SMTP_SETTINGS = SmtpSettings(host="smtp.internal", port=25, use_tls=False, from_address="scanner@internal")


@pytest.fixture()
def engine():
    eng = create_engine(DATABASE_URL, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean(engine):
    with engine.begin() as conn:
        for table in ("notification_log", "secret_findings", "findings", "repositories"):
            conn.execute(text(f"DELETE FROM {table}"))
    yield


@pytest.fixture()
def session_factory(engine):
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)


def test_record_and_maybe_send_is_idempotent_for_same_dedup_recipient(session_factory):
    with session_factory() as session:
        with patch("core.notifications.send_email") as mock_send:
            sent1 = record_and_maybe_send(
                session, event_type=EVENT_CRITICAL_SCA_FINDING, dedup_key="finding:1", channel=CHANNEL_EMAIL,
                recipients=["owner@internal"], subject="s", body="b", smtp_settings=_SMTP_SETTINGS,
            )
            session.commit()
        assert sent1 == 1
        mock_send.assert_called_once()

    with session_factory() as session:
        with patch("core.notifications.send_email") as mock_send:
            sent2 = record_and_maybe_send(
                session, event_type=EVENT_CRITICAL_SCA_FINDING, dedup_key="finding:1", channel=CHANNEL_EMAIL,
                recipients=["owner@internal"], subject="s", body="b", smtp_settings=_SMTP_SETTINGS,
            )
            session.commit()
        assert sent2 == 0  # idempotent -- ayni dedup_key+channel+recipient IKINCI kez gonderilmez
        mock_send.assert_not_called()

    with session_factory() as session:
        assert session.query(NotificationLog).count() == 1


def test_record_and_maybe_send_different_recipients_both_get_sent(session_factory):
    with session_factory() as session:
        with patch("core.notifications.send_email") as mock_send:
            sent = record_and_maybe_send(
                session, event_type=EVENT_CRITICAL_SCA_FINDING, dedup_key="finding:2", channel=CHANNEL_EMAIL,
                recipients=["a@internal", "b@internal"], subject="s", body="b", smtp_settings=_SMTP_SETTINGS,
            )
            session.commit()
        assert sent == 2
        assert mock_send.call_count == 2


def test_record_and_maybe_send_returns_zero_without_smtp_settings(session_factory):
    with session_factory() as session:
        sent = record_and_maybe_send(
            session, event_type=EVENT_CRITICAL_SCA_FINDING, dedup_key="finding:3", channel=CHANNEL_EMAIL,
            recipients=["a@internal"], subject="s", body="b", smtp_settings=None,
        )
    assert sent == 0


def test_notify_critical_sca_findings_skips_baseline(session_factory):
    finding = Finding(
        id=101, repo_id=1, lockfile_path="x", ecosystem="npm", package_name="lodash", version="4.17.15",
        canonical_vulnerability_id="GHSA-x", verification_status="VERIFIED", lifecycle_status="OPEN",
        kev=True, baseline=True,
    )
    with session_factory() as session:
        with patch("orchestrator.matching.record_and_maybe_send") as mock_record:
            _notify_critical_sca_findings(session, [finding], _SMTP_SETTINGS, ["owner@internal"])
        mock_record.assert_not_called()


def test_notify_critical_sca_findings_sends_for_non_baseline_kev(session_factory):
    finding = Finding(
        id=102, repo_id=1, lockfile_path="x", ecosystem="npm", package_name="lodash", version="4.17.15",
        canonical_vulnerability_id="GHSA-y", verification_status="VERIFIED", lifecycle_status="OPEN",
        kev=True, baseline=False,
    )
    with session_factory() as session:
        with patch("core.notifications.send_email") as mock_send:
            _notify_critical_sca_findings(session, [finding], _SMTP_SETTINGS, ["owner@internal"])
            session.commit()
        mock_send.assert_called_once()
    with session_factory() as session:
        row = session.query(NotificationLog).filter_by(dedup_key="finding:102").one()
        assert row.event_type == EVENT_CRITICAL_SCA_FINDING


def test_notify_new_secret_findings_skips_baseline(session_factory):
    secret = SecretFinding(
        id=201, repo_id=1, rule_id="aws-key", file_path="x.env",
        custom_fingerprint="fp1", secret_content_hash="h1", baseline=True, lifecycle_status="OPEN",
    )
    with session_factory() as session:
        with patch("orchestrator.secret_scan.record_and_maybe_send") as mock_record:
            _notify_new_secret_findings(session, [secret], _SMTP_SETTINGS, ["owner@internal"])
        mock_record.assert_not_called()


def test_notify_new_secret_findings_sends_for_non_baseline(session_factory):
    secret = SecretFinding(
        id=202, repo_id=1, rule_id="aws-key", file_path="x.env",
        custom_fingerprint="fp2", secret_content_hash="h2", baseline=False, lifecycle_status="OPEN",
    )
    with session_factory() as session:
        with patch("core.notifications.send_email") as mock_send:
            _notify_new_secret_findings(session, [secret], _SMTP_SETTINGS, ["owner@internal"])
            session.commit()
        mock_send.assert_called_once()
    with session_factory() as session:
        row = session.query(NotificationLog).filter_by(dedup_key="secret_finding:202").one()
        assert row.event_type == "new_secret_finding"
        # Ham secret degeri hicbir alanda yok -- sadece dosya/kural bilgisi.
        assert "h2" not in (row.subject or "")
