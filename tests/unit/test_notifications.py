"""core/notifications.py testleri -- karar mantigi + SMTP gonderimi (mock'lu,
kullanici karari: gercek bir test SMTP sunucusu bu oturumda kurulmadi).
`record_and_maybe_send` (idempotent DB yazimi) gercek Postgres gerektirir,
bkz. tests/integration/test_app_panel_postgres.py (Asama 4 part 3)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.notifications import (  # noqa: E402
    SmtpSettings,
    build_daily_digest_summary,
    send_email,
    should_notify_critical_sca,
    should_notify_new_secret,
)


def test_baseline_secret_never_notifies():
    assert should_notify_new_secret(is_baseline=True) is False


def test_non_baseline_secret_always_notifies():
    assert should_notify_new_secret(is_baseline=False) is True


def test_baseline_sca_finding_never_notifies_even_if_kev():
    assert should_notify_critical_sca(kev=True, cvss_score=10.0, is_baseline=True) is False


def test_kev_sca_finding_notifies_regardless_of_cvss():
    assert should_notify_critical_sca(kev=True, cvss_score=None, is_baseline=False) is True


def test_high_cvss_sca_finding_notifies():
    assert should_notify_critical_sca(kev=False, cvss_score=9.5, is_baseline=False) is True


def test_moderate_cvss_sca_finding_does_not_notify_immediately():
    assert should_notify_critical_sca(kev=False, cvss_score=7.0, is_baseline=False) is False


def test_custom_critical_threshold_is_respected():
    assert should_notify_critical_sca(kev=False, cvss_score=7.5, is_baseline=False, critical_cvss_threshold=7.0) is True


def test_no_severity_data_does_not_notify():
    assert should_notify_critical_sca(kev=False, cvss_score=None, is_baseline=False) is False


def test_send_email_uses_starttls_and_login_when_credentials_present():
    # NOT: parola degerleri her testte benzersiz/uzun secilir -- register_secret
    # SURECIN TAMAMI icin GLOBAL bir maskeleme listesi tutar (core/logging_setup.py),
    # kisa/ortak bir deger (ör. "p") baska bir testteki metni de yanlislikla
    # redakte edip o testi kirabilir.
    settings = SmtpSettings(host="smtp.example.internal", port=587, use_tls=True, from_address="scanner@internal", username="smtp-user", password="unit-test-smtp-password-001")
    with patch("core.notifications.smtplib.SMTP") as mock_smtp:
        client = MagicMock()
        mock_smtp.return_value.__enter__.return_value = client
        send_email(settings, "owner@internal", "subject", "body")
        mock_smtp.assert_called_once_with("smtp.example.internal", 587, timeout=15)
        client.starttls.assert_called_once()
        client.login.assert_called_once_with("smtp-user", "unit-test-smtp-password-001")
        client.send_message.assert_called_once()


def test_send_email_skips_login_without_credentials():
    settings = SmtpSettings(host="smtp.example.internal", port=25, use_tls=False, from_address="scanner@internal")
    with patch("core.notifications.smtplib.SMTP") as mock_smtp:
        client = MagicMock()
        mock_smtp.return_value.__enter__.return_value = client
        send_email(settings, "owner@internal", "subject", "body")
        client.starttls.assert_not_called()
        client.login.assert_not_called()
        client.send_message.assert_called_once()


def test_send_email_password_is_registered_for_log_redaction():
    from core import logging_setup

    settings = SmtpSettings(host="h", port=25, use_tls=False, from_address="f", username="u", password="SuperSecretSmtpPw123")
    with patch("core.notifications.smtplib.SMTP") as mock_smtp:
        client = MagicMock()
        mock_smtp.return_value.__enter__.return_value = client
        send_email(settings, "owner@internal", "subject", "body")
    assert logging_setup._redact("password=SuperSecretSmtpPw123") == "password=***REDACTED***"


def test_build_daily_digest_summary_consolidated_single_message():
    """master_prompt.md 6: 'Bulgu basina mesaj yok, konsolide'."""
    import datetime as dt

    result = build_daily_digest_summary({"new": 3, "resolved": 1, "new_kev": 1}, as_of=dt.date(2026, 1, 1))
    assert result["subject"] == "Günlük özet (2026-01-01)"
    assert "Yeni bulgu: 3" in result["body"]
    assert "KEV'e yeni giren: 1" in result["body"]
    assert "\n" in result["body"]  # tek mesaj, cok satir -- bulgu basina ayri mesaj degil
