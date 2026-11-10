"""core/notifications.py testleri -- karar mantigi + SMTP gonderimi (mock'lu,
kullanici karari: gercek bir test SMTP sunucusu bu oturumda kurulmadi).
`record_and_maybe_send` (idempotent DB yazimi) gercek Postgres gerektirir,
bkz. tests/integration/test_app_panel_postgres.py (Asama 4 part 3)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.notifications import (  # noqa: E402
    SmtpSettings,
    build_daily_digest_summary,
    build_minimal_teams_text,
    send_email,
    send_teams_message,
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


def test_send_teams_message_posts_messagecard_payload():
    with patch("core.notifications.httpx.Client") as mock_client_cls:
        client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = client
        response = MagicMock()
        client.post.return_value = response
        send_teams_message("https://contoso.webhook.office.com/webhookb2/unit-test-token", "title", "text")
        client.post.assert_called_once()
        url, kwargs = client.post.call_args[0][0], client.post.call_args[1]
        assert url == "https://contoso.webhook.office.com/webhookb2/unit-test-token"
        assert kwargs["json"]["@type"] == "MessageCard"
        assert kwargs["json"]["title"] == "title"
        assert kwargs["json"]["text"] == "text"
        response.raise_for_status.assert_called_once()


def test_send_teams_message_raises_on_http_error():
    import httpx

    with patch("core.notifications.httpx.Client") as mock_client_cls:
        client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = client
        response = MagicMock()
        response.raise_for_status.side_effect = httpx.HTTPStatusError("bad", request=MagicMock(), response=MagicMock())
        client.post.return_value = response
        with pytest.raises(httpx.HTTPStatusError):
            send_teams_message("https://contoso.webhook.office.com/webhookb2/unit-test-token-2", "t", "x")


def test_send_teams_message_webhook_url_is_registered_for_log_redaction():
    from core import logging_setup

    with patch("core.notifications.httpx.Client") as mock_client_cls:
        client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = client
        send_teams_message("https://contoso.webhook.office.com/webhookb2/unit-test-secret-token-3", "t", "x")
    assert "unit-test-secret-token-3" not in logging_setup._redact(
        "https://contoso.webhook.office.com/webhookb2/unit-test-secret-token-3"
    )


def test_send_teams_message_suppresses_httpx_request_log_leak(caplog):
    """Regresyon testi: httpx, istek URL'sini loglarken yeniden serilestirir
    (ör. varsayilan :443 portunu dusurur) -- register_secret'teki metin
    eslesmesi bu durumda TUTMAZ ve webhook imzasi DUZ METIN sizar (gercek
    bir Power Automate webhook'una karsi ampirik olarak bulundu). send_teams_message
    bu yuzden httpx/httpcore'un istek logunu CAGRI SIRASINDA komple
    susturmali -- bu test gercek bir httpx.Client + MockTransport ile (tam
    httpx logging makinesini calistirarak, mock'lamadan) dogrular."""
    import logging

    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    real_client_cls = httpx.Client

    def client_factory(*args, **kwargs):
        return real_client_cls(transport=httpx.MockTransport(handler))

    secret_token = "super-secret-webhook-signature-xyz-789"
    url_with_default_port = f"https://contoso.webhook.office.com:443/webhookb2/{secret_token}"

    httpx_logger = logging.getLogger("httpx")
    original_level = httpx_logger.level
    httpx_logger.setLevel(logging.INFO)
    try:
        with caplog.at_level(logging.INFO, logger="httpx"):
            with patch("core.notifications.httpx.Client", side_effect=client_factory):
                send_teams_message(url_with_default_port, "t", "x")
        assert not any(secret_token in record.getMessage() for record in caplog.records), (
            "webhook URL'si httpx'in kendi istek loguna sizdi"
        )
        assert httpx_logger.level == logging.INFO  # cagri sonrasi onceki seviyeye geri donmeli
    finally:
        httpx_logger.setLevel(original_level)


def test_build_minimal_teams_text_never_includes_package_or_cve_details():
    """docs/THREAT_MODEL.md madde 9: Teams icerigi SADECE minimal olmali --
    bu fonksiyon finding/secret nesnesini parametre olarak bile almaz, bu
    yuzden yanlislikla detay sizdirmasi yapisal olarak imkansiz."""
    from core.notifications import EVENT_CRITICAL_SCA_FINDING, EVENT_NEW_SECRET_FINDING

    result = build_minimal_teams_text(EVENT_CRITICAL_SCA_FINDING)
    assert "title" in result and "text" in result
    assert "lodash" not in result["text"]  # ornek paket adi asla gecmemeli

    result2 = build_minimal_teams_text(EVENT_NEW_SECRET_FINDING, panel_base_url="https://scanner.internal")
    assert "https://scanner.internal/secrets" in result2["text"]


def test_build_daily_digest_summary_consolidated_single_message():
    """master_prompt.md 6: 'Bulgu basina mesaj yok, konsolide'."""
    import datetime as dt

    result = build_daily_digest_summary({"new": 3, "resolved": 1, "new_kev": 1}, as_of=dt.date(2026, 1, 1))
    assert result["subject"] == "Günlük özet (2026-01-01)"
    assert "Yeni bulgu: 3" in result["body"]
    assert "KEV'e yeni giren: 1" in result["body"]
    assert "\n" in result["body"]  # tek mesaj, cok satir -- bulgu basina ayri mesaj degil
