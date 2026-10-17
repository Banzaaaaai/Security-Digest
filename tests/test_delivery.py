import smtplib
from copy import deepcopy
from datetime import timedelta
from email import policy
from email.parser import BytesParser
from unittest.mock import MagicMock, Mock

import pytest

from secdigest.delivery import compose, digest_message, recipients, send, send_failure_email, subject
from secdigest.fixtures import FIXTURE_NOW
from secdigest.operations import safe_trace, source_health_due, write_run
from secdigest.rendering import archive
from secdigest.reporting import build_report


@pytest.fixture
def mail_env(monkeypatch):
    for key, value in {
        "SMTP_USER": "sender@example.test",
        "SMTP_PASSWORD": "test-only-password",
        "EMAIL_TO": "one@example.test, , two@example.test",
    }.items():
        monkeypatch.setenv(key, value)


def test_mime_and_headers(config, populated, tmp_path):
    config.settings["output"] = str(tmp_path)
    report = build_report(config, populated, "daily", now=FIXTURE_NOW, dry_run=True)
    paths = archive(config, report)
    message = digest_message(config, report, paths, preview=True, now=FIXTURE_NOW)
    parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
    assert parsed.get_content_type() == "multipart/mixed"
    parts = list(parsed.iter_parts())
    assert parts[0].get_content_type() == "multipart/alternative"
    assert [p.get_content_type() for p in parts[0].iter_parts()] == ["text/plain", "text/html"]
    assert len(parts) == 3
    assert parsed["X-SecDigest"] == "daily"
    assert parsed["Date"] and parsed["Message-ID"]
    assert "SecDigest" in parsed["From"]


def test_all_subjects(config, populated):
    report = build_report(config, populated, "daily", now=FIXTURE_NOW, dry_run=True)
    assert "critical" in subject("daily", report)
    quiet = deepcopy(report)
    quiet["counts"].update(critical=0, high=0)
    assert "Quiet day" in subject("daily", quiet)
    assert "Weekly" in subject("weekly", report)
    assert "Run failed — ingestion" in subject("failure", stage="ingestion")
    assert "3 feeds failing" in subject("source_health", failures=3)
    assert recipients(" a@example.test, , b@example.test, a@example.test ") == [
        "a@example.test",
        "b@example.test",
    ]
    with pytest.raises(ValueError):
        recipients("a@example.test\nBcc:b@example.test")


def test_transient_retry_and_tls(config, mail_env):
    factory = MagicMock()
    server = factory.return_value.__enter__.return_value
    server.sendmail.side_effect = [smtplib.SMTPDataError(451, b"Temporary"), {}]
    sleep = Mock()
    message = compose("daily", "Test", "Plain", "<p>HTML</p>")
    send(config, message, factory, sleep)
    assert factory.call_count == 2
    sleep.assert_called_once_with(2)
    assert server.starttls.call_args.kwargs["context"].check_hostname


def test_auth_error_never_retries(config, mail_env):
    factory = MagicMock()
    factory.return_value.__enter__.return_value.login.side_effect = smtplib.SMTPAuthenticationError(
        535, b"Denied"
    )
    message = compose("daily", "Test", "Plain", "<p>HTML</p>")
    with pytest.raises(smtplib.SMTPAuthenticationError):
        send(config, message, factory, Mock())
    assert factory.call_count == 1


def test_failure_alert_never_raises(config, mail_env, caplog):
    sender = Mock(side_effect=RuntimeError("Secret must not appear"))
    assert not send_failure_email(config, "test", "Trace", 1, sender)
    assert "Failure alert could not be sent" in caplog.text
    assert "Secret must not appear" not in caplog.text


def test_source_health_suppression(config, populated, tmp_path):
    config.root = tmp_path
    populated.put("source_health", {"enabled": 10, "failures": 4, "new": 1})
    populated.put("last_new", FIXTURE_NOW.isoformat())
    assert source_health_due(config, populated, FIXTURE_NOW)
    write_run(
        tmp_path,
        {
            "timestamp": FIXTURE_NOW.isoformat(),
            "status": "success",
            "emails": [{"email_type": "source_health", "email_sent": True}],
        },
    )
    assert not source_health_due(config, populated, FIXTURE_NOW + timedelta(days=2))
    assert source_health_due(config, populated, FIXTURE_NOW + timedelta(days=3))


def test_safe_trace_excludes_exception_and_source_values():
    try:
        raise RuntimeError("SECRET_VALUE=do-not-log")
    except RuntimeError as exc:
        assert "SECRET_VALUE" not in safe_trace(exc)
        assert "RuntimeError" in safe_trace(exc)
