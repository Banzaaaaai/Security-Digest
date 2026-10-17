"""Multipart MIME, preview files and bounded SMTP retry policy."""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import time
from email import policy
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import format_datetime, make_msgid

from .rendering import render_html, render_markdown

log = logging.getLogger(__name__)


def recipients(value):
    if "\r" in value or "\n" in value:
        raise ValueError("EMAIL_TO contains invalid header characters")
    values = list(dict.fromkeys(v.strip() for v in value.split(",") if v.strip()))
    if not values or any("@" not in v or " " in v for v in values):
        raise ValueError("EMAIL_TO must contain comma-separated email addresses")
    return values


def subject(kind, report=None, stage=None, failures=0):
    if kind == "failure":
        return f"[SecDigest] ⚠️ Run failed — {stage or 'unknown stage'}"
    if kind == "source_health":
        return f"[SecDigest] 🟡 Source health — {failures} feeds failing"
    if kind == "weekly":
        top = report["items"][0]["headline"][:70] if report["items"] else "Quiet week"
        return f"[SecDigest] Weekly {report['period']} — {top}"
    counts = report["counts"]
    parts = [f"🔴 {counts['critical']} critical"] if counts["critical"] else []
    if counts["high"]:
        parts.append(f"🟠 {counts['high']} high")
    return f"[SecDigest] {' · '.join(parts) if parts else 'Quiet day'} — Daily {report['period']}"


def compose(kind, title, plain, html_body, attachments=(), preview=False, now=None):
    from datetime import UTC, datetime

    now = now or datetime.now(UTC)
    user = os.getenv("SMTP_USER", "preview@example.invalid" if preview else "")
    targets = recipients(os.getenv("EMAIL_TO", "preview@example.invalid" if preview else ""))
    if not user or any(c in user for c in "\r\n"):
        raise ValueError("SMTP_USER is missing or invalid")
    message = MIMEMultipart("mixed", policy=policy.SMTP)
    message["Subject"] = " ".join(title.splitlines())
    message["From"] = f"SecDigest <{user}>"
    message["To"] = ", ".join(targets)
    message["Date"] = format_datetime(now)
    message["Message-ID"] = make_msgid(domain=user.rsplit("@", 1)[-1])
    message["X-SecDigest"] = kind
    alternative = MIMEMultipart("alternative")
    alternative.attach(MIMEText(plain, "plain", "utf-8"))
    alternative.attach(MIMEText(html_body, "html", "utf-8"))
    message.attach(alternative)
    for name, payload in attachments:
        part = MIMEApplication(payload, _subtype="octet-stream")
        part.add_header("Content-Disposition", "attachment", filename=name)
        message.attach(part)
    return message


def digest_message(config, report, paths, preview=False, now=None):
    extensions = ["html", "csv"] + (["md"] if report["kind"] == "weekly" else [])
    attachments = [
        (f"secdigest-{report['kind']}-{report['period']}.{ext}", paths[ext].read_bytes())
        for ext in extensions
    ]
    return compose(
        report["kind"],
        subject(report["kind"], report),
        render_markdown(config, report),
        render_html(config, report, email=True),
        attachments,
        preview,
        now,
    )


def preview_message(config, message, name):
    path = config.output / "preview" / f"{name}.eml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(message.as_bytes())
    return path


def transient(exc):
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return False
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return bool(exc.recipients) and all(400 <= value[0] < 500 for value in exc.recipients.values())
    if isinstance(exc, smtplib.SMTPResponseException):
        return 400 <= exc.smtp_code < 500
    return isinstance(exc, (smtplib.SMTPServerDisconnected, TimeoutError, OSError))


def send(config, message, smtp_factory=smtplib.SMTP, sleeper=time.sleep):
    required = ("SMTP_USER", "SMTP_PASSWORD", "EMAIL_TO")
    if any(not os.getenv(key) for key in required):
        raise RuntimeError("Configure SMTP_USER, SMTP_PASSWORD and EMAIL_TO before sending")
    targets = recipients(os.environ["EMAIL_TO"])
    retries = config.settings["email"]["retry_count"]
    for attempt in range(retries + 1):
        try:
            with smtp_factory(
                os.getenv("SMTP_HOST") or "smtp.gmail.com", int(os.getenv("SMTP_PORT") or "587"), timeout=30
            ) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                refused = server.sendmail(os.environ["SMTP_USER"], targets, message.as_bytes())
                if refused:
                    raise RuntimeError("SMTP accepted only some recipients; inspect delivery before retrying")
            return
        except (smtplib.SMTPException, OSError) as exc:
            if attempt == retries or not transient(exc):
                raise
            sleeper(2 ** (attempt + 1))


def send_failure_email(config, stage, trace, duration, sender=None):
    import html

    try:
        body = f"Stage: {stage}\nDuration: {duration:.1f}s\n{trace}"
        message = compose(
            "failure",
            subject("failure", stage=stage),
            body,
            "<html><body><pre>" + html.escape(body) + "</pre></body></html>",
        )
        (sender or send)(config, message)
        return True
    except Exception as exc:
        log.error("Failure alert could not be sent (%s)", type(exc).__name__)
        return False
