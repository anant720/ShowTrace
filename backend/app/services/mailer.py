import logging
import smtplib
import ssl
from typing import Optional

import requests

from app.config import settings

logger = logging.getLogger("shadowtrace.services.mailer")


class MailerError(RuntimeError):
    pass


def _smtp_configured() -> bool:
    return bool(
        getattr(settings, "SMTP_HOST", "")
        and getattr(settings, "SMTP_USERNAME", "")
        and getattr(settings, "SMTP_PASSWORD", "")
        and getattr(settings, "MAIL_FROM", "")
    )


def _sendgrid_configured() -> bool:
    return bool(getattr(settings, "SENDGRID_API_KEY", "") and getattr(settings, "MAIL_FROM", ""))


def send_email_smtp(
    *,
    to_email: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
) -> None:
    """
    Send email via SMTP (Gmail supported).

    Requires environment variables (Render):
      - SMTP_HOST (e.g. smtp.gmail.com)
      - SMTP_PORT (587 for STARTTLS)
      - SMTP_USERNAME (gmail address)
      - SMTP_PASSWORD (16-char App Password)
      - MAIL_FROM (from address; usually same as SMTP_USERNAME)
    """
    host = getattr(settings, "SMTP_HOST", "")
    port = int(getattr(settings, "SMTP_PORT", 587) or 587)
    username = getattr(settings, "SMTP_USERNAME", "")
    password = getattr(settings, "SMTP_PASSWORD", "")
    from_email = getattr(settings, "MAIL_FROM", "")

    if not host:
        raise MailerError("SMTP_HOST is not set")
    if not username:
        raise MailerError("SMTP_USERNAME is not set")
    if not password:
        raise MailerError("SMTP_PASSWORD is not set")
    if not from_email:
        raise MailerError("MAIL_FROM is not set")

    try:
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")

        # STARTTLS
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(username, password)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"SMTP send failed: {e}")
        raise MailerError(f"SMTP send failed: {e}") from e


def send_email_sendgrid(
    *,
    to_email: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
) -> None:
    """
    Send an email via SendGrid Web API.

    Requires environment variables (Render):
      - SENDGRID_API_KEY
      - MAIL_FROM
    """
    api_key = getattr(settings, "SENDGRID_API_KEY", "")
    from_email = getattr(settings, "MAIL_FROM", "")

    if not api_key:
        raise MailerError("SENDGRID_API_KEY is not set")
    if not from_email:
        raise MailerError("MAIL_FROM is not set")

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email},
        "subject": subject,
        "content": [{"type": "text/plain", "value": text}],
    }
    if html:
        payload["content"].append({"type": "text/html", "value": html})

    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=10,
    )

    if resp.status_code >= 400:
        logger.error(f"SendGrid error {resp.status_code}: {resp.text}")
        raise MailerError(f"SendGrid rejected request (status={resp.status_code})")


def send_email(
    *,
    to_email: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
) -> None:
    """
    Provider-agnostic email sender.

    Preference order:
      1) SMTP (if configured) - simplest free setup for small scale
      2) SendGrid (if configured)
    """
    if _smtp_configured():
        return send_email_smtp(to_email=to_email, subject=subject, text=text, html=html)
    if _sendgrid_configured():
        return send_email_sendgrid(to_email=to_email, subject=subject, text=text, html=html)
    raise MailerError(
        "No email provider configured. Set SMTP_* + MAIL_FROM (recommended) or SENDGRID_API_KEY + MAIL_FROM."
    )
