import logging
from typing import Optional

import requests

from app.config import settings

logger = logging.getLogger("shadowtrace.services.mailer")


class MailerError(RuntimeError):
    pass


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

