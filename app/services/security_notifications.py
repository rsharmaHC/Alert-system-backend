"""
Security-related user notifications.
All sends are fire-and-forget — failures are logged but never block auth flow.
"""

import asyncio
import logging
from app.services.email_service import send_email

logger = logging.getLogger(__name__)

LOCKOUT_SUBJECT = "Suspicious login activity on your account"

LOCKOUT_BODY = """
Someone attempted to log into your account {attempt_count} times with an incorrect password.

If this was you, you can try again after the temporary lockout expires.

If this was NOT you:
  1. Change your password immediately
  2. Contact your administrator if you suspect unauthorized access

Details:
  - IP Address: {ip_address}
  - Time: {timestamp}

This is an automated security alert. Do not reply to this email.
""".strip()


async def notify_suspicious_login(
    email: str,
    attempt_count: int,
    ip_address: str,
    timestamp: str,
):
    """
    Fire-and-forget email alert for suspicious login activity.
    Runs in background — does NOT block the login response.
    """
    body = LOCKOUT_BODY.format(
        attempt_count=attempt_count,
        ip_address=ip_address,
        timestamp=timestamp,
    )

    # Fire and forget — don't await in the request path
    asyncio.create_task(
        _safe_send(email, LOCKOUT_SUBJECT, body)
    )


async def _safe_send(to: str, subject: str, body: str):
    """Wrapper that catches all exceptions to prevent task crashes."""
    try:
        await send_email(to, subject, body)
    except Exception as e:
        logger.error(f"Security notification failed for {to}: {e}")
