import logging
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)


# ─── TWILIO SERVICE ───────────────────────────────────────────────────────────

class TwilioService:
    def __init__(self):
        self.client = None
        self._init_client()

    def _init_client(self):
        if settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN:
            try:
                from twilio.rest import Client
                self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                logger.info("Twilio client initialized")
            except Exception as e:
                logger.warning(f"Twilio init failed: {e}")

    def send_sms(self, to: str, body: str) -> dict:
        if not self.client:
            logger.warning(f"[MOCK SMS] To: {to} | Body: {body[:50]}...")
            return {"sid": "MOCK_SID", "status": "sent", "mock": True}
        try:
            message = self.client.messages.create(
                body=body,
                from_=settings.TWILIO_FROM_NUMBER,
                to=to
            )
            return {"sid": message.sid, "status": message.status}
        except Exception as e:
            logger.error(f"SMS failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}

    def make_voice_call(self, to: str, message: str) -> dict:
        if not self.client:
            logger.warning(f"[MOCK VOICE] To: {to} | Message: {message[:50]}...")
            return {"sid": "MOCK_VOICE_SID", "status": "initiated", "mock": True}
        try:
            twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice" loop="2">{message}</Say>
  <Pause length="1"/>
  <Say voice="alice">Press 1 if you are safe. Press 2 if you need help.</Say>
  <Gather numDigits="1" action="/api/v1/webhooks/voice-response" method="POST">
    <Say>Please press a key now.</Say>
  </Gather>
</Response>"""
            call = self.client.calls.create(
                twiml=twiml,
                from_=settings.TWILIO_FROM_NUMBER,
                to=to
            )
            return {"sid": call.sid, "status": call.status}
        except Exception as e:
            logger.error(f"Voice call failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}

    def send_whatsapp(self, to: str, body: str) -> dict:
        if not self.client:
            logger.warning(f"[MOCK WHATSAPP] To: {to} | Body: {body[:50]}...")
            return {"sid": "MOCK_WA_SID", "status": "sent", "mock": True}
        try:
            whatsapp_to = f"whatsapp:{to}" if not to.startswith("whatsapp:") else to
            message = self.client.messages.create(
                body=body,
                from_=settings.TWILIO_WHATSAPP_FROM,
                to=whatsapp_to
            )
            return {"sid": message.sid, "status": message.status}
        except Exception as e:
            logger.error(f"WhatsApp failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}


# ─── EMAIL SERVICE (AWS SES) ──────────────────────────────────────────────────

class EmailService:
    def __init__(self):
        self.client = None
        self._init_client()

    def _init_client(self):
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            try:
                import boto3
                self.client = boto3.client(
                    "ses",
                    region_name=settings.AWS_REGION,
                    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
                )
                logger.info("AWS SES client initialized")
            except Exception as e:
                logger.warning(f"SES init failed: {e}")

    def send_email(self, to: str, subject: str, body_text: str, body_html: Optional[str] = None) -> dict:
        if not self.client:
            logger.warning(f"[MOCK EMAIL] To: {to} | Subject: {subject}")
            return {"message_id": "MOCK_EMAIL_ID", "status": "sent", "mock": True}
        try:
            html_body = body_html or self._text_to_html(body_text)
            response = self.client.send_email(
                Source=f"{settings.SES_FROM_NAME} <{settings.SES_FROM_EMAIL}>",
                Destination={"ToAddresses": [to]},
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {
                        "Text": {"Data": body_text, "Charset": "UTF-8"},
                        "Html": {"Data": html_body, "Charset": "UTF-8"},
                    },
                },
            )
            return {"message_id": response["MessageId"], "status": "sent"}
        except Exception as e:
            logger.error(f"Email failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}

    def send_password_reset_email(self, to: str, reset_token: str, user_name: str) -> dict:
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        subject = "TM Alert - Password Reset Request"
        body_text = f"Hi {user_name},\n\nClick the link to reset your password:\n{reset_url}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, ignore this email."
        body_html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e40af; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">TM Alert</h1>
        </div>
        <div style="padding: 30px;">
            <h2>Password Reset Request</h2>
            <p>Hi {user_name},</p>
            <p>Someone requested a password reset for your TM Alert account.</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}" style="background: #1e40af; color: white; padding: 12px 24px; 
                   text-decoration: none; border-radius: 6px; font-weight: bold;">Reset My Password</a>
            </p>
            <p style="color: #666; font-size: 14px;">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
        </div>
        </body></html>"""
        return self.send_email(to, subject, body_text, body_html)

    def _text_to_html(self, text: str) -> str:
        paragraphs = text.split("\n\n")
        html_parts = [f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs]
        return f"""<html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e40af; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">🚨 TM Alert</h1>
        </div>
        <div style="padding: 30px;">{''.join(html_parts)}</div>
        </body></html>"""


# ─── WEBHOOK SERVICE (Slack / Teams) ─────────────────────────────────────────

class WebhookService:
    def send_slack(self, webhook_url: str, message: str, title: str = "") -> dict:
        if not webhook_url:
            webhook_url = settings.SLACK_DEFAULT_WEBHOOK_URL
        if not webhook_url:
            logger.warning(f"[MOCK SLACK] Title: {title} | Message: {message[:50]}...")
            return {"status": "mock"}
        try:
            import httpx
            payload = {
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {title}"}},
                    {"type": "section", "text": {"type": "mrkdwn", "text": message}},
                ]
            }
            response = httpx.post(webhook_url, json=payload, timeout=10)
            return {"status": "sent" if response.status_code == 200 else "failed"}
        except Exception as e:
            logger.error(f"Slack webhook failed: {e}")
            return {"error": str(e), "status": "failed"}

    def send_teams(self, webhook_url: str, message: str, title: str = "") -> dict:
        if not webhook_url:
            webhook_url = settings.TEAMS_DEFAULT_WEBHOOK_URL
        if not webhook_url:
            logger.warning(f"[MOCK TEAMS] Title: {title} | Message: {message[:50]}...")
            return {"status": "mock"}
        try:
            import httpx
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "DC2626",
                "summary": title,
                "sections": [{"activityTitle": f"🚨 {title}", "activityText": message}]
            }
            response = httpx.post(webhook_url, json=payload, timeout=10)
            return {"status": "sent" if response.status_code == 200 else "failed"}
        except Exception as e:
            logger.error(f"Teams webhook failed: {e}")
            return {"error": str(e), "status": "failed"}


# Singletons
twilio_service = TwilioService()
email_service = EmailService()
webhook_service = WebhookService()
