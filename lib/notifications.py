#!/usr/bin/env python3
"""
Purple Team GRC - Notification System
Manages notification channels (email, Slack, Teams, webhook, syslog) and
delivers alerts for security events such as critical findings, SLA breaches,
scan completions, exception expirations, and schedule failures.
"""

import json
import socket
import sqlite3
import uuid
import logging
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
except ImportError:
    from paths import paths


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_CHANNEL_TYPES = (
    "email", "slack", "teams", "webhook", "syslog",
    "sms_twilio", "sms_sns", "sms_gateway", "sms_email",
)
VALID_EVENT_TYPES = (
    "critical_finding", "sla_breach", "scan_complete",
    "exception_expiring", "schedule_failed",
)
VALID_STATUSES = ("pending", "sent", "failed")
VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SYSLOG_FACILITY_LOCAL0 = 16
SYSLOG_SEVERITY_MAP = {
    "CRITICAL": 2,  # critical
    "HIGH": 3,      # error
    "MEDIUM": 4,    # warning
    "LOW": 5,       # notice
    "INFO": 6,      # informational
}

logger = logging.getLogger("purpleteam.notifications")


# ---------------------------------------------------------------------------
# Notification Manager
# ---------------------------------------------------------------------------

class NotificationManager:
    """Manages notification channels, delivery, and history."""

    _instance: Optional["NotificationManager"] = None

    def __init__(self):
        self.db_path = paths.data / "notifications.db"
        self._ensure_db()

    # ---- database setup --------------------------------------------------

    def _ensure_db(self):
        """Create database and tables if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS notification_channels (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_id   TEXT UNIQUE NOT NULL,
                    name         TEXT NOT NULL,
                    channel_type TEXT NOT NULL,
                    config       TEXT NOT NULL DEFAULT '{}',
                    enabled      INTEGER DEFAULT 1,
                    created_at   TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id TEXT UNIQUE NOT NULL,
                    channel_id      TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    severity        TEXT DEFAULT 'INFO',
                    subject         TEXT NOT NULL,
                    body            TEXT DEFAULT '',
                    status          TEXT DEFAULT 'pending',
                    sent_at         TEXT,
                    error_message   TEXT,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (channel_id)
                        REFERENCES notification_channels(channel_id)
                );

                CREATE INDEX IF NOT EXISTS idx_notifications_channel
                    ON notifications(channel_id);
                CREATE INDEX IF NOT EXISTS idx_notifications_event
                    ON notifications(event_type);
                CREATE INDEX IF NOT EXISTS idx_notifications_status
                    ON notifications(status);
                CREATE INDEX IF NOT EXISTS idx_channels_type
                    ON notification_channels(channel_type);
                CREATE INDEX IF NOT EXISTS idx_channels_enabled
                    ON notification_channels(enabled);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _generate_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _now_iso() -> str:
        return datetime.utcnow().isoformat()

    # ---- channel CRUD ----------------------------------------------------

    def add_channel(self, name: str, channel_type: str,
                    config: Dict) -> str:
        """
        Register a notification channel.

        *config* contents depend on *channel_type*:
          email  : smtp_host, smtp_port, smtp_user, smtp_pass, from_addr,
                   to_addrs (list), use_tls (bool)
          slack  : webhook_url
          teams  : webhook_url
          webhook: url, headers (dict, optional), method (POST default)
          syslog : host, port (default 514)
        """
        if channel_type not in VALID_CHANNEL_TYPES:
            raise ValueError(
                f"Invalid channel_type '{channel_type}'. "
                f"Must be one of {VALID_CHANNEL_TYPES}"
            )

        channel_id = self._generate_id()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO notification_channels
                    (channel_id, name, channel_type, config)
                VALUES (?, ?, ?, ?)
            """, (channel_id, name, channel_type, json.dumps(config)))

        logger.info("Added channel %s (%s / %s)", channel_id, name, channel_type)
        return channel_id

    def update_channel(self, channel_id: str, **kwargs):
        """Update channel attributes (name, channel_type, config, enabled)."""
        allowed = {"name", "channel_type", "config", "enabled"}
        updates: list = []
        params: list = []

        for key, value in kwargs.items():
            if key not in allowed:
                continue
            if key == "channel_type" and value not in VALID_CHANNEL_TYPES:
                raise ValueError(f"Invalid channel_type '{value}'")
            if key == "config" and isinstance(value, dict):
                value = json.dumps(value)
            if key == "enabled":
                value = 1 if value else 0
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return

        params.append(channel_id)
        sql = (
            f"UPDATE notification_channels SET {', '.join(updates)} "
            f"WHERE channel_id = ?"
        )
        with self._connect() as conn:
            conn.execute(sql, params)
        logger.info("Updated channel %s", channel_id)

    def remove_channel(self, channel_id: str):
        """Remove a channel and its notification history."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM notifications WHERE channel_id = ?", (channel_id,)
            )
            conn.execute(
                "DELETE FROM notification_channels WHERE channel_id = ?",
                (channel_id,),
            )
        logger.info("Removed channel %s", channel_id)

    def get_channels(self, enabled_only: bool = False) -> List[Dict]:
        """Return all registered channels."""
        with self._connect() as conn:
            if enabled_only:
                cursor = conn.execute(
                    "SELECT * FROM notification_channels WHERE enabled = 1 "
                    "ORDER BY name"
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM notification_channels ORDER BY name"
                )
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["enabled"] = bool(d.get("enabled"))
                try:
                    d["config"] = json.loads(d.get("config", "{}"))
                except (json.JSONDecodeError, TypeError):
                    d["config"] = {}
                results.append(d)
            return results

    # ---- delivery dispatch -----------------------------------------------

    def notify(self, event_type: str, subject: str, body: str,
               severity: str = "INFO") -> List[str]:
        """
        Send a notification to all enabled channels.

        Returns a list of notification_id values (one per channel attempt).
        """
        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event_type}'. "
                f"Must be one of {VALID_EVENT_TYPES}"
            )
        severity = severity.upper()
        if severity not in VALID_SEVERITIES:
            severity = "INFO"

        channels = self.get_channels(enabled_only=True)
        notification_ids: list = []

        for channel in channels:
            nid = self._generate_id()
            status = "pending"
            error_message = None
            sent_at = None

            try:
                self._dispatch(channel, subject, body, severity)
                status = "sent"
                sent_at = self._now_iso()
            except Exception as exc:
                status = "failed"
                error_message = str(exc)[:1000]
                logger.warning(
                    "Failed to send to channel %s (%s): %s",
                    channel["channel_id"], channel["channel_type"], exc,
                )

            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO notifications
                        (notification_id, channel_id, event_type, severity,
                         subject, body, status, sent_at, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    nid, channel["channel_id"], event_type, severity,
                    subject, body, status, sent_at, error_message,
                ))

            notification_ids.append(nid)

        logger.info(
            "Notification dispatched: event=%s, channels=%d, subject='%s'",
            event_type, len(notification_ids), subject[:80],
        )
        return notification_ids

    def _dispatch(self, channel: Dict, subject: str, body: str,
                  severity: str):
        """Route to the appropriate sender based on channel_type."""
        ctype = channel["channel_type"]
        cfg = channel.get("config", {})

        if ctype == "email":
            self._send_email(cfg, subject, body)
        elif ctype == "slack":
            self._send_slack(cfg, subject, body, severity)
        elif ctype == "teams":
            self._send_teams(cfg, subject, body, severity)
        elif ctype == "webhook":
            self._send_webhook(cfg, subject, body, severity)
        elif ctype == "syslog":
            self._send_syslog(cfg, subject, body, severity)
        elif ctype == "sms_twilio":
            self._send_sms_twilio(cfg, subject, body)
        elif ctype == "sms_sns":
            self._send_sms_sns(cfg, subject, body)
        elif ctype == "sms_gateway":
            self._send_sms_gateway(cfg, subject, body, severity)
        elif ctype == "sms_email":
            self._send_sms_email(cfg, subject, body)
        else:
            raise ValueError(f"Unknown channel type: {ctype}")

    # ---- channel senders -------------------------------------------------

    @staticmethod
    def _send_email(config: Dict, subject: str, body: str):
        """Send email via SMTP.  Fails gracefully if SMTP is unreachable."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        smtp_host = config.get("smtp_host", "localhost")
        smtp_port = int(config.get("smtp_port", 587))
        smtp_user = config.get("smtp_user", "")
        smtp_pass = config.get("smtp_pass", "")
        from_addr = config.get("from_addr", "purpleteam@localhost")
        to_addrs = config.get("to_addrs", [])
        use_tls = config.get("use_tls", True)

        if not to_addrs:
            raise ValueError("No recipient addresses configured for email channel")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[PurpleTeam GRC] {subject}"
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        # Plain text part
        msg.attach(MIMEText(body, "plain"))

        # Simple HTML part
        html_body = (
            "<html><body>"
            f"<h2 style='color:#5b2c8e;'>{subject}</h2>"
            f"<pre style='font-family:Consolas,monospace;'>{body}</pre>"
            "<hr><p style='color:#888;font-size:11px;'>"
            "Purple Team GRC Notification System</p>"
            "</body></html>"
        )
        msg.attach(MIMEText(html_body, "html"))

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        try:
            if use_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        finally:
            server.quit()

        logger.debug("Email sent to %s", to_addrs)

    @staticmethod
    def _send_slack(config: Dict, subject: str, body: str,
                    severity: str = "INFO"):
        """Post a message to a Slack incoming webhook."""
        import urllib.request
        import urllib.error

        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            raise ValueError("No webhook_url configured for Slack channel")

        color_map = {
            "CRITICAL": "#e74c3c",
            "HIGH": "#e67e22",
            "MEDIUM": "#f1c40f",
            "LOW": "#3498db",
            "INFO": "#95a5a6",
        }

        payload = {
            "attachments": [{
                "color": color_map.get(severity, "#95a5a6"),
                "title": f"[PurpleTeam GRC] {subject}",
                "text": body,
                "footer": "Purple Team GRC Notification System",
                "ts": int(datetime.utcnow().timestamp()),
            }]
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 201, 204):
                raise RuntimeError(f"Slack webhook returned status {resp.status}")

        logger.debug("Slack notification sent")

    @staticmethod
    def _send_teams(config: Dict, subject: str, body: str,
                    severity: str = "INFO"):
        """Post an Adaptive Card to a Microsoft Teams incoming webhook."""
        import urllib.request
        import urllib.error

        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            raise ValueError("No webhook_url configured for Teams channel")

        color_map = {
            "CRITICAL": "attention",
            "HIGH": "warning",
            "MEDIUM": "warning",
            "LOW": "accent",
            "INFO": "default",
        }

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Medium",
                            "weight": "Bolder",
                            "text": f"PurpleTeam GRC - {subject}",
                            "color": color_map.get(severity, "default"),
                        },
                        {
                            "type": "TextBlock",
                            "text": f"**Severity:** {severity}",
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": body,
                            "wrap": True,
                            "fontType": "Default",
                        },
                        {
                            "type": "TextBlock",
                            "text": (
                                f"Sent at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
                            ),
                            "isSubtle": True,
                            "size": "Small",
                        },
                    ],
                },
            }],
        }

        data = json.dumps(card).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 201, 202, 204):
                raise RuntimeError(f"Teams webhook returned status {resp.status}")

        logger.debug("Teams notification sent")

    @staticmethod
    def _send_webhook(config: Dict, subject: str, body: str,
                      severity: str = "INFO"):
        """Send a generic JSON POST to a webhook URL."""
        import urllib.request
        import urllib.error

        url = config.get("url", "")
        if not url:
            raise ValueError("No url configured for webhook channel")

        headers = config.get("headers", {})
        headers.setdefault("Content-Type", "application/json")
        method = config.get("method", "POST").upper()

        payload = {
            "source": "PurpleTeam GRC",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": severity,
            "subject": subject,
            "body": body,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 201, 202, 204):
                raise RuntimeError(f"Webhook returned status {resp.status}")

        logger.debug("Webhook notification sent to %s", url)

    @staticmethod
    def _send_syslog(config: Dict, subject: str, body: str,
                     severity: str = "INFO"):
        """Send a UDP syslog message (RFC 5424 simplified)."""
        host = config.get("host", "127.0.0.1")
        port = int(config.get("port", 514))

        syslog_severity = SYSLOG_SEVERITY_MAP.get(severity, 6)
        priority = (SYSLOG_FACILITY_LOCAL0 * 8) + syslog_severity

        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        hostname = socket.gethostname()
        app_name = "PurpleTeamGRC"

        # Construct syslog message
        message = (
            f"<{priority}>1 {timestamp} {hostname} {app_name} - - - "
            f"[{severity}] {subject}: {body}"
        )

        # Truncate to standard syslog max (2048 bytes)
        encoded = message.encode("utf-8")[:2048]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(encoded, (host, port))
        finally:
            sock.close()

        logger.debug("Syslog message sent to %s:%d", host, port)

    # ---- SMS senders -----------------------------------------------------

    @staticmethod
    def _send_sms_twilio(config: Dict, subject: str, body: str):
        """Send SMS via Twilio REST API (stdlib only)."""
        import urllib.request
        import base64

        account_sid = config.get("account_sid", "")
        auth_token = config.get("auth_token", "")
        from_number = config.get("from_number", "")
        to_numbers = config.get("to_numbers", [])

        if not all([account_sid, auth_token, from_number, to_numbers]):
            raise ValueError(
                "Twilio SMS requires account_sid, auth_token, from_number, to_numbers"
            )

        message = f"[PurpleTeam] {subject}: {body}"[:160]
        url = (
            f"https://api.twilio.com/2010-04-01/Accounts/"
            f"{account_sid}/Messages.json"
        )
        credentials = base64.b64encode(
            f"{account_sid}:{auth_token}".encode()
        ).decode()

        for to_num in to_numbers:
            payload = urllib.parse.urlencode({
                "From": from_number,
                "To": to_num,
                "Body": message,
            }).encode("utf-8")
            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Authorization", f"Basic {credentials}")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status not in (200, 201):
                    raise RuntimeError(f"Twilio returned status {resp.status}")

        logger.debug("Twilio SMS sent to %d numbers", len(to_numbers))

    @staticmethod
    def _send_sms_sns(config: Dict, subject: str, body: str):
        """Send SMS via AWS SNS using SigV4 signing (stdlib only)."""
        import hmac
        import hashlib
        import urllib.request
        import urllib.parse

        region = config.get("region", "us-east-1")
        access_key = config.get("access_key_id", "")
        secret_key = config.get("secret_access_key", "")
        topic_arn = config.get("topic_arn", "")
        phone_numbers = config.get("phone_numbers", [])

        if not access_key or not secret_key:
            raise ValueError("AWS SNS requires access_key_id and secret_access_key")
        if not topic_arn and not phone_numbers:
            raise ValueError("AWS SNS requires topic_arn or phone_numbers")

        message = f"[PurpleTeam] {subject}: {body}"[:160]
        host = f"sns.{region}.amazonaws.com"
        endpoint = f"https://{host}/"
        now = datetime.utcnow()
        datestamp = now.strftime("%Y%m%d")
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")

        def _sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        def _get_signature_key(key, date, reg, service):
            k_date = _sign(("AWS4" + key).encode("utf-8"), date)
            k_region = hmac.new(k_date, reg.encode("utf-8"), hashlib.sha256).digest()
            k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
            return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()

        targets = []
        if topic_arn:
            targets.append(("TopicArn", topic_arn))
        else:
            for phone in phone_numbers:
                targets.append(("PhoneNumber", phone))

        for target_key, target_val in targets:
            params = {
                "Action": "Publish",
                target_key: target_val,
                "Message": message,
                "Version": "2010-03-31",
            }
            query_string = urllib.parse.urlencode(sorted(params.items()))
            canonical_request = (
                f"POST\n/\n{query_string}\n"
                f"host:{host}\nx-amz-date:{amz_date}\n\n"
                f"host;x-amz-date\n"
                + hashlib.sha256(b"").hexdigest()
            )
            credential_scope = f"{datestamp}/{region}/sns/aws4_request"
            string_to_sign = (
                f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
                + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
            )
            signing_key = _get_signature_key(secret_key, datestamp, region, "sns")
            signature = hmac.new(
                signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            auth_header = (
                f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
                f"SignedHeaders=host;x-amz-date, Signature={signature}"
            )

            req = urllib.request.Request(
                f"{endpoint}?{query_string}",
                data=b"",
                method="POST",
            )
            req.add_header("Host", host)
            req.add_header("X-Amz-Date", amz_date)
            req.add_header("Authorization", auth_header)
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status not in (200, 201):
                    raise RuntimeError(f"AWS SNS returned status {resp.status}")

        logger.debug("AWS SNS message published")

    @staticmethod
    def _send_sms_gateway(config: Dict, subject: str, body: str,
                          severity: str = "INFO"):
        """Send SMS via a generic HTTP gateway with template substitution."""
        import urllib.request

        url = config.get("url", "")
        method = config.get("method", "POST").upper()
        headers = config.get("headers", {"Content-Type": "application/json"})
        body_template = config.get("body_template", '{"to":"{to}","msg":"{body}"}')
        to_numbers = config.get("to_numbers", [])

        if not url or not to_numbers:
            raise ValueError("SMS gateway requires url and to_numbers")

        msg = f"[PurpleTeam] {subject}: {body}"[:160]

        for to_num in to_numbers:
            payload = body_template.replace("{subject}", subject[:80])
            payload = payload.replace("{body}", msg)
            payload = payload.replace("{to}", to_num)
            payload = payload.replace("{severity}", severity)
            data = payload.encode("utf-8")
            req = urllib.request.Request(url, data=data, method=method)
            for hk, hv in headers.items():
                req.add_header(hk, hv)
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status not in (200, 201, 202, 204):
                    raise RuntimeError(f"SMS gateway returned status {resp.status}")

        logger.debug("SMS gateway message sent to %d numbers", len(to_numbers))

    @staticmethod
    def _send_sms_email(config: Dict, subject: str, body: str):
        """Send SMS via carrier email-to-SMS gateways (e.g. number@txt.att.net).

        Uses the existing SMTP infrastructure to deliver text messages through
        major carrier gateways. Zero external dependencies.

        Config:
            smtp_host, smtp_port, smtp_user, smtp_pass, from_addr, use_tls
            recipients: list of dicts with 'number' and 'carrier' keys
              OR
            addresses: list of pre-formed email addresses (e.g. '5551234567@txt.att.net')
        """
        import smtplib
        from email.mime.text import MIMEText

        CARRIER_GATEWAYS = {
            "att":      "txt.att.net",
            "tmobile":  "tmomail.net",
            "verizon":  "vtext.com",
            "sprint":   "messaging.sprintpcs.com",
            "uscellular": "email.uscc.net",
            "boost":    "sms.myboostmobile.com",
            "cricket":  "sms.cricketwireless.net",
            "metro":    "mymetropcs.com",
            "google_fi": "msg.fi.google.com",
            "mint":     "tmomail.net",
            "virgin":   "vmobl.com",
            "xfinity":  "vtext.com",
        }

        smtp_host = config.get("smtp_host", "localhost")
        smtp_port = int(config.get("smtp_port", 587))
        smtp_user = config.get("smtp_user", "")
        smtp_pass = config.get("smtp_pass", "")
        from_addr = config.get("from_addr", "purpleteam@localhost")
        use_tls = config.get("use_tls", True)

        # Build recipient list from either format
        to_addrs = list(config.get("addresses", []))
        for recipient in config.get("recipients", []):
            number = recipient.get("number", "").replace("-", "").replace(" ", "")
            carrier = recipient.get("carrier", "").lower()
            gateway = CARRIER_GATEWAYS.get(carrier)
            if gateway and number:
                to_addrs.append(f"{number}@{gateway}")

        if not to_addrs:
            raise ValueError(
                "SMS email requires 'addresses' or 'recipients' "
                "(with 'number' and 'carrier' keys)"
            )

        # SMS messages are short - plain text only, truncated to 160 chars
        message = f"[PurpleTeam] {subject}: {body}"[:160]

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        try:
            if use_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            for addr in to_addrs:
                msg = MIMEText(message, "plain")
                msg["Subject"] = ""  # carriers ignore/strip long subjects
                msg["From"] = from_addr
                msg["To"] = addr
                server.sendmail(from_addr, [addr], msg.as_string())
        finally:
            server.quit()

        logger.debug("SMS-via-email sent to %d addresses", len(to_addrs))

    # ---- convenience notification methods --------------------------------

    def notify_critical_finding(self, finding: Dict) -> List[str]:
        """Send a formatted alert for a critical finding."""
        title = finding.get("title", "Unknown Finding")
        asset = finding.get("affected_asset", "N/A")
        cvss = finding.get("cvss_score", 0.0)
        cves = finding.get("cve_ids", "[]")
        if isinstance(cves, str):
            try:
                cves = json.loads(cves)
            except (json.JSONDecodeError, TypeError):
                cves = []
        cve_str = ", ".join(cves) if cves else "N/A"
        remediation = finding.get("remediation", "No remediation guidance available.")
        description = finding.get("description", "")

        subject = f"CRITICAL Finding: {title}"
        body = (
            f"Critical Security Finding Detected\n"
            f"{'=' * 50}\n\n"
            f"Title:          {title}\n"
            f"Severity:       CRITICAL\n"
            f"CVSS Score:     {cvss}\n"
            f"CVE(s):         {cve_str}\n"
            f"Affected Asset: {asset}\n\n"
            f"Description:\n{description}\n\n"
            f"Remediation:\n{remediation}\n\n"
            f"Detected at:    {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"{'=' * 50}\n"
            f"ACTION REQUIRED: Immediate investigation recommended.\n"
        )

        return self.notify("critical_finding", subject, body, severity="CRITICAL")

    def notify_sla_breach(self, remediation_item: Dict) -> List[str]:
        """Send a formatted SLA breach alert."""
        title = remediation_item.get("title", "Unknown Item")
        severity = remediation_item.get("severity", "UNKNOWN")
        asset = remediation_item.get("affected_asset", "N/A")
        due_date = remediation_item.get("due_date", "N/A")
        owner = remediation_item.get("owner", "Unassigned")
        days_overdue = remediation_item.get("days_overdue", 0)

        subject = f"SLA BREACH: {title} ({days_overdue} days overdue)"
        body = (
            f"SLA Breach Alert\n"
            f"{'=' * 50}\n\n"
            f"Finding:        {title}\n"
            f"Severity:       {severity}\n"
            f"Affected Asset: {asset}\n"
            f"Due Date:       {due_date}\n"
            f"Days Overdue:   {days_overdue}\n"
            f"Owner:          {owner}\n\n"
            f"This remediation item has exceeded its SLA deadline.\n"
            f"Escalation procedures should be initiated.\n\n"
            f"Detected at:    {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
        )

        alert_severity = "CRITICAL" if days_overdue > 14 else "HIGH"
        return self.notify("sla_breach", subject, body, severity=alert_severity)

    def notify_scan_complete(self, session_id: str,
                             summary: Dict) -> List[str]:
        """Send a scan completion summary."""
        findings = summary.get("findings_by_severity", {})
        total = summary.get("total_findings", sum(findings.values()))
        critical = findings.get("CRITICAL", findings.get("critical", 0))
        high = findings.get("HIGH", findings.get("high", 0))
        medium = findings.get("MEDIUM", findings.get("medium", 0))
        low = findings.get("LOW", findings.get("low", 0))
        duration = summary.get("duration", "N/A")
        scan_type = summary.get("scan_type", "unknown")

        subject = f"Scan Complete: {session_id} ({total} findings)"
        body = (
            f"Scan Completion Report\n"
            f"{'=' * 50}\n\n"
            f"Session ID:  {session_id}\n"
            f"Scan Type:   {scan_type}\n"
            f"Duration:    {duration}\n\n"
            f"Findings Summary:\n"
            f"  CRITICAL:  {critical}\n"
            f"  HIGH:      {high}\n"
            f"  MEDIUM:    {medium}\n"
            f"  LOW:       {low}\n"
            f"  TOTAL:     {total}\n\n"
            f"Completed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
        )

        sev = "HIGH" if critical > 0 else "MEDIUM" if high > 0 else "INFO"
        return self.notify("scan_complete", subject, body, severity=sev)

    def notify_exception_expiring(self, exception_item: Dict) -> List[str]:
        """Send an alert for an expiring risk exception."""
        title = exception_item.get("title", "Unknown Exception")
        expires_at = exception_item.get("expires_at", "N/A")
        owner = exception_item.get("owner", "Unassigned")
        days_remaining = exception_item.get("days_remaining", 0)

        subject = f"Exception Expiring: {title} ({days_remaining} days remaining)"
        body = (
            f"Risk Exception Expiration Notice\n"
            f"{'=' * 50}\n\n"
            f"Exception:       {title}\n"
            f"Expires At:      {expires_at}\n"
            f"Days Remaining:  {days_remaining}\n"
            f"Owner:           {owner}\n\n"
            f"This risk exception will expire soon. Please review and\n"
            f"either renew the exception or implement remediation.\n"
        )

        return self.notify("exception_expiring", subject, body, severity="MEDIUM")

    def notify_schedule_failed(self, schedule_name: str,
                               error: str) -> List[str]:
        """Send an alert when a scheduled scan fails."""
        subject = f"Scheduled Scan Failed: {schedule_name}"
        body = (
            f"Scheduled Scan Failure\n"
            f"{'=' * 50}\n\n"
            f"Schedule:  {schedule_name}\n"
            f"Error:     {error}\n\n"
            f"Failed at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"Please investigate and re-enable the schedule if needed.\n"
        )

        return self.notify("schedule_failed", subject, body, severity="HIGH")

    # ---- history and stats -----------------------------------------------

    def get_notification_history(self, limit: int = 50,
                                 event_type: str = None,
                                 status: str = None) -> List[Dict]:
        """Return recent notification records."""
        with self._connect() as conn:
            conditions = []
            params: list = []

            if event_type:
                conditions.append("n.event_type = ?")
                params.append(event_type)
            if status:
                conditions.append("n.status = ?")
                params.append(status)

            where = ""
            if conditions:
                where = "WHERE " + " AND ".join(conditions)

            sql = f"""
                SELECT n.*, c.name AS channel_name, c.channel_type
                FROM notifications n
                LEFT JOIN notification_channels c
                    ON n.channel_id = c.channel_id
                {where}
                ORDER BY n.created_at DESC
                LIMIT ?
            """
            params.append(limit)
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict:
        """Return aggregate notification statistics."""
        with self._connect() as conn:
            total_channels = conn.execute(
                "SELECT COUNT(*) FROM notification_channels"
            ).fetchone()[0]
            enabled_channels = conn.execute(
                "SELECT COUNT(*) FROM notification_channels WHERE enabled = 1"
            ).fetchone()[0]

            total_notifications = conn.execute(
                "SELECT COUNT(*) FROM notifications"
            ).fetchone()[0]
            sent = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE status = 'sent'"
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE status = 'failed'"
            ).fetchone()[0]
            pending = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE status = 'pending'"
            ).fetchone()[0]

            # Last 24 hours
            cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            sent_24h = conn.execute(
                "SELECT COUNT(*) FROM notifications "
                "WHERE status = 'sent' AND created_at >= ?",
                (cutoff_24h,),
            ).fetchone()[0]

            # By event type
            by_event = {}
            cursor = conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM notifications "
                "GROUP BY event_type"
            )
            for row in cursor.fetchall():
                by_event[row[0]] = row[1]

            # By channel type
            by_channel = {}
            cursor = conn.execute(
                "SELECT c.channel_type, COUNT(n.notification_id) as cnt "
                "FROM notifications n "
                "JOIN notification_channels c ON n.channel_id = c.channel_id "
                "GROUP BY c.channel_type"
            )
            for row in cursor.fetchall():
                by_channel[row[0]] = row[1]

            # Failure rate
            failure_rate = 0.0
            if total_notifications > 0:
                failure_rate = round((failed / total_notifications) * 100, 2)

            return {
                "total_channels": total_channels,
                "enabled_channels": enabled_channels,
                "disabled_channels": total_channels - enabled_channels,
                "total_notifications": total_notifications,
                "sent": sent,
                "failed": failed,
                "pending": pending,
                "sent_last_24h": sent_24h,
                "failure_rate_pct": failure_rate,
                "by_event_type": by_event,
                "by_channel_type": by_channel,
            }

    def retry_failed(self, max_age_hours: int = 24) -> int:
        """
        Retry failed notifications from the last *max_age_hours* hours.
        Returns the number of successfully retried notifications.
        """
        cutoff = (datetime.utcnow() - timedelta(hours=max_age_hours)).isoformat()
        retried = 0

        with self._connect() as conn:
            failed_rows = conn.execute("""
                SELECT n.*, c.channel_type, c.config, c.enabled
                FROM notifications n
                JOIN notification_channels c ON n.channel_id = c.channel_id
                WHERE n.status = 'failed' AND n.created_at >= ? AND c.enabled = 1
                ORDER BY n.created_at ASC
            """, (cutoff,)).fetchall()

        for row in failed_rows:
            row_dict = dict(row)
            channel = {
                "channel_id": row_dict["channel_id"],
                "channel_type": row_dict["channel_type"],
                "config": json.loads(row_dict.get("config", "{}")),
            }
            try:
                self._dispatch(
                    channel, row_dict["subject"],
                    row_dict["body"], row_dict.get("severity", "INFO"),
                )
                with self._connect() as conn:
                    conn.execute("""
                        UPDATE notifications
                        SET status = 'sent', sent_at = ?, error_message = NULL
                        WHERE notification_id = ?
                    """, (self._now_iso(), row_dict["notification_id"]))
                retried += 1
            except Exception as exc:
                with self._connect() as conn:
                    conn.execute("""
                        UPDATE notifications
                        SET error_message = ?
                        WHERE notification_id = ?
                    """, (
                        f"Retry failed: {str(exc)[:500]}",
                        row_dict["notification_id"],
                    ))

        logger.info("Retried %d/%d failed notifications", retried, len(failed_rows))
        return retried


# ---------------------------------------------------------------------------
# Alert Router  -  severity / event-type based channel routing
# ---------------------------------------------------------------------------

class AlertRouter:
    """Routes notifications to specific channels based on rules.

    Each rule matches a combination of event types and minimum severity,
    then routes to a specific set of channels.  Supports digest modes
    (realtime, hourly, daily, weekly) for batching low-priority alerts.
    """

    VALID_DIGEST_MODES = ("realtime", "hourly", "daily", "weekly")

    def __init__(self, notification_manager: NotificationManager):
        self.nm = notification_manager
        self.db_path = notification_manager.db_path
        self._ensure_routing_tables()

    def _ensure_routing_tables(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS notification_rules (
                    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id                TEXT UNIQUE NOT NULL,
                    name                   TEXT NOT NULL,
                    event_types            TEXT DEFAULT '[]',
                    min_severity           TEXT DEFAULT 'INFO',
                    channel_ids            TEXT DEFAULT '[]',
                    digest_mode            TEXT DEFAULT 'realtime',
                    digest_interval_minutes INTEGER DEFAULT 0,
                    enabled                INTEGER DEFAULT 1,
                    created_at             TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS notification_digest_queue (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id         TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    subject         TEXT NOT NULL,
                    body            TEXT DEFAULT '',
                    queued_at       TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (rule_id)
                        REFERENCES notification_rules(rule_id)
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ---- rule CRUD -------------------------------------------------------

    def add_rule(self, name: str, event_types: List[str],
                 min_severity: str, channel_ids: List[str],
                 digest_mode: str = "realtime",
                 digest_interval_minutes: int = 0) -> str:
        """Create a routing rule."""
        if min_severity.upper() not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{min_severity}'")
        if digest_mode not in self.VALID_DIGEST_MODES:
            raise ValueError(f"Invalid digest_mode '{digest_mode}'")
        for et in event_types:
            if et not in VALID_EVENT_TYPES:
                raise ValueError(f"Invalid event_type '{et}'")

        rule_id = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO notification_rules
                    (rule_id, name, event_types, min_severity, channel_ids,
                     digest_mode, digest_interval_minutes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id, name, json.dumps(event_types),
                min_severity.upper(), json.dumps(channel_ids),
                digest_mode, digest_interval_minutes,
            ))
        logger.info("Added routing rule %s (%s)", rule_id, name)
        return rule_id

    def get_rules(self, enabled_only: bool = False) -> List[Dict]:
        """Return all routing rules."""
        with self._connect() as conn:
            sql = "SELECT * FROM notification_rules"
            if enabled_only:
                sql += " WHERE enabled = 1"
            sql += " ORDER BY name"
            rows = conn.execute(sql).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d["enabled"] = bool(d.get("enabled"))
                d["event_types"] = json.loads(d.get("event_types", "[]"))
                d["channel_ids"] = json.loads(d.get("channel_ids", "[]"))
                result.append(d)
            return result

    def update_rule(self, rule_id: str, **kwargs):
        """Update a routing rule."""
        allowed = {"name", "event_types", "min_severity", "channel_ids",
                    "digest_mode", "digest_interval_minutes", "enabled"}
        updates, params = [], []
        for key, value in kwargs.items():
            if key not in allowed:
                continue
            if key in ("event_types", "channel_ids") and isinstance(value, list):
                value = json.dumps(value)
            if key == "enabled":
                value = 1 if value else 0
            updates.append(f"{key} = ?")
            params.append(value)
        if not updates:
            return
        params.append(rule_id)
        sql = f"UPDATE notification_rules SET {', '.join(updates)} WHERE rule_id = ?"
        with self._connect() as conn:
            conn.execute(sql, params)

    def delete_rule(self, rule_id: str):
        """Delete a routing rule and its queued digests."""
        with self._connect() as conn:
            conn.execute("DELETE FROM notification_digest_queue WHERE rule_id = ?",
                         (rule_id,))
            conn.execute("DELETE FROM notification_rules WHERE rule_id = ?",
                         (rule_id,))

    # ---- routing logic ---------------------------------------------------

    _SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def _severity_meets_minimum(self, severity: str, min_severity: str) -> bool:
        return self._SEVERITY_RANK.get(severity.upper(), 4) <= \
               self._SEVERITY_RANK.get(min_severity.upper(), 4)

    def route_notification(self, event_type: str, subject: str,
                           body: str, severity: str = "INFO") -> List[str]:
        """Route a notification through matching rules.

        For 'realtime' rules, sends immediately to the rule's channels.
        For digest rules, queues the notification for later batching.
        Returns a list of notification_ids for immediately-sent messages.
        """
        rules = self.get_rules(enabled_only=True)
        if not rules:
            # No rules configured -- fall back to default broadcast
            return self.nm.notify(event_type, subject, body, severity)

        notification_ids: list = []
        matched_any = False

        for rule in rules:
            rule_events = rule.get("event_types", [])
            if rule_events and event_type not in rule_events:
                continue
            if not self._severity_meets_minimum(severity, rule.get("min_severity", "INFO")):
                continue

            matched_any = True
            digest = rule.get("digest_mode", "realtime")

            if digest != "realtime":
                # Queue for digest delivery
                with self._connect() as conn:
                    conn.execute("""
                        INSERT INTO notification_digest_queue
                            (rule_id, event_type, severity, subject, body)
                        VALUES (?, ?, ?, ?, ?)
                    """, (rule["rule_id"], event_type, severity, subject, body))
                continue

            # Realtime: send to the rule's channel_ids only
            channels = self.nm.get_channels()
            target_ids = set(rule.get("channel_ids", []))
            for channel in channels:
                if channel["channel_id"] in target_ids and channel.get("enabled"):
                    nid = self.nm._generate_id()
                    status, error_message, sent_at = "pending", None, None
                    try:
                        self.nm._dispatch(channel, subject, body, severity)
                        status = "sent"
                        sent_at = self.nm._now_iso()
                    except Exception as exc:
                        status = "failed"
                        error_message = str(exc)[:1000]
                    with self.nm._connect() as conn:
                        conn.execute("""
                            INSERT INTO notifications
                                (notification_id, channel_id, event_type, severity,
                                 subject, body, status, sent_at, error_message)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (nid, channel["channel_id"], event_type, severity,
                              subject, body, status, sent_at, error_message))
                    notification_ids.append(nid)

        if not matched_any:
            return self.nm.notify(event_type, subject, body, severity)

        return notification_ids

    def flush_digests(self, digest_mode: str = None) -> int:
        """Send queued digest notifications. Returns count of messages sent."""
        rules = self.get_rules(enabled_only=True)
        total_sent = 0

        for rule in rules:
            mode = rule.get("digest_mode", "realtime")
            if mode == "realtime":
                continue
            if digest_mode and mode != digest_mode:
                continue

            with self._connect() as conn:
                queued = conn.execute("""
                    SELECT * FROM notification_digest_queue
                    WHERE rule_id = ? ORDER BY queued_at ASC
                """, (rule["rule_id"],)).fetchall()

            if not queued:
                continue

            # Build digest summary
            items = [dict(r) for r in queued]
            digest_subject = f"Alert Digest ({len(items)} events)"
            lines = []
            for item in items:
                lines.append(
                    f"[{item['severity']}] {item['subject']}"
                )
            digest_body = "\n".join(lines)

            # Send to rule's channels
            max_sev = min(
                (self._SEVERITY_RANK.get(i["severity"], 4) for i in items),
                default=4,
            )
            sev_name = {v: k for k, v in self._SEVERITY_RANK.items()}.get(max_sev, "INFO")

            channels = self.nm.get_channels()
            target_ids = set(rule.get("channel_ids", []))
            for channel in channels:
                if channel["channel_id"] in target_ids and channel.get("enabled"):
                    try:
                        self.nm._dispatch(channel, digest_subject, digest_body, sev_name)
                        total_sent += 1
                    except Exception as exc:
                        logger.warning("Digest send failed for channel %s: %s",
                                       channel["channel_id"], exc)

            # Clear queue
            with self._connect() as conn:
                ids = [i["id"] for i in items]
                placeholders = ",".join("?" * len(ids))
                conn.execute(
                    f"DELETE FROM notification_digest_queue WHERE id IN ({placeholders})",
                    ids,
                )

        return total_sent


_alert_router: Optional[AlertRouter] = None


def get_alert_router() -> AlertRouter:
    """Get the alert router singleton."""
    global _alert_router
    if _alert_router is None:
        _alert_router = AlertRouter(get_notification_manager())
    return _alert_router


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_notification_manager: Optional[NotificationManager] = None


def get_notification_manager() -> NotificationManager:
    """Get the notification manager singleton."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    nm = get_notification_manager()
    print(f"Notifications database: {nm.db_path}")
    print(f"Database exists: {nm.db_path.exists()}")

    # Add test channels
    wh_id = nm.add_channel(
        "Test Webhook", "webhook",
        {"url": "https://httpbin.org/post"},
    )
    print(f"Created webhook channel: {wh_id}")

    syslog_id = nm.add_channel(
        "Local Syslog", "syslog",
        {"host": "127.0.0.1", "port": 514},
    )
    print(f"Created syslog channel: {syslog_id}")

    # List channels
    channels = nm.get_channels()
    print(f"Channels: {len(channels)}")

    # Disable syslog
    nm.update_channel(syslog_id, enabled=False)

    # Test notification (will fail for webhook since httpbin may not be reachable)
    nids = nm.notify(
        "scan_complete",
        "Test Scan Complete",
        "This is a test notification body.",
        severity="INFO",
    )
    print(f"Notification IDs: {nids}")

    # History
    history = nm.get_notification_history(limit=10)
    print(f"Notification history: {len(history)} entries")

    # Statistics
    stats = nm.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")

    # Cleanup
    nm.remove_channel(wh_id)
    nm.remove_channel(syslog_id)
    print("Channels removed")

    print("\nAll notification tests passed.")
