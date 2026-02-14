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

VALID_CHANNEL_TYPES = ("email", "slack", "teams", "webhook", "syslog")
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
