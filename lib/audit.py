#!/usr/bin/env python3
"""
Purple Team GRC Platform - Audit Trail Module
Immutable audit log for every significant platform action, with full-text
search, activity summaries, CSV/JSON export, and retention management.
"""

import csv
import io
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('audit')


VALID_ACTIONS = (
    'scan_started', 'scan_completed',
    'finding_created', 'finding_updated',
    'remediation_created', 'remediation_updated',
    'config_changed',
    'export_performed',
    'user_login', 'user_logout',
    'risk_created', 'risk_updated',
    'exception_created',
    'asset_created', 'asset_updated',
    'system_event',
)

VALID_TARGET_TYPES = (
    'scan', 'finding', 'asset', 'remediation', 'risk',
    'config', 'export', 'session', 'system',
)


class AuditTrail:
    """Append-mostly audit log backed by SQLite."""

    _instance: Optional['AuditTrail'] = None

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_path = paths.data / 'audit.db'
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    actor       TEXT DEFAULT 'system',
                    target_type TEXT,
                    target_id   TEXT,
                    details     TEXT DEFAULT '{}',
                    ip_address  TEXT,
                    session_id  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_al_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_al_action ON audit_log(action);
                CREATE INDEX IF NOT EXISTS idx_al_actor ON audit_log(actor);
                CREATE INDEX IF NOT EXISTS idx_al_target ON audit_log(target_type, target_id);
                CREATE INDEX IF NOT EXISTS idx_al_session ON audit_log(session_id);
            ''')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        d = dict(row)
        if 'details' in d and isinstance(d['details'], str):
            try:
                d['details'] = json.loads(d['details'])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    def _get_local_ip(self) -> str:
        """Best-effort local IP for the ip_address field."""
        try:
            import socket
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return '127.0.0.1'

    # ------------------------------------------------------------------
    # Core logging
    # ------------------------------------------------------------------
    def log(
        self,
        action: str,
        actor: str = 'system',
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Any] = None,
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """
        Append an entry to the audit log.

        Parameters:
            action      - What happened (see VALID_ACTIONS).
            actor       - Who performed the action (username or 'system').
            target_type - The kind of object affected.
            target_id   - Identifier of the affected object.
            details     - Arbitrary JSON-serialisable context.
            ip_address  - Source IP (auto-detected if omitted).
            session_id  - Optional scan session ID for correlation.
        """
        if ip_address is None:
            ip_address = self._get_local_ip()

        details_json = json.dumps(details) if details is not None else '{}'

        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_log "
                "(timestamp, action, actor, target_type, target_id, "
                "details, ip_address, session_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self._now(), action, actor, target_type,
                    target_id, details_json, ip_address, session_id,
                ),
            )

        logger.debug(f"Audit: {action} by {actor} on {target_type}/{target_id}")

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------
    def get_log(
        self,
        limit: int = 100,
        offset: int = 0,
        action: Optional[str] = None,
        actor: Optional[str] = None,
        target_type: Optional[str] = None,
        since: Optional[str] = None,
    ) -> List[Dict]:
        """
        Query the audit log with optional filters.

        Parameters:
            limit       - Max rows to return.
            offset      - Row offset for pagination.
            action      - Filter by action type.
            actor       - Filter by actor.
            target_type - Filter by target type.
            since       - ISO-8601 timestamp lower bound.
        """
        clauses: List[str] = []
        params: list = []

        if action:
            clauses.append("action = ?")
            params.append(action)
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        sql = (f"SELECT * FROM audit_log{where} "
               "ORDER BY timestamp DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Activity summary
    # ------------------------------------------------------------------
    def get_activity_summary(self, days: int = 30) -> Dict:
        """
        Summarise audit activity over the last *days* days.

        Returns dict with:
            by_action  - {action: count}
            by_actor   - {actor: count}
            by_day     - [{date, count}, ...]
        """
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        summary: Dict[str, Any] = {
            'period_days': days,
            'by_action': {},
            'by_actor': {},
            'by_day': [],
        }

        with self._conn() as conn:
            # By action
            for r in conn.execute(
                "SELECT action, COUNT(*) AS cnt FROM audit_log "
                "WHERE timestamp >= ? GROUP BY action ORDER BY cnt DESC",
                (cutoff,),
            ):
                summary['by_action'][r['action']] = r['cnt']

            # By actor
            for r in conn.execute(
                "SELECT actor, COUNT(*) AS cnt FROM audit_log "
                "WHERE timestamp >= ? GROUP BY actor ORDER BY cnt DESC",
                (cutoff,),
            ):
                summary['by_actor'][r['actor']] = r['cnt']

            # By day  (SQLite date() extracts YYYY-MM-DD from ISO timestamp)
            for r in conn.execute(
                "SELECT date(timestamp) AS day, COUNT(*) AS cnt "
                "FROM audit_log WHERE timestamp >= ? "
                "GROUP BY day ORDER BY day ASC",
                (cutoff,),
            ):
                summary['by_day'].append({'date': r['day'], 'count': r['cnt']})

        return summary

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------
    def search(self, query: str, limit: int = 100) -> List[Dict]:
        """
        Full-text search across the details JSON and action/actor fields.
        Uses LIKE for broad compatibility (no FTS extension required).
        """
        pattern = f"%{query}%"
        sql = (
            "SELECT * FROM audit_log "
            "WHERE details LIKE ? OR action LIKE ? OR actor LIKE ? "
            "OR target_id LIKE ? "
            "ORDER BY timestamp DESC LIMIT ?"
        )
        with self._conn() as conn:
            rows = conn.execute(sql, (pattern, pattern, pattern, pattern, limit)).fetchall()
            return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_log(self, filepath: str, format: str = 'csv'):
        """
        Export the full audit log to a file.

        Supported formats: 'csv', 'json'.
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        entries = self.get_log(limit=1_000_000, offset=0)

        if format == 'json':
            with open(filepath, 'w', encoding='utf-8') as fh:
                json.dump(entries, fh, indent=2, default=str)
        else:
            # Default to CSV
            columns = [
                'log_id', 'timestamp', 'action', 'actor', 'target_type',
                'target_id', 'details', 'ip_address', 'session_id',
            ]
            with open(filepath, 'w', newline='', encoding='utf-8') as fh:
                writer = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
                writer.writeheader()
                for entry in entries:
                    row = dict(entry)
                    # Serialise details back to string for CSV column
                    if isinstance(row.get('details'), (dict, list)):
                        row['details'] = json.dumps(row['details'])
                    writer.writerow(row)

        logger.info(f"Exported {len(entries)} audit entries to {filepath} ({format})")

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> Dict:
        """High-level audit trail statistics."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

            oldest_row = conn.execute(
                "SELECT timestamp FROM audit_log ORDER BY timestamp ASC LIMIT 1"
            ).fetchone()
            newest_row = conn.execute(
                "SELECT timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()

            unique_actors = conn.execute(
                "SELECT COUNT(DISTINCT actor) FROM audit_log"
            ).fetchone()[0]
            unique_actions = conn.execute(
                "SELECT COUNT(DISTINCT action) FROM audit_log"
            ).fetchone()[0]

        return {
            'total_entries': total,
            'oldest_entry': oldest_row['timestamp'] if oldest_row else None,
            'newest_entry': newest_row['timestamp'] if newest_row else None,
            'unique_actors': unique_actors,
            'unique_actions': unique_actions,
            'summary_30d': self.get_activity_summary(days=30),
        }

    # ------------------------------------------------------------------
    # Retention / purge
    # ------------------------------------------------------------------
    def purge_old(self, days: int = 365) -> int:
        """
        Delete audit log entries older than *days* days.

        Returns:
            Number of entries deleted.
        """
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?", (cutoff,)
            )
            deleted = cursor.rowcount

        logger.info(f"Purged {deleted} audit entries older than {days} days")
        return deleted


# ======================================================================
# Singleton accessor
# ======================================================================
_audit_trail: Optional[AuditTrail] = None


def get_audit_trail() -> AuditTrail:
    """Get the AuditTrail singleton."""
    global _audit_trail
    if _audit_trail is None:
        _audit_trail = AuditTrail()
    return _audit_trail


# ======================================================================
# Self-test
# ======================================================================
if __name__ == '__main__':
    at = get_audit_trail()
    print(f"Audit DB: {at.db_path}")
    print(f"DB exists: {at.db_path.exists()}")

    # Log some events
    at.log('scan_started', actor='admin', target_type='scan',
           target_id='SESSION-001', details={'networks': ['10.0.0.0/24']})
    at.log('finding_created', actor='scanner', target_type='finding',
           target_id='FND-001', details={'severity': 'high', 'title': 'SQL Injection'})
    at.log('remediation_updated', actor='alice', target_type='remediation',
           target_id='REM-001', details={'old_status': 'open', 'new_status': 'in_progress'})
    at.log('config_changed', actor='admin', target_type='config',
           details={'key': 'stealth_level', 'old': 3, 'new': 5})
    at.log('export_performed', actor='auditor', target_type='export',
           details={'format': 'csv', 'rows': 150})
    print("Logged 5 sample events")

    # Query
    recent = at.get_log(limit=10)
    print(f"Recent entries: {len(recent)}")

    # Search
    results = at.search('SQL')
    print(f"Search 'SQL': {len(results)} results")

    # Summary
    summary = at.get_activity_summary(days=7)
    print(f"Activity summary (7d): {json.dumps(summary, indent=2)}")

    # Statistics
    stats = at.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
