#!/usr/bin/env python3
"""
Purple Team GRC Platform - Remediation Tracking Module
Tracks remediation items, SLA compliance, assignment workflow,
and provides MTTR / resolution-rate metrics with full audit history.
"""

import json
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

logger = get_logger('remediation')


# SLA defaults (calendar days) by severity
_SLA_MAP = {
    'critical': 3,
    'high': 7,
    'medium': 30,
    'low': 90,
}

VALID_STATUSES = (
    'open', 'in_progress', 'resolved', 'verified', 'closed', 'deferred',
)
VALID_PRIORITIES = ('P1', 'P2', 'P3', 'P4')


class RemediationTracker:
    """Manages remediation items with SLA tracking and audit history."""

    _instance: Optional['RemediationTracker'] = None

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

        self.db_path = paths.data / 'remediation.db'
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS remediation_items (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id         TEXT UNIQUE NOT NULL,
                    finding_id      TEXT,
                    asset_id        TEXT,
                    title           TEXT NOT NULL,
                    description     TEXT,
                    severity        TEXT NOT NULL,
                    assigned_to     TEXT,
                    status          TEXT DEFAULT 'open',
                    priority        TEXT DEFAULT 'P3',
                    sla_days        INTEGER,
                    due_date        TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    resolved_at     TEXT,
                    verified_at     TEXT,
                    resolution_notes TEXT,
                    ticket_ref      TEXT
                );

                CREATE TABLE IF NOT EXISTS remediation_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    history_id  TEXT UNIQUE NOT NULL,
                    item_id     TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    old_value   TEXT,
                    new_value   TEXT,
                    changed_by  TEXT DEFAULT 'system',
                    changed_at  TEXT NOT NULL,
                    FOREIGN KEY (item_id) REFERENCES remediation_items(item_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ri_status ON remediation_items(status);
                CREATE INDEX IF NOT EXISTS idx_ri_severity ON remediation_items(severity);
                CREATE INDEX IF NOT EXISTS idx_ri_assigned ON remediation_items(assigned_to);
                CREATE INDEX IF NOT EXISTS idx_ri_due ON remediation_items(due_date);
                CREATE INDEX IF NOT EXISTS idx_ri_finding ON remediation_items(finding_id);
                CREATE INDEX IF NOT EXISTS idx_rh_item ON remediation_history(item_id);
            ''')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _generate_id(self, prefix: str = 'REM') -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"

    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        return dict(row)

    def _compute_sla(self, severity: str) -> int:
        """Return SLA days for the given severity."""
        return _SLA_MAP.get(severity.lower(), 30)

    def _compute_due(self, created_at: str, sla_days: int) -> str:
        """Compute the due date from creation time + SLA days."""
        dt = datetime.fromisoformat(created_at)
        return (dt + timedelta(days=sla_days)).isoformat()

    def _record_history(self, conn: sqlite3.Connection, item_id: str,
                        action: str, old_value: str = '',
                        new_value: str = '', changed_by: str = 'system'):
        """Insert a row into remediation_history."""
        conn.execute(
            "INSERT INTO remediation_history "
            "(history_id, item_id, action, old_value, new_value, changed_by, changed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._generate_id('HIST'), item_id, action,
             old_value, new_value, changed_by, self._now()),
        )

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------
    def create_item(self, finding_id: str, title: str, severity: str,
                    **kwargs) -> str:
        """
        Create a new remediation item.

        Returns:
            item_id (str)
        """
        now = self._now()
        item_id = self._generate_id('REM')
        sla_days = kwargs.get('sla_days') or self._compute_sla(severity)
        due_date = kwargs.get('due_date') or self._compute_due(now, sla_days)

        with self._conn() as conn:
            conn.execute('''
                INSERT INTO remediation_items
                (item_id, finding_id, asset_id, title, description, severity,
                 assigned_to, status, priority, sla_days, due_date,
                 created_at, updated_at, resolution_notes, ticket_ref)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item_id,
                finding_id,
                kwargs.get('asset_id'),
                title,
                kwargs.get('description', ''),
                severity.lower(),
                kwargs.get('assigned_to'),
                kwargs.get('status', 'open'),
                kwargs.get('priority', 'P3'),
                sla_days,
                due_date,
                now,
                now,
                kwargs.get('resolution_notes'),
                kwargs.get('ticket_ref'),
            ))
            self._record_history(conn, item_id, 'created',
                                 new_value=f"severity={severity}",
                                 changed_by=kwargs.get('changed_by', 'system'))

        logger.info(f"Created remediation item {item_id}: {title}")
        return item_id

    # ------------------------------------------------------------------
    # Assign
    # ------------------------------------------------------------------
    def assign(self, item_id: str, assigned_to: str,
               changed_by: str = 'system'):
        """Assign (or reassign) a remediation item."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT assigned_to FROM remediation_items WHERE item_id = ?",
                (item_id,),
            ).fetchone()
            old = row['assigned_to'] if row else ''

            conn.execute(
                "UPDATE remediation_items SET assigned_to = ?, updated_at = ? "
                "WHERE item_id = ?",
                (assigned_to, self._now(), item_id),
            )
            self._record_history(conn, item_id, 'assigned',
                                 old_value=old or '', new_value=assigned_to,
                                 changed_by=changed_by)
        logger.info(f"Assigned {item_id} to {assigned_to}")

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------
    def update_status(self, item_id: str, new_status: str,
                      notes: Optional[str] = None,
                      changed_by: str = 'system'):
        """Transition an item to a new status."""
        if new_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}. "
                             f"Must be one of {VALID_STATUSES}")
        now = self._now()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT status FROM remediation_items WHERE item_id = ?",
                (item_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"Remediation item not found: {item_id}")
            old_status = row['status']

            updates = {
                'status': new_status,
                'updated_at': now,
            }
            if notes:
                updates['resolution_notes'] = notes
            if new_status == 'resolved':
                updates['resolved_at'] = now
            if new_status == 'verified':
                updates['verified_at'] = now

            set_clause = ', '.join(f"{k} = ?" for k in updates)
            values = list(updates.values()) + [item_id]
            conn.execute(
                f"UPDATE remediation_items SET {set_clause} WHERE item_id = ?",
                values,
            )
            self._record_history(conn, item_id, 'status_change',
                                 old_value=old_status, new_value=new_status,
                                 changed_by=changed_by)

        logger.info(f"Updated {item_id} status: {old_status} -> {new_status}")

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------
    def get_item(self, item_id: str) -> Optional[Dict]:
        """Return a single remediation item."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM remediation_items WHERE item_id = ?",
                (item_id,),
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def get_open_items(
        self,
        assigned_to: Optional[str] = None,
        severity: Optional[str] = None,
        overdue_only: bool = False,
    ) -> List[Dict]:
        """Retrieve open / in-progress remediation items."""
        clauses = ["status IN ('open', 'in_progress')"]
        params: list = []

        if assigned_to:
            clauses.append("assigned_to = ?")
            params.append(assigned_to)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        if overdue_only:
            clauses.append("due_date < ?")
            params.append(self._now())

        where = ' AND '.join(clauses)
        sql = (f"SELECT * FROM remediation_items WHERE {where} "
               "ORDER BY due_date ASC")
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_overdue_items(self) -> List[Dict]:
        """Return items that are past their SLA due date."""
        return self.get_open_items(overdue_only=True)

    # ------------------------------------------------------------------
    # SLA / Metrics
    # ------------------------------------------------------------------
    def get_sla_status(self) -> Dict:
        """
        Counts by severity, percent within SLA, percent overdue.
        """
        now = self._now()
        result: Dict[str, Any] = {'by_severity': {}, 'overall': {}}

        with self._conn() as conn:
            for sev in ('critical', 'high', 'medium', 'low'):
                total = conn.execute(
                    "SELECT COUNT(*) FROM remediation_items "
                    "WHERE severity = ? AND status IN ('open', 'in_progress')",
                    (sev,),
                ).fetchone()[0]

                overdue = conn.execute(
                    "SELECT COUNT(*) FROM remediation_items "
                    "WHERE severity = ? AND status IN ('open', 'in_progress') "
                    "AND due_date < ?",
                    (sev, now),
                ).fetchone()[0]

                within = total - overdue
                result['by_severity'][sev] = {
                    'total_open': total,
                    'within_sla': within,
                    'overdue': overdue,
                    'pct_within_sla': round(within / total * 100, 2) if total else 100.0,
                    'pct_overdue': round(overdue / total * 100, 2) if total else 0.0,
                }

            # Overall
            total_open = conn.execute(
                "SELECT COUNT(*) FROM remediation_items "
                "WHERE status IN ('open', 'in_progress')"
            ).fetchone()[0]
            total_overdue = conn.execute(
                "SELECT COUNT(*) FROM remediation_items "
                "WHERE status IN ('open', 'in_progress') AND due_date < ?",
                (now,),
            ).fetchone()[0]
            within_all = total_open - total_overdue
            result['overall'] = {
                'total_open': total_open,
                'within_sla': within_all,
                'overdue': total_overdue,
                'pct_within_sla': round(within_all / total_open * 100, 2) if total_open else 100.0,
                'pct_overdue': round(total_overdue / total_open * 100, 2) if total_open else 0.0,
            }

        return result

    def get_remediation_metrics(self) -> Dict:
        """
        MTTR by severity, open/closed counts, resolution rates.
        """
        metrics: Dict[str, Any] = {
            'mttr_by_severity': {},
            'counts': {},
            'resolution_rate': 0.0,
        }

        with self._conn() as conn:
            # MTTR (mean time to resolve) per severity
            for sev in ('critical', 'high', 'medium', 'low'):
                rows = conn.execute(
                    "SELECT created_at, resolved_at FROM remediation_items "
                    "WHERE severity = ? AND resolved_at IS NOT NULL",
                    (sev,),
                ).fetchall()
                if rows:
                    deltas = []
                    for r in rows:
                        try:
                            created = datetime.fromisoformat(r['created_at'])
                            resolved = datetime.fromisoformat(r['resolved_at'])
                            deltas.append((resolved - created).total_seconds() / 86400)
                        except (ValueError, TypeError):
                            continue
                    if deltas:
                        metrics['mttr_by_severity'][sev] = {
                            'avg_days': round(sum(deltas) / len(deltas), 2),
                            'min_days': round(min(deltas), 2),
                            'max_days': round(max(deltas), 2),
                            'count': len(deltas),
                        }

            # Counts by status
            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM remediation_items GROUP BY status"
            ).fetchall()
            metrics['counts'] = {r['status']: r['cnt'] for r in status_rows}

            total = sum(metrics['counts'].values())
            resolved = sum(
                metrics['counts'].get(s, 0)
                for s in ('resolved', 'verified', 'closed')
            )
            metrics['resolution_rate'] = (
                round(resolved / total * 100, 2) if total else 0.0
            )

        return metrics

    # ------------------------------------------------------------------
    # Bulk creation from scan session
    # ------------------------------------------------------------------
    def bulk_create_from_scan(self, session_id: str) -> int:
        """
        Create remediation items for all open findings in a scan session.
        Reads findings from the evidence database.

        Returns:
            Number of remediation items created.
        """
        evidence_db = paths.data / 'evidence' / 'evidence.db'
        if not evidence_db.exists():
            logger.warning("Evidence database not found; cannot bulk-create.")
            return 0

        count = 0
        with sqlite3.connect(str(evidence_db)) as econn:
            econn.row_factory = sqlite3.Row
            findings = econn.execute(
                "SELECT finding_id, severity, title, description, "
                "affected_asset, remediation FROM findings "
                "WHERE session_id = ? AND status = 'open'",
                (session_id,),
            ).fetchall()

        for f in findings:
            sev = (f['severity'] or 'medium').lower()
            if sev not in _SLA_MAP:
                sev = 'medium'
            self.create_item(
                finding_id=f['finding_id'],
                title=f"Remediate: {f['title']}",
                severity=sev,
                description=f['description'] or '',
                asset_id=f['affected_asset'] or None,
            )
            count += 1

        logger.info(f"Bulk-created {count} remediation items from session {session_id}")
        return count

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------
    def get_history(self, item_id: str) -> List[Dict]:
        """Return the full audit trail for a remediation item."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM remediation_history WHERE item_id = ? "
                "ORDER BY changed_at ASC",
                (item_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> Dict:
        """High-level dashboard statistics."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM remediation_items"
            ).fetchone()[0]
            open_count = conn.execute(
                "SELECT COUNT(*) FROM remediation_items "
                "WHERE status IN ('open', 'in_progress')"
            ).fetchone()[0]
            overdue = conn.execute(
                "SELECT COUNT(*) FROM remediation_items "
                "WHERE status IN ('open', 'in_progress') AND due_date < ?",
                (self._now(),),
            ).fetchone()[0]
            resolved = conn.execute(
                "SELECT COUNT(*) FROM remediation_items "
                "WHERE status IN ('resolved', 'verified', 'closed')"
            ).fetchone()[0]
            deferred = conn.execute(
                "SELECT COUNT(*) FROM remediation_items WHERE status = 'deferred'"
            ).fetchone()[0]

        return {
            'total_items': total,
            'open': open_count,
            'overdue': overdue,
            'resolved': resolved,
            'deferred': deferred,
            'sla_status': self.get_sla_status(),
            'metrics': self.get_remediation_metrics(),
        }


# ======================================================================
# Singleton accessor
# ======================================================================
_remediation_tracker: Optional[RemediationTracker] = None


def get_remediation_tracker() -> RemediationTracker:
    """Get the RemediationTracker singleton."""
    global _remediation_tracker
    if _remediation_tracker is None:
        _remediation_tracker = RemediationTracker()
    return _remediation_tracker


# ======================================================================
# Self-test
# ======================================================================
if __name__ == '__main__':
    rt = get_remediation_tracker()
    print(f"Remediation DB: {rt.db_path}")
    print(f"DB exists: {rt.db_path.exists()}")

    # Create a sample item
    item_id = rt.create_item(
        finding_id='FND-SAMPLE001',
        title='Patch Apache CVE-2024-12345',
        severity='high',
        description='Remote code execution in Apache 2.4.x',
        assigned_to='sec-ops',
        ticket_ref='JIRA-4567',
    )
    print(f"Created item: {item_id}")

    # Assign
    rt.assign(item_id, 'alice@corp.com')

    # Transition
    rt.update_status(item_id, 'in_progress', changed_by='alice')
    rt.update_status(item_id, 'resolved', notes='Patched to 2.4.59',
                     changed_by='alice')

    # History
    history = rt.get_history(item_id)
    print(f"History entries: {len(history)}")

    # SLA
    sla = rt.get_sla_status()
    print(f"SLA status: {json.dumps(sla, indent=2)}")

    # Statistics
    stats = rt.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
