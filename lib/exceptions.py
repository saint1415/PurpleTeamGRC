#!/usr/bin/env python3
"""
Purple Team Portable - Exception / Risk Acceptance Management
Creates, tracks, and enforces exception policies (false-positives,
accepted risks, compensating controls, deferrals) against scan findings.
"""

import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
except ImportError:
    from paths import paths


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_EXCEPTION_TYPES = (
    'false_positive',
    'accepted_risk',
    'compensating_control',
    'deferred',
)

VALID_STATUSES = (
    'pending',
    'approved',
    'expired',
    'revoked',
)


# ---------------------------------------------------------------------------
# ExceptionManager
# ---------------------------------------------------------------------------

class ExceptionManager:
    """Manages exception / risk-acceptance records in a dedicated SQLite DB."""

    def __init__(self):
        self.db_path = paths.data / 'exceptions.db'
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------

    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exception_id TEXT UNIQUE NOT NULL,
                    finding_type TEXT,
                    title_pattern TEXT NOT NULL,
                    asset_pattern TEXT,
                    exception_type TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    expires_at TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    compensating_control TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT,
                    reviewed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS exception_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exception_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT,
                    timestamp TEXT NOT NULL,
                    notes TEXT,
                    FOREIGN KEY (exception_id) REFERENCES exceptions(exception_id)
                );

                CREATE INDEX IF NOT EXISTS idx_exc_status
                    ON exceptions(status);
                CREATE INDEX IF NOT EXISTS idx_exc_type
                    ON exceptions(exception_type);
                CREATE INDEX IF NOT EXISTS idx_exc_expires
                    ON exceptions(expires_at);
                CREATE INDEX IF NOT EXISTS idx_exh_exception
                    ON exception_history(exception_id);
            ''')

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_id(self) -> str:
        """Generate a unique exception ID."""
        return f"EXC-{uuid.uuid4().hex[:12].upper()}"

    def _now_iso(self) -> str:
        return datetime.utcnow().isoformat()

    def _log_history(self, conn: sqlite3.Connection, exception_id: str,
                     action: str, actor: str = '', notes: str = ''):
        """Append an entry to exception_history inside an existing connection."""
        conn.execute('''
            INSERT INTO exception_history (exception_id, action, actor, timestamp, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (exception_id, action, actor, self._now_iso(), notes))

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _get_exception_row(self, conn: sqlite3.Connection,
                           exception_id: str) -> Optional[Dict]:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            'SELECT * FROM exceptions WHERE exception_id = ?', (exception_id,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_exception(self, finding_type: str, title_pattern: str,
                         exception_type: str, justification: str,
                         **kwargs) -> str:
        """Create a new exception record.

        Optional kwargs:
            asset_pattern, approved_by, expires_at (ISO str or None),
            compensating_control, created_by, expires_days (int)
        """
        if exception_type not in VALID_EXCEPTION_TYPES:
            raise ValueError(
                f"Invalid exception_type '{exception_type}'. "
                f"Must be one of: {', '.join(VALID_EXCEPTION_TYPES)}"
            )

        exception_id = self._generate_id()
        now = self._now_iso()

        # Resolve expiry
        expires_at = kwargs.get('expires_at')
        expires_days = kwargs.get('expires_days')
        if expires_days and not expires_at:
            expires_at = (datetime.utcnow() + timedelta(days=int(expires_days))).isoformat()

        created_by = kwargs.get('created_by', '')
        asset_pattern = kwargs.get('asset_pattern', '')
        compensating_control = kwargs.get('compensating_control', '')
        approved_by = kwargs.get('approved_by', '')

        # If approved_by is supplied at creation time, auto-approve
        status = 'approved' if approved_by else 'pending'
        approved_at = now if approved_by else None

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO exceptions
                (exception_id, finding_type, title_pattern, asset_pattern,
                 exception_type, justification, approved_by, approved_at,
                 expires_at, status, compensating_control, created_at, created_by,
                 reviewed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                exception_id, finding_type or '', title_pattern,
                asset_pattern, exception_type, justification,
                approved_by, approved_at, expires_at, status,
                compensating_control, now, created_by,
                approved_at,  # reviewed_at = approved_at when auto-approved
            ))
            self._log_history(conn, exception_id, 'created',
                              actor=created_by,
                              notes=f'Type: {exception_type}')
            if status == 'approved':
                self._log_history(conn, exception_id, 'approved',
                                  actor=approved_by,
                                  notes='Auto-approved at creation')

        return exception_id

    def approve_exception(self, exception_id: str, approved_by: str,
                          notes: str = ''):
        """Approve a pending exception."""
        now = self._now_iso()
        with sqlite3.connect(self.db_path) as conn:
            exc = self._get_exception_row(conn, exception_id)
            if not exc:
                raise ValueError(f"Exception not found: {exception_id}")
            if exc['status'] != 'pending':
                raise ValueError(
                    f"Cannot approve exception in '{exc['status']}' status"
                )
            conn.execute('''
                UPDATE exceptions
                SET status = 'approved', approved_by = ?, approved_at = ?,
                    reviewed_at = ?
                WHERE exception_id = ?
            ''', (approved_by, now, now, exception_id))
            self._log_history(conn, exception_id, 'approved',
                              actor=approved_by, notes=notes)

    def revoke_exception(self, exception_id: str, reason: str = '',
                         actor: str = ''):
        """Revoke an active exception."""
        now = self._now_iso()
        with sqlite3.connect(self.db_path) as conn:
            exc = self._get_exception_row(conn, exception_id)
            if not exc:
                raise ValueError(f"Exception not found: {exception_id}")
            if exc['status'] not in ('pending', 'approved'):
                raise ValueError(
                    f"Cannot revoke exception in '{exc['status']}' status"
                )
            conn.execute('''
                UPDATE exceptions
                SET status = 'revoked', reviewed_at = ?
                WHERE exception_id = ?
            ''', (now, exception_id))
            self._log_history(conn, exception_id, 'revoked',
                              actor=actor, notes=reason)

    # ------------------------------------------------------------------
    # Matching engine
    # ------------------------------------------------------------------

    def _matches_pattern(self, pattern: str, value: str) -> bool:
        """Check if *value* matches *pattern* (treated as regex)."""
        if not pattern:
            return True  # empty pattern matches everything
        try:
            return bool(re.search(pattern, value, re.IGNORECASE))
        except re.error:
            # Fall back to plain substring match if regex is invalid
            return pattern.lower() in value.lower()

    def is_excepted(self, finding: Dict) -> Optional[Dict]:
        """Check whether a finding is covered by any active, non-expired exception.

        Returns the matching exception dict or None.
        """
        now = self._now_iso()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM exceptions
                WHERE status = 'approved'
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
            ''', (now,)).fetchall()

        finding_title = finding.get('title', '')
        finding_asset = finding.get('affected_asset', '')
        finding_type = (finding.get('finding_type')
                        or finding.get('type', ''))

        for row in rows:
            exc = dict(row)
            # Match finding_type (if the exception specifies one)
            if exc['finding_type']:
                if not self._matches_pattern(exc['finding_type'], finding_type):
                    continue
            # Match title_pattern (required)
            if not self._matches_pattern(exc['title_pattern'], finding_title):
                continue
            # Match asset_pattern
            if exc['asset_pattern']:
                if not self._matches_pattern(exc['asset_pattern'], finding_asset):
                    continue
            return exc

        return None

    def apply_exceptions(self, findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Split findings into (active, excepted).

        Excepted findings are annotated with an ``exception`` key containing
        the matching exception details.
        """
        active: List[Dict] = []
        excepted: List[Dict] = []

        for f in findings:
            exc = self.is_excepted(f)
            if exc:
                annotated = dict(f)
                annotated['exception'] = {
                    'exception_id': exc['exception_id'],
                    'exception_type': exc['exception_type'],
                    'justification': exc['justification'],
                    'approved_by': exc['approved_by'],
                    'expires_at': exc['expires_at'],
                    'compensating_control': exc.get('compensating_control', ''),
                }
                excepted.append(annotated)
            else:
                active.append(f)

        return active, excepted

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_exception(self, exception_id: str) -> Optional[Dict]:
        """Retrieve a single exception by ID."""
        with sqlite3.connect(self.db_path) as conn:
            return self._get_exception_row(conn, exception_id)

    def get_active_exceptions(self) -> List[Dict]:
        """Return all currently active (approved, non-expired) exceptions."""
        now = self._now_iso()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM exceptions
                WHERE status = 'approved'
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
            ''', (now,)).fetchall()
            return [dict(r) for r in rows]

    def get_pending_exceptions(self) -> List[Dict]:
        """Return exceptions awaiting approval."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM exceptions
                WHERE status = 'pending'
                ORDER BY created_at ASC
            ''').fetchall()
            return [dict(r) for r in rows]

    def get_expiring_soon(self, days: int = 30) -> List[Dict]:
        """Return approved exceptions expiring within *days*."""
        now = datetime.utcnow()
        cutoff = (now + timedelta(days=days)).isoformat()
        now_iso = now.isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM exceptions
                WHERE status = 'approved'
                  AND expires_at IS NOT NULL
                  AND expires_at > ?
                  AND expires_at <= ?
                ORDER BY expires_at ASC
            ''', (now_iso, cutoff)).fetchall()
            return [dict(r) for r in rows]

    def get_expired(self) -> List[Dict]:
        """Return exceptions that have expired but are still marked approved."""
        now = self._now_iso()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM exceptions
                WHERE status = 'approved'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                ORDER BY expires_at ASC
            ''', (now,)).fetchall()
            return [dict(r) for r in rows]

    def get_all_exceptions(self, include_revoked: bool = False) -> List[Dict]:
        """Return all exception records."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if include_revoked:
                rows = conn.execute(
                    'SELECT * FROM exceptions ORDER BY created_at DESC'
                ).fetchall()
            else:
                rows = conn.execute('''
                    SELECT * FROM exceptions
                    WHERE status != 'revoked'
                    ORDER BY created_at DESC
                ''').fetchall()
            return [dict(r) for r in rows]

    def get_history(self, exception_id: str) -> List[Dict]:
        """Return the full audit trail for an exception."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM exception_history
                WHERE exception_id = ?
                ORDER BY timestamp ASC
            ''', (exception_id,)).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Mark all expired exceptions as 'expired'. Returns count updated."""
        now = self._now_iso()
        with sqlite3.connect(self.db_path) as conn:
            # Identify expired rows first for history logging
            conn.row_factory = sqlite3.Row
            expired = conn.execute('''
                SELECT exception_id FROM exceptions
                WHERE status = 'approved'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
            ''', (now,)).fetchall()

            count = 0
            for row in expired:
                eid = row['exception_id']
                conn.execute('''
                    UPDATE exceptions SET status = 'expired', reviewed_at = ?
                    WHERE exception_id = ?
                ''', (now, eid))
                self._log_history(conn, eid, 'expired', actor='system',
                                  notes='Automatic expiry')
                count += 1

        return count

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Return aggregate statistics about exceptions."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Total by status
            status_rows = conn.execute('''
                SELECT status, COUNT(*) as cnt FROM exceptions GROUP BY status
            ''').fetchall()
            by_status = {r['status']: r['cnt'] for r in status_rows}

            # Total by exception_type (only approved / active)
            type_rows = conn.execute('''
                SELECT exception_type, COUNT(*) as cnt FROM exceptions
                WHERE status = 'approved'
                GROUP BY exception_type
            ''').fetchall()
            by_type = {r['exception_type']: r['cnt'] for r in type_rows}

            # Expiring soon (30 days)
            expiring_soon = len(self.get_expiring_soon(30))

            # Already expired but not cleaned up
            expired_pending = len(self.get_expired())

            total = conn.execute('SELECT COUNT(*) FROM exceptions').fetchone()[0]

        return {
            'total': total,
            'by_status': by_status,
            'by_type': by_type,
            'expiring_within_30_days': expiring_soon,
            'expired_pending_cleanup': expired_pending,
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self) -> str:
        """Generate a human-readable text report of exception status."""
        stats = self.get_statistics()
        active = self.get_active_exceptions()
        pending = self.get_pending_exceptions()
        expiring = self.get_expiring_soon(30)

        lines: List[str] = []
        w = 72

        lines.append('=' * w)
        lines.append('  EXCEPTION / RISK ACCEPTANCE REPORT')
        lines.append('=' * w)
        lines.append(f'  Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}')
        lines.append('')

        # Statistics
        lines.append('  STATISTICS')
        lines.append('  ' + '-' * 40)
        lines.append(f'  Total exceptions   : {stats["total"]}')
        for status, cnt in stats['by_status'].items():
            lines.append(f'    {status:20s}: {cnt}')
        lines.append(f'  Active by type:')
        for etype, cnt in stats['by_type'].items():
            lines.append(f'    {etype:20s}: {cnt}')
        lines.append(f'  Expiring in 30 days: {stats["expiring_within_30_days"]}')
        lines.append(f'  Expired (pending)  : {stats["expired_pending_cleanup"]}')
        lines.append('')

        # Pending approval
        if pending:
            lines.append('-' * w)
            lines.append(f'  PENDING APPROVAL ({len(pending)})')
            lines.append('-' * w)
            for exc in pending:
                lines.append(f'  ID   : {exc["exception_id"]}')
                lines.append(f'  Type : {exc["exception_type"]}')
                lines.append(f'  Title: {exc["title_pattern"]}')
                lines.append(f'  By   : {exc["created_by"] or "N/A"}')
                lines.append('')

        # Expiring soon
        if expiring:
            lines.append('-' * w)
            lines.append(f'  EXPIRING WITHIN 30 DAYS ({len(expiring)})')
            lines.append('-' * w)
            for exc in expiring:
                lines.append(f'  ID     : {exc["exception_id"]}')
                lines.append(f'  Title  : {exc["title_pattern"]}')
                lines.append(f'  Expires: {exc["expires_at"]}')
                lines.append('')

        # Active exceptions
        lines.append('-' * w)
        lines.append(f'  ACTIVE EXCEPTIONS ({len(active)})')
        lines.append('-' * w)
        if active:
            for exc in active:
                etype = exc['exception_type']
                lines.append(f'  [{etype.upper()}] {exc["title_pattern"]}')
                lines.append(f'         ID      : {exc["exception_id"]}')
                lines.append(f'         Asset   : {exc["asset_pattern"] or "*"}')
                lines.append(f'         Approved: {exc["approved_by"] or "N/A"}')
                expires = exc['expires_at'] or 'permanent'
                lines.append(f'         Expires : {expires}')
                if exc.get('compensating_control'):
                    lines.append(f'         Control : {exc["compensating_control"]}')
                lines.append('')
        else:
            lines.append('  (none)')
            lines.append('')

        lines.append('=' * w)
        lines.append('  END OF REPORT')
        lines.append('=' * w)

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_exception_manager: Optional[ExceptionManager] = None


def get_exception_manager() -> ExceptionManager:
    """Get the exception manager singleton."""
    global _exception_manager
    if _exception_manager is None:
        _exception_manager = ExceptionManager()
    return _exception_manager


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    em = get_exception_manager()
    print(f"Exceptions database: {em.db_path}")
    print(f"Database exists: {em.db_path.exists()}")

    # Create a sample exception
    eid = em.create_exception(
        finding_type='vulnerability',
        title_pattern='SSL.*Weak Cipher',
        exception_type='accepted_risk',
        justification='Internal-only service behind VPN; cipher upgrade scheduled Q3.',
        asset_pattern='192\\.168\\.1\\..*',
        created_by='analyst',
        expires_days=90,
    )
    print(f"Created exception: {eid}")

    # Approve it
    em.approve_exception(eid, approved_by='ciso', notes='Approved per risk review.')
    print(f"Approved exception: {eid}")

    # Check a finding
    sample_finding = {
        'title': 'SSL/TLS Weak Cipher Suite Detected',
        'affected_asset': '192.168.1.50',
        'finding_type': 'vulnerability',
    }
    match = em.is_excepted(sample_finding)
    print(f"Finding excepted: {match is not None}")

    # Statistics
    stats = em.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")

    # Report
    print(em.generate_report())
