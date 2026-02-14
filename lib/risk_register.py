#!/usr/bin/env python3
"""
Purple Team GRC Platform - Risk Register Module
Enterprise risk register with likelihood/impact scoring, 5x5 risk matrix,
automated risk generation from scan findings, and trend tracking.
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

logger = get_logger('risk_register')


VALID_CATEGORIES = ('technical', 'operational', 'compliance', 'strategic')
VALID_STATUSES = ('identified', 'assessed', 'mitigating', 'accepted', 'closed')


class RiskRegister:
    """Enterprise risk register backed by SQLite."""

    _instance: Optional['RiskRegister'] = None

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

        self.db_path = paths.data / 'risk_register.db'
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS risks (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id             TEXT UNIQUE NOT NULL,
                    title               TEXT NOT NULL,
                    description         TEXT,
                    risk_category       TEXT DEFAULT 'technical',
                    likelihood          INTEGER DEFAULT 3,
                    impact              INTEGER DEFAULT 3,
                    risk_score          INTEGER DEFAULT 9,
                    inherent_risk_score INTEGER,
                    residual_risk_score INTEGER,
                    risk_owner          TEXT,
                    business_unit       TEXT,
                    status              TEXT DEFAULT 'identified',
                    mitigation_plan     TEXT,
                    related_findings    TEXT DEFAULT '[]',
                    related_controls    TEXT DEFAULT '[]',
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL,
                    review_date         TEXT,
                    notes               TEXT
                );

                CREATE TABLE IF NOT EXISTS risk_snapshots (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_date TEXT NOT NULL,
                    total_risks INTEGER,
                    avg_score   REAL,
                    critical_count INTEGER,
                    high_count  INTEGER,
                    medium_count INTEGER,
                    low_count   INTEGER,
                    data        TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_risks_category ON risks(risk_category);
                CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
                CREATE INDEX IF NOT EXISTS idx_risks_score ON risks(risk_score);
                CREATE INDEX IF NOT EXISTS idx_risks_bu ON risks(business_unit);
                CREATE INDEX IF NOT EXISTS idx_snap_date ON risk_snapshots(snapshot_date);
            ''')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _generate_id(self) -> str:
        return f"RISK-{uuid.uuid4().hex[:12].upper()}"

    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        d = dict(row)
        for jf in ('related_findings', 'related_controls'):
            if jf in d and isinstance(d[jf], str):
                try:
                    d[jf] = json.loads(d[jf])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    @staticmethod
    def _clamp(value: int, lo: int = 1, hi: int = 5) -> int:
        return max(lo, min(hi, value))

    @staticmethod
    def _score_band(score: int) -> str:
        """Map a risk score (1-25) to a severity band."""
        if score >= 20:
            return 'critical'
        if score >= 12:
            return 'high'
        if score >= 6:
            return 'medium'
        return 'low'

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def add_risk(self, title: str, category: str, likelihood: int,
                 impact: int, **kwargs) -> str:
        """
        Register a new risk.

        Returns:
            risk_id (str)
        """
        now = self._now()
        risk_id = self._generate_id()
        likelihood = self._clamp(likelihood)
        impact = self._clamp(impact)
        risk_score = likelihood * impact
        inherent = kwargs.get('inherent_risk_score', risk_score)
        residual = kwargs.get('residual_risk_score', risk_score)

        related_findings = kwargs.get('related_findings', [])
        related_controls = kwargs.get('related_controls', [])
        if not isinstance(related_findings, str):
            related_findings = json.dumps(related_findings)
        if not isinstance(related_controls, str):
            related_controls = json.dumps(related_controls)

        review_date = kwargs.get(
            'review_date',
            (datetime.utcnow() + timedelta(days=90)).isoformat(),
        )

        with self._conn() as conn:
            conn.execute('''
                INSERT INTO risks
                (risk_id, title, description, risk_category, likelihood,
                 impact, risk_score, inherent_risk_score, residual_risk_score,
                 risk_owner, business_unit, status, mitigation_plan,
                 related_findings, related_controls,
                 created_at, updated_at, review_date, notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                risk_id, title,
                kwargs.get('description', ''),
                category if category in VALID_CATEGORIES else 'technical',
                likelihood, impact, risk_score, inherent, residual,
                kwargs.get('risk_owner', ''),
                kwargs.get('business_unit', ''),
                kwargs.get('status', 'identified'),
                kwargs.get('mitigation_plan', ''),
                related_findings, related_controls,
                now, now, review_date,
                kwargs.get('notes', ''),
            ))

        logger.info(f"Added risk {risk_id}: {title} (score={risk_score})")
        return risk_id

    def update_risk(self, risk_id: str, **kwargs):
        """Update fields on an existing risk entry."""
        allowed = {
            'title', 'description', 'risk_category', 'likelihood', 'impact',
            'inherent_risk_score', 'residual_risk_score', 'risk_owner',
            'business_unit', 'status', 'mitigation_plan', 'related_findings',
            'related_controls', 'review_date', 'notes',
        }
        updates: Dict[str, Any] = {}
        for k, v in kwargs.items():
            if k in allowed:
                if k in ('related_findings', 'related_controls') and not isinstance(v, str):
                    v = json.dumps(v)
                updates[k] = v

        # Recompute score if likelihood or impact changed
        if 'likelihood' in updates or 'impact' in updates:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT likelihood, impact FROM risks WHERE risk_id = ?",
                    (risk_id,),
                ).fetchone()
                if row:
                    lk = self._clamp(updates.get('likelihood', row['likelihood']))
                    imp = self._clamp(updates.get('impact', row['impact']))
                    updates['likelihood'] = lk
                    updates['impact'] = imp
                    updates['risk_score'] = lk * imp

        if not updates:
            return

        updates['updated_at'] = self._now()
        set_clause = ', '.join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [risk_id]

        with self._conn() as conn:
            conn.execute(
                f"UPDATE risks SET {set_clause} WHERE risk_id = ?", values
            )
        logger.info(f"Updated risk {risk_id}: {list(updates.keys())}")

    def get_risk(self, risk_id: str) -> Optional[Dict]:
        """Retrieve a single risk by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM risks WHERE risk_id = ?", (risk_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def get_risks(
        self,
        category: Optional[str] = None,
        status: Optional[str] = None,
        business_unit: Optional[str] = None,
        min_score: Optional[int] = None,
        limit: int = 500,
    ) -> List[Dict]:
        """Flexible risk query with optional filters."""
        clauses: List[str] = []
        params: list = []

        if category:
            clauses.append("risk_category = ?")
            params.append(category)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if business_unit:
            clauses.append("business_unit = ?")
            params.append(business_unit)
        if min_score is not None:
            clauses.append("risk_score >= ?")
            params.append(min_score)

        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        sql = f"SELECT * FROM risks{where} ORDER BY risk_score DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Posture & matrix
    # ------------------------------------------------------------------
    def calculate_risk_posture(self) -> Dict:
        """
        Overall organisational risk posture: total risks by severity band,
        average scores, top-10 risks, risk grouped by business unit.
        """
        with self._conn() as conn:
            all_risks = conn.execute(
                "SELECT * FROM risks WHERE status != 'closed'"
            ).fetchall()

        if not all_risks:
            return {
                'total': 0, 'by_band': {}, 'avg_score': 0,
                'top_risks': [], 'by_business_unit': {},
            }

        by_band: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        by_bu: Dict[str, list] = {}
        scores = []

        for r in all_risks:
            score = r['risk_score']
            scores.append(score)
            band = self._score_band(score)
            by_band[band] = by_band.get(band, 0) + 1
            bu = r['business_unit'] or 'unassigned'
            by_bu.setdefault(bu, []).append(score)

        sorted_risks = sorted(all_risks, key=lambda r: r['risk_score'], reverse=True)
        top_risks = [
            {'risk_id': r['risk_id'], 'title': r['title'],
             'score': r['risk_score'], 'category': r['risk_category']}
            for r in sorted_risks[:10]
        ]

        bu_summary = {
            bu: {'count': len(sc), 'avg_score': round(sum(sc) / len(sc), 2)}
            for bu, sc in by_bu.items()
        }

        return {
            'total': len(all_risks),
            'by_band': by_band,
            'avg_score': round(sum(scores) / len(scores), 2),
            'top_risks': top_risks,
            'by_business_unit': bu_summary,
        }

    def get_risk_matrix(self) -> List[List[int]]:
        """
        Build a 5x5 risk matrix.  Returns a list of 5 rows (likelihood
        5 down to 1) each containing 5 cells (impact 1..5) with the count
        of risks in that cell.
        """
        matrix = [[0] * 5 for _ in range(5)]

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT likelihood, impact, COUNT(*) AS cnt "
                "FROM risks WHERE status != 'closed' "
                "GROUP BY likelihood, impact"
            ).fetchall()

        for r in rows:
            lk = self._clamp(r['likelihood']) - 1   # 0-indexed
            imp = self._clamp(r['impact']) - 1
            # Row index: 4 = likelihood 5 (top), 0 = likelihood 1 (bottom)
            matrix[4 - lk][imp] = r['cnt']

        return matrix

    # ------------------------------------------------------------------
    # Auto-generate from findings
    # ------------------------------------------------------------------
    def auto_generate_from_findings(self, session_id: str) -> int:
        """
        Create or update risks based on findings in a scan session.
        Maps finding severity to likelihood/impact and groups by title
        similarity.

        Returns:
            Number of risks created.
        """
        evidence_db = paths.data / 'evidence' / 'evidence.db'
        if not evidence_db.exists():
            logger.warning("Evidence DB not found; cannot auto-generate risks.")
            return 0

        severity_map = {
            'critical': (5, 5),
            'high': (4, 4),
            'medium': (3, 3),
            'low': (2, 2),
            'info': (1, 1),
        }

        with sqlite3.connect(str(evidence_db)) as econn:
            econn.row_factory = sqlite3.Row
            findings = econn.execute(
                "SELECT finding_id, severity, title, description, affected_asset "
                "FROM findings WHERE session_id = ? AND status = 'open'",
                (session_id,),
            ).fetchall()

        count = 0
        for f in findings:
            sev = (f['severity'] or 'medium').lower()
            lk, imp = severity_map.get(sev, (3, 3))
            self.add_risk(
                title=f"Risk: {f['title']}",
                category='technical',
                likelihood=lk,
                impact=imp,
                description=f['description'] or '',
                related_findings=[f['finding_id']],
                notes=f"Auto-generated from session {session_id}",
            )
            count += 1

        logger.info(f"Auto-generated {count} risks from session {session_id}")
        return count

    # ------------------------------------------------------------------
    # Trends / snapshots
    # ------------------------------------------------------------------
    def _take_snapshot(self):
        """Store a point-in-time snapshot of risk metrics."""
        posture = self.calculate_risk_posture()
        now = self._now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO risk_snapshots "
                "(snapshot_date, total_risks, avg_score, "
                "critical_count, high_count, medium_count, low_count, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    now,
                    posture['total'],
                    posture['avg_score'],
                    posture['by_band'].get('critical', 0),
                    posture['by_band'].get('high', 0),
                    posture['by_band'].get('medium', 0),
                    posture['by_band'].get('low', 0),
                    json.dumps(posture),
                ),
            )

    def get_risk_trends(self, days: int = 90) -> List[Dict]:
        """
        Return risk-score snapshots over the last *days* days.
        If no snapshots exist a fresh one is taken first.
        """
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM risk_snapshots").fetchone()[0]

        if count == 0:
            self._take_snapshot()

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT snapshot_date, total_risks, avg_score, "
                "critical_count, high_count, medium_count, low_count "
                "FROM risk_snapshots WHERE snapshot_date >= ? "
                "ORDER BY snapshot_date ASC",
                (cutoff,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> Dict:
        """Dashboard-ready statistics."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM risks").fetchone()[0]
            open_risks = conn.execute(
                "SELECT COUNT(*) FROM risks WHERE status != 'closed'"
            ).fetchone()[0]
            accepted = conn.execute(
                "SELECT COUNT(*) FROM risks WHERE status = 'accepted'"
            ).fetchone()[0]
            closed = conn.execute(
                "SELECT COUNT(*) FROM risks WHERE status = 'closed'"
            ).fetchone()[0]

            # Average score of open risks
            avg_row = conn.execute(
                "SELECT AVG(risk_score) FROM risks WHERE status != 'closed'"
            ).fetchone()
            avg_score = round(avg_row[0], 2) if avg_row[0] else 0.0

            # Review overdue (review_date in the past, not closed)
            overdue_review = conn.execute(
                "SELECT COUNT(*) FROM risks "
                "WHERE status != 'closed' AND review_date < ?",
                (self._now(),),
            ).fetchone()[0]

        return {
            'total_risks': total,
            'open': open_risks,
            'accepted': accepted,
            'closed': closed,
            'avg_risk_score': avg_score,
            'overdue_for_review': overdue_review,
            'posture': self.calculate_risk_posture(),
            'matrix': self.get_risk_matrix(),
        }


# ======================================================================
# Singleton accessor
# ======================================================================
_risk_register: Optional[RiskRegister] = None


def get_risk_register() -> RiskRegister:
    """Get the RiskRegister singleton."""
    global _risk_register
    if _risk_register is None:
        _risk_register = RiskRegister()
    return _risk_register


# ======================================================================
# Self-test
# ======================================================================
if __name__ == '__main__':
    rr = get_risk_register()
    print(f"Risk Register DB: {rr.db_path}")
    print(f"DB exists: {rr.db_path.exists()}")

    # Add sample risks
    r1 = rr.add_risk(
        title='Unpatched critical servers',
        category='technical',
        likelihood=4,
        impact=5,
        description='Multiple servers running EOL operating systems',
        business_unit='Infrastructure',
        risk_owner='ciso',
    )
    print(f"Created risk: {r1}")

    r2 = rr.add_risk(
        title='Third-party vendor data exposure',
        category='compliance',
        likelihood=3,
        impact=4,
        business_unit='Legal',
        risk_owner='dpo',
    )
    print(f"Created risk: {r2}")

    r3 = rr.add_risk(
        title='Weak password policy',
        category='operational',
        likelihood=5,
        impact=3,
        business_unit='IT',
    )
    print(f"Created risk: {r3}")

    # Posture
    posture = rr.calculate_risk_posture()
    print(f"Risk posture: {json.dumps(posture, indent=2)}")

    # Matrix
    matrix = rr.get_risk_matrix()
    print("Risk matrix (likelihood 5->1, impact 1->5):")
    for row in matrix:
        print(f"  {row}")

    # Statistics
    stats = rr.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
