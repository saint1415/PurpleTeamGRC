#!/usr/bin/env python3
"""
Purple Team Portable - Evidence Manager
Collects, stores, and manages audit evidence with compliance mapping.
"""

import os
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .config import config
except ImportError:
    from paths import paths
    from config import config


class EvidenceManager:
    """Manages evidence collection, storage, and compliance mapping."""

    def __init__(self):
        self.db_path = paths.evidence_db
        self._ensure_db()
        self._migrate_schema()

    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT UNIQUE NOT NULL,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    source_tool TEXT,
                    file_path TEXT,
                    file_hash TEXT,
                    raw_data TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS control_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    control_name TEXT,
                    control_family TEXT,
                    mapping_type TEXT DEFAULT 'supports',
                    notes TEXT,
                    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT UNIQUE NOT NULL,
                    session_id TEXT NOT NULL,
                    evidence_id TEXT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    affected_asset TEXT,
                    cvss_score REAL,
                    cve_ids TEXT,
                    remediation TEXT,
                    status TEXT DEFAULT 'open',
                    metadata TEXT,
                    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    scan_type TEXT,
                    target_networks TEXT,
                    status TEXT DEFAULT 'running',
                    summary TEXT,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS attestations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attestation_id TEXT UNIQUE NOT NULL,
                    framework TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    period_end TEXT NOT NULL,
                    status TEXT NOT NULL,
                    evidence_ids TEXT,
                    attester TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS finding_overrides (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    override_id TEXT UNIQUE NOT NULL,
                    match_rule TEXT NOT NULL,
                    action TEXT NOT NULL DEFAULT 'false_positive',
                    new_severity TEXT,
                    reason TEXT,
                    created_by TEXT DEFAULT 'analyst',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(type);
                CREATE INDEX IF NOT EXISTS idx_mappings_framework ON control_mappings(framework);
                CREATE INDEX IF NOT EXISTS idx_mappings_control ON control_mappings(control_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            ''')

    def _migrate_schema(self):
        """Migrate database schema - add new columns for v6.0 features."""
        migration_columns = [
            ('findings', 'kev_status', 'TEXT'),
            ('findings', 'epss_score', 'REAL'),
            ('findings', 'epss_percentile', 'REAL'),
            ('findings', 'effective_priority', 'REAL'),
            ('findings', 'quality_of_detection', 'REAL'),
            ('findings', 'detection_source', 'TEXT'),
            ('findings', 'false_positive', 'INTEGER DEFAULT 0'),
            ('findings', 'fp_reason', 'TEXT'),
            ('findings', 'scanner_name', 'TEXT'),
        ]

        with sqlite3.connect(self.db_path) as conn:
            for table, column, col_type in migration_columns:
                try:
                    conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {col_type}')
                except Exception:
                    pass  # Column already exists

            # Create indexes for new columns
            try:
                conn.execute('CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(effective_priority)')
            except Exception:
                pass
            try:
                conn.execute('CREATE INDEX IF NOT EXISTS idx_findings_kev ON findings(kev_status)')
            except Exception:
                pass
            try:
                conn.execute('CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(false_positive)')
            except Exception:
                pass

    def _generate_id(self, prefix: str) -> str:
        """Generate unique ID with prefix."""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
        return f"{prefix}-{timestamp}"

    def _hash_content(self, content: str) -> str:
        """Generate SHA-256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()

    def start_session(self, scan_type: str, target_networks: List[str],
                      metadata: Optional[Dict] = None) -> str:
        """Start a new scanning session."""
        session_id = self._generate_id('SESSION')

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO sessions (session_id, start_time, scan_type, target_networks, metadata)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session_id,
                datetime.utcnow().isoformat(),
                scan_type,
                json.dumps(target_networks),
                json.dumps(metadata or {})
            ))

        # Create session directory
        paths.session_dir(session_id)
        return session_id

    def end_session(self, session_id: str, summary: Optional[Dict] = None):
        """End a scanning session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE sessions
                SET end_time = ?, status = 'completed', summary = ?
                WHERE session_id = ?
            ''', (
                datetime.utcnow().isoformat(),
                json.dumps(summary or {}),
                session_id
            ))

    def add_evidence(self, session_id: str, evidence_type: str, title: str,
                     description: str = '', source_tool: str = '',
                     file_path: Optional[Path] = None, raw_data: Any = None,
                     metadata: Optional[Dict] = None) -> str:
        """Add evidence artifact to the database."""
        evidence_id = self._generate_id('EVD')

        # Calculate file hash if file provided
        file_hash = None
        if file_path and file_path.exists():
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

        # Hash raw data
        raw_json = json.dumps(raw_data) if raw_data else None
        if raw_json:
            file_hash = file_hash or self._hash_content(raw_json)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO evidence
                (evidence_id, session_id, timestamp, type, title, description,
                 source_tool, file_path, file_hash, raw_data, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence_id, session_id, datetime.utcnow().isoformat(),
                evidence_type, title, description, source_tool,
                str(file_path) if file_path else None,
                file_hash, raw_json, json.dumps(metadata or {})
            ))

        return evidence_id

    def map_to_control(self, evidence_id: str, framework: str, control_id: str,
                       control_name: str = '', control_family: str = '',
                       mapping_type: str = 'supports', notes: str = ''):
        """Map evidence to a compliance control."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO control_mappings
                (evidence_id, framework, control_id, control_name, control_family, mapping_type, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (evidence_id, framework, control_id, control_name, control_family, mapping_type, notes))

    def add_finding(self, session_id: str, severity: str, title: str,
                    description: str = '', affected_asset: str = '',
                    cvss_score: float = 0.0, cve_ids: List[str] = None,
                    remediation: str = '', evidence_id: str = None,
                    metadata: Optional[Dict] = None) -> str:
        """Add a security finding."""
        finding_id = self._generate_id('FND')

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO findings
                (finding_id, session_id, evidence_id, timestamp, severity, title,
                 description, affected_asset, cvss_score, cve_ids, remediation, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding_id, session_id, evidence_id,
                datetime.utcnow().isoformat(), severity, title, description,
                affected_asset, cvss_score, json.dumps(cve_ids or []),
                remediation, json.dumps(metadata or {})
            ))

        return finding_id

    def create_attestation(self, framework: str, control_id: str,
                           period_start: datetime, period_end: datetime,
                           status: str, evidence_ids: List[str],
                           attester: str = '', notes: str = '') -> str:
        """Create a control attestation."""
        attestation_id = self._generate_id('ATT')

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO attestations
                (attestation_id, framework, control_id, period_start, period_end,
                 status, evidence_ids, attester, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attestation_id, framework, control_id,
                period_start.isoformat(), period_end.isoformat(),
                status, json.dumps(evidence_ids), attester, notes
            ))

        return attestation_id

    def get_evidence_for_control(self, framework: str, control_id: str) -> List[Dict]:
        """Get all evidence mapped to a specific control."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT e.*, cm.mapping_type, cm.notes as mapping_notes
                FROM evidence e
                JOIN control_mappings cm ON e.evidence_id = cm.evidence_id
                WHERE cm.framework = ? AND cm.control_id = ?
                ORDER BY e.timestamp DESC
            ''', (framework, control_id))
            return [dict(row) for row in cursor.fetchall()]

    def get_findings_by_severity(self, severity: str = None,
                                  status: str = 'open') -> List[Dict]:
        """Get findings filtered by severity and status."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if severity:
                cursor = conn.execute('''
                    SELECT * FROM findings
                    WHERE severity = ? AND status = ?
                    ORDER BY cvss_score DESC, timestamp DESC
                ''', (severity, status))
            else:
                cursor = conn.execute('''
                    SELECT * FROM findings
                    WHERE status = ?
                    ORDER BY cvss_score DESC, timestamp DESC
                ''', (status,))
            return [dict(row) for row in cursor.fetchall()]

    def get_session_summary(self, session_id: str) -> Dict:
        """Get summary of a scanning session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get session info
            session = conn.execute(
                'SELECT * FROM sessions WHERE session_id = ?', (session_id,)
            ).fetchone()

            if not session:
                return {}

            # Count evidence
            evidence_count = conn.execute(
                'SELECT COUNT(*) FROM evidence WHERE session_id = ?', (session_id,)
            ).fetchone()[0]

            # Count findings by severity
            findings = conn.execute('''
                SELECT severity, COUNT(*) as count
                FROM findings WHERE session_id = ?
                GROUP BY severity
            ''', (session_id,)).fetchall()

            return {
                'session': dict(session),
                'evidence_count': evidence_count,
                'findings_by_severity': {row['severity']: row['count'] for row in findings}
            }

    def cleanup_old_evidence(self, retention_days: int = None):
        """Remove evidence older than retention period."""
        if retention_days is None:
            retention_days = config.get_retention_days()

        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Get sessions to clean up
            old_sessions = conn.execute('''
                SELECT session_id FROM sessions
                WHERE end_time < ? AND status = 'completed'
            ''', (cutoff,)).fetchall()

            for (session_id,) in old_sessions:
                # Delete related data
                conn.execute('DELETE FROM control_mappings WHERE evidence_id IN '
                           '(SELECT evidence_id FROM evidence WHERE session_id = ?)',
                           (session_id,))
                conn.execute('DELETE FROM findings WHERE session_id = ?', (session_id,))
                conn.execute('DELETE FROM evidence WHERE session_id = ?', (session_id,))
                conn.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))

                # Remove session directory
                session_dir = paths.results / session_id
                if session_dir.exists():
                    import shutil
                    shutil.rmtree(session_dir)

    def update_finding_enrichment(self, finding_id: str, kev_status: str = None,
                                   epss_score: float = None, epss_percentile: float = None,
                                   effective_priority: float = None,
                                   quality_of_detection: float = None,
                                   detection_source: str = None,
                                   false_positive: int = None, fp_reason: str = None,
                                   scanner_name: str = None):
        """Update enrichment data on an existing finding."""
        updates = []
        params = []

        field_map = {
            'kev_status': kev_status,
            'epss_score': epss_score,
            'epss_percentile': epss_percentile,
            'effective_priority': effective_priority,
            'quality_of_detection': quality_of_detection,
            'detection_source': detection_source,
            'false_positive': false_positive,
            'fp_reason': fp_reason,
            'scanner_name': scanner_name,
        }

        for field, value in field_map.items():
            if value is not None:
                updates.append(f"{field} = ?")
                params.append(value)

        if not updates:
            return

        params.append(finding_id)
        sql = f"UPDATE findings SET {', '.join(updates)} WHERE finding_id = ?"

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(sql, params)

    def add_override(self, match_rule: Dict, action: str = 'false_positive',
                     new_severity: str = None, reason: str = '',
                     created_by: str = 'analyst',
                     expires_days: int = None) -> str:
        """Add a finding override rule."""
        override_id = self._generate_id('OVR')

        expires_at = None
        if expires_days:
            expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO finding_overrides
                (override_id, match_rule, action, new_severity, reason, created_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                override_id, json.dumps(match_rule), action,
                new_severity, reason, created_by, expires_at
            ))

        return override_id

    def get_overrides(self, include_expired: bool = False) -> List[Dict]:
        """Get all active overrides."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if include_expired:
                cursor = conn.execute('SELECT * FROM finding_overrides ORDER BY created_at DESC')
            else:
                cursor = conn.execute('''
                    SELECT * FROM finding_overrides
                    WHERE expires_at IS NULL OR expires_at > ?
                    ORDER BY created_at DESC
                ''', (datetime.utcnow().isoformat(),))
            return [dict(row) for row in cursor.fetchall()]

    def check_overrides(self, finding: Dict) -> Optional[Dict]:
        """Check if any override applies to a finding."""
        overrides = self.get_overrides()

        for override in overrides:
            try:
                rule = json.loads(override['match_rule'])
            except (json.JSONDecodeError, TypeError):
                continue

            matches = True
            for key, value in rule.items():
                if key == 'title' and value.lower() not in finding.get('title', '').lower():
                    matches = False
                    break
                elif key == 'asset' and value != finding.get('affected_asset', ''):
                    matches = False
                    break
                elif key == 'scanner' and value != finding.get('scanner', ''):
                    matches = False
                    break
                elif key == 'cve' and value not in str(finding.get('cve_ids', [])):
                    matches = False
                    break

            if matches:
                return override

        return None

    def apply_overrides(self, findings_list: List[Dict]) -> List[Dict]:
        """Batch apply overrides to a list of findings."""
        for finding in findings_list:
            override = self.check_overrides(finding)
            if override:
                if override['action'] == 'false_positive':
                    finding['false_positive'] = 1
                    finding['fp_reason'] = override.get('reason', 'Override rule')
                elif override['action'] == 'severity_change' and override.get('new_severity'):
                    finding['original_severity'] = finding.get('severity')
                    finding['severity'] = override['new_severity']
                elif override['action'] == 'accepted_risk':
                    finding['status'] = 'accepted_risk'
                    finding['fp_reason'] = override.get('reason', 'Accepted risk')
        return findings_list

    def delete_override(self, override_id: str):
        """Delete an override by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM finding_overrides WHERE override_id = ?', (override_id,))

    def get_findings_for_session(self, session_id: str) -> List[Dict]:
        """Get all findings for a specific session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM findings
                WHERE session_id = ?
                ORDER BY effective_priority DESC, cvss_score DESC, timestamp DESC
            ''', (session_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_all_sessions(self, limit: int = 50) -> List[Dict]:
        """Get all sessions ordered by start time."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM sessions
                ORDER BY start_time DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def export_for_framework(self, framework: str, output_path: Path) -> Path:
        """Export all evidence for a specific framework."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get all controls with evidence
            controls = conn.execute('''
                SELECT DISTINCT cm.control_id, cm.control_name, cm.control_family
                FROM control_mappings cm
                WHERE cm.framework = ?
                ORDER BY cm.control_family, cm.control_id
            ''', (framework,)).fetchall()

            export_data = {
                'framework': framework,
                'export_date': datetime.utcnow().isoformat(),
                'controls': []
            }

            for control in controls:
                evidence = self.get_evidence_for_control(framework, control['control_id'])
                export_data['controls'].append({
                    'control_id': control['control_id'],
                    'control_name': control['control_name'],
                    'control_family': control['control_family'],
                    'evidence_count': len(evidence),
                    'evidence': evidence
                })

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

            return output_path


# Singleton instance
_evidence_manager: Optional[EvidenceManager] = None


def get_evidence_manager() -> EvidenceManager:
    """Get the evidence manager singleton."""
    global _evidence_manager
    if _evidence_manager is None:
        _evidence_manager = EvidenceManager()
    return _evidence_manager


if __name__ == '__main__':
    # Self-test
    em = get_evidence_manager()
    print(f"Evidence database: {paths.evidence_db}")
    print(f"Database exists: {paths.evidence_db.exists()}")

    # Test session
    session = em.start_session('test', ['192.168.1.0/24'])
    print(f"Created session: {session}")

    # Test evidence
    evd = em.add_evidence(session, 'scan_result', 'Test Scan',
                          description='Test evidence', source_tool='test')
    print(f"Created evidence: {evd}")

    # Test mapping
    em.map_to_control(evd, 'NIST-800-53', 'RA-5', 'Vulnerability Scanning',
                      'Risk Assessment')
    print("Mapped to NIST RA-5")

    # Test finding
    finding = em.add_finding(session, 'HIGH', 'Test Finding',
                             description='Test vulnerability',
                             cvss_score=7.5, evidence_id=evd)
    print(f"Created finding: {finding}")

    em.end_session(session, {'test': True})
    print("Session ended")
