#!/usr/bin/env python3
"""
Purple Team Portable - Scan Comparison/Diffing Module
Compares two or more scan sessions to identify what changed between scans.
Tracks finding trends over time and generates diff reports.
"""

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .evidence import get_evidence_manager
except ImportError:
    from paths import paths
    from evidence import get_evidence_manager


# ---------------------------------------------------------------------------
# Severity utilities
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1,
    'informational': 1,
    'none': 0,
}


def _severity_rank(severity: str) -> int:
    """Return numeric rank for a severity string."""
    return SEVERITY_ORDER.get((severity or '').strip().lower(), 0)


def _severity_label(rank: int) -> str:
    """Return the canonical label for a severity rank."""
    for label, r in SEVERITY_ORDER.items():
        if r == rank and label not in ('informational', 'none'):
            return label.upper()
    return 'UNKNOWN'


# ---------------------------------------------------------------------------
# Composite key helper
# ---------------------------------------------------------------------------

def _finding_key(finding: Dict) -> str:
    """Build a composite key from title + affected_asset + finding_type.

    The key is used to match findings across sessions.  We normalise the
    components to lower-case so that trivial casing differences do not
    cause false mismatches.
    """
    title = (finding.get('title') or '').strip().lower()
    asset = (finding.get('affected_asset') or '').strip().lower()
    # finding_type may not always be present; fall back to empty string
    ftype = (finding.get('finding_type') or finding.get('type') or '').strip().lower()
    return f"{title}||{asset}||{ftype}"


# ---------------------------------------------------------------------------
# ScanDiffer
# ---------------------------------------------------------------------------

class ScanDiffer:
    """Compares scan sessions to identify new, resolved, and changed findings."""

    def __init__(self):
        self.em = get_evidence_manager()
        self.db_path = paths.evidence_db

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _index_findings(self, findings: List[Dict]) -> Dict[str, Dict]:
        """Index a list of findings by composite key.

        When duplicate keys exist (same title+asset+type reported more than
        once in a session), we keep the one with the highest severity so that
        the comparison is conservative.
        """
        index: Dict[str, Dict] = {}
        for f in findings:
            key = _finding_key(f)
            if key in index:
                existing_rank = _severity_rank(index[key].get('severity', ''))
                new_rank = _severity_rank(f.get('severity', ''))
                if new_rank > existing_rank:
                    index[key] = f
            else:
                index[key] = f
        return index

    def _get_session_info(self, session_id: str) -> Optional[Dict]:
        """Retrieve basic session metadata."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                'SELECT * FROM sessions WHERE session_id = ?', (session_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compare_sessions(self, session_id_old: str,
                         session_id_new: str) -> Dict[str, Any]:
        """Compare two scan sessions and categorise finding differences.

        Returns a dict with keys:
            new_findings        - findings present only in the new session
            resolved_findings   - findings present only in the old session
            unchanged_findings  - findings present in both (same severity)
            severity_changes    - findings in both but with changed severity
            summary             - aggregate counts and net risk change
        """
        old_findings = self.em.get_findings_for_session(session_id_old)
        new_findings = self.em.get_findings_for_session(session_id_new)

        old_index = self._index_findings(old_findings)
        new_index = self._index_findings(new_findings)

        old_keys = set(old_index.keys())
        new_keys = set(new_index.keys())

        # Classify findings
        new_only_keys = new_keys - old_keys
        resolved_keys = old_keys - new_keys
        common_keys = old_keys & new_keys

        new_list: List[Dict] = [new_index[k] for k in sorted(new_only_keys)]
        resolved_list: List[Dict] = [old_index[k] for k in sorted(resolved_keys)]
        unchanged_list: List[Dict] = []
        severity_changes: List[Dict] = []

        for key in sorted(common_keys):
            old_sev = _severity_rank(old_index[key].get('severity', ''))
            new_sev = _severity_rank(new_index[key].get('severity', ''))
            if old_sev != new_sev:
                severity_changes.append({
                    'finding_old': old_index[key],
                    'finding_new': new_index[key],
                    'old_severity': old_index[key].get('severity', ''),
                    'new_severity': new_index[key].get('severity', ''),
                    'direction': 'escalated' if new_sev > old_sev else 'reduced',
                })
            else:
                unchanged_list.append(new_index[key])

        # Calculate net risk change (sum of severity ranks)
        old_risk = sum(_severity_rank(f.get('severity', '')) for f in old_findings)
        new_risk = sum(_severity_rank(f.get('severity', '')) for f in new_findings)
        net_risk_change = new_risk - old_risk

        summary = {
            'old_session': session_id_old,
            'new_session': session_id_new,
            'total_old': len(old_findings),
            'total_new': len(new_findings),
            'new_findings_count': len(new_list),
            'resolved_findings_count': len(resolved_list),
            'unchanged_count': len(unchanged_list),
            'severity_changes_count': len(severity_changes),
            'net_risk_change': net_risk_change,
            'risk_direction': (
                'increased' if net_risk_change > 0
                else 'decreased' if net_risk_change < 0
                else 'unchanged'
            ),
        }

        return {
            'new_findings': new_list,
            'resolved_findings': resolved_list,
            'unchanged_findings': unchanged_list,
            'severity_changes': severity_changes,
            'summary': summary,
        }

    # ------------------------------------------------------------------

    def get_trend(self, session_ids: List[str]) -> List[Dict]:
        """Return finding counts for each session in the provided list.

        The result is ordered by the supplied list (assumed chronological)
        and contains per-session counts broken down by severity.
        """
        trend: List[Dict] = []
        for sid in session_ids:
            info = self._get_session_info(sid)
            findings = self.em.get_findings_for_session(sid)

            severity_counts: Dict[str, int] = {}
            for f in findings:
                sev = (f.get('severity') or 'unknown').lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            total_risk = sum(_severity_rank(f.get('severity', '')) for f in findings)

            entry: Dict[str, Any] = {
                'session_id': sid,
                'start_time': info.get('start_time') if info else None,
                'scan_type': info.get('scan_type') if info else None,
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'total_risk_score': total_risk,
            }
            trend.append(entry)

        return trend

    # ------------------------------------------------------------------

    def get_finding_history(self, title_pattern: str,
                            asset: Optional[str] = None) -> List[Dict]:
        """Track occurrences of a specific finding type across all sessions.

        *title_pattern* is matched case-insensitively as a substring of the
        finding title.  Optionally narrow by *asset*.
        """
        pattern_lower = title_pattern.strip().lower()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if asset:
                cursor = conn.execute('''
                    SELECT f.*, s.start_time, s.scan_type
                    FROM findings f
                    LEFT JOIN sessions s ON f.session_id = s.session_id
                    WHERE LOWER(f.title) LIKE ? AND LOWER(f.affected_asset) = ?
                    ORDER BY s.start_time ASC, f.timestamp ASC
                ''', (f'%{pattern_lower}%', asset.strip().lower()))
            else:
                cursor = conn.execute('''
                    SELECT f.*, s.start_time, s.scan_type
                    FROM findings f
                    LEFT JOIN sessions s ON f.session_id = s.session_id
                    WHERE LOWER(f.title) LIKE ?
                    ORDER BY s.start_time ASC, f.timestamp ASC
                ''', (f'%{pattern_lower}%',))

            results = [dict(row) for row in cursor.fetchall()]

        return results

    # ------------------------------------------------------------------

    def generate_diff_report(self, session_old: str,
                             session_new: str) -> str:
        """Generate a human-readable text report of changes between two sessions."""
        diff = self.compare_sessions(session_old, session_new)
        summary = diff['summary']

        lines: List[str] = []
        width = 72

        lines.append('=' * width)
        lines.append('  SCAN DIFF REPORT')
        lines.append('=' * width)
        lines.append(f'  Generated : {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}')
        lines.append(f'  Old Session: {summary["old_session"]}')
        lines.append(f'  New Session: {summary["new_session"]}')
        lines.append('-' * width)

        # Summary section
        lines.append('')
        lines.append('  SUMMARY')
        lines.append('  ' + '-' * 40)
        lines.append(f'  Findings in old scan : {summary["total_old"]}')
        lines.append(f'  Findings in new scan : {summary["total_new"]}')
        lines.append(f'  New findings         : {summary["new_findings_count"]}')
        lines.append(f'  Resolved findings    : {summary["resolved_findings_count"]}')
        lines.append(f'  Unchanged findings   : {summary["unchanged_count"]}')
        lines.append(f'  Severity changes     : {summary["severity_changes_count"]}')
        lines.append(f'  Net risk change      : {summary["net_risk_change"]:+d} ({summary["risk_direction"]})')
        lines.append('')

        # New findings
        if diff['new_findings']:
            lines.append('-' * width)
            lines.append(f'  NEW FINDINGS ({len(diff["new_findings"])})')
            lines.append('-' * width)
            for f in diff['new_findings']:
                sev = (f.get('severity') or 'UNKNOWN').upper()
                title = f.get('title', 'Untitled')
                asset = f.get('affected_asset', 'N/A')
                cvss = f.get('cvss_score', 0.0) or 0.0
                lines.append(f'  [{sev}] {title}')
                lines.append(f'         Asset: {asset}  |  CVSS: {cvss}')
                desc = f.get('description', '')
                if desc:
                    # Wrap description at ~60 chars
                    for i in range(0, len(desc), 60):
                        lines.append(f'         {desc[i:i+60]}')
                lines.append('')

        # Resolved findings
        if diff['resolved_findings']:
            lines.append('-' * width)
            lines.append(f'  RESOLVED FINDINGS ({len(diff["resolved_findings"])})')
            lines.append('-' * width)
            for f in diff['resolved_findings']:
                sev = (f.get('severity') or 'UNKNOWN').upper()
                title = f.get('title', 'Untitled')
                asset = f.get('affected_asset', 'N/A')
                lines.append(f'  [{sev}] {title}')
                lines.append(f'         Asset: {asset}')
                lines.append('')

        # Severity changes
        if diff['severity_changes']:
            lines.append('-' * width)
            lines.append(f'  SEVERITY CHANGES ({len(diff["severity_changes"])})')
            lines.append('-' * width)
            for sc in diff['severity_changes']:
                title = sc['finding_new'].get('title', 'Untitled')
                asset = sc['finding_new'].get('affected_asset', 'N/A')
                old_s = sc['old_severity'].upper()
                new_s = sc['new_severity'].upper()
                direction = sc['direction'].upper()
                lines.append(f'  [{direction}] {title}')
                lines.append(f'         Asset: {asset}')
                lines.append(f'         {old_s} -> {new_s}')
                lines.append('')

        # Unchanged (brief)
        lines.append('-' * width)
        lines.append(f'  UNCHANGED FINDINGS ({len(diff["unchanged_findings"])})')
        lines.append('-' * width)
        if diff['unchanged_findings']:
            for f in diff['unchanged_findings']:
                sev = (f.get('severity') or 'UNKNOWN').upper()
                title = f.get('title', 'Untitled')
                lines.append(f'  [{sev}] {title}')
        else:
            lines.append('  (none)')

        lines.append('')
        lines.append('=' * width)
        lines.append('  END OF REPORT')
        lines.append('=' * width)

        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def get_latest_sessions(self, limit: int = 10) -> List[Dict]:
        """Return the most recent sessions (thin wrapper for trend usage)."""
        return self.em.get_all_sessions(limit=limit)

    def auto_trend(self, limit: int = 10) -> List[Dict]:
        """Build a trend from the most recent *limit* sessions automatically."""
        sessions = self.get_latest_sessions(limit=limit)
        # Chronological order (oldest first)
        sessions.sort(key=lambda s: s.get('start_time', ''))
        session_ids = [s['session_id'] for s in sessions]
        return self.get_trend(session_ids)

    def get_risk_delta(self, session_id_old: str,
                       session_id_new: str) -> Dict[str, Any]:
        """Quick risk-only comparison without full diff detail."""
        old_findings = self.em.get_findings_for_session(session_id_old)
        new_findings = self.em.get_findings_for_session(session_id_new)

        def _counts(findings: List[Dict]) -> Dict[str, int]:
            counts: Dict[str, int] = {}
            for f in findings:
                sev = (f.get('severity') or 'unknown').lower()
                counts[sev] = counts.get(sev, 0) + 1
            return counts

        old_counts = _counts(old_findings)
        new_counts = _counts(new_findings)
        all_sevs = set(old_counts.keys()) | set(new_counts.keys())

        deltas: Dict[str, int] = {}
        for sev in sorted(all_sevs, key=lambda s: _severity_rank(s), reverse=True):
            deltas[sev] = new_counts.get(sev, 0) - old_counts.get(sev, 0)

        old_risk = sum(_severity_rank(f.get('severity', '')) for f in old_findings)
        new_risk = sum(_severity_rank(f.get('severity', '')) for f in new_findings)

        return {
            'old_session': session_id_old,
            'new_session': session_id_new,
            'old_counts': old_counts,
            'new_counts': new_counts,
            'deltas': deltas,
            'old_risk_score': old_risk,
            'new_risk_score': new_risk,
            'net_risk_change': new_risk - old_risk,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_scan_differ: Optional[ScanDiffer] = None


def get_scan_differ() -> ScanDiffer:
    """Get the scan differ singleton."""
    global _scan_differ
    if _scan_differ is None:
        _scan_differ = ScanDiffer()
    return _scan_differ


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    sd = get_scan_differ()
    print("ScanDiffer initialised successfully.")
    sessions = sd.get_latest_sessions(limit=5)
    print(f"Recent sessions: {len(sessions)}")
    for s in sessions:
        print(f"  {s.get('session_id')}  {s.get('start_time')}  {s.get('scan_type')}")
    if len(sessions) >= 2:
        old_s = sessions[-1]['session_id']
        new_s = sessions[0]['session_id']
        report = sd.generate_diff_report(old_s, new_s)
        print(report)
    else:
        print("Need at least 2 sessions to demonstrate diff.")
