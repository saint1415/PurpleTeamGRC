#!/usr/bin/env python3
"""
Purple Team Platform v6.0 - Delta Reporting & Trend Analysis
Matches OpenVAS delta reports. Compare scan sessions, track trends,
calculate mean time to remediate, identify recurring findings.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from paths import paths
from evidence import get_evidence_manager
from logger import get_logger

logger = get_logger('delta_report')


class DeltaReporter:
    """Compare scan sessions and generate trend analysis."""

    def __init__(self):
        self.db_path = paths.evidence_db
        self.evidence = get_evidence_manager()

    def compare_sessions(self, session_id_1: str, session_id_2: str) -> Dict:
        """
        Compare two scan sessions and return delta.

        Returns:
            new_findings: findings in session 2 not in session 1
            resolved_findings: findings in session 1 not in session 2
            persistent_findings: findings in both sessions
            changed_severity: findings where severity changed
            new_assets: assets first seen in session 2
            removed_assets: assets not seen in session 2
        """
        findings_1 = self.evidence.get_findings_for_session(session_id_1)
        findings_2 = self.evidence.get_findings_for_session(session_id_2)

        # Build fingerprints for matching
        def fingerprint(f):
            """Create matching key: same CVE OR (same title + same asset + same scanner)."""
            cve_ids = f.get('cve_ids', '[]')
            if isinstance(cve_ids, str):
                try:
                    cve_ids = json.loads(cve_ids)
                except json.JSONDecodeError:
                    cve_ids = []
            # Use first CVE as primary key if available
            if cve_ids:
                return f"cve:{cve_ids[0]}:{f.get('affected_asset', '')}"
            return f"title:{f.get('title', '')}:{f.get('affected_asset', '')}:{f.get('scanner_name', '')}"

        fp_map_1 = {fingerprint(f): f for f in findings_1}
        fp_map_2 = {fingerprint(f): f for f in findings_2}

        fps_1 = set(fp_map_1.keys())
        fps_2 = set(fp_map_2.keys())

        # Delta calculations
        new_fps = fps_2 - fps_1
        resolved_fps = fps_1 - fps_2
        persistent_fps = fps_1 & fps_2

        # Check for severity changes in persistent findings
        changed_severity = []
        for fp in persistent_fps:
            f1 = fp_map_1[fp]
            f2 = fp_map_2[fp]
            if f1.get('severity') != f2.get('severity'):
                changed_severity.append({
                    'finding': f2,
                    'old_severity': f1.get('severity'),
                    'new_severity': f2.get('severity'),
                })

        # Asset comparison
        assets_1 = set(f.get('affected_asset', '') for f in findings_1 if f.get('affected_asset'))
        assets_2 = set(f.get('affected_asset', '') for f in findings_2 if f.get('affected_asset'))

        return {
            'session_1': session_id_1,
            'session_2': session_id_2,
            'new_findings': [fp_map_2[fp] for fp in new_fps],
            'resolved_findings': [fp_map_1[fp] for fp in resolved_fps],
            'persistent_findings': [fp_map_2[fp] for fp in persistent_fps],
            'changed_severity': changed_severity,
            'new_assets': list(assets_2 - assets_1),
            'removed_assets': list(assets_1 - assets_2),
            'summary': {
                'new_count': len(new_fps),
                'resolved_count': len(resolved_fps),
                'persistent_count': len(persistent_fps),
                'severity_changes': len(changed_severity),
                'new_assets_count': len(assets_2 - assets_1),
                'removed_assets_count': len(assets_1 - assets_2),
            }
        }

    def trend_analysis(self, last_n_sessions: int = 10) -> Dict:
        """
        Analyze trends across recent scan sessions.

        Returns:
            findings_over_time: count by severity per session
            mean_time_to_remediate: avg days between finding open -> resolved
            top_recurring_findings: findings that persist across sessions
            risk_trend: increasing/decreasing/stable
        """
        sessions = self.evidence.get_all_sessions(limit=last_n_sessions)

        if not sessions:
            return {'error': 'No sessions found'}

        findings_over_time = []
        all_finding_fps = {}  # fingerprint -> list of session_ids

        for session in sessions:
            sid = session['session_id']
            findings = self.evidence.get_findings_for_session(sid)

            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for f in findings:
                sev = f.get('severity', 'INFO').upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1

                # Track recurrence
                fp = f"{f.get('title', '')}:{f.get('affected_asset', '')}"
                if fp not in all_finding_fps:
                    all_finding_fps[fp] = []
                all_finding_fps[fp].append(sid)

            findings_over_time.append({
                'session_id': sid,
                'start_time': session.get('start_time', ''),
                'severity_counts': severity_counts,
                'total': sum(severity_counts.values()),
            })

        # Top recurring findings (appear in most sessions)
        recurring = sorted(
            [
                {'finding': fp, 'session_count': len(sids), 'sessions': sids}
                for fp, sids in all_finding_fps.items()
                if len(sids) > 1
            ],
            key=lambda x: -x['session_count']
        )[:20]

        # Risk trend (compare first half vs second half of sessions)
        if len(findings_over_time) >= 2:
            mid = len(findings_over_time) // 2
            first_half_avg = sum(f['total'] for f in findings_over_time[:mid]) / max(mid, 1)
            second_half_avg = sum(f['total'] for f in findings_over_time[mid:]) / max(len(findings_over_time) - mid, 1)

            if second_half_avg > first_half_avg * 1.1:
                risk_trend = 'increasing'
            elif second_half_avg < first_half_avg * 0.9:
                risk_trend = 'decreasing'
            else:
                risk_trend = 'stable'
        else:
            risk_trend = 'insufficient_data'

        # Mean time to remediate (estimated from resolved findings between sessions)
        mttr_days = self._calculate_mttr(sessions)

        return {
            'sessions_analyzed': len(sessions),
            'findings_over_time': findings_over_time,
            'mean_time_to_remediate_days': mttr_days,
            'top_recurring_findings': recurring,
            'risk_trend': risk_trend,
        }

    def _calculate_mttr(self, sessions: List[Dict]) -> Optional[float]:
        """Calculate mean time to remediate based on session comparisons."""
        if len(sessions) < 2:
            return None

        total_days = 0
        resolved_count = 0

        for i in range(len(sessions) - 1):
            s1 = sessions[i + 1]  # older
            s2 = sessions[i]      # newer

            try:
                delta = self.compare_sessions(s1['session_id'], s2['session_id'])
                resolved = len(delta.get('resolved_findings', []))
                if resolved > 0:
                    t1 = datetime.fromisoformat(s1.get('start_time', ''))
                    t2 = datetime.fromisoformat(s2.get('start_time', ''))
                    days = (t2 - t1).days
                    total_days += days * resolved
                    resolved_count += resolved
            except Exception:
                continue

        if resolved_count > 0:
            return round(total_days / resolved_count, 1)
        return None

    def generate_delta_html(self, comparison: Dict) -> str:
        """Generate HTML report with visual diff of two sessions."""
        summary = comparison.get('summary', {})

        new_rows = ""
        for f in comparison.get('new_findings', [])[:50]:
            sev = f.get('severity', 'INFO')
            sev_class = sev.lower()
            new_rows += f"""
            <tr class="new-finding">
                <td><span class="badge {sev_class}">{sev}</span></td>
                <td>{f.get('title', 'N/A')}</td>
                <td>{f.get('affected_asset', 'N/A')}</td>
                <td>{f.get('cvss_score', 0)}</td>
            </tr>"""

        resolved_rows = ""
        for f in comparison.get('resolved_findings', [])[:50]:
            sev = f.get('severity', 'INFO')
            resolved_rows += f"""
            <tr class="resolved-finding">
                <td><span class="badge {sev.lower()}">{sev}</span></td>
                <td>{f.get('title', 'N/A')}</td>
                <td>{f.get('affected_asset', 'N/A')}</td>
                <td>{f.get('cvss_score', 0)}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Delta Report: {comparison.get('session_1', '')} vs {comparison.get('session_2', '')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #6f42c1; padding-bottom: 10px; }}
        h2 {{ color: #6f42c1; margin-top: 30px; }}
        .delta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .delta-card {{ padding: 20px; border-radius: 8px; text-align: center; }}
        .delta-new {{ background: #fff3cd; border: 2px solid #ffc107; }}
        .delta-resolved {{ background: #d4edda; border: 2px solid #28a745; }}
        .delta-persistent {{ background: #d1ecf1; border: 2px solid #17a2b8; }}
        .delta-count {{ font-size: 36px; font-weight: bold; }}
        .delta-label {{ font-size: 14px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #6f42c1; color: white; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; color: white; font-size: 12px; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}
        .new-finding {{ background: #fff8e1; }}
        .resolved-finding {{ background: #e8f5e9; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Delta Report</h1>
        <p><strong>Baseline:</strong> {comparison.get('session_1', 'N/A')} |
           <strong>Current:</strong> {comparison.get('session_2', 'N/A')}</p>

        <div class="delta-grid">
            <div class="delta-card delta-new">
                <div class="delta-count">{summary.get('new_count', 0)}</div>
                <div class="delta-label">New Findings</div>
            </div>
            <div class="delta-card delta-resolved">
                <div class="delta-count">{summary.get('resolved_count', 0)}</div>
                <div class="delta-label">Resolved</div>
            </div>
            <div class="delta-card delta-persistent">
                <div class="delta-count">{summary.get('persistent_count', 0)}</div>
                <div class="delta-label">Persistent</div>
            </div>
        </div>

        <h2>New Findings (Regression)</h2>
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>CVSS</th></tr></thead>
            <tbody>{new_rows if new_rows else '<tr><td colspan="4">No new findings</td></tr>'}</tbody>
        </table>

        <h2>Resolved Findings (Progress)</h2>
        <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>CVSS</th></tr></thead>
            <tbody>{resolved_rows if resolved_rows else '<tr><td colspan="4">No resolved findings</td></tr>'}</tbody>
        </table>

        <h2>Asset Changes</h2>
        <p><strong>New assets:</strong> {', '.join(comparison.get('new_assets', [])) or 'None'}</p>
        <p><strong>Removed assets:</strong> {', '.join(comparison.get('removed_assets', [])) or 'None'}</p>

        <div class="footer">
            <p>Generated by Purple Team Platform v6.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def generate_trend_ascii(self, trend_data: Dict) -> str:
        """Generate ASCII trend chart for terminal display."""
        findings = trend_data.get('findings_over_time', [])
        if not findings:
            return "No trend data available."

        lines = []
        lines.append("Findings Trend (last sessions):")
        lines.append("-" * 60)

        max_total = max(f['total'] for f in findings) if findings else 1

        for entry in reversed(findings):  # oldest first
            sid = entry['session_id'][:20]
            total = entry['total']
            bar_len = int((total / max(max_total, 1)) * 30)
            bar = "#" * bar_len

            crit = entry['severity_counts'].get('CRITICAL', 0)
            high = entry['severity_counts'].get('HIGH', 0)

            lines.append(f"  {sid:<20} |{bar:<30}| {total:>4} (C:{crit} H:{high})")

        lines.append("-" * 60)
        lines.append(f"Risk trend: {trend_data.get('risk_trend', 'unknown')}")

        mttr = trend_data.get('mean_time_to_remediate_days')
        if mttr:
            lines.append(f"Mean time to remediate: {mttr} days")

        return "\n".join(lines)


if __name__ == '__main__':
    reporter = DeltaReporter()
    print("Delta Reporter initialized")
    print(f"Database: {reporter.db_path}")

    # Test trend analysis
    print("\nTrend Analysis:")
    trends = reporter.trend_analysis(last_n_sessions=5)
    for k, v in trends.items():
        if k != 'findings_over_time' and k != 'top_recurring_findings':
            print(f"  {k}: {v}")

    print(f"\n{reporter.generate_trend_ascii(trends)}")
