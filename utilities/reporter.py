#!/usr/bin/env python3
"""
Purple Team Portable - Report Generator
Generates comprehensive reports in multiple formats for auditors.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from paths import paths
from config import config
from evidence import get_evidence_manager
from compliance import get_compliance_mapper
from logger import get_logger


class ReportGenerator:
    """Generates audit-ready reports in multiple formats."""

    def __init__(self):
        self.paths = paths
        self.config = config
        self.evidence = get_evidence_manager()
        self.compliance = get_compliance_mapper()
        self.logger = get_logger('reporter')

    def generate_executive_summary(self, session_id: str,
                                    output_path: Path = None) -> Path:
        """Generate executive summary report."""
        session_summary = self.evidence.get_session_summary(session_id)

        if not session_summary:
            raise ValueError(f"Session {session_id} not found")

        if not output_path:
            output_path = self.paths.reports / f"executive_summary_{session_id}.html"

        html_content = self._build_executive_html(session_summary)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)

        self.logger.info(f"Executive summary saved to {output_path}")
        return output_path

    def _build_executive_html(self, summary: Dict) -> str:
        """Build executive summary HTML."""
        session = summary.get('session', {})
        findings = summary.get('findings_by_severity', {})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Executive Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4a90d9; padding-bottom: 10px; }}
        h2 {{ color: #4a90d9; margin-top: 30px; }}
        .summary-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .severity-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
        .severity-card {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}
        .severity-count {{ font-size: 36px; font-weight: bold; }}
        .severity-label {{ font-size: 14px; text-transform: uppercase; }}
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #e9ecef; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 28px; font-weight: bold; color: #4a90d9; }}
        .metric-label {{ color: #666; margin-top: 5px; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Executive Summary</h1>

        <div class="summary-box">
            <strong>Session ID:</strong> {session.get('session_id', 'N/A')}<br>
            <strong>Scan Type:</strong> {session.get('scan_type', 'N/A')}<br>
            <strong>Start Time:</strong> {session.get('start_time', 'N/A')}<br>
            <strong>End Time:</strong> {session.get('end_time', 'N/A')}<br>
            <strong>Status:</strong> {session.get('status', 'N/A')}
        </div>

        <h2>Findings by Severity</h2>
        <div class="severity-grid">
            <div class="severity-card critical">
                <div class="severity-count">{findings.get('CRITICAL', 0)}</div>
                <div class="severity-label">Critical</div>
            </div>
            <div class="severity-card high">
                <div class="severity-count">{findings.get('HIGH', 0)}</div>
                <div class="severity-label">High</div>
            </div>
            <div class="severity-card medium">
                <div class="severity-count">{findings.get('MEDIUM', 0)}</div>
                <div class="severity-label">Medium</div>
            </div>
            <div class="severity-card low">
                <div class="severity-count">{findings.get('LOW', 0)}</div>
                <div class="severity-label">Low</div>
            </div>
            <div class="severity-card info">
                <div class="severity-count">{findings.get('INFO', 0)}</div>
                <div class="severity-label">Info</div>
            </div>
        </div>

        <h2>Assessment Metrics</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{summary.get('evidence_count', 0)}</div>
                <div class="metric-label">Evidence Collected</div>
            </div>
            <div class="metric">
                <div class="metric-value">{sum(findings.values())}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="metric-value">{findings.get('CRITICAL', 0) + findings.get('HIGH', 0)}</div>
                <div class="metric-label">Critical/High Issues</div>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Purple Team Portable v4.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>This report is intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def generate_compliance_report(self, framework: str,
                                    output_path: Path = None) -> Path:
        """Generate compliance report for a specific framework."""
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"compliance_{framework}_{timestamp}.html"

        summary = self.compliance.generate_compliance_summary(self.evidence, framework)

        html_content = self._build_compliance_html(summary)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)

        self.logger.info(f"Compliance report saved to {output_path}")
        return output_path

    def _build_compliance_html(self, summary: Dict) -> str:
        """Build compliance report HTML."""
        framework = summary.get('framework', 'Unknown')
        total = summary.get('total_controls', 0)
        with_evidence = summary.get('controls_with_evidence', 0)
        without_evidence = summary.get('controls_without_evidence', 0)
        compliance_rate = (with_evidence / total * 100) if total > 0 else 0

        # Build control rows
        control_rows = ""
        for control in summary.get('control_details', []):
            status_class = 'pass' if control['has_evidence'] else 'fail'
            status_text = '✓ Evidence' if control['has_evidence'] else '✗ Gap'

            control_rows += f"""
            <tr class="{status_class}">
                <td>{control['control_id']}</td>
                <td>{control['control_name']}</td>
                <td>{control['family']}</td>
                <td>{control['evidence_count']}</td>
                <td>{status_text}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{framework} Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4a90d9; padding-bottom: 10px; }}
        h2 {{ color: #4a90d9; margin-top: 30px; }}
        .compliance-meter {{ background: #e9ecef; border-radius: 10px; height: 30px; margin: 20px 0; overflow: hidden; }}
        .compliance-fill {{ background: linear-gradient(90deg, #28a745, #4a90d9); height: 100%; border-radius: 10px; transition: width 0.5s; }}
        .compliance-rate {{ font-size: 48px; font-weight: bold; color: #4a90d9; text-align: center; margin: 20px 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-value {{ font-size: 32px; font-weight: bold; }}
        .summary-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4a90d9; color: white; }}
        tr.pass td:last-child {{ color: #28a745; font-weight: bold; }}
        tr.fail td:last-child {{ color: #dc3545; font-weight: bold; }}
        tr:hover {{ background: #f5f5f5; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{framework} Compliance Report</h1>

        <div class="compliance-rate">{compliance_rate:.1f}%</div>
        <div class="compliance-meter">
            <div class="compliance-fill" style="width: {compliance_rate}%;"></div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{total}</div>
                <div class="summary-label">Total Controls</div>
            </div>
            <div class="summary-card">
                <div class="summary-value" style="color: #28a745;">{with_evidence}</div>
                <div class="summary-label">With Evidence</div>
            </div>
            <div class="summary-card">
                <div class="summary-value" style="color: #dc3545;">{without_evidence}</div>
                <div class="summary-label">Gaps</div>
            </div>
        </div>

        <h2>Control Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Control Name</th>
                    <th>Family</th>
                    <th>Evidence Count</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {control_rows}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by Purple Team Portable v4.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>This report is intended for authorized audit personnel only.</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def generate_findings_csv(self, session_id: str = None,
                               output_path: Path = None) -> Path:
        """Generate CSV export of all findings."""
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"findings_{session_id or 'all'}_{timestamp}.csv"
            output_path = self.paths.reports / filename

        # Get findings
        findings = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            findings.extend(self.evidence.get_findings_by_severity(severity, 'open'))

        # Write CSV
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            # Header
            f.write("Finding ID,Session ID,Timestamp,Severity,Title,Description,")
            f.write("Affected Asset,CVSS Score,CVE IDs,Status,Remediation\n")

            for finding in findings:
                cve_ids = finding.get('cve_ids', '[]')
                if isinstance(cve_ids, str):
                    cve_ids = cve_ids.replace(',', ';')

                row = [
                    finding.get('finding_id', ''),
                    finding.get('session_id', ''),
                    finding.get('timestamp', ''),
                    finding.get('severity', ''),
                    f"\"{finding.get('title', '').replace('\"', '\"\"')}\"",
                    f"\"{finding.get('description', '').replace('\"', '\"\"')[:500]}\"",
                    finding.get('affected_asset', ''),
                    str(finding.get('cvss_score', 0)),
                    cve_ids,
                    finding.get('status', ''),
                    f"\"{finding.get('remediation', '').replace('\"', '\"\"')[:200]}\""
                ]
                f.write(','.join(row) + '\n')

        self.logger.info(f"Findings CSV saved to {output_path}")
        return output_path

    def generate_json_export(self, session_id: str,
                              output_path: Path = None) -> Path:
        """Generate JSON export for GRC platform import."""
        if not output_path:
            output_path = self.paths.reports / f"export_{session_id}.json"

        session_summary = self.evidence.get_session_summary(session_id)
        findings = self.evidence.get_findings_by_severity(status='open')

        export_data = {
            'export_version': '1.0',
            'export_date': datetime.utcnow().isoformat(),
            'platform': 'Purple Team Portable v4.0',
            'session': session_summary.get('session', {}),
            'summary': {
                'evidence_count': session_summary.get('evidence_count', 0),
                'findings_by_severity': session_summary.get('findings_by_severity', {})
            },
            'findings': findings,
            'compliance': {}
        }

        # Add compliance data for each framework
        for framework in self.config.get_frameworks():
            export_data['compliance'][framework] = self.compliance.generate_compliance_summary(
                self.evidence, framework
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        self.logger.info(f"JSON export saved to {output_path}")
        return output_path


    def generate_delta_report(self, session_id_1: str, session_id_2: str,
                               output_path: Path = None) -> Path:
        """Generate delta report comparing two sessions."""
        try:
            from delta_report import DeltaReporter
        except ImportError:
            import sys
            sys.path.insert(0, str(Path(__file__).parent))
            from delta_report import DeltaReporter

        delta = DeltaReporter()
        comparison = delta.compare_sessions(session_id_1, session_id_2)

        if not output_path:
            output_path = self.paths.reports / f"delta_{session_id_1}_vs_{session_id_2}.html"

        html_content = delta.generate_delta_html(comparison)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)

        self.logger.info(f"Delta report saved to {output_path}")
        return output_path

    def generate_trend_report(self, last_n_sessions: int = 10,
                               output_path: Path = None) -> Path:
        """Generate trend analysis report."""
        try:
            from delta_report import DeltaReporter
        except ImportError:
            import sys
            sys.path.insert(0, str(Path(__file__).parent))
            from delta_report import DeltaReporter

        delta = DeltaReporter()
        trends = delta.trend_analysis(last_n_sessions)

        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"trend_analysis_{timestamp}.html"

        html_content = self._build_trend_html(trends)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)

        self.logger.info(f"Trend report saved to {output_path}")
        return output_path

    def _build_trend_html(self, trends: Dict) -> str:
        """Build trend analysis HTML report."""
        findings_data = trends.get('findings_over_time', [])
        risk_trend = trends.get('risk_trend', 'unknown')
        mttr = trends.get('mean_time_to_remediate_days')
        recurring = trends.get('top_recurring_findings', [])

        # Build trend rows
        trend_rows = ""
        for entry in findings_data:
            sc = entry.get('severity_counts', {})
            trend_rows += f"""
            <tr>
                <td>{entry.get('session_id', '')[:25]}</td>
                <td>{entry.get('start_time', '')[:19]}</td>
                <td style="color:#dc3545;font-weight:bold">{sc.get('CRITICAL', 0)}</td>
                <td style="color:#fd7e14;font-weight:bold">{sc.get('HIGH', 0)}</td>
                <td style="color:#ffc107">{sc.get('MEDIUM', 0)}</td>
                <td style="color:#28a745">{sc.get('LOW', 0)}</td>
                <td>{entry.get('total', 0)}</td>
            </tr>"""

        recurring_rows = ""
        for r in recurring[:10]:
            recurring_rows += f"""
            <tr>
                <td>{r.get('finding', '')[:80]}</td>
                <td>{r.get('session_count', 0)}</td>
            </tr>"""

        trend_color = '#dc3545' if risk_trend == 'increasing' else '#28a745' if risk_trend == 'decreasing' else '#ffc107'

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Trend Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #6f42c1; padding-bottom: 10px; }}
        h2 {{ color: #6f42c1; margin-top: 30px; }}
        .trend-badge {{ display: inline-block; padding: 8px 16px; border-radius: 20px; color: white; font-weight: bold; background: {trend_color}; }}
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 28px; font-weight: bold; color: #6f42c1; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #6f42c1; color: white; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Trend Analysis</h1>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{trends.get('sessions_analyzed', 0)}</div>
                <div>Sessions Analyzed</div>
            </div>
            <div class="metric">
                <div class="trend-badge">{risk_trend.upper()}</div>
                <div style="margin-top:8px">Risk Trend</div>
            </div>
            <div class="metric">
                <div class="metric-value">{mttr or 'N/A'}</div>
                <div>Avg Days to Remediate</div>
            </div>
        </div>

        <h2>Findings Over Time</h2>
        <table>
            <thead><tr><th>Session</th><th>Date</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
            <tbody>{trend_rows if trend_rows else '<tr><td colspan="7">No data</td></tr>'}</tbody>
        </table>

        <h2>Top Recurring Findings</h2>
        <table>
            <thead><tr><th>Finding</th><th>Sessions</th></tr></thead>
            <tbody>{recurring_rows if recurring_rows else '<tr><td colspan="2">No recurring findings</td></tr>'}</tbody>
        </table>

        <div class="footer">
            <p>Generated by Purple Team Platform v6.0 on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>"""


if __name__ == '__main__':
    reporter = ReportGenerator()
    print("Report Generator initialized")
    print(f"Reports directory: {reporter.paths.reports}")
