#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Executive Dashboard
Terminal-based and HTML-export security dashboard.
Displays risk gauges, finding trends, compliance meters, and key metrics.
"""

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from paths import paths
from config import config
from evidence import get_evidence_manager
from compliance import get_compliance_mapper
from asset_manager import get_asset_manager
from logger import get_logger
from tui import C, TUI


class ExecutiveDashboard:
    """Terminal-based and HTML-export executive security dashboard."""

    def __init__(self):
        self.paths = paths
        self.evidence = get_evidence_manager()
        self.compliance = get_compliance_mapper()
        self.assets = get_asset_manager()
        self.logger = get_logger('dashboard')
        self.tui = TUI()

    # ------------------------------------------------------------------
    # Data aggregation
    # ------------------------------------------------------------------

    def _get_dashboard_data(self, session_id: str = None) -> dict:
        """
        Aggregate dashboard data from evidence.db.
        Uses the latest session when session_id is not provided.
        """
        # Resolve session
        if not session_id:
            sessions = self.evidence.get_all_sessions(limit=1)
            if sessions:
                session_id = sessions[0]['session_id']

        # Findings by severity
        findings_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        top_findings: List[Dict] = []

        if session_id:
            all_findings = self.evidence.get_findings_for_session(session_id)
            for f in all_findings:
                sev = f.get('severity', 'INFO').upper()
                if sev in findings_by_severity:
                    findings_by_severity[sev] += 1

            # Top 5 critical/high findings sorted by CVSS
            critical_high = [
                f for f in all_findings
                if f.get('severity', '').upper() in ('CRITICAL', 'HIGH')
            ]
            critical_high.sort(key=lambda x: float(x.get('cvss_score', 0) or 0), reverse=True)
            top_findings = critical_high[:5]

        risk_score = self._calculate_risk_score(findings_by_severity)
        compliance_rates = self._get_compliance_rates()
        asset_summary = self.assets.get_inventory_summary()
        trend = self._get_trend(last_n=5)

        return {
            'session_id': session_id or 'N/A',
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'risk_score': risk_score,
            'findings_by_severity': findings_by_severity,
            'total_findings': sum(findings_by_severity.values()),
            'top_findings': top_findings,
            'compliance_rates': compliance_rates,
            'asset_count': asset_summary.get('total_assets', 0),
            'open_ports': asset_summary.get('total_open_ports', 0),
            'trend': trend,
        }

    def _calculate_risk_score(self, findings_by_severity: dict) -> int:
        """
        Calculate a composite risk score from 0-100.
        CRITICAL * 10  +  HIGH * 7  +  MEDIUM * 4  +  LOW * 1
        Capped at 100.
        """
        score = (
            findings_by_severity.get('CRITICAL', 0) * 10
            + findings_by_severity.get('HIGH', 0) * 7
            + findings_by_severity.get('MEDIUM', 0) * 4
            + findings_by_severity.get('LOW', 0) * 1
        )
        return min(score, 100)

    def _get_compliance_rates(self) -> dict:
        """
        For each active framework, compute the percentage of controls
        that have supporting evidence.
        """
        rates: Dict[str, float] = {}
        frameworks = config.get_frameworks()

        for fw in frameworks:
            try:
                summary = self.compliance.generate_compliance_summary(self.evidence, fw)
                total = summary.get('total_controls', 0)
                with_ev = summary.get('controls_with_evidence', 0)
                if total > 0:
                    rates[fw] = round(with_ev / total * 100, 1)
                else:
                    rates[fw] = 0.0
            except Exception:
                # Framework may not have controls loaded
                continue

        return rates

    def _get_trend(self, last_n: int = 5) -> str:
        """
        Compare recent sessions' total finding counts.
        Returns 'improving', 'worsening', or 'stable'.
        """
        sessions = self.evidence.get_all_sessions(limit=last_n)
        if len(sessions) < 2:
            return 'stable'

        totals = []
        for sess in sessions:
            findings = self.evidence.get_findings_for_session(sess['session_id'])
            totals.append(len(findings))

        # sessions are newest-first; compare newest half vs oldest half
        mid = len(totals) // 2
        newer_avg = sum(totals[:mid]) / max(mid, 1)
        older_avg = sum(totals[mid:]) / max(len(totals) - mid, 1)

        if newer_avg < older_avg * 0.9:
            return 'improving'
        elif newer_avg > older_avg * 1.1:
            return 'worsening'
        return 'stable'

    # ------------------------------------------------------------------
    # Terminal dashboard
    # ------------------------------------------------------------------

    def display_terminal_dashboard(self, session_id: str = None):
        """
        Render an ANSI-colored dashboard in the terminal.
        Uses box-drawing characters; no curses required.
        """
        data = self._get_dashboard_data(session_id)
        W = 54  # inner width

        H  = TUI.BOX_H
        V  = TUI.BOX_V
        TL = TUI.BOX_TL
        TR = TUI.BOX_TR
        BL = TUI.BOX_BL
        BR = TUI.BOX_BR
        LT = TUI.BOX_LT
        RT = TUI.BOX_RT

        def row(text: str):
            """Pad text inside box walls."""
            stripped = text
            # Visible length approximation (strip ANSI)
            import re
            vis = re.sub(r'\033\[[0-9;]*m', '', stripped)
            pad = W - len(vis)
            if pad < 0:
                pad = 0
            print(f"{C.CYAN}{V}{C.RESET} {text}{' ' * pad} {C.CYAN}{V}{C.RESET}")

        def separator():
            print(f"{C.CYAN}{LT}{H * (W + 2)}{RT}{C.RESET}")

        # Top border
        print(f"{C.CYAN}{TL}{H * (W + 2)}{TR}{C.RESET}")

        # Title
        title = f"SECURITY DASHBOARD - Session: {str(data['session_id'])[:18]}"
        row(f"{C.BOLD}{C.BRIGHT_WHITE}{title}{C.RESET}")

        separator()

        # Risk score gauge
        score = data['risk_score']
        filled = int(score / 100 * 20)
        empty = 20 - filled
        if score >= 70:
            gauge_color = C.RED
        elif score >= 40:
            gauge_color = C.YELLOW
        else:
            gauge_color = C.GREEN
        gauge = f"{gauge_color}{'█' * filled}{C.DIM}{'░' * empty}{C.RESET}"
        row(f"RISK SCORE: {gauge}  {score}/100")

        # Trend
        trend = data['trend']
        if trend == 'improving':
            trend_display = f"{C.GREEN}▼ IMPROVING{C.RESET}"
        elif trend == 'worsening':
            trend_display = f"{C.RED}▲ WORSENING{C.RESET}"
        else:
            trend_display = f"{C.YELLOW}▬ STABLE{C.RESET}"
        row(f"Trend: {trend_display}")

        separator()

        # Severity cards
        sev = data['findings_by_severity']
        sev_line = (
            f"{C.RED}CRITICAL: {sev['CRITICAL']}{C.RESET}  "
            f"{C.BRIGHT_RED}HIGH: {sev['HIGH']}{C.RESET}  "
            f"{C.YELLOW}MEDIUM: {sev['MEDIUM']}{C.RESET}  "
            f"{C.GREEN}LOW: {sev['LOW']}{C.RESET}"
        )
        row(sev_line)
        row(f"Total findings: {data['total_findings']}   Assets: {data['asset_count']}")

        separator()

        # Compliance meters
        row(f"{C.BOLD}COMPLIANCE{C.RESET}")
        rates = data.get('compliance_rates', {})
        if rates:
            for fw, pct in list(rates.items())[:6]:
                bar_w = 10
                bar_filled = int(pct / 100 * bar_w)
                bar_empty = bar_w - bar_filled
                if pct >= 80:
                    bar_color = C.GREEN
                elif pct >= 50:
                    bar_color = C.YELLOW
                else:
                    bar_color = C.RED
                bar = f"{bar_color}{'█' * bar_filled}{C.DIM}{'░' * bar_empty}{C.RESET}"
                label = f"{fw[:14]:<14}"
                row(f"  {label} {bar} {pct:5.1f}%")
        else:
            row(f"  {C.DIM}No compliance data available{C.RESET}")

        separator()

        # Top risks
        row(f"{C.BOLD}TOP RISKS{C.RESET}")
        top = data.get('top_findings', [])
        if top:
            for i, f in enumerate(top, 1):
                sev_tag = f.get('severity', 'INFO')[:4]
                title_text = f.get('title', 'Unknown')[:35]
                asset = f.get('affected_asset', '')[:14]
                if sev_tag == 'CRIT':
                    tag_color = C.RED
                else:
                    tag_color = C.BRIGHT_RED
                row(f"  {i}. [{tag_color}{sev_tag}{C.RESET}] {title_text} {C.DIM}{asset}{C.RESET}")
        else:
            row(f"  {C.DIM}No critical/high findings{C.RESET}")

        # Bottom border
        print(f"{C.CYAN}{BL}{H * (W + 2)}{BR}{C.RESET}")
        print(f"{C.DIM}Generated: {data['timestamp']}{C.RESET}")

    # ------------------------------------------------------------------
    # HTML dashboard export
    # ------------------------------------------------------------------

    def export_html_dashboard(self, session_id: str = None,
                              output_path: Path = None) -> Optional[Path]:
        """
        Export a static HTML executive dashboard.
        Returns the output path on success, None on failure.
        """
        data = self._get_dashboard_data(session_id)

        if output_path is None:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"dashboard_{timestamp}.html"

        try:
            html = self._build_html_dashboard(data)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as fh:
                fh.write(html)
            self.logger.info(f"HTML dashboard exported to {output_path}")
            return output_path
        except Exception as exc:
            self.logger.error(f"Failed to export HTML dashboard: {exc}")
            return None

    def _build_html_dashboard(self, data: dict) -> str:
        """Build the full HTML dashboard with professional CSS styling."""

        # Severity cards HTML
        sev = data['findings_by_severity']
        severity_cards = ""
        card_map = [
            ('CRITICAL', '#dc3545', 'white'),
            ('HIGH', '#fd7e14', 'white'),
            ('MEDIUM', '#ffc107', '#333'),
            ('LOW', '#28a745', 'white'),
            ('INFO', '#17a2b8', 'white'),
        ]
        for label, bg, fg in card_map:
            severity_cards += f"""
            <div class="sev-card" style="background:{bg};color:{fg};">
                <div class="sev-count">{sev.get(label, 0)}</div>
                <div class="sev-label">{label}</div>
            </div>"""

        # Compliance meters HTML
        compliance_html = ""
        for fw, pct in data.get('compliance_rates', {}).items():
            if pct >= 80:
                bar_color = '#28a745'
            elif pct >= 50:
                bar_color = '#ffc107'
            else:
                bar_color = '#dc3545'
            compliance_html += f"""
            <div class="compliance-row">
                <span class="fw-label">{fw}</span>
                <div class="meter-track">
                    <div class="meter-fill" style="width:{pct}%;background:{bar_color};"></div>
                </div>
                <span class="fw-pct">{pct:.1f}%</span>
            </div>"""

        if not compliance_html:
            compliance_html = '<p class="muted">No compliance data available.</p>'

        # Top findings table rows
        top_rows = ""
        for f in data.get('top_findings', []):
            sev_label = f.get('severity', 'INFO')
            sev_class = sev_label.lower()
            cvss = f.get('cvss_score', 0) or 0
            top_rows += f"""
            <tr>
                <td><span class="badge {sev_class}">{sev_label}</span></td>
                <td>{f.get('title', 'N/A')}</td>
                <td>{f.get('affected_asset', 'N/A')}</td>
                <td>{cvss:.1f}</td>
            </tr>"""

        if not top_rows:
            top_rows = '<tr><td colspan="4" class="muted">No critical/high findings</td></tr>'

        # Risk gauge colour
        score = data['risk_score']
        if score >= 70:
            gauge_color = '#dc3545'
        elif score >= 40:
            gauge_color = '#ffc107'
        else:
            gauge_color = '#28a745'

        # Trend indicator
        trend = data['trend']
        if trend == 'improving':
            trend_html = '<span class="trend-badge" style="background:#28a745;">&#x25BC; IMPROVING</span>'
        elif trend == 'worsening':
            trend_html = '<span class="trend-badge" style="background:#dc3545;">&#x25B2; WORSENING</span>'
        else:
            trend_html = '<span class="trend-badge" style="background:#6c757d;">&#x25AC; STABLE</span>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Dashboard</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #333; }}
        .container {{ max-width: 1100px; margin: 30px auto; padding: 0 20px; }}
        header {{ background: linear-gradient(135deg, #2c3e50, #4a6fa5); color: white;
                  padding: 30px 40px; border-radius: 12px 12px 0 0; }}
        header h1 {{ font-size: 26px; margin-bottom: 4px; }}
        header .sub {{ opacity: 0.85; font-size: 14px; }}
        .body-wrap {{ background: white; padding: 30px 40px; border-radius: 0 0 12px 12px;
                      box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}

        /* Risk gauge */
        .gauge-section {{ text-align: center; margin: 24px 0; }}
        .gauge-track {{ width: 100%; max-width: 500px; height: 28px; background: #e9ecef;
                        border-radius: 14px; margin: 12px auto; overflow: hidden; }}
        .gauge-fill {{ height: 100%; border-radius: 14px; transition: width .4s; }}
        .gauge-score {{ font-size: 48px; font-weight: 700; }}
        .gauge-label {{ font-size: 14px; color: #666; }}
        .trend-badge {{ display: inline-block; padding: 4px 14px; border-radius: 16px;
                        color: white; font-weight: 600; font-size: 13px; margin-top: 6px; }}

        /* Severity cards */
        .sev-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin: 24px 0; }}
        .sev-card {{ padding: 18px 10px; border-radius: 10px; text-align: center; }}
        .sev-count {{ font-size: 34px; font-weight: 700; }}
        .sev-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

        /* Metrics row */
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 20px 0; }}
        .metric {{ background: #f8f9fa; padding: 18px; border-radius: 10px; text-align: center; }}
        .metric-value {{ font-size: 30px; font-weight: 700; color: #4a6fa5; }}
        .metric-label {{ font-size: 13px; color: #666; margin-top: 4px; }}

        /* Compliance */
        h2 {{ color: #2c3e50; margin: 28px 0 14px; font-size: 20px;
              border-bottom: 2px solid #4a6fa5; padding-bottom: 6px; }}
        .compliance-row {{ display: flex; align-items: center; margin: 10px 0; }}
        .fw-label {{ width: 140px; font-size: 13px; font-weight: 600; flex-shrink: 0; }}
        .meter-track {{ flex: 1; height: 16px; background: #e9ecef; border-radius: 8px;
                        overflow: hidden; margin: 0 12px; }}
        .meter-fill {{ height: 100%; border-radius: 8px; transition: width .4s; }}
        .fw-pct {{ width: 60px; text-align: right; font-size: 13px; font-weight: 600; }}

        /* Top findings table */
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e9ecef; }}
        th {{ background: #2c3e50; color: white; font-size: 13px; text-transform: uppercase;
              letter-spacing: .5px; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; color: white;
                  font-size: 12px; font-weight: 600; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}

        .muted {{ color: #999; font-style: italic; }}

        footer {{ text-align: center; margin: 28px 0 10px; padding-top: 18px;
                  border-top: 1px solid #e9ecef; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Executive Security Dashboard</h1>
        <div class="sub">Session: {data['session_id']}  |  {data['timestamp']}</div>
    </header>
    <div class="body-wrap">

        <!-- Risk Score Gauge -->
        <div class="gauge-section">
            <div class="gauge-score" style="color:{gauge_color};">{score}</div>
            <div class="gauge-label">RISK SCORE (0-100)</div>
            <div class="gauge-track">
                <div class="gauge-fill" style="width:{score}%;background:{gauge_color};"></div>
            </div>
            {trend_html}
        </div>

        <!-- Severity Cards -->
        <div class="sev-grid">{severity_cards}
        </div>

        <!-- Key Metrics -->
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{data['total_findings']}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="metric-value">{data['asset_count']}</div>
                <div class="metric-label">Tracked Assets</div>
            </div>
            <div class="metric">
                <div class="metric-value">{data['open_ports']}</div>
                <div class="metric-label">Open Ports</div>
            </div>
        </div>

        <!-- Compliance -->
        <h2>Compliance Status</h2>
        {compliance_html}

        <!-- Top Risks -->
        <h2>Top Critical / High Findings</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Finding</th><th>Asset</th><th>CVSS</th></tr>
            </thead>
            <tbody>
                {top_rows}
            </tbody>
        </table>

        <footer>
            Generated by Purple Team Platform v7.0 on {data['timestamp']}<br>
            This report is intended for authorized personnel only.
        </footer>
    </div>
</div>
</body>
</html>"""
        return html


# ------------------------------------------------------------------
# Self-test
# ------------------------------------------------------------------

if __name__ == '__main__':
    dashboard = ExecutiveDashboard()
    print("Executive Dashboard initialized")
    print(f"Evidence DB: {dashboard.paths.evidence_db}")

    # Get dashboard data
    data = dashboard._get_dashboard_data()
    print(f"\nDashboard Data:")
    print(f"  Risk Score: {data.get('risk_score', 0)}/100")
    print(f"  Findings: {data.get('findings_by_severity', {})}")
    print(f"  Trend: {data.get('trend', 'unknown')}")
    print(f"  Assets: {data.get('asset_count', 0)}")

    # Export HTML
    output = dashboard.export_html_dashboard()
    if output:
        print(f"\nHTML Dashboard: {output}")

    print("\nDashboard ready")
