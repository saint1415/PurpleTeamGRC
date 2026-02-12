#!/usr/bin/env python3
"""
Purple Team Portable - Comprehensive Audit Report Generator
Generates detailed audit reports with compliance requirement citations.
Designed for internal and third-party auditors.
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

logger = get_logger('audit_report')


class AuditReportGenerator:
    """Generates comprehensive audit reports with requirement citations."""

    # Compliance requirement citations
    REQUIREMENT_CITATIONS = {
        'NIST-800-53': {
            'AC-1': 'NIST SP 800-53 Rev. 5, AC-1: Access Control Policy and Procedures',
            'AC-2': 'NIST SP 800-53 Rev. 5, AC-2: Account Management',
            'AC-3': 'NIST SP 800-53 Rev. 5, AC-3: Access Enforcement',
            'AC-6': 'NIST SP 800-53 Rev. 5, AC-6: Least Privilege',
            'AU-2': 'NIST SP 800-53 Rev. 5, AU-2: Event Logging',
            'AU-6': 'NIST SP 800-53 Rev. 5, AU-6: Audit Record Review, Analysis, and Reporting',
            'CA-7': 'NIST SP 800-53 Rev. 5, CA-7: Continuous Monitoring',
            'CM-2': 'NIST SP 800-53 Rev. 5, CM-2: Baseline Configuration',
            'CM-6': 'NIST SP 800-53 Rev. 5, CM-6: Configuration Settings',
            'CM-7': 'NIST SP 800-53 Rev. 5, CM-7: Least Functionality',
            'CM-8': 'NIST SP 800-53 Rev. 5, CM-8: System Component Inventory',
            'IA-2': 'NIST SP 800-53 Rev. 5, IA-2: Identification and Authentication',
            'IA-5': 'NIST SP 800-53 Rev. 5, IA-5: Authenticator Management',
            'RA-3': 'NIST SP 800-53 Rev. 5, RA-3: Risk Assessment',
            'RA-5': 'NIST SP 800-53 Rev. 5, RA-5: Vulnerability Monitoring and Scanning',
            'SC-7': 'NIST SP 800-53 Rev. 5, SC-7: Boundary Protection',
            'SC-8': 'NIST SP 800-53 Rev. 5, SC-8: Transmission Confidentiality and Integrity',
            'SC-12': 'NIST SP 800-53 Rev. 5, SC-12: Cryptographic Key Establishment and Management',
            'SC-13': 'NIST SP 800-53 Rev. 5, SC-13: Cryptographic Protection',
            'SI-2': 'NIST SP 800-53 Rev. 5, SI-2: Flaw Remediation',
            'SI-3': 'NIST SP 800-53 Rev. 5, SI-3: Malicious Code Protection',
            'SI-4': 'NIST SP 800-53 Rev. 5, SI-4: System Monitoring',
        },
        'HIPAA': {
            '164.308(a)(1)': 'HIPAA Security Rule 45 CFR § 164.308(a)(1): Security Management Process',
            '164.308(a)(3)': 'HIPAA Security Rule 45 CFR § 164.308(a)(3): Workforce Security',
            '164.308(a)(4)': 'HIPAA Security Rule 45 CFR § 164.308(a)(4): Information Access Management',
            '164.308(a)(5)': 'HIPAA Security Rule 45 CFR § 164.308(a)(5): Security Awareness and Training',
            '164.308(a)(6)': 'HIPAA Security Rule 45 CFR § 164.308(a)(6): Security Incident Procedures',
            '164.308(a)(7)': 'HIPAA Security Rule 45 CFR § 164.308(a)(7): Contingency Plan',
            '164.308(a)(8)': 'HIPAA Security Rule 45 CFR § 164.308(a)(8): Evaluation',
            '164.310(a)(1)': 'HIPAA Security Rule 45 CFR § 164.310(a)(1): Facility Access Controls',
            '164.310(b)': 'HIPAA Security Rule 45 CFR § 164.310(b): Workstation Use',
            '164.310(d)(1)': 'HIPAA Security Rule 45 CFR § 164.310(d)(1): Device and Media Controls',
            '164.312(a)(1)': 'HIPAA Security Rule 45 CFR § 164.312(a)(1): Access Control',
            '164.312(b)': 'HIPAA Security Rule 45 CFR § 164.312(b): Audit Controls',
            '164.312(c)(1)': 'HIPAA Security Rule 45 CFR § 164.312(c)(1): Integrity',
            '164.312(d)': 'HIPAA Security Rule 45 CFR § 164.312(d): Person or Entity Authentication',
            '164.312(e)(1)': 'HIPAA Security Rule 45 CFR § 164.312(e)(1): Transmission Security',
        },
        'PCI-DSS-v4': {
            '1.1': 'PCI DSS v4.0, Requirement 1.1: Network Security Controls Defined and Understood',
            '1.2': 'PCI DSS v4.0, Requirement 1.2: Network Security Controls Configured and Maintained',
            '2.1': 'PCI DSS v4.0, Requirement 2.1: Processes to Protect Systems',
            '2.2': 'PCI DSS v4.0, Requirement 2.2: System Components Securely Configured',
            '3.1': 'PCI DSS v4.0, Requirement 3.1: Account Data Storage Kept to Minimum',
            '3.5': 'PCI DSS v4.0, Requirement 3.5: Primary Account Number Protected',
            '4.1': 'PCI DSS v4.0, Requirement 4.1: Strong Cryptography During Transmission',
            '5.1': 'PCI DSS v4.0, Requirement 5.1: Malicious Software Prevented/Detected',
            '5.2': 'PCI DSS v4.0, Requirement 5.2: Anti-Malware Mechanisms Active',
            '6.1': 'PCI DSS v4.0, Requirement 6.1: Security Vulnerabilities Identified and Addressed',
            '6.2': 'PCI DSS v4.0, Requirement 6.2: Bespoke Software Developed Securely',
            '6.3': 'PCI DSS v4.0, Requirement 6.3: Security Vulnerabilities in Software Addressed',
            '7.1': 'PCI DSS v4.0, Requirement 7.1: Access Limited by Business Need',
            '7.2': 'PCI DSS v4.0, Requirement 7.2: Access Appropriately Defined and Assigned',
            '8.1': 'PCI DSS v4.0, Requirement 8.1: User Identification Managed',
            '8.3': 'PCI DSS v4.0, Requirement 8.3: Strong Authentication',
            '10.1': 'PCI DSS v4.0, Requirement 10.1: Audit Logs Enabled and Active',
            '10.2': 'PCI DSS v4.0, Requirement 10.2: Audit Logs Record User Activities',
            '10.3': 'PCI DSS v4.0, Requirement 10.3: Audit Logs Protected',
            '11.3': 'PCI DSS v4.0, Requirement 11.3: Vulnerabilities Identified/Prioritized/Addressed',
            '11.4': 'PCI DSS v4.0, Requirement 11.4: Penetration Testing Performed',
            '12.1': 'PCI DSS v4.0, Requirement 12.1: Information Security Policy',
        },
        'SOC2-Type2': {
            'CC1.1': 'SOC 2 Trust Services Criteria, CC1.1: COSO Principle 1 - Integrity and Ethical Values',
            'CC2.1': 'SOC 2 Trust Services Criteria, CC2.1: COSO Principle 13 - Quality Information',
            'CC3.1': 'SOC 2 Trust Services Criteria, CC3.1: COSO Principle 6 - Risk Assessment',
            'CC3.2': 'SOC 2 Trust Services Criteria, CC3.2: Risk Identification and Analysis',
            'CC4.1': 'SOC 2 Trust Services Criteria, CC4.1: COSO Principle 16 - Monitoring Activities',
            'CC5.1': 'SOC 2 Trust Services Criteria, CC5.1: COSO Principle 10 - Control Activities',
            'CC6.1': 'SOC 2 Trust Services Criteria, CC6.1: Logical Access Security Software',
            'CC6.2': 'SOC 2 Trust Services Criteria, CC6.2: Registration and Authorization',
            'CC6.3': 'SOC 2 Trust Services Criteria, CC6.3: Access Removal',
            'CC6.6': 'SOC 2 Trust Services Criteria, CC6.6: System Boundaries Protected',
            'CC6.7': 'SOC 2 Trust Services Criteria, CC6.7: Data Transmission Restricted',
            'CC6.8': 'SOC 2 Trust Services Criteria, CC6.8: Malicious Software Prevention',
            'CC7.1': 'SOC 2 Trust Services Criteria, CC7.1: Vulnerability Detection',
            'CC7.2': 'SOC 2 Trust Services Criteria, CC7.2: System Anomaly Monitoring',
            'CC7.3': 'SOC 2 Trust Services Criteria, CC7.3: Security Event Evaluation',
            'CC7.4': 'SOC 2 Trust Services Criteria, CC7.4: Security Incident Response',
            'CC8.1': 'SOC 2 Trust Services Criteria, CC8.1: Change Management Process',
            'CC9.1': 'SOC 2 Trust Services Criteria, CC9.1: Vendor and Business Partner Risk',
        },
        'SOC1-Type2': {
            'ITGC-01': 'SSAE 18 / SOC 1, ITGC-01: User Access Management',
            'ITGC-02': 'SSAE 18 / SOC 1, ITGC-02: Privileged Access',
            'ITGC-03': 'SSAE 18 / SOC 1, ITGC-03: Authentication Mechanisms',
            'ITGC-04': 'SSAE 18 / SOC 1, ITGC-04: Change Authorization',
            'ITGC-05': 'SSAE 18 / SOC 1, ITGC-05: Change Testing',
            'ITGC-06': 'SSAE 18 / SOC 1, ITGC-06: Segregation of Duties',
            'ITGC-07': 'SSAE 18 / SOC 1, ITGC-07: Job Scheduling',
            'ITGC-08': 'SSAE 18 / SOC 1, ITGC-08: Backup and Recovery',
            'ITGC-09': 'SSAE 18 / SOC 1, ITGC-09: Incident Management',
        },
        'ISO27001-2022': {
            '5.1': 'ISO/IEC 27001:2022, Control 5.1: Policies for Information Security',
            '5.15': 'ISO/IEC 27001:2022, Control 5.15: Access Control',
            '5.17': 'ISO/IEC 27001:2022, Control 5.17: Authentication Information',
            '8.1': 'ISO/IEC 27001:2022, Control 8.1: User Endpoint Devices',
            '8.5': 'ISO/IEC 27001:2022, Control 8.5: Secure Authentication',
            '8.7': 'ISO/IEC 27001:2022, Control 8.7: Protection Against Malware',
            '8.8': 'ISO/IEC 27001:2022, Control 8.8: Management of Technical Vulnerabilities',
            '8.9': 'ISO/IEC 27001:2022, Control 8.9: Configuration Management',
            '8.15': 'ISO/IEC 27001:2022, Control 8.15: Logging',
            '8.16': 'ISO/IEC 27001:2022, Control 8.16: Monitoring Activities',
            '8.20': 'ISO/IEC 27001:2022, Control 8.20: Networks Security',
            '8.21': 'ISO/IEC 27001:2022, Control 8.21: Security of Network Services',
            '8.24': 'ISO/IEC 27001:2022, Control 8.24: Use of Cryptography',
        },
    }

    def __init__(self):
        self.paths = paths
        self.config = config
        self.evidence = get_evidence_manager()
        self.compliance = get_compliance_mapper()

    def get_citation(self, framework: str, control_id: str) -> str:
        """Get the formal citation for a control."""
        fw_citations = self.REQUIREMENT_CITATIONS.get(framework, {})
        return fw_citations.get(control_id, f'{framework} {control_id}')

    def generate_full_audit_report(self, output_path: Path = None) -> Path:
        """Generate comprehensive audit report with all formats."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        if not output_path:
            output_path = paths.reports / f'audit_report_{timestamp}.html'

        frameworks = self.config.get_frameworks()

        # Gather all data
        report_data = {
            'generated': datetime.utcnow().isoformat(),
            'retention_days': self.config.get_retention_days(),
            'frameworks': {}
        }

        for framework in frameworks:
            summary = self.compliance.generate_compliance_summary(self.evidence, framework)
            summary['citations'] = {}

            for control in summary.get('control_details', []):
                control_id = control['control_id']
                control['citation'] = self.get_citation(framework, control_id)
                summary['citations'][control_id] = control['citation']

            report_data['frameworks'][framework] = summary

        # Generate HTML report
        html = self._build_audit_html(report_data)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        # Also generate JSON for raw data
        json_path = output_path.with_suffix('.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        # Generate CSV
        csv_path = output_path.with_suffix('.csv')
        self._write_audit_csv(report_data, csv_path)

        logger.info(f"Audit report saved: {output_path}")
        logger.info(f"Raw JSON: {json_path}")
        logger.info(f"CSV export: {csv_path}")

        return output_path

    def _build_audit_html(self, data: Dict) -> str:
        """Build comprehensive audit HTML report."""
        frameworks_html = ""

        for fw_name, fw_data in data['frameworks'].items():
            if 'error' in fw_data:
                continue

            total = fw_data.get('total_controls', 0)
            with_evidence = fw_data.get('controls_with_evidence', 0)
            rate = (with_evidence / total * 100) if total > 0 else 0

            controls_html = ""
            for control in fw_data.get('control_details', []):
                status_class = 'pass' if control['has_evidence'] else 'fail'
                status_icon = '✓' if control['has_evidence'] else '✗'
                status_text = 'MET' if control['has_evidence'] else 'GAP'

                controls_html += f"""
                <tr class="{status_class}">
                    <td><strong>{control['control_id']}</strong></td>
                    <td>{control['control_name']}</td>
                    <td>{control['family']}</td>
                    <td class="citation">{control.get('citation', '')}</td>
                    <td>{control['evidence_count']}</td>
                    <td class="status">{status_icon} {status_text}</td>
                </tr>"""

            frameworks_html += f"""
            <div class="framework-section">
                <h2>{fw_name}</h2>
                <div class="compliance-summary">
                    <div class="rate-box">
                        <div class="rate-value">{rate:.1f}%</div>
                        <div class="rate-label">Compliance Rate</div>
                    </div>
                    <div class="metrics-row">
                        <div class="metric">
                            <span class="value">{total}</span>
                            <span class="label">Total Controls</span>
                        </div>
                        <div class="metric met">
                            <span class="value">{with_evidence}</span>
                            <span class="label">Requirements Met</span>
                        </div>
                        <div class="metric gap">
                            <span class="value">{total - with_evidence}</span>
                            <span class="label">Gaps Identified</span>
                        </div>
                    </div>
                </div>
                <table class="controls-table">
                    <thead>
                        <tr>
                            <th>Control ID</th>
                            <th>Control Name</th>
                            <th>Family</th>
                            <th>Requirement Citation</th>
                            <th>Evidence</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {controls_html}
                    </tbody>
                </table>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Security Audit Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 32px;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 16px;
        }}
        .header .meta {{
            margin-top: 20px;
            display: flex;
            gap: 30px;
            font-size: 14px;
            opacity: 0.8;
        }}
        .framework-section {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .framework-section h2 {{
            color: #1a1a2e;
            border-bottom: 3px solid #4a90d9;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .compliance-summary {{
            display: flex;
            align-items: center;
            gap: 40px;
            margin-bottom: 25px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .rate-box {{
            text-align: center;
            min-width: 120px;
        }}
        .rate-value {{
            font-size: 48px;
            font-weight: bold;
            color: #4a90d9;
        }}
        .rate-label {{
            color: #666;
            font-size: 14px;
        }}
        .metrics-row {{
            display: flex;
            gap: 30px;
        }}
        .metric {{
            text-align: center;
            padding: 15px 25px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .metric .value {{
            display: block;
            font-size: 28px;
            font-weight: bold;
            color: #333;
        }}
        .metric .label {{
            display: block;
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }}
        .metric.met .value {{ color: #28a745; }}
        .metric.gap .value {{ color: #dc3545; }}
        .controls-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        .controls-table th {{
            background: #1a1a2e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        .controls-table td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }}
        .controls-table tr:hover {{
            background: #f8f9fa;
        }}
        .controls-table tr.pass .status {{
            color: #28a745;
            font-weight: bold;
        }}
        .controls-table tr.fail .status {{
            color: #dc3545;
            font-weight: bold;
        }}
        .controls-table .citation {{
            font-size: 12px;
            color: #666;
            max-width: 300px;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 12px;
        }}
        .footer a {{
            color: #4a90d9;
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .framework-section {{ box-shadow: none; page-break-inside: avoid; }}
            .header {{ background: #333; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Comprehensive Security Audit Report</h1>
            <div class="subtitle">Multi-Framework Compliance Assessment with Requirement Citations</div>
            <div class="meta">
                <span>Generated: {data['generated']}</span>
                <span>Retention Period: {data['retention_days']} days</span>
                <span>Frameworks Assessed: {len(data['frameworks'])}</span>
            </div>
        </div>

        {frameworks_html}

        <div class="footer">
            <p>Generated by Purple Team Portable v4.0</p>
            <p>This report contains evidence mappings to compliance framework requirements.</p>
            <p>All raw data is available in JSON and CSV formats for GRC platform import.</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def _write_audit_csv(self, data: Dict, output_path: Path):
        """Write audit data to CSV format."""
        import csv

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Framework', 'Control ID', 'Control Name', 'Family',
                'Requirement Citation', 'Evidence Count', 'Status',
                'Assessment Date'
            ])

            for fw_name, fw_data in data['frameworks'].items():
                if 'error' in fw_data:
                    continue

                for control in fw_data.get('control_details', []):
                    writer.writerow([
                        fw_name,
                        control['control_id'],
                        control['control_name'],
                        control['family'],
                        control.get('citation', ''),
                        control['evidence_count'],
                        'MET' if control['has_evidence'] else 'GAP',
                        data['generated']
                    ])


def generate_audit_report():
    """Convenience function to generate audit report."""
    generator = AuditReportGenerator()
    return generator.generate_full_audit_report()


if __name__ == '__main__':
    report_path = generate_audit_report()
    print(f"Audit report generated: {report_path}")
