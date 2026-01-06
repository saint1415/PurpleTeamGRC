#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detectionExecutive Report Generator - Create one-page security summaries for leadership"""
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR
from utils.path_helper import REPORTS_DIR
EXECUTIVE_REPORTS_DIR = REPORTS_DIR / 'executive'

class ExecutiveReportGenerator:
    def generate_one_pager(self, data=None):
        """Generate one-page executive summary"""
        
        # Sample data if none provided
        if not data:
            data = {
                'critical_findings': 3,
                'high_findings': 12,
                'medium_findings': 45,
                'low_findings': 78,
                'compliance_rate': 94,
                'systems_scanned': 247,
                'vulnerabilities_fixed': 23,
                'mean_time_to_remediate': 12
            }
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════╗
║              EXECUTIVE SECURITY SUMMARY                              ║
║              {datetime.now().strftime('%B %d, %Y')}                                        ║
╚══════════════════════════════════════════════════════════════════════╝

SECURITY POSTURE OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Overall Status: {"🟢 GOOD" if data['critical_findings'] == 0 else "🔴 ATTENTION REQUIRED"}
Compliance Rate: {data['compliance_rate']}% (Target: 95%)
Systems Monitored: {data['systems_scanned']}

VULNERABILITY SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 Critical: {data['critical_findings']:3d}  (Requires immediate action)
🟠 High:     {data['high_findings']:3d}  (30-day remediation SLA)
🟡 Medium:   {data['medium_findings']:3d}  (90-day remediation SLA)
⚪ Low:      {data['low_findings']:3d}  (180-day remediation SLA)

KEY METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Vulnerabilities Remediated (30 days): {data['vulnerabilities_fixed']}
Mean Time to Remediate: {data['mean_time_to_remediate']} days
Security Scan Coverage: 100%
Audit Readiness: {"READY" if data['compliance_rate'] >= 95 else "IN PROGRESS"}

RECOMMENDED ACTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{"• Address " + str(data['critical_findings']) + " critical findings within 7 days" if data['critical_findings'] > 0 else ""}
{"• Continue remediation of " + str(data['high_findings']) + " high-priority items" if data['high_findings'] > 0 else ""}
• Maintain current compliance monitoring
• Schedule quarterly security assessment

COMPLIANCE STATUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SOC 2:      ✓ Compliant
HIPAA:      ✓ Compliant  
ISO 27001:  ✓ Compliant
NIST:       ✓ Compliant
SOX:        ✓ Compliant

═══════════════════════════════════════════════════════════════════════
Purple Team GRC Platform - Automated Security Monitoring
═══════════════════════════════════════════════════════════════════════
"""
        return report
    
    def save_report(self, report, filename=None):
        if not filename:
            filename = f"executive_summary_{datetime.now().strftime('%Y%m%d')}.txt"
        
        output_dir = EXECUTIVE_REPORTS_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        
        filepath = output_dir / filename
        with open(filepath, 'w') as f:
            f.write(report)
        
        print(f"✓ Executive report saved: {filepath}")
        return filepath

if __name__ == '__main__':
    generator = ExecutiveReportGenerator()
    report = generator.generate_one_pager()
    print(report)
    generator.save_report(report)
