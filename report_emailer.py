#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

REPORTS_DIR = RESULTS_DIR / 'reports'
"""
Automated Report Emailer
Sends scan results, compliance reports, and alerts via email

Easy to implement, high value for keeping teams informed
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
import json
import yaml
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths

class ReportEmailer:
    """Send automated email reports"""
    
    def __init__(self):
        self.config = self.load_config()
        self.smtp_config = self.config.get('email', {})
        
        # Default email settings
        self.smtp_server = self.smtp_config.get('smtp_server', 'localhost')
        self.smtp_port = self.smtp_config.get('smtp_port', 587)
        self.use_tls = self.smtp_config.get('use_tls', True)
        self.username = self.smtp_config.get('username', '')
        self.password = self.smtp_config.get('password', '')
        self.from_email = self.smtp_config.get('from_email', 'purple-team@company.com')
        
        # Recipients
        self.security_team = self.smtp_config.get('security_team', [])
        self.audit_team = self.smtp_config.get('audit_team', [])
        self.management = self.smtp_config.get('management', [])
    
    def load_config(self):
        """Load email configuration"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Config not found, using defaults: {e}")
            return {}
    
    def send_email(self, to_addresses, subject, body, attachments=None, html=False):
        """
        Send email with optional attachments
        
        Args:
            to_addresses: List of recipient email addresses
            subject: Email subject
            body: Email body (text or HTML)
            attachments: List of file paths to attach
            html: If True, body is HTML
        """
        
        if not to_addresses:
            logger.warning("No recipients specified")
            return False
        
        try:
            # Create message
            message = MIMEMultipart()
            message['From'] = self.from_email
            message['To'] = ', '.join(to_addresses)
            message['Subject'] = subject
            
            # Add body
            if html:
                message.attach(MIMEText(body, 'html'))
            else:
                message.attach(MIMEText(body, 'plain'))
            
            # Add attachments
            if attachments:
                for filepath in attachments:
                    self._attach_file(message, filepath)
            
            # Send email
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                server.send_message(message)
            
            logger.info(f"Email sent to {', '.join(to_addresses)}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def _attach_file(self, message, filepath):
        """Attach file to email message"""
        
        try:
            with open(filepath, 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={Path(filepath).name}'
            )
            message.attach(part)
            
        except Exception as e:
            logger.error(f"Failed to attach {filepath}: {e}")
    
    def send_vulnerability_report(self, scan_date=None):
        """Send vulnerability scan summary"""
        
        if not scan_date:
            scan_date = datetime.now().strftime('%Y%m%d')
        
        # Find latest vulnerability report
        report_file = REPORTS_DIR / f'vulnerability_scan_{scan_date}*.html'
        reports = list(REPORTS_DIR.glob(f'vulnerability_scan_{scan_date}*.html'))
        
        if not reports:
            logger.warning(f"No vulnerability report found for {scan_date}")
            return False
        
        latest_report = max(reports, key=lambda p: p.stat().st_mtime)
        
        # Generate email
        subject = f"Vulnerability Scan Report - {scan_date}"
        body = f"""
Purple Team Security Platform - Vulnerability Scan Results

Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated report from your Purple Team security platform.

Key Highlights:
- Scan completed successfully
- Detailed findings attached
- Review critical and high severity items
- Remediation tracking in progress

Please review the attached HTML report for complete details.

---
Purple Team GRC Platform v2.5
Automated Security & Compliance Monitoring
"""
        
        return self.send_email(
            to_addresses=self.security_team,
            subject=subject,
            body=body,
            attachments=[str(latest_report)]
        )
    
    def send_compliance_report(self):
        """Send compliance validation summary"""
        
        # Find latest compliance report
        reports = list(REPORTS_DIR.glob('compliance_check_*.html'))
        
        if not reports:
            logger.warning("No compliance report found")
            return False
        
        latest_report = max(reports, key=lambda p: p.stat().st_mtime)
        
        subject = f"Compliance Validation Report - {datetime.now().strftime('%Y-%m-%d')}"
        body = f"""
Purple Team Security Platform - Compliance Status

Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This automated compliance check validates controls across:
- SOC 2 Type II
- NIST 800-53 / CSF
- ISO/IEC 27001:2022
- HIPAA Security Rule
- SOX IT General Controls

Please review the attached report for:
- Control test results
- Compliance rates by framework
- Gap analysis
- Remediation requirements

---
Purple Team GRC Platform v2.5
"""
        
        return self.send_email(
            to_addresses=self.audit_team,
            subject=subject,
            body=body,
            attachments=[str(latest_report)]
        )
    
    def send_critical_alert(self, finding):
        """Send immediate alert for critical findings"""
        
        subject = f"ðŸš¨ CRITICAL SECURITY FINDING - {finding.get('title', 'Unknown')}"
        
        body = f"""
CRITICAL SECURITY ALERT

A critical security finding requires immediate attention:

Finding: {finding.get('title', 'Unknown')}
Severity: CRITICAL
Host: {finding.get('host', 'Unknown')}
Discovered: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Description:
{finding.get('description', 'No description available')}

Validation Status: {finding.get('validated', 'Not validated')}
Risk Score: {finding.get('risk_score', 'N/A')}

RECOMMENDED ACTIONS:
1. Verify the finding immediately
2. Assess business impact
3. Initiate emergency change if needed
4. Document response actions

This is an automated alert from the Purple Team security platform.
Review the finding in the dashboard: http://localhost:5000

---
Purple Team GRC Platform v2.5
Automated Critical Finding Alert
"""
        
        # Send to both security and management
        recipients = list(set(self.security_team + self.management))
        
        return self.send_email(
            to_addresses=recipients,
            subject=subject,
            body=body
        )
    
    def send_weekly_summary(self):
        """Send weekly summary report"""
        
        subject = f"Weekly Security Summary - {datetime.now().strftime('%Y-%m-%d')}"
        
        # TODO: Generate actual statistics from database
        body = f"""
Purple Team Security Platform - Weekly Summary

Week Ending: {datetime.now().strftime('%Y-%m-%d')}

SCAN ACTIVITY:
- Vulnerability Scans: 7 (weekly schedule)
- Network Scans: 3 (bi-weekly)
- Compliance Checks: 7 (daily)

FINDINGS SUMMARY:
- Total Findings: TBD
- Critical: TBD (remediation SLA: 7 days)
- High: TBD (remediation SLA: 30 days)
- Medium: TBD (remediation SLA: 90 days)
- Low: TBD (remediation SLA: 180 days)

VALIDATION STATUS:
- Findings Validated: TBD
- False Positives Filtered: TBD
- Awaiting Validation: TBD

COMPLIANCE STATUS:
- SOC 2: TBD%
- NIST: TBD%
- ISO 27001: TBD%
- HIPAA: TBD%
- SOX: TBD%

REMEDIATION TRACKING:
- Tasks Created: TBD
- Tasks Completed: TBD
- Overdue Tasks: TBD

Access the dashboard for detailed reports:
http://localhost:5000

---
Purple Team GRC Platform v2.5
Automated Weekly Summary
"""
        
        return self.send_email(
            to_addresses=self.management,
            subject=subject,
            body=body
        )
    
    def send_audit_package_ready(self, package_path):
        """Notify when audit package is ready"""
        
        subject = f"Audit Package Ready - {datetime.now().strftime('%Y-%m-%d')}"
        
        body = f"""
Purple Team Security Platform - Audit Package Notification

Your requested audit package is ready for download.

Package Details:
- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Location: {package_path}
- Includes: Evidence, control citations, test results

This package contains:
- All audit evidence with SHA-256 verification
- Control test results across all frameworks
- Evidence index with chain of custody
- Control coverage summary

The package is ready for auditor review.

Access the package on the Purple Team laptop:
{package_path}

---
Purple Team GRC Platform v2.5
Audit Package Generation
"""
        
        return self.send_email(
            to_addresses=self.audit_team,
            subject=subject,
            body=body
        )

def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Send automated security reports')
    parser.add_argument('--type', choices=['vulnerability', 'compliance', 'weekly', 'test'],
                       default='test', help='Report type to send')
    parser.add_argument('--to', type=str, help='Override recipient email')
    
    args = parser.parse_args()
    
    emailer = ReportEmailer()
    
    if args.type == 'vulnerability':
        emailer.send_vulnerability_report()
    elif args.type == 'compliance':
        emailer.send_compliance_report()
    elif args.type == 'weekly':
        emailer.send_weekly_summary()
    elif args.type == 'test':
        # Send test email
        test_recipients = [args.to] if args.to else emailer.security_team
        emailer.send_email(
            to_addresses=test_recipients,
            subject='Purple Team Platform - Test Email',
            body='This is a test email from the Purple Team GRC Platform.\n\nIf you received this, email notifications are working correctly!'
        )

if __name__ == '__main__':
    main()
