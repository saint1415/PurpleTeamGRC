#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

CERT_DB = RESULTS_DIR / 'certificates' / 'cert_tracking.json'
REPORTS_DIR = RESULTS_DIR / 'certificates'
"""
Certificate Expiration Monitor
Tracks SSL/TLS certificates and alerts before expiration

Monitors:
- Web server certificates
- Internal service certificates
- Database certificates
- Email server certificates
"""

import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path
import json
import logging
import subprocess

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths already defined at top of file (lines 11-12)


class CertificateMonitor:
    """Monitor SSL/TLS certificate expiration"""
    
    def __init__(self):
        CERT_DB.parent.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.certificates = self.load_tracked_certs()
    
    def load_tracked_certs(self):
        """Load list of certificates to monitor"""
        
        if CERT_DB.exists():
            with open(CERT_DB, 'r') as f:
                return json.load(f)
        
        # Default certificates to monitor
        return {
            'hosts': [
                {'hostname': 'localhost', 'port': 443, 'name': 'Dashboard'},
            ],
            'alerts': {
                'critical_days': 7,   # Alert if expires in 7 days
                'warning_days': 30,   # Warning if expires in 30 days
                'info_days': 60       # Info if expires in 60 days
            }
        }
    
    def save_tracked_certs(self):
        """Save certificate tracking configuration"""
        
        with open(CERT_DB, 'w') as f:
            json.dump(self.certificates, f, indent=2)
    
    def add_certificate(self, hostname, port=443, name=None):
        """Add a certificate to monitor"""
        
        cert_entry = {
            'hostname': hostname,
            'port': port,
            'name': name or hostname
        }
        
        self.certificates['hosts'].append(cert_entry)
        self.save_tracked_certs()
        
        logger.info(f"Added certificate: {hostname}:{port}")
    
    def get_certificate_info(self, hostname, port=443):
        """
        Retrieve certificate information from host
        
        Returns:
            dict with certificate details or None if error
        """
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse dates
                    not_before = datetime.strptime(
                        cert['notBefore'], 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.strptime(
                        cert['notAfter'], 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    # Calculate days until expiry
                    days_remaining = (not_after - datetime.now()).days
                    
                    # Extract subject info
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    return {
                        'hostname': hostname,
                        'port': port,
                        'subject': subject.get('commonName', 'Unknown'),
                        'issuer': issuer.get('commonName', 'Unknown'),
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'days_remaining': days_remaining,
                        'is_valid': not_before <= datetime.now() <= not_after,
                        'serial_number': cert.get('serialNumber', 'Unknown'),
                        'version': cert.get('version', 'Unknown')
                    }
        
        except Exception as e:
            logger.error(f"Error retrieving certificate from {hostname}:{port}: {e}")
            return {
                'hostname': hostname,
                'port': port,
                'error': str(e),
                'days_remaining': None
            }
    
    def check_all_certificates(self):
        """Check all tracked certificates"""
        
        logger.info("Checking all certificates...")
        
        results = {
            'scan_time': datetime.now().isoformat(),
            'certificates': [],
            'summary': {
                'total': 0,
                'expired': 0,
                'critical': 0,
                'warning': 0,
                'ok': 0,
                'errors': 0
            }
        }
        
        alerts = self.certificates.get('alerts', {})
        critical_days = alerts.get('critical_days', 7)
        warning_days = alerts.get('warning_days', 30)
        
        for cert_entry in self.certificates.get('hosts', []):
            hostname = cert_entry['hostname']
            port = cert_entry.get('port', 443)
            name = cert_entry.get('name', hostname)
            
            logger.info(f"  Checking: {name} ({hostname}:{port})")
            
            cert_info = self.get_certificate_info(hostname, port)
            cert_info['name'] = name
            
            # Determine status
            if 'error' in cert_info:
                cert_info['status'] = 'error'
                results['summary']['errors'] += 1
            elif cert_info['days_remaining'] is None:
                cert_info['status'] = 'error'
                results['summary']['errors'] += 1
            elif cert_info['days_remaining'] < 0:
                cert_info['status'] = 'expired'
                results['summary']['expired'] += 1
            elif cert_info['days_remaining'] <= critical_days:
                cert_info['status'] = 'critical'
                results['summary']['critical'] += 1
            elif cert_info['days_remaining'] <= warning_days:
                cert_info['status'] = 'warning'
                results['summary']['warning'] += 1
            else:
                cert_info['status'] = 'ok'
                results['summary']['ok'] += 1
            
            results['certificates'].append(cert_info)
            results['summary']['total'] += 1
        
        return results
    
    def generate_report(self, results, format='text'):
        """Generate certificate expiration report"""
        
        if format == 'json':
            return json.dumps(results, indent=2)
        
        # Text report
        report = []
        report.append("=" * 70)
        report.append("CERTIFICATE EXPIRATION REPORT")
        report.append("=" * 70)
        report.append(f"Scan Time: {results['scan_time']}")
        report.append(f"Total Certificates: {results['summary']['total']}")
        report.append("")
        
        # Summary
        summary = results['summary']
        if summary['expired'] > 0:
            report.append(f"Ã°Å¸Å¡Â¨ EXPIRED: {summary['expired']}")
        if summary['critical'] > 0:
            report.append(f"Ã°Å¸â€Â´ CRITICAL (< 7 days): {summary['critical']}")
        if summary['warning'] > 0:
            report.append(f"Ã°Å¸Å¸Â¡ WARNING (< 30 days): {summary['warning']}")
        if summary['errors'] > 0:
            report.append(f"Ã¢ÂÅ’ ERRORS: {summary['errors']}")
        report.append(f"Ã¢Å“â€¦ OK: {summary['ok']}")
        report.append("")
        
        # Group by status
        for status in ['expired', 'critical', 'warning', 'error', 'ok']:
            certs = [c for c in results['certificates'] if c.get('status') == status]
            
            if not certs:
                continue
            
            status_name = status.upper()
            if status == 'expired':
                status_name = 'Ã°Å¸Å¡Â¨ EXPIRED'
            elif status == 'critical':
                status_name = 'Ã°Å¸â€Â´ CRITICAL'
            elif status == 'warning':
                status_name = 'Ã°Å¸Å¸Â¡ WARNING'
            elif status == 'error':
                status_name = 'Ã¢ÂÅ’ ERRORS'
            elif status == 'ok':
                status_name = 'Ã¢Å“â€¦ OK'
            
            report.append(f"\n{status_name}:")
            report.append("-" * 70)
            
            for cert in certs:
                report.append(f"\n{cert['name']}")
                report.append(f"  Host: {cert['hostname']}:{cert['port']}")
                
                if 'error' in cert:
                    report.append(f"  Error: {cert['error']}")
                else:
                    report.append(f"  Subject: {cert.get('subject', 'Unknown')}")
                    report.append(f"  Issuer: {cert.get('issuer', 'Unknown')}")
                    report.append(f"  Expires: {cert['not_after']}")
                    
                    if cert['days_remaining'] is not None:
                        if cert['days_remaining'] < 0:
                            report.append(f"  Status: Expired {abs(cert['days_remaining'])} days ago!")
                        else:
                            report.append(f"  Days Remaining: {cert['days_remaining']}")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)
    
    def save_report(self, results):
        """Save report to file"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save JSON
        json_file = REPORTS_DIR / f'cert_check_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save text report
        txt_file = REPORTS_DIR / f'cert_check_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write(self.generate_report(results, format='text'))
        
        logger.info(f"Reports saved: {json_file}")
        return txt_file
    
    def get_alerts(self, results):
        """Get list of certificates requiring alerts"""
        
        alerts = {
            'expired': [],
            'critical': [],
            'warning': []
        }
        
        for cert in results['certificates']:
            status = cert.get('status')
            if status in ['expired', 'critical', 'warning']:
                alerts[status].append(cert)
        
        return alerts

def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Certificate Expiration Monitor'
    )
    
    parser.add_argument('--check', action='store_true',
                       help='Check all tracked certificates')
    parser.add_argument('--add', type=str,
                       help='Add certificate to monitor (hostname:port)')
    parser.add_argument('--list', action='store_true',
                       help='List tracked certificates')
    parser.add_argument('--json', action='store_true',
                       help='Output as JSON')
    parser.add_argument('--save', action='store_true',
                       help='Save report to file')
    
    args = parser.parse_args()
    
    monitor = CertificateMonitor()
    
    if args.add:
        parts = args.add.split(':')
        hostname = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443
        monitor.add_certificate(hostname, port)
        print(f"Ã¢Å“â€œ Added: {hostname}:{port}")
    
    elif args.list:
        print("\nTracked Certificates:")
        print("-" * 70)
        for i, cert in enumerate(monitor.certificates.get('hosts', []), 1):
            print(f"{i}. {cert.get('name', cert['hostname'])}")
            print(f"   {cert['hostname']}:{cert.get('port', 443)}")
        print()
    
    elif args.check or not any([args.add, args.list]):
        results = monitor.check_all_certificates()
        
        if args.json:
            print(monitor.generate_report(results, format='json'))
        else:
            print(monitor.generate_report(results, format='text'))
        
        if args.save:
            monitor.save_report(results)
        
        # Exit code based on status
        if results['summary']['expired'] > 0:
            exit(2)  # Expired certificates
        elif results['summary']['critical'] > 0:
            exit(1)  # Critical (expires soon)
        else:
            exit(0)  # All OK

if __name__ == '__main__':
    main()
