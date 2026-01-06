#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detection
Compliance Checker Module
Maps security findings to compliance frameworks
"""

import json
import yaml
import logging
from datetime import datetime
from pathlib import Path
import subprocess

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR
# Specific results directory
COMPLIANCE_CHECKS_DIR = RESULTS_DIR / 'compliance-checks'

# Paths

# Compliance framework mappings
COMPLIANCE_CONTROLS = {
    'SOC2': {
        'CC6.1': {
            'name': 'Logical and Physical Access Controls',
            'checks': ['authentication', 'authorization', 'access_control', 'network_segmentation']
        },
        'CC6.6': {
            'name': 'Vulnerability Management',
            'checks': ['vulnerability_scanning', 'patch_management', 'configuration_management']
        },
        'CC6.7': {
            'name': 'System Monitoring',
            'checks': ['logging', 'monitoring', 'intrusion_detection']
        },
        'CC7.1': {
            'name': 'Detection of Security Incidents',
            'checks': ['ids_ips', 'siem', 'threat_detection']
        },
        'CC7.2': {
            'name': 'Response to Security Incidents',
            'checks': ['incident_response', 'forensics']
        }
    },
    'NIST': {
        'AC-2': {
            'name': 'Account Management',
            'checks': ['user_accounts', 'privilege_management', 'account_monitoring']
        },
        'AC-3': {
            'name': 'Access Enforcement',
            'checks': ['access_control', 'authorization', 'rbac']
        },
        'RA-5': {
            'name': 'Vulnerability Scanning',
            'checks': ['vulnerability_scanning', 'authenticated_scanning', 'scan_coverage']
        },
        'SC-7': {
            'name': 'Boundary Protection',
            'checks': ['firewall', 'network_segmentation', 'dmz']
        },
        'SI-2': {
            'name': 'Flaw Remediation',
            'checks': ['patch_management', 'vulnerability_remediation']
        },
        'SI-4': {
            'name': 'Information System Monitoring',
            'checks': ['logging', 'monitoring', 'alerting']
        }
    },
    'ISO27001': {
        'A.9.2.1': {
            'name': 'User Registration and De-registration',
            'checks': ['user_provisioning', 'account_lifecycle']
        },
        'A.9.4.1': {
            'name': 'Information Access Restriction',
            'checks': ['access_control', 'data_classification']
        },
        'A.12.6.1': {
            'name': 'Management of Technical Vulnerabilities',
            'checks': ['vulnerability_management', 'patch_management']
        },
        'A.13.1.1': {
            'name': 'Network Controls',
            'checks': ['network_segmentation', 'firewall', 'network_security']
        },
        'A.14.2.8': {
            'name': 'System Security Testing',
            'checks': ['penetration_testing', 'vulnerability_assessment']
        }
    },
    'HIPAA': {
        '164.308(a)(1)(ii)(A)': {
            'name': 'Risk Analysis',
            'checks': ['risk_assessment', 'vulnerability_scanning', 'threat_analysis']
        },
        '164.308(a)(5)(ii)(B)': {
            'name': 'Protection from Malicious Software',
            'checks': ['antivirus', 'malware_protection', 'endpoint_security']
        },
        '164.312(a)(1)': {
            'name': 'Access Control',
            'checks': ['authentication', 'authorization', 'unique_user_id']
        },
        '164.312(b)': {
            'name': 'Audit Controls',
            'checks': ['logging', 'audit_trails', 'monitoring']
        },
        '164.312(e)(1)': {
            'name': 'Transmission Security',
            'checks': ['encryption_in_transit', 'ssl_tls', 'vpn']
        }
    },
    'SOX': {
        'Section 302': {
            'name': 'Corporate Responsibility for Financial Reports',
            'checks': ['access_control', 'change_management', 'segregation_of_duties']
        },
        'Section 404': {
            'name': 'Management Assessment of Internal Controls',
            'checks': ['control_documentation', 'control_testing', 'vulnerability_management']
        },
        'ITGC': {
            'name': 'IT General Controls',
            'checks': ['access_control', 'change_management', 'backup_recovery']
        }
    }
}

class ComplianceChecker:
    """Compliance framework checker"""
    
    def __init__(self):
        self.config = self.load_config()
        self.results = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'scan_type': 'compliance_check',
            'start_time': datetime.now().isoformat(),
            'frameworks': {},
            'findings': [],
            'summary': {}
        }
    
    def load_config(self):
        """Load configuration"""
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    
    def load_latest_scans(self):
        """Load results from latest vulnerability and network scans"""
        scans = {}
        
        # Load latest vulnerability scan
        # Try both possible locations: subdirectory and main results dir
        vuln_files = []
        
        # Try subdirectory first
        vuln_subdir = BASE_DIR / 'results' / 'vulnerability-scans'
        if vuln_subdir.exists():
            vuln_files = sorted(vuln_subdir.glob('*.json'), reverse=True)
        
        # If no files in subdirectory, try main results directory
        if not vuln_files:
            vuln_files = sorted(RESULTS_DIR.glob('*VulnerabilityScan*.json'), reverse=True)
        if vuln_files:
            with open(vuln_files[0], 'r') as f:
                scans['vulnerability'] = json.load(f)
        
        # Load latest network scan
        # Try both possible locations
        net_files = []
        
        # Try subdirectory first
        net_subdir = BASE_DIR / 'results' / 'network-scans'
        if net_subdir.exists():
            net_files = sorted(net_subdir.glob('*.json'), reverse=True)
        
        # If no files in subdirectory, try main results directory
        if not net_files:
            net_files = sorted(RESULTS_DIR.glob('*NetworkScan*.json'), reverse=True)
        
        if net_files:
            with open(net_files[0], 'r') as f:
                scans['network'] = json.load(f)
        
        return scans
    
    def check_authentication_controls(self, scans):
        """Check authentication and access controls"""
        findings = []
        
        # Check for open authentication services
        if 'network' in scans:
            for host in scans['network'].get('hosts', []):
                for port in host.get('ports', []):
                    # Check for unencrypted authentication protocols
                    if port['port'] in [21, 23, 80] and port['service'] in ['ftp', 'telnet', 'http']:
                        findings.append({
                            'severity': 'high',
                            'control': 'authentication',
                            'host': host['ip'],
                            'issue': f"Unencrypted service detected: {port['service']} on port {port['port']}",
                            'recommendation': f"Disable {port['service']} or use encrypted alternative"
                        })
        
        return findings
    
    def check_vulnerability_management(self, scans):
        """Check vulnerability management compliance"""
        findings = []
        
        if 'vulnerability' in scans:
            vuln_summary = scans['vulnerability'].get('summary', {})
            
            # Critical/High vulnerabilities indicate poor vulnerability management
            if vuln_summary.get('critical', 0) > 0:
                findings.append({
                    'severity': 'critical',
                    'control': 'vulnerability_management',
                    'issue': f"{vuln_summary['critical']} critical vulnerabilities detected",
                    'recommendation': 'Immediate remediation required for critical vulnerabilities'
                })
            
            if vuln_summary.get('high', 0) > 5:
                findings.append({
                    'severity': 'high',
                    'control': 'vulnerability_management',
                    'issue': f"{vuln_summary['high']} high-severity vulnerabilities detected",
                    'recommendation': 'Prioritize remediation of high-severity vulnerabilities'
                })
        
        return findings
    
    def check_network_segmentation(self, scans):
        """Check network segmentation"""
        findings = []
        
        if 'network' in scans:
            # Check if internal services are exposed
            for host in scans['network'].get('hosts', []):
                exposed_services = []
                for port in host.get('ports', []):
                    # Database ports
                    if port['port'] in [1433, 3306, 5432, 27017]:
                        exposed_services.append(f"{port['service']} ({port['port']})")
                    # Admin interfaces
                    if port['port'] in [3389, 5900, 22]:
                        exposed_services.append(f"{port['service']} ({port['port']})")
                
                if exposed_services:
                    findings.append({
                        'severity': 'medium',
                        'control': 'network_segmentation',
                        'host': host['ip'],
                        'issue': f"Potentially sensitive services exposed: {', '.join(exposed_services)}",
                        'recommendation': 'Review network segmentation and implement firewall rules'
                    })
        
        return findings
    
    def check_encryption(self, scans):
        """Check encryption controls"""
        findings = []
        
        if 'vulnerability' in scans:
            for finding in scans['vulnerability'].get('findings', []):
                # SSL/TLS issues
                if finding.get('tool') == 'testssl.sh':
                    if finding.get('severity') in ['critical', 'high']:
                        findings.append({
                            'severity': finding['severity'],
                            'control': 'encryption_in_transit',
                            'host': finding['host'],
                            'issue': finding['title'],
                            'recommendation': 'Update SSL/TLS configuration to use secure protocols and ciphers'
                        })
        
        return findings
    
    def perform_compliance_checks(self):
        """Main compliance checking function"""
        logger.info("Starting compliance checks")
        
        # Load latest scan results
        scans = self.load_latest_scans()
        
        if not scans:
            logger.warning("No scan results found to analyze")
            # Set end_time even when no scans found
            self.results['end_time'] = datetime.now().isoformat()
            self.results['summary'] = {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            return self.results
        
        # Perform checks
        auth_findings = self.check_authentication_controls(scans)
        vuln_findings = self.check_vulnerability_management(scans)
        network_findings = self.check_network_segmentation(scans)
        encryption_findings = self.check_encryption(scans)
        
        all_findings = auth_findings + vuln_findings + network_findings + encryption_findings
        
        # Map findings to frameworks
        enabled_frameworks = self.config.get('compliance', {}).get('frameworks', [])
        
        for framework in enabled_frameworks:
            if framework not in COMPLIANCE_CONTROLS:
                continue
            
            framework_results = {
                'controls': {},
                'compliant': 0,
                'non_compliant': 0,
                'total': len(COMPLIANCE_CONTROLS[framework])
            }
            
            for control_id, control_info in COMPLIANCE_CONTROLS[framework].items():
                control_findings = []
                
                # Map findings to controls
                for finding in all_findings:
                    if finding['control'] in control_info['checks']:
                        control_findings.append(finding)
                
                framework_results['controls'][control_id] = {
                    'name': control_info['name'],
                    'status': 'Non-Compliant' if control_findings else 'Compliant',
                    'findings': control_findings
                }
                
                if control_findings:
                    framework_results['non_compliant'] += 1
                else:
                    framework_results['compliant'] += 1
            
            self.results['frameworks'][framework] = framework_results
        
        self.results['findings'] = all_findings
        self.results['end_time'] = datetime.now().isoformat()
        
        # Calculate summary
        self.results['summary'] = {
            'total_findings': len(all_findings),
            'critical': len([f for f in all_findings if f['severity'] == 'critical']),
            'high': len([f for f in all_findings if f['severity'] == 'high']),
            'medium': len([f for f in all_findings if f['severity'] == 'medium']),
            'low': len([f for f in all_findings if f['severity'] == 'low'])
        }
        
        logger.info("Compliance checks completed")
        return self.results
    
    def save_results(self):
        """Save compliance check results"""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_ComplianceCheck_Results.json"
        filepath = RESULTS_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Results saved to {filepath}")
        
        # Create HTML report
        self.create_html_report(filepath.with_suffix('.html'))
    
    def create_html_report(self, filepath):
        """Create HTML compliance report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {self.results['scan_id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .compliant {{ color: green; font-weight: bold; }}
        .non-compliant {{ color: red; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .framework-section {{ margin-top: 30px; padding: 15px; border-left: 4px solid #2196F3; background-color: #f5f5f5; }}
        .summary {{ background-color: #e7f3fe; padding: 15px; border-left: 6px solid #2196F3; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Compliance Assessment Report</h1>
    <p><strong>Scan ID:</strong> {self.results['scan_id']}</p>
    <p><strong>Start Time:</strong> {self.results['start_time']}</p>
    <p><strong>End Time:</strong> {self.results['end_time']}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Findings:</strong> {self.results['summary']['total_findings']}</p>
        <p><strong>Critical:</strong> {self.results['summary']['critical']}</p>
        <p><strong>High:</strong> {self.results['summary']['high']}</p>
        <p><strong>Medium:</strong> {self.results['summary']['medium']}</p>
        <p><strong>Low:</strong> {self.results['summary']['low']}</p>
    </div>
"""
        
        # Add framework sections
        for framework, data in self.results['frameworks'].items():
            compliance_rate = (data['compliant'] / data['total'] * 100) if data['total'] > 0 else 0
            
            html += f"""
    <div class="framework-section">
        <h2>{framework} Compliance</h2>
        <p><strong>Compliance Rate:</strong> {compliance_rate:.1f}%</p>
        <p><strong>Compliant Controls:</strong> {data['compliant']} / {data['total']}</p>
        
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Status</th>
                <th>Findings</th>
            </tr>
"""
            
            for control_id, control_data in data['controls'].items():
                status_class = 'compliant' if control_data['status'] == 'Compliant' else 'non-compliant'
                findings_count = len(control_data['findings'])
                
                html += f"""
            <tr>
                <td>{control_id}</td>
                <td>{control_data['name']}</td>
                <td class="{status_class}">{control_data['status']}</td>
                <td>{findings_count}</td>
            </tr>
"""
            
            html += """
        </table>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        logger.info(f"HTML report saved to {filepath}")

def main():
    """Main entry point"""
    try:
        checker = ComplianceChecker()
        results = checker.perform_compliance_checks()
        checker.save_results()
        logger.info("Compliance checking completed successfully")
    except Exception as e:
        logger.error(f"Compliance checking failed: {e}")
        raise

if __name__ == '__main__':
    main()
