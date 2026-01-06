#!/usr/bin/env python3
"""
Purple Team GRC Platform v4.0
Enhanced Compliance Checker - Granular Framework Analysis

NEW: Detailed HTML reports with:
- Framework-by-framework breakdown
- Control-by-control status
- Evidence for each finding
- Visual compliance scoring
- Remediation guidance
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

# Compliance framework mappings (EXPANDED)
COMPLIANCE_CONTROLS = {
    'SOC2': {
        'CC6.1': {
            'name': 'Logical and Physical Access Controls',
            'description': "",
            'checks': ['authentication', 'authorization', 'access_control', 'network_segmentation'],
            'requirements': [
                'Multi-factor authentication for remote access',
                'Encrypted authentication protocols (no telnet, no plain FTP)',
                'Access restricted to authorized personnel',
                'Network segmentation for sensitive systems'
            ]
        },
        'CC6.6': {
            'name': 'Vulnerability Management',
            'description': "",
            'checks': ['vulnerability_scanning', 'patch_management', 'configuration_management'],
            'requirements': [
                'Regular vulnerability scanning',
                'Timely patch deployment',
                'Configuration management',
                'Vulnerability remediation tracking'
            ]
        },
        'CC6.7': {
            'name': 'System Monitoring',
            'description': "",
            'checks': ['logging', 'monitoring', 'intrusion_detection'],
            'requirements': [
                'Centralized logging',
                'Real-time monitoring',
                'Intrusion detection systems',
                'Security event alerting'
            ]
        },
        'CC7.1': {
            'name': 'Detection of Security Incidents',
            'description': "",
            'checks': ['ids_ips', 'siem', 'threat_detection'],
            'requirements': [
                'IDS/IPS deployment',
                'SIEM implementation',
                'Threat intelligence',
                'Anomaly detection'
            ]
        },
        'CC7.2': {
            'name': 'Response to Security Incidents',
            'description': "",
            'checks': ['incident_response', 'forensics'],
            'requirements': [
                'Incident response plan',
                'Forensics capabilities',
                'Communication procedures',
                'Post-incident analysis'
            ]
        }
    },
    'NIST': {
        'AC-2': {
            'name': 'Account Management',
            'description': "",
            'checks': ['user_accounts', 'privilege_management', 'account_monitoring'],
            'requirements': [
                'Account creation/removal procedures',
                'Privilege management',
                'Account monitoring and review',
                'Automated account management'
            ]
        },
        'AC-3': {
            'name': 'Access Enforcement',
            'description': "",
            'checks': ['access_control', 'authorization', 'rbac'],
            'requirements': [
                'Role-based access control',
                'Least privilege principle',
                'Access enforcement mechanisms',
                'Authorization verification'
            ]
        },
        'RA-5': {
            'name': 'Vulnerability Scanning',
            'description': "",
            'checks': ['vulnerability_scanning', 'authenticated_scanning', 'scan_coverage'],
            'requirements': [
                'Regular vulnerability scans',
                'Authenticated scanning',
                'Full system coverage',
                'Scan result analysis'
            ]
        },
        'SC-7': {
            'name': 'Boundary Protection',
            'description': "",
            'checks': ['firewall', 'network_segmentation', 'dmz'],
            'requirements': [
                'Firewall deployment',
                'Network segmentation',
                'DMZ implementation',
                'Boundary monitoring'
            ]
        },
        'SI-2': {
            'name': 'Flaw Remediation',
            'description': "",
            'checks': ['patch_management', 'vulnerability_remediation'],
            'requirements': [
                'Flaw identification process',
                'Patch testing procedures',
                'Timely remediation',
                'Remediation tracking'
            ]
        },
        'SI-4': {
            'name': 'Information System Monitoring',
            'description': "",
            'checks': ['logging', 'monitoring', 'alerting'],
            'requirements': [
                'Continuous monitoring',
                'Log aggregation',
                'Alert generation',
                'Monitoring tool deployment'
            ]
        }
    },
    'ISO27001': {
        'A.9.2.1': {
            'name': 'User Registration and De-registration',
            'description': "",
            'checks': ['user_provisioning', 'account_lifecycle'],
            'requirements': [
                'Formal registration process',
                'De-registration procedures',
                'Access rights assignment',
                'Account lifecycle management'
            ]
        },
        'A.9.4.1': {
            'name': 'Information Access Restriction',
            'description': "",
            'checks': ['access_control', 'data_classification'],
            'requirements': [
                'Access control policy',
                'Information classification',
                'Access restrictions',
                'Need-to-know principle'
            ]
        },
        'A.12.6.1': {
            'name': 'Management of Technical Vulnerabilities',
            'description': "",
            'checks': ['vulnerability_management', 'patch_management'],
            'requirements': [
                'Vulnerability information sources',
                'Timely vulnerability assessment',
                'Patch deployment',
                'Vulnerability tracking'
            ]
        },
        'A.13.1.1': {
            'name': 'Network Controls',
            'description': "",
            'checks': ['network_segmentation', 'firewall', 'network_security'],
            'requirements': [
                'Network security controls',
                'Network segmentation',
                'Access controls',
                'Network monitoring'
            ]
        },
        'A.14.2.8': {
            'name': 'System Security Testing',
            'description': "",
            'checks': ['security_testing', 'penetration_testing'],
            'requirements': [
                'Security test planning',
                'Regular security testing',
                'Penetration testing',
                'Test result analysis'
            ]
        }
    },
    'PCI-DSS': {
        '1.1': {
            'name': 'Firewall Configuration Standards',
            'description': "",
            'checks': ['firewall', 'network_security'],
            'requirements': [
                'Firewall configuration standards',
                'Router configuration standards',
                'Configuration review process',
                'Change management'
            ]
        },
        '2.2': {
            'name': 'Configuration Standards',
            'description': "",
            'checks': ['configuration_management', 'hardening'],
            'requirements': [
                'System hardening standards',
                'Unnecessary services disabled',
                'Security parameters configured',
                'Configuration documentation'
            ]
        },
        '4.1': {
            'name': 'Encryption of Cardholder Data',
            'description': "",
            'checks': ['encryption', 'authentication'],
            'requirements': [
                'Strong encryption protocols',
                'No unencrypted transmission',
                'TLS/SSL implementation',
                'Encryption key management'
            ]
        },
        '8.2': {
            'name': 'User Authentication',
            'description': "",
            'checks': ['authentication', 'access_control'],
            'requirements': [
                'Unique user IDs',
                'Strong authentication',
                'Multi-factor authentication',
                'Password policies'
            ]
        },
        '11.2': {
            'name': 'Vulnerability Scanning',
            'description': "",
            'checks': ['vulnerability_scanning'],
            'requirements': [
                'Quarterly vulnerability scans',
                'Scan after significant changes',
                'Remediation of high-risk vulnerabilities',
                'Scan evidence retention'
            ]
        }
    },
    'HIPAA': {
        '164.308(a)(1)(ii)(A)': {
            'name': 'Risk Analysis',
            'description': "",
            'checks': ['risk_assessment', 'vulnerability_scanning'],
            'requirements': [
                'Regular risk assessments',
                'Vulnerability identification',
                'Threat analysis',
                'Risk documentation'
            ]
        },
        '164.308(a)(5)(ii)(C)': {
            'name': 'Log-in Monitoring',
            'description': "",
            'checks': ['logging', 'monitoring', 'access_control'],
            'requirements': [
                'Login monitoring procedures',
                'Failed login tracking',
                'Access attempt logging',
                'Discrepancy reporting'
            ]
        },
        '164.312(a)(2)(iv)': {
            'name': 'Encryption and Decryption',
            'description': "",
            'checks': ['encryption', 'authentication'],
            'requirements': [
                'Encryption implementation',
                'Encryption key management',
                'Decryption controls',
                'Encryption policies'
            ]
        },
        '164.312(e)(1)': {
            'name': 'Transmission Security',
            'description': "",
            'checks': ['encryption', 'network_security'],
            'requirements': [
                'Transmission encryption',
                'Network security controls',
                'VPN implementation',
                'Secure transmission protocols'
            ]
        }
    }
}

class EnhancedComplianceChecker:
    """Enhanced compliance checker with detailed reporting"""
    
    def __init__(self):
        self.config = self.load_config()
        self.results = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'scan_type': 'enhanced_compliance_check',
            'start_time': datetime.now().isoformat(),
            'frameworks': {},
            'findings': [],
            'summary': {}
        }
    
    def load_config(self):
        """Load configuration"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            return {}
    
    def load_latest_scans(self):
        """Load most recent scan results"""
        scans = {}
        
        # Load network scan
        network_files = sorted(RESULTS_DIR.glob('*NetworkScan*.json'), reverse=True)
        if network_files:
            with open(network_files[0], 'r') as f:
                scans['network'] = json.load(f)
        
        # Load vulnerability scan
        vuln_files = sorted(RESULTS_DIR.glob('*VulnerabilityScan*.json'), reverse=True)
        if vuln_files:
            with open(vuln_files[0], 'r') as f:
                scans['vulnerability'] = json.load(f)
        
        return scans
    
    def check_authentication_controls(self, scans):
        """Check authentication and access control"""
        findings = []
        
        if 'network' not in scans:
            return findings
        
        for host in scans['network'].get('hosts', []):
            ip = host.get('ip')
            
            for port in host.get('ports', []):
                service = port.get('service', '').lower()
                port_num = port.get('port')
                
                # Check for unencrypted authentication
                if service == 'telnet' or port_num == 23:
                    findings.append({
                        'severity': 'high',
                        'control': 'authentication',
                        'host': ip,
                        'port': port_num,
                        'service': service,
                        'issue': f'Unencrypted service detected: telnet on port {port_num}',
                        'recommendation': 'Disable telnet or use encrypted alternative (SSH)',
                        'evidence': f'Port {port_num} ({service}) open on {ip}',
                        'cve_reference': 'Generic - Cleartext Protocol'
                    })
                
                if service == 'http' or port_num == 80:
                    findings.append({
                        'severity': 'high',
                        'control': 'authentication',
                        'host': ip,
                        'port': port_num,
                        'service': service,
                        'issue': f'Unencrypted service detected: http on port {port_num}',
                        'recommendation': 'Disable http or use encrypted alternative (HTTPS)',
                        'evidence': f'Port {port_num} ({service}) open on {ip}',
                        'cve_reference': 'Generic - Unencrypted HTTP'
                    })
        
        return findings
    
    def check_network_segmentation(self, scans):
        """Check network segmentation"""
        findings = []
        
        if 'network' not in scans:
            return findings
        
        for host in scans['network'].get('hosts', []):
            ip = host.get('ip')
            
            for port in host.get('ports', []):
                service = port.get('service', '').lower()
                port_num = port.get('port')
                
                # Check for sensitive services
                if port_num in [22, 3389, 5900]:  # SSH, RDP, VNC
                    findings.append({
                        'severity': 'medium',
                        'control': 'network_segmentation',
                        'host': ip,
                        'port': port_num,
                        'service': service,
                        'issue': f'Potentially sensitive services exposed: {service} ({port_num})',
                        'recommendation': 'Review network segmentation and implement firewall rules',
                        'evidence': f'Management port {port_num} ({service}) accessible on {ip}',
                        'cve_reference': 'N/A - Configuration Issue'
                    })
        
        return findings
    
    def check_encryption(self, scans):
        """Check encryption requirements"""
        findings = []
        
        if 'network' not in scans:
            return findings
        
        for host in scans['network'].get('hosts', []):
            ip = host.get('ip')
            
            for port in host.get('ports', []):
                service = port.get('service', '').lower()
                port_num = port.get('port')
                
                # FTP check
                if 'ftp' in service and port_num == 21:
                    findings.append({
                        'severity': 'high',
                        'control': 'encryption',
                        'host': ip,
                        'port': port_num,
                        'service': service,
                        'issue': 'Unencrypted FTP service detected',
                        'recommendation': 'Use SFTP or FTPS instead',
                        'evidence': f'FTP service on port {port_num} at {ip}',
                        'cve_reference': 'Generic - Cleartext File Transfer'
                    })
        
        return findings
    
    def check_vulnerability_management(self, scans):
        """Check vulnerability management"""
        findings = []
        
        # This would integrate with vulnerability scan results
        # For now, placeholder
        
        return findings
    
    def perform_compliance_check(self):
        """Main compliance checking workflow"""
        logger.info("Starting enhanced compliance checks")
        
        scans = self.load_latest_scans()
        
        if not scans:
            logger.warning("No scan results found to analyze")
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
        network_findings = self.check_network_segmentation(scans)
        encryption_findings = self.check_encryption(scans)
        vuln_findings = self.check_vulnerability_management(scans)
        
        all_findings = auth_findings + network_findings + encryption_findings + vuln_findings
        
        # Default to checking all major frameworks
        enabled_frameworks = self.config.get('compliance', {}).get('frameworks', 
            ['SOC2', 'NIST', 'ISO27001', 'PCI-DSS', 'HIPAA'])
        
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
                    if finding.get('control') in control_info['checks']:
                        control_findings.append(finding)
                
                framework_results['controls'][control_id] = {
                    'name': control_info['name'],
                    'description': control_info.get('description', ''),
                    'requirements': control_info.get('requirements', []),
                    'status': 'Non-Compliant' if control_findings else 'Compliant',
                    'findings': control_findings,
                    'finding_count': len(control_findings)
                }
                
                if control_findings:
                    framework_results['non_compliant'] += 1
                else:
                    framework_results['compliant'] += 1
            
            # Calculate compliance percentage
            if framework_results['total'] > 0:
                framework_results['compliance_percentage'] = round(
                    (framework_results['compliant'] / framework_results['total']) * 100, 1
                )
            else:
                framework_results['compliance_percentage'] = 0
            
            self.results['frameworks'][framework] = framework_results
        
        self.results['findings'] = all_findings
        self.results['end_time'] = datetime.now().isoformat()
        
        # Calculate summary
        self.results['summary'] = {
            'total_findings': len(all_findings),
            'critical': len([f for f in all_findings if f.get('severity') == 'critical']),
            'high': len([f for f in all_findings if f.get('severity') == 'high']),
            'medium': len([f for f in all_findings if f.get('severity') == 'medium']),
            'low': len([f for f in all_findings if f.get('severity') == 'low'])
        }
        
        logger.info("Enhanced compliance checks completed")
        return self.results
    
    def save_results(self):
        """Save compliance check results"""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_EnhancedComplianceCheck_Results.json"
        filepath = RESULTS_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Results saved to {filepath}")
        
        # Create detailed HTML report
        self.create_enhanced_html_report(filepath.with_suffix('.html'))
    
    def create_enhanced_html_report(self, filepath):
        """Create enhanced HTML compliance report with granular details"""
        
        # Calculate overall compliance
        total_controls = 0
        total_compliant = 0
        
        for framework_data in self.results['frameworks'].values():
            total_controls += framework_data['total']
            total_compliant += framework_data['compliant']
        
        overall_compliance = round((total_compliant / total_controls * 100), 1) if total_controls > 0 else 0
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Compliance Report - {self.results['scan_id']}</title>
    <meta charset="UTF-8">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .executive-summary {{
            background: #f8f9fa;
            border-left: 6px solid #667eea;
            padding: 30px;
            margin: 30px;
        }}
        
        .executive-summary h2 {{
            color: #667eea;
            margin-bottom: 20px;
        }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .metric-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        
        .metric-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .metric-label {{
            color: #666;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        
        .framework-section {{
            margin: 30px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .framework-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .framework-header h2 {{
            font-size: 1.8em;
        }}
        
        .compliance-badge {{
            background: white;
            color: #667eea;
            padding: 10px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .compliance-badge.high {{
            background: #10b981;
            color: white;
        }}
        
        .compliance-badge.medium {{
            background: #f59e0b;
            color: white;
        }}
        
        .compliance-badge.low {{
            background: #ef4444;
            color: white;
        }}
        
        .control-grid {{
            padding: 30px;
            background: #fafafa;
        }}
        
        .control-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .control-header {{
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .control-header h3 {{
            color: #333;
            font-size: 1.3em;
        }}
        
        .control-id {{
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 15px;
            font-size: 0.9em;
            font-weight: bold;
        }}
        
        .status-badge {{
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .status-badge.compliant {{
            background: #10b981;
            color: white;
        }}
        
        .status-badge.non-compliant {{
            background: #ef4444;
            color: white;
        }}
        
        .control-body {{
            padding: 20px;
        }}
        
        .control-description {{
            color: #666;
            margin-bottom: 15px;
            font-style: italic;
        }}
        
        .requirements-list {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        
        .requirements-list h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .requirements-list ul {{
            list-style-position: inside;
            color: #666;
        }}
        
        .requirements-list li {{
            padding: 5px 0;
        }}
        
        .findings-section {{
            background: #fff5f5;
            border: 1px solid #feb2b2;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }}
        
        .findings-section h4 {{
            color: #c53030;
            margin-bottom: 15px;
        }}
        
        .finding-item {{
            background: white;
            border-left: 4px solid #ef4444;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .severity-critical {{
            background: #7f1d1d;
            color: white;
        }}
        
        .severity-high {{
            background: #ef4444;
            color: white;
        }}
        
        .severity-medium {{
            background: #f59e0b;
            color: white;
        }}
        
        .severity-low {{
            background: #3b82f6;
            color: white;
        }}
        
        .finding-details {{
            color: #666;
            font-size: 0.95em;
        }}
        
        .finding-detail-row {{
            margin: 5px 0;
        }}
        
        .finding-detail-row strong {{
            color: #333;
        }}
        
        .recommendation-box {{
            background: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
        }}
        
        .recommendation-box strong {{
            color: #065f46;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Enhanced Compliance Assessment Report</h1>
            <div class="subtitle">Scan ID: {self.results['scan_id']}</div>
            <div class="subtitle">Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</div>
        </div>
        
        <!-- Executive Summary -->
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">{overall_compliance}%</div>
                    <div class="metric-label">Overall Compliance</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{len(self.results['frameworks'])}</div>
                    <div class="metric-label">Frameworks Analyzed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{total_controls}</div>
                    <div class="metric-label">Total Controls</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #10b981;">{total_compliant}</div>
                    <div class="metric-label">Compliant</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #ef4444;">{total_controls - total_compliant}</div>
                    <div class="metric-label">Non-Compliant</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #ef4444;">{self.results['summary']['high']}</div>
                    <div class="metric-label">High Severity Findings</div>
                </div>
            </div>
        </div>
"""
        
        # Framework sections
        for framework_name, framework_data in self.results['frameworks'].items():
            compliance_pct = framework_data.get('compliance_percentage', 0)
            
            # Determine badge class
            if compliance_pct >= 90:
                badge_class = "high"
            elif compliance_pct >= 70:
                badge_class = "medium"
            else:
                badge_class = "low"
            
            html += f"""
        <!-- {framework_name} Framework -->
        <div class="framework-section">
            <div class="framework-header">
                <h2>{framework_name}</h2>
                <div class="compliance-badge {badge_class}">{compliance_pct}% Compliant</div>
            </div>
            <div class="control-grid">
"""
            
            # Controls
            for control_id, control_data in framework_data['controls'].items():
                status_class = "compliant" if control_data['status'] == 'Compliant' else "non-compliant"
                
                html += f"""
                <div class="control-card">
                    <div class="control-header">
                        <div>
                            <span class="control-id">{control_id}</span>
                            <h3>{control_data['name']}</h3>
                        </div>
                        <span class="status-badge {status_class}">{control_data['status']}</span>
                    </div>
                    <div class="control-body">
                        <div class="control-description">{control_data.get('description', '')}</div>
                        
                        <div class="requirements-list">
                            <h4>📋 Requirements:</h4>
                            <ul>
"""
                
                for req in control_data.get('requirements', []):
                    html += f"                                <li>{req}</li>\n"
                
                html += """
                            </ul>
                        </div>
"""
                
                # Findings
                if control_data['findings']:
                    html += f"""
                        <div class="findings-section">
                            <h4>⚠️ Findings ({len(control_data['findings'])})</h4>
"""
                    
                    for finding in control_data['findings']:
                        severity = finding.get('severity', 'medium')
                        html += f"""
                            <div class="finding-item">
                                <div class="finding-header">
                                    <strong>{finding.get('issue', 'No description')}</strong>
                                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                                </div>
                                <div class="finding-details">
                                    <div class="finding-detail-row"><strong>Host:</strong> {finding.get('host', 'N/A')}</div>
                                    <div class="finding-detail-row"><strong>Port:</strong> {finding.get('port', 'N/A')} ({finding.get('service', 'N/A')})</div>
                                    <div class="finding-detail-row"><strong>Evidence:</strong> {finding.get('evidence', 'N/A')}</div>
                                    <div class="recommendation-box">
                                        <strong>💡 Recommendation:</strong> {finding.get('recommendation', 'No recommendation provided')}
                                    </div>
                                </div>
                            </div>
"""
                    
                    html += """
                        </div>
"""
                
                html += """
                    </div>
                </div>
"""
            
            html += """
            </div>
        </div>
"""
        
        # Footer
        html += f"""
        <div class="footer">
            <p><strong>Purple Team GRC Platform v4.0</strong></p>
            <p>Enhanced Compliance Assessment System</p>
            <p>Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        logger.info(f"Enhanced HTML report saved to {filepath}")

def main():
    """Main entry point"""
    checker = EnhancedComplianceChecker()
    results = checker.perform_compliance_check()
    checker.save_results()
    
    print(f"\n{'='*70}")
    print(f"Enhanced Compliance Check Complete!")
    print(f"{'='*70}\n")
    print(f"Scan ID: {results['scan_id']}")
    print(f"Total Findings: {results['summary']['total_findings']}")
    print(f"  Critical: {results['summary']['critical']}")
    print(f"  High: {results['summary']['high']}")
    print(f"  Medium: {results['summary']['medium']}")
    print(f"  Low: {results['summary']['low']}")
    print(f"\nFrameworks Analyzed: {len(results['frameworks'])}")
    
    for framework, data in results['frameworks'].items():
        print(f"  {framework}: {data['compliance_percentage']}% compliant")
    
    print(f"\n{'='*70}\n")

if __name__ == '__main__':
    main()
