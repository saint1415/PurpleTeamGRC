#!/usr/bin/env python3
"""
Purple Team GRC Platform v4.0
Smart Recommendations Engine

Analyzes scan results and provides intelligent, actionable recommendations
for security improvements, remediation priorities, and next steps.

Usage:
  python3 recommendations_engine.py [--format text|json]
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
import argparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, RESULTS_DIR, REPORTS_DIR

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    NC = '\033[0m'
    BOLD = '\033[1m'

class RecommendationsEngine:
    """Intelligent recommendations based on scan results"""
    
    def __init__(self):
        self.recommendations = []
        self.priorities = {'critical': [], 'high': [], 'medium': [], 'low': []}
        self.quick_wins = []
        self.long_term = []
        
    def load_latest_results(self):
        """Load the most recent scan results"""
        results = {}
        
        # Load network scan
        network_files = sorted(RESULTS_DIR.glob('*NetworkScan*.json'), reverse=True)
        if network_files:
            with open(network_files[0], 'r') as f:
                results['network'] = json.load(f)
        
        # Load vulnerability scan
        vuln_files = sorted(RESULTS_DIR.glob('*VulnerabilityScan*.json'), reverse=True)
        if vuln_files:
            with open(vuln_files[0], 'r') as f:
                results['vulnerability'] = json.load(f)
        
        # Load compliance check
        compliance_files = sorted(RESULTS_DIR.glob('*ComplianceCheck*.json'), reverse=True)
        if compliance_files:
            with open(compliance_files[0], 'r') as f:
                results['compliance'] = json.load(f)
        
        return results
    
    def analyze_network_findings(self, network_data):
        """Analyze network scan results for recommendations"""
        if not network_data:
            return
        
        hosts = network_data.get('hosts', [])
        summary = network_data.get('summary', {})
        
        # Check for unencrypted services
        unencrypted_services = []
        smb_hosts = []
        rdp_hosts = []
        telnet_hosts = []
        http_hosts = []
        
        for host in hosts:
            ip = host.get('ip')
            for port in host.get('ports', []):
                service = port.get('service', '').lower()
                port_num = port.get('port')
                
                # Telnet detection
                if port_num == 23 or service == 'telnet':
                    telnet_hosts.append(ip)
                    self.add_recommendation(
                        priority='critical',
                        category='Unencrypted Management',
                        title=f'Telnet detected on {ip}',
                        description=f'Host {ip} has telnet (port 23) enabled, which transmits credentials in plaintext.',
                        impact='CRITICAL - Complete credential compromise possible',
                        effort='Low (15 minutes)',
                        steps=[
                            '1. Enable SSH on the device',
                            '2. Test SSH connectivity',
                            '3. Disable telnet service',
                            '4. Verify with re-scan'
                        ],
                        quick_win=True
                    )
                
                # HTTP detection
                if port_num == 80 or service == 'http':
                    http_hosts.append(ip)
                    self.add_recommendation(
                        priority='high',
                        category='Unencrypted Services',
                        title=f'HTTP detected on {ip}',
                        description=f'Host {ip} is serving HTTP (port 80) without encryption.',
                        impact='HIGH - Data transmission in cleartext, session hijacking possible',
                        effort='Low (30 minutes)',
                        steps=[
                            '1. Obtain SSL/TLS certificate',
                            '2. Configure HTTPS (port 443)',
                            '3. Redirect HTTP to HTTPS',
                            '4. Test SSL configuration with testssl.sh'
                        ],
                        quick_win=True
                    )
                
                # SMB detection
                if port_num in [139, 445] or 'smb' in service or 'microsoft-ds' in service:
                    if ip not in smb_hosts:
                        smb_hosts.append(ip)
                
                # RDP detection
                if port_num == 3389 or service == 'ms-wbt-server':
                    rdp_hosts.append(ip)
        
        # SMB recommendations
        if smb_hosts:
            self.add_recommendation(
                priority='high',
                category='Network Segmentation',
                title=f'SMB file sharing exposed on {len(smb_hosts)} hosts',
                description=f'SMB ports (139, 445) are open on: {", ".join(smb_hosts[:3])}{"..." if len(smb_hosts) > 3 else ""}',
                impact='HIGH - SMB vulnerabilities (EternalBlue, etc.) could allow network compromise',
                effort='Medium (2-4 hours)',
                steps=[
                    '1. Review which hosts require SMB access',
                    '2. Implement network segmentation (VLANs)',
                    '3. Configure firewall rules to restrict SMB to necessary segments',
                    '4. Enable SMB signing and encryption',
                    '5. Disable SMBv1 if still enabled'
                ],
                quick_win=False
            )
        
        # RDP recommendations
        if rdp_hosts:
            self.add_recommendation(
                priority='high',
                category='Remote Access Security',
                title=f'RDP exposed on {len(rdp_hosts)} hosts',
                description=f'Remote Desktop Protocol detected on: {", ".join(rdp_hosts)}',
                impact='HIGH - Brute force attacks, ransomware entry point',
                effort='Medium (1-2 hours)',
                steps=[
                    '1. Implement Network Level Authentication (NLA)',
                    '2. Use VPN or jump box for RDP access',
                    '3. Enable account lockout policies',
                    '4. Consider Remote Desktop Gateway',
                    '5. Monitor RDP login attempts'
                ],
                quick_win=False
            )
        
        # Network size recommendations
        total_hosts = summary.get('live_hosts', 0)
        if total_hosts > 50:
            self.add_recommendation(
                priority='medium',
                category='Asset Management',
                title=f'Large network detected ({total_hosts} hosts)',
                description='Consider implementing automated asset inventory and monitoring.',
                impact='MEDIUM - Difficulty tracking changes, shadow IT risk',
                effort='High (1-2 days)',
                steps=[
                    '1. Tag all hosts by function (production/staging/dev)',
                    '2. Implement continuous monitoring (scheduled scans)',
                    '3. Set up alerting for new hosts',
                    '4. Create network documentation/diagrams',
                    '5. Establish change management process'
                ],
                quick_win=False
            )
    
    def analyze_vulnerability_findings(self, vuln_data):
        """Analyze vulnerability scan results"""
        if not vuln_data:
            return
        
        summary = vuln_data.get('summary', {})
        findings = vuln_data.get('findings', [])
        
        critical_count = summary.get('critical', 0)
        high_count = summary.get('high', 0)
        
        # Critical vulnerabilities
        if critical_count > 0:
            self.add_recommendation(
                priority='critical',
                category='Vulnerability Management',
                title=f'{critical_count} critical vulnerabilities require immediate action',
                description='Critical vulnerabilities pose imminent risk to the organization.',
                impact='CRITICAL - Active exploitation likely, potential for complete compromise',
                effort='Varies by vulnerability',
                steps=[
                    '1. Review all critical findings in detail',
                    '2. Prioritize by exploitability and exposure',
                    '3. Apply patches or mitigations within 24-48 hours',
                    '4. Consider isolating affected systems if patches unavailable',
                    '5. Re-scan to verify remediation'
                ],
                quick_win=False
            )
        
        # High vulnerabilities
        if high_count > 5:
            self.add_recommendation(
                priority='high',
                category='Vulnerability Management',
                title=f'{high_count} high-severity vulnerabilities detected',
                description='Establish 30-day remediation SLA for high-severity findings.',
                impact='HIGH - Significant security risk',
                effort='Medium to High',
                steps=[
                    '1. Create vulnerability remediation tracker',
                    '2. Assign owners for each finding',
                    '3. Establish 30-day SLA for high-severity items',
                    '4. Implement monthly vulnerability scanning',
                    '5. Track mean time to remediate (MTTR)'
                ],
                quick_win=False
            )
    
    def analyze_compliance_findings(self, compliance_data):
        """Analyze compliance check results"""
        if not compliance_data:
            return
        
        frameworks = compliance_data.get('frameworks', {})
        summary = compliance_data.get('summary', {})
        findings = compliance_data.get('findings', [])
        
        for framework_name, framework_data in frameworks.items():
            compliance_rate = 0
            if framework_data.get('total', 0) > 0:
                compliance_rate = (framework_data.get('compliant', 0) / framework_data.get('total', 0)) * 100
            
            if compliance_rate < 80:
                non_compliant = framework_data.get('non_compliant', 0)
                
                self.add_recommendation(
                    priority='high',
                    category='Compliance',
                    title=f'{framework_name} compliance at {compliance_rate:.1f}% ({non_compliant} controls failing)',
                    description=f'Current compliance rate below target of 95% for {framework_name}.',
                    impact='HIGH - Audit failure risk, regulatory penalties possible',
                    effort='High (varies by control)',
                    steps=[
                        f'1. Review failed controls in {framework_name} report',
                        '2. Prioritize controls by audit importance',
                        '3. Create remediation plan with timelines',
                        '4. Implement compensating controls if needed',
                        '5. Document evidence for each control',
                        '6. Schedule quarterly compliance scans'
                    ],
                    quick_win=False
                )
    
    def add_recommendation(self, priority, category, title, description, impact, effort, steps, quick_win=False):
        """Add a recommendation to the list"""
        rec = {
            'priority': priority,
            'category': category,
            'title': title,
            'description': description,
            'impact': impact,
            'effort': effort,
            'steps': steps,
            'quick_win': quick_win,
            'timestamp': datetime.now().isoformat()
        }
        
        self.recommendations.append(rec)
        self.priorities[priority].append(rec)
        
        if quick_win:
            self.quick_wins.append(rec)
        else:
            self.long_term.append(rec)
    
    def generate_recommendations(self):
        """Generate all recommendations based on scan results"""
        results = self.load_latest_results()
        
        if not results:
            print(f"{Colors.YELLOW}⚠ No scan results found. Run a scan first.{Colors.NC}")
            return
        
        # Analyze each type of result
        self.analyze_network_findings(results.get('network'))
        self.analyze_vulnerability_findings(results.get('vulnerability'))
        self.analyze_compliance_findings(results.get('compliance'))
        
        # Add general recommendations
        self.add_general_recommendations(results)
    
    def add_general_recommendations(self, results):
        """Add general best practice recommendations"""
        
        # Check scan age
        if 'network' in results:
            scan_time = results['network'].get('start_time', '')
            if scan_time:
                scan_date = datetime.fromisoformat(scan_time.replace('Z', '+00:00').replace('+00:00', ''))
                age_days = (datetime.now() - scan_date).days
                
                if age_days > 30:
                    self.add_recommendation(
                        priority='medium',
                        category='Continuous Monitoring',
                        title='Last scan over 30 days old',
                        description='Regular scanning is essential for maintaining security posture.',
                        impact='MEDIUM - New vulnerabilities may be undiscovered',
                        effort='Low (automated)',
                        steps=[
                            '1. Enable scheduled weekly scans',
                            '2. Configure email alerts for new findings',
                            '3. Set up continuous monitoring mode',
                            '4. Establish quarterly compliance assessments'
                        ],
                        quick_win=True
                    )
    
    def print_text_report(self):
        """Print recommendations as formatted text"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.CYAN}   SMART RECOMMENDATIONS - SECURITY IMPROVEMENT PLAN{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}\n")
        
        print(f"{Colors.BOLD}Generated:{Colors.NC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}Total Recommendations:{Colors.NC} {len(self.recommendations)}")
        print(f"{Colors.BOLD}Quick Wins:{Colors.NC} {len(self.quick_wins)}\n")
        
        # Quick wins section
        if self.quick_wins:
            print(f"{Colors.BOLD}{Colors.GREEN}{'─'*70}{Colors.NC}")
            print(f"{Colors.BOLD}{Colors.GREEN}⚡ QUICK WINS (High Impact, Low Effort){Colors.NC}")
            print(f"{Colors.GREEN}{'─'*70}{Colors.NC}\n")
            
            for i, rec in enumerate(self.quick_wins, 1):
                self.print_recommendation(i, rec)
        
        # Priority sections
        for priority in ['critical', 'high', 'medium', 'low']:
            priority_recs = [r for r in self.priorities[priority] if not r['quick_win']]
            
            if priority_recs:
                color = Colors.RED if priority == 'critical' else Colors.YELLOW if priority in ['high', 'medium'] else Colors.CYAN
                icon = '🔴' if priority == 'critical' else '🟠' if priority == 'high' else '🟡' if priority == 'medium' else '⚪'
                
                print(f"\n{Colors.BOLD}{color}{'─'*70}{Colors.NC}")
                print(f"{Colors.BOLD}{color}{icon} {priority.upper()} PRIORITY{Colors.NC}")
                print(f"{color}{'─'*70}{Colors.NC}\n")
                
                for i, rec in enumerate(priority_recs, 1):
                    self.print_recommendation(i, rec)
        
        # Summary
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BOLD}NEXT STEPS:{Colors.NC}\n")
        print(f"  1. Address {len(self.priorities['critical'])} critical items immediately (today)")
        print(f"  2. Complete {len(self.quick_wins)} quick wins this week")
        print(f"  3. Plan {len(self.priorities['high'])} high-priority items (30-day SLA)")
        print(f"  4. Schedule {len(self.priorities['medium'])} medium items for next quarter")
        print(f"\n{Colors.CYAN}💡 Tip:{Colors.NC} Start with quick wins for immediate security improvement!")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}\n")
    
    def print_recommendation(self, num, rec):
        """Print a single recommendation"""
        print(f"{Colors.BOLD}#{num}. {rec['title']}{Colors.NC}")
        print(f"{Colors.CYAN}Category:{Colors.NC} {rec['category']}")
        print(f"{Colors.CYAN}Description:{Colors.NC} {rec['description']}")
        print(f"{Colors.YELLOW}Impact:{Colors.NC} {rec['impact']}")
        print(f"{Colors.GREEN}Effort:{Colors.NC} {rec['effort']}")
        print(f"\n{Colors.BOLD}Remediation Steps:{Colors.NC}")
        for step in rec['steps']:
            print(f"  {step}")
        print()
    
    def save_json_report(self):
        """Save recommendations as JSON"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = REPORTS_DIR / f"recommendations_{timestamp}.json"
        
        report = {
            'generated': datetime.now().isoformat(),
            'total_recommendations': len(self.recommendations),
            'quick_wins': len(self.quick_wins),
            'by_priority': {
                'critical': len(self.priorities['critical']),
                'high': len(self.priorities['high']),
                'medium': len(self.priorities['medium']),
                'low': len(self.priorities['low'])
            },
            'recommendations': self.recommendations
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Colors.GREEN}✓ Recommendations saved:{Colors.NC} {output_file}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Purple Team Smart Recommendations Engine'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json', 'both'],
        default='text',
        help='Output format (default: text)'
    )
    
    args = parser.parse_args()
    
    engine = RecommendationsEngine()
    engine.generate_recommendations()
    
    if args.format in ['text', 'both']:
        engine.print_text_report()
    
    if args.format in ['json', 'both']:
        engine.save_json_report()

if __name__ == '__main__':
    main()
