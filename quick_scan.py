#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detection
Quick Scan Utility
Fast, targeted security scans for immediate needs

Perfect for:
- Quick checks before meetings
- Rapid verification after changes
- Targeted scans on specific hosts
- Emergency security checks
"""

import subprocess
import json
from pathlib import Path
from datetime import datetime
import argparse
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
# FIX: Added REPORTS_DIR to imports
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR, REPORTS_DIR

# Specific results directory
QUICK_SCANS_DIR = RESULTS_DIR / 'quick-scans'

class QuickScanner:
    """Fast security scanning for immediate results"""
    
    def __init__(self):
        # FIX: Removed redundant line - REPORTS_DIR.mkdir() is already handled by path_helper
        pass
    
    def quick_port_scan(self, target, ports='top100'):
        """
        Fast port scan
        
        Args:
            target: IP address or hostname
            ports: 'top100', 'top1000', or specific ports like '80,443,22'
        """
        
        logger.info(f"Quick port scan: {target}")
        
        if ports == 'top100':
            port_arg = '--top-ports 100'
        elif ports == 'top1000':
            port_arg = '--top-ports 1000'
        else:
            port_arg = f'-p {ports}'
        
        cmd = f"nmap -Pn -T4 {port_arg} {target}"
        
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return self._parse_nmap_output(result.stdout, target)
            
        except subprocess.TimeoutExpired:
            logger.error("Scan timeout")
            return {'error': 'Scan timeout'}
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {'error': str(e)}
    
    def quick_vuln_check(self, target):
        """Quick vulnerability check on specific target"""
        
        logger.info(f"Quick vulnerability check: {target}")
        
        # Use Nuclei with severity high and critical only
        cmd = [
            'nuclei',
            '-target', target,
            '-severity', 'high,critical',
            '-silent',
            '-jsonl'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append({
                            'title': finding.get('info', {}).get('name'),
                            'severity': finding.get('info', {}).get('severity'),
                            'description': finding.get('info', {}).get('description'),
                            'matched_at': finding.get('matched-at')
                        })
                    except:
                        pass
            
            return {
                'target': target,
                'findings_count': len(findings),
                'findings': findings
            }
            
        except Exception as e:
            logger.error(f"Vulnerability check failed: {e}")
            return {'error': str(e)}
    
    def quick_web_scan(self, url):
        """Quick web application scan"""
        
        logger.info(f"Quick web scan: {url}")
        
        findings = []
        
        # Quick Nikto scan (fast mode)
        cmd = [
            'nikto',
            '-h', url,
            '-Tuning', '1,2,3',  # Interesting files, misconfig, info disclosure
            '-output', '/tmp/nikto_quick.json',
            '-Format', 'json'
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
            
            # Parse results
            try:
                with open('/tmp/nikto_quick.json', 'r') as f:
                    data = json.load(f)
                    
                for vuln in data.get('vulnerabilities', []):
                    findings.append({
                        'title': vuln.get('msg'),
                        'severity': 'medium',
                        'url': vuln.get('url')
                    })
            except:
                pass
            
        except Exception as e:
            logger.warning(f"Nikto scan failed: {e}")
        
        return {
            'url': url,
            'findings_count': len(findings),
            'findings': findings
        }
    
    def quick_ssl_check(self, host):
        """Quick SSL/TLS security check"""
        
        logger.info(f"Quick SSL check: {host}")
        
        cmd = ['testssl.sh', '--fast', '--json', host]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            issues = []
            # Parse testssl.sh JSON output
            for line in result.stdout.split('\n'):
                if '"severity"' in line and '"HIGH"' in line:
                    issues.append(line)
            
            return {
                'host': host,
                'issues_count': len(issues),
                'has_issues': len(issues) > 0
            }
            
        except Exception as e:
            logger.error(f"SSL check failed: {e}")
            return {'error': str(e)}
    
    def quick_host_discovery(self, network):
        """Quick host discovery on network"""
        
        logger.info(f"Quick host discovery: {network}")
        
        cmd = f"nmap -sn -T4 {network}"
        
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse for up hosts
            hosts = []
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    host = line.split('for ')[-1].strip()
                    hosts.append(host)
            
            return {
                'network': network,
                'hosts_found': len(hosts),
                'hosts': hosts
            }
            
        except Exception as e:
            logger.error(f"Host discovery failed: {e}")
            return {'error': str(e)}
    
    def _parse_nmap_output(self, output, target):
        """Parse nmap output"""
        
        open_ports = []
        
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    open_ports.append({
                        'port': port,
                        'service': service
                    })
        
        return {
            'target': target,
            'open_ports_count': len(open_ports),
            'open_ports': open_ports
        }
    
    def save_results(self, results, scan_type):
        """Save scan results"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'quick_{scan_type}_{timestamp}.json'
        filepath = REPORTS_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Results saved: {filepath}")
        return filepath
    
    def print_results(self, results, scan_type):
        """Print results to console"""
        
        print("\n" + "="*70)
        print(f"QUICK {scan_type.upper()} SCAN RESULTS")
        print("="*70)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if 'error' in results:
            print(f"\n✗ Error: {results['error']}")
        else:
            if scan_type == 'port':
                print(f"\nTarget: {results.get('target')}")
                print(f"Open Ports: {results.get('open_ports_count', 0)}")
                if results.get('open_ports'):
                    print("\nOpen Ports:")
                    for port in results['open_ports']:
                        print(f"  {port['port']:6s} - {port['service']}")
            
            elif scan_type == 'vuln':
                print(f"\nTarget: {results.get('target')}")
                print(f"Findings: {results.get('findings_count', 0)}")
                if results.get('findings'):
                    print("\nHigh/Critical Findings:")
                    for finding in results['findings']:
                        print(f"\n  [{finding.get('severity', 'unknown').upper()}] {finding.get('title')}")
                        print(f"  {finding.get('matched_at', 'N/A')}")
            
            elif scan_type == 'web':
                print(f"\nURL: {results.get('url')}")
                print(f"Findings: {results.get('findings_count', 0)}")
                if results.get('findings'):
                    print("\nFindings:")
                    for finding in results['findings']:
                        print(f"  • {finding.get('title')}")
            
            elif scan_type == 'ssl':
                print(f"\nHost: {results.get('host')}")
                print(f"SSL Issues: {'Yes' if results.get('has_issues') else 'No'}")
            
            elif scan_type == 'discovery':
                print(f"\nNetwork: {results.get('network')}")
                print(f"Hosts Found: {results.get('hosts_found', 0)}")
                if results.get('hosts'):
                    print("\nLive Hosts:")
                    for host in results['hosts']:
                        print(f"  • {host}")
        
        print("\n" + "="*70 + "\n")

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description='Quick Scan Utility - Fast targeted security scans'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Scan type')
    
    # Port scan
    port_parser = subparsers.add_parser('port', help='Quick port scan')
    port_parser.add_argument('target', help='IP or hostname')
    port_parser.add_argument('--ports', default='top100',
                            help='Ports to scan (top100, top1000, or comma-separated)')
    
    # Vulnerability scan
    vuln_parser = subparsers.add_parser('vuln', help='Quick vulnerability check')
    vuln_parser.add_argument('target', help='Target URL or IP')
    
    # Web scan
    web_parser = subparsers.add_parser('web', help='Quick web scan')
    web_parser.add_argument('url', help='Target URL')
    
    # SSL check
    ssl_parser = subparsers.add_parser('ssl', help='Quick SSL/TLS check')
    ssl_parser.add_argument('host', help='Hostname:port')
    
    # Host discovery
    discovery_parser = subparsers.add_parser('discovery', help='Quick host discovery')
    discovery_parser.add_argument('network', help='Network range (e.g., 10.0.1.0/24)')
    
    # Common options
    parser.add_argument('--save', action='store_true', help='Save results to file')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        exit(1)
    
    scanner = QuickScanner()
    
    # Run appropriate scan
    if args.command == 'port':
        results = scanner.quick_port_scan(args.target, args.ports)
    elif args.command == 'vuln':
        results = scanner.quick_vuln_check(args.target)
    elif args.command == 'web':
        results = scanner.quick_web_scan(args.url)
    elif args.command == 'ssl':
        results = scanner.quick_ssl_check(args.host)
    elif args.command == 'discovery':
        results = scanner.quick_host_discovery(args.network)
    else:
        print("Unknown command")
        exit(1)
    
    # Output results
    if not args.quiet:
        scanner.print_results(results, args.command)
    
    # Save if requested
    if args.save:
        scanner.save_results(results, args.command)

if __name__ == '__main__':
    main()
