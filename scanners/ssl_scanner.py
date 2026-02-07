#!/usr/bin/env python3
"""
Purple Team Portable - SSL/TLS Scanner
Comprehensive SSL/TLS configuration assessment using testssl.sh.
"""

import re
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


class SSLScanner(BaseScanner):
    """SSL/TLS configuration scanner."""

    SCANNER_NAME = "ssl"
    SCANNER_DESCRIPTION = "SSL/TLS configuration assessment"

    # SSL/TLS ports
    SSL_PORTS = [443, 8443, 993, 995, 465, 636, 989, 990, 992, 994, 5061]

    # Severity mapping for testssl findings
    SEVERITY_MAP = {
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW',
        'WARN': 'LOW',
        'INFO': 'INFO',
        'OK': 'INFO'
    }

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.testssl_path = None

    def scan(self, targets: List[str], ports: List[int] = None,
             scan_type: str = 'standard', **kwargs) -> Dict:
        """
        Execute SSL/TLS scan.

        Args:
            targets: List of hosts to scan
            ports: List of ports to check
            scan_type: 'quick', 'standard', or 'deep'
        """
        self.start_time = datetime.utcnow()

        # Check for testssl.sh
        if not self.check_tool('testssl.sh'):
            self.scan_logger.error("testssl.sh not available")
            return {'error': 'testssl.sh not installed'}

        self.testssl_path = self.paths.find_tool('testssl.sh')
        ports = ports or self.SSL_PORTS

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'certificates': [],
            'protocols': [],
            'ciphers': [],
            'vulnerabilities': [],
            'summary': {}
        }

        for target in targets:
            for port in ports:
                self.scan_logger.info(f"Scanning SSL/TLS on {target}:{port}")

                try:
                    scan_result = self._run_testssl(target, port, scan_type)
                    if scan_result:
                        results['certificates'].extend(scan_result.get('certificates', []))
                        results['protocols'].extend(scan_result.get('protocols', []))
                        results['ciphers'].extend(scan_result.get('ciphers', []))
                        results['vulnerabilities'].extend(scan_result.get('vulnerabilities', []))
                except Exception as e:
                    self.scan_logger.warning(f"Error scanning {target}:{port}: {e}")

                self.human_delay()

        # Generate summary
        results['summary'] = self._generate_summary(results)

        self.end_time = datetime.utcnow()
        self.save_results()

        return results

    def _run_testssl(self, host: str, port: int, scan_type: str) -> Optional[Dict]:
        """Run testssl.sh scanner."""
        target = f"{host}:{port}"

        cmd = [
            str(self.testssl_path),
            '--jsonfile-pretty', '-',  # JSON to stdout
            '--warnings', 'off',
            '--color', '0'
        ]

        # Adjust scan based on type
        if scan_type == 'quick':
            cmd.extend(['--fast'])
        elif scan_type == 'deep':
            cmd.extend(['--full'])

        cmd.append(target)

        try:
            result = self.run_tool(cmd, timeout=300, description=f"testssl on {target}")

            # Parse JSON output
            try:
                data = json.loads(result.stdout)
                return self._parse_testssl_json(data, host, port)
            except json.JSONDecodeError:
                # Fallback to text parsing
                return self._parse_testssl_text(result.stdout, host, port)

        except Exception as e:
            self.scan_logger.warning(f"testssl error: {e}")
            return None

    def _parse_testssl_json(self, data: Dict, host: str, port: int) -> Dict:
        """Parse testssl.sh JSON output."""
        result = {
            'certificates': [],
            'protocols': [],
            'ciphers': [],
            'vulnerabilities': []
        }

        if not isinstance(data, list):
            data = [data]

        for entry in data:
            finding_type = entry.get('id', '')
            severity = self.SEVERITY_MAP.get(entry.get('severity', 'INFO'), 'INFO')
            finding = entry.get('finding', '')

            # Categorize findings
            if 'cert' in finding_type.lower():
                result['certificates'].append({
                    'host': host,
                    'port': port,
                    'check': finding_type,
                    'finding': finding,
                    'severity': severity
                })

                # Check for certificate issues
                if severity in ['HIGH', 'CRITICAL', 'MEDIUM']:
                    self._add_ssl_finding(host, port, finding_type, finding, severity, 'expired_certificate')

            elif 'protocol' in finding_type.lower() or finding_type.startswith('SSL') or finding_type.startswith('TLS'):
                result['protocols'].append({
                    'host': host,
                    'port': port,
                    'protocol': finding_type,
                    'status': finding,
                    'severity': severity
                })

                if severity in ['HIGH', 'CRITICAL']:
                    self._add_ssl_finding(host, port, finding_type, finding, severity, 'ssl_vulnerability')

            elif 'cipher' in finding_type.lower():
                result['ciphers'].append({
                    'host': host,
                    'port': port,
                    'cipher': finding_type,
                    'status': finding,
                    'severity': severity
                })

                if severity in ['HIGH', 'CRITICAL', 'MEDIUM']:
                    self._add_ssl_finding(host, port, finding_type, finding, severity, 'weak_cipher')

            else:
                # Vulnerability checks
                if severity in ['HIGH', 'CRITICAL', 'MEDIUM']:
                    result['vulnerabilities'].append({
                        'host': host,
                        'port': port,
                        'vuln': finding_type,
                        'finding': finding,
                        'severity': severity
                    })
                    self._add_ssl_finding(host, port, finding_type, finding, severity, 'ssl_vulnerability')

        return result

    def _parse_testssl_text(self, output: str, host: str, port: int) -> Dict:
        """Parse testssl.sh text output (fallback)."""
        result = {
            'certificates': [],
            'protocols': [],
            'ciphers': [],
            'vulnerabilities': []
        }

        # Common vulnerability patterns
        vuln_patterns = [
            (r'VULNERABLE', 'CRITICAL', 'ssl_vulnerability'),
            (r'NOT ok', 'HIGH', 'ssl_vulnerability'),
            (r'WEAK', 'MEDIUM', 'weak_cipher'),
            (r'expired', 'HIGH', 'expired_certificate'),
            (r'SSLv2', 'CRITICAL', 'ssl_vulnerability'),
            (r'SSLv3', 'HIGH', 'ssl_vulnerability'),
            (r'RC4', 'MEDIUM', 'weak_cipher'),
            (r'DES', 'MEDIUM', 'weak_cipher'),
            (r'MD5', 'MEDIUM', 'weak_cipher'),
        ]

        for line in output.split('\n'):
            for pattern, severity, finding_type in vuln_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = {
                        'host': host,
                        'port': port,
                        'finding': line.strip(),
                        'severity': severity
                    }
                    result['vulnerabilities'].append(finding)
                    self._add_ssl_finding(host, port, pattern, line.strip(), severity, finding_type)
                    break

        return result

    def _add_ssl_finding(self, host: str, port: int, check: str,
                          finding: str, severity: str, finding_type: str):
        """Add SSL/TLS finding."""
        self.add_finding(
            severity=severity,
            title=f"SSL/TLS Issue: {check}",
            description=finding,
            affected_asset=f"{host}:{port}",
            finding_type=finding_type,
            remediation=self._get_ssl_remediation(finding_type),
            raw_data={'check': check, 'finding': finding},
            detection_method='protocol_test'
        )

    def _get_ssl_remediation(self, finding_type: str) -> str:
        """Get remediation advice for SSL findings."""
        remediation = {
            'ssl_vulnerability': 'Update SSL/TLS configuration. Disable vulnerable protocols (SSLv2, SSLv3, TLS 1.0/1.1). Enable TLS 1.2/1.3 only.',
            'weak_cipher': 'Disable weak cipher suites. Use only strong ciphers (AES-GCM, ChaCha20). Follow Mozilla SSL Configuration Generator recommendations.',
            'expired_certificate': 'Renew SSL certificate before expiration. Implement certificate monitoring and automated renewal.',
        }
        return remediation.get(finding_type, 'Review and update SSL/TLS configuration.')

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate SSL scan summary."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for vuln in results['vulnerabilities']:
            sev = vuln.get('severity', 'INFO')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            'certificates_checked': len(results['certificates']),
            'protocols_checked': len(results['protocols']),
            'cipher_issues': len(results['ciphers']),
            'vulnerabilities_found': len(results['vulnerabilities']),
            'by_severity': severity_counts
        }


if __name__ == '__main__':
    scanner = SSLScanner()
    print(f"SSL Scanner initialized")
    print(f"testssl.sh available: {scanner.check_tool('testssl.sh')}")
