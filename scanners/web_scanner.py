#!/usr/bin/env python3
"""
Purple Team Portable - Web Application Scanner
Web server and application vulnerability assessment using nikto.
"""

import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


class WebScanner(BaseScanner):
    """Web application vulnerability scanner."""

    SCANNER_NAME = "web"
    SCANNER_DESCRIPTION = "Web application vulnerability assessment"

    # Common web ports
    WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.nikto_path = None

    def scan(self, targets: List[str], ports: List[int] = None,
             scan_type: str = 'standard', **kwargs) -> Dict:
        """
        Execute web application scan.

        Args:
            targets: List of hosts to scan
            ports: List of ports to check (default: common web ports)
            scan_type: 'quick', 'standard', or 'deep'
        """
        self.start_time = datetime.utcnow()

        # Check for nikto
        if not self.check_tool('nikto'):
            self.scan_logger.error("Nikto not available")
            return {'error': 'Nikto not installed'}

        self.nikto_path = self.paths.find_tool('nikto')
        ports = ports or self.WEB_PORTS

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'findings': [],
            'summary': {}
        }

        for target in targets:
            for port in ports:
                # Determine protocol
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{target}:{port}"

                self.scan_logger.info(f"Scanning web service at {url}")

                try:
                    findings = self._run_nikto(target, port, protocol, scan_type)
                    results['findings'].extend(findings)
                except Exception as e:
                    self.scan_logger.warning(f"Error scanning {url}: {e}")

                self.human_delay()

        # Generate summary
        results['summary'] = {
            'total_findings': len(results['findings']),
            'targets_scanned': len(targets),
            'ports_checked': len(ports)
        }

        self.end_time = datetime.utcnow()
        self.save_results()

        return results

    def _run_nikto(self, host: str, port: int, protocol: str,
                    scan_type: str) -> List[Dict]:
        """Run nikto web scanner."""
        findings = []

        cmd = [
            str(self.nikto_path),
            '-h', host,
            '-p', str(port),
            '-Format', 'txt',
            '-nointeractive',
            '-maxtime', '300s'
        ]

        if protocol == 'https':
            cmd.append('-ssl')

        # Adjust scan intensity
        if scan_type == 'quick':
            cmd.extend(['-Tuning', '1'])  # Interesting files only
        elif scan_type == 'deep':
            cmd.extend(['-Tuning', 'x'])  # All checks

        try:
            result = self.run_tool(cmd, timeout=600, description=f"Nikto scan on {host}:{port}")
            findings = self._parse_nikto_output(result.stdout, host, port)
        except Exception as e:
            self.scan_logger.warning(f"Nikto error: {e}")

        return findings

    def _parse_nikto_output(self, output: str, host: str, port: int) -> List[Dict]:
        """Parse nikto output."""
        findings = []

        for line in output.split('\n'):
            # Skip header/info lines
            if not line.startswith('+ '):
                continue

            line = line[2:].strip()

            # Skip certain info lines
            if any(skip in line.lower() for skip in ['target ip:', 'target hostname:', 'target port:', 'start time:', 'end time:']):
                continue

            # Determine severity based on content
            severity = 'INFO'
            finding_type = 'web_vulnerability'

            if any(term in line.lower() for term in ['vulnerability', 'vulnerable', 'exploit']):
                severity = 'HIGH'
            elif any(term in line.lower() for term in ['outdated', 'old version', 'deprecated']):
                severity = 'MEDIUM'
            elif any(term in line.lower() for term in ['information disclosure', 'directory listing', 'backup file']):
                severity = 'MEDIUM'
                finding_type = 'information_disclosure'
            elif any(term in line.lower() for term in ['header', 'cookie', 'missing']):
                severity = 'LOW'
                finding_type = 'insecure_configuration'

            # Extract OSVDB/CVE if present
            cve_ids = re.findall(r'CVE-\d{4}-\d+', line, re.IGNORECASE)
            osvdb = re.findall(r'OSVDB-\d+', line, re.IGNORECASE)

            finding = {
                'host': host,
                'port': port,
                'finding': line,
                'severity': severity,
                'cve_ids': cve_ids,
                'osvdb': osvdb,
                'tool': 'nikto'
            }
            findings.append(finding)

            # Add as formal finding
            self.add_finding(
                severity=severity,
                title=line[:100],
                description=line,
                affected_asset=f"{host}:{port}",
                finding_type=finding_type,
                cve_ids=cve_ids,
                raw_data=finding,
                detection_method='banner_grab'
            )

        return findings


if __name__ == '__main__':
    scanner = WebScanner()
    print(f"Web Scanner initialized")
    print(f"Nikto available: {scanner.check_tool('nikto')}")
