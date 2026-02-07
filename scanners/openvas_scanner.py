#!/usr/bin/env python3
"""
Purple Team Platform v6.0 - OpenVAS/GVM Integration Scanner
Direct integration with OpenVAS/Greenbone Vulnerability Manager.
Three modes: GMP protocol, CLI mode, and XML import mode.
Enriches imported findings with our KEV/EPSS data (value-add over standalone OpenVAS).
"""

import re
import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from threat_intel import get_threat_intel
except ImportError:
    get_threat_intel = None


class OpenVASScanner(BaseScanner):
    """OpenVAS/GVM integration scanner."""

    SCANNER_NAME = "openvas"
    SCANNER_DESCRIPTION = "OpenVAS/GVM vulnerability scanner integration"

    # OpenVAS severity to our severity mapping
    SEVERITY_MAP = {
        'Log': 'INFO',
        'Low': 'LOW',
        'Medium': 'MEDIUM',
        'High': 'HIGH',
        'Critical': 'CRITICAL',
    }

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.gvm_available = False
        self.gvm_mode = None
        self._detect_gvm()

    def _detect_gvm(self):
        """Detect available GVM integration mode."""
        # Check for python-gvm library
        try:
            import gvm
            self.gvm_mode = 'gmp'
            self.gvm_available = True
            self.scan_logger.info("GVM detected: python-gvm library (GMP mode)")
            return
        except ImportError:
            pass

        # Check for gvm-cli
        import shutil
        if shutil.which('gvm-cli'):
            self.gvm_mode = 'cli'
            self.gvm_available = True
            self.scan_logger.info("GVM detected: gvm-cli (CLI mode)")
            return

        # Check for Docker image
        try:
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}'],
                capture_output=True, text=True, timeout=10
            )
            if 'greenbone' in result.stdout.lower() or 'gvm' in result.stdout.lower():
                self.gvm_mode = 'docker'
                self.gvm_available = True
                self.scan_logger.info("GVM detected: Docker container")
                return
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Import mode is always available (for XML files)
        self.gvm_mode = 'import'
        self.scan_logger.info("GVM: Import mode only (no live scanner detected)")

    def scan(self, targets: List[str], scan_type: str = 'standard',
             report_path: str = None, **kwargs) -> Dict:
        """
        Execute OpenVAS scan or import results.

        Args:
            targets: List of hosts to scan
            scan_type: 'quick', 'standard', 'deep'
            report_path: Path to existing OpenVAS XML report to import
        """
        self.start_time = datetime.utcnow()

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'mode': self.gvm_mode,
            'findings': [],
            'summary': {}
        }

        if report_path:
            # Import mode
            results['findings'] = self.import_openvas_report(report_path)
            results['mode'] = 'import'
        elif self.gvm_mode == 'gmp':
            results['findings'] = self._scan_gmp(targets, scan_type)
        elif self.gvm_mode == 'cli':
            results['findings'] = self._scan_cli(targets, scan_type)
        else:
            self.scan_logger.warning("No live OpenVAS scanner available. Use import mode.")
            results['error'] = 'No live OpenVAS scanner. Provide report_path for import.'

        # Enrich all findings with KEV/EPSS
        if get_threat_intel is not None:
            self._enrich_findings(results['findings'])

        results['summary'] = self._generate_summary(results['findings'])

        self.end_time = datetime.utcnow()
        self.save_results()

        return results

    def _scan_gmp(self, targets: List[str], scan_type: str) -> List[Dict]:
        """Scan using GMP protocol via python-gvm."""
        findings = []

        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform

            connection = UnixSocketConnection()
            transform = EtreeTransform()

            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate('admin', 'admin')

                # Create target
                target_list = ' '.join(targets)
                target_id = gmp.create_target(
                    name=f'PurpleTeam-{datetime.utcnow().strftime("%Y%m%d%H%M")}',
                    hosts=targets
                ).get('id')

                # Select scan config
                config_map = {
                    'quick': 'daba56c8-73ec-11df-a475-002264764cea',  # Discovery
                    'standard': '085569ce-73ed-11df-83c3-002264764cea',  # Full and fast
                    'deep': '698f691e-7489-11df-9d8c-002264764cea',  # Full and deep
                }
                config_id = config_map.get(scan_type, config_map['standard'])

                # Create and start task
                task_id = gmp.create_task(
                    name=f'PurpleTeam Scan {scan_type}',
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id='08b69003-5fc2-4037-a479-93b440211c73'
                ).get('id')

                gmp.start_task(task_id)
                self.scan_logger.info(f"Started OpenVAS task: {task_id}")

                # Note: In production, would poll for completion
                # For now, log that task was started
                findings.append({
                    'title': 'OpenVAS scan started',
                    'severity': 'INFO',
                    'description': f'GMP task {task_id} started for {target_list}',
                    'affected_host': target_list,
                    'tool': 'openvas-gmp',
                })

        except Exception as e:
            self.scan_logger.error(f"GMP scan error: {e}")

        return findings

    def _scan_cli(self, targets: List[str], scan_type: str) -> List[Dict]:
        """Scan using gvm-cli."""
        findings = []
        target_list = ' '.join(targets)

        try:
            # Create XML command for gvm-cli
            cmd = [
                'gvm-cli', '--gmp-username', 'admin', '--gmp-password', 'admin',
                'socket', '--xml',
                f'<get_version/>'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.scan_logger.info(f"GVM CLI connected: {result.stdout[:100]}")
                findings.append({
                    'title': 'OpenVAS CLI connection established',
                    'severity': 'INFO',
                    'description': f'Connected to GVM via CLI for targets: {target_list}',
                    'affected_host': target_list,
                    'tool': 'openvas-cli',
                })
            else:
                self.scan_logger.warning(f"GVM CLI error: {result.stderr}")

        except Exception as e:
            self.scan_logger.error(f"CLI scan error: {e}")

        return findings

    def import_openvas_report(self, xml_path: str) -> List[Dict]:
        """Import findings from an OpenVAS XML report."""
        findings = []
        path = Path(xml_path)

        if not path.exists():
            self.scan_logger.error(f"Report file not found: {xml_path}")
            return findings

        self.scan_logger.info(f"Importing OpenVAS report: {xml_path}")

        try:
            tree = ET.parse(str(path))
            root = tree.getroot()

            # Handle both report formats
            results = root.findall('.//result') or root.findall('.//results/result')

            for result_elem in results:
                finding = self._parse_openvas_result(result_elem)
                if finding:
                    findings.append(finding)
                    self._record_finding(finding)

            self.scan_logger.info(f"Imported {len(findings)} findings from OpenVAS report")

        except ET.ParseError as e:
            self.scan_logger.error(f"XML parse error: {e}")
        except Exception as e:
            self.scan_logger.error(f"Import error: {e}")

        return findings

    def _parse_openvas_result(self, result_elem) -> Optional[Dict]:
        """Parse a single OpenVAS XML result element."""
        try:
            name = result_elem.findtext('name', 'Unknown')
            host_elem = result_elem.find('host')
            host = host_elem.text if host_elem is not None else 'unknown'
            port = result_elem.findtext('port', '')
            severity_text = result_elem.findtext('threat', 'Log')

            # Get NVT details
            nvt = result_elem.find('nvt')
            cvss = 0.0
            cve_ids = []
            qod_value = 0
            oid = ''

            if nvt is not None:
                oid = nvt.get('oid', '')
                cvss_text = nvt.findtext('cvss_base', '0')
                try:
                    cvss = float(cvss_text)
                except (ValueError, TypeError):
                    cvss = 0.0

                # Extract CVEs
                cve_text = nvt.findtext('cve', '')
                if cve_text and cve_text != 'NOCVE':
                    cve_ids = [c.strip() for c in cve_text.split(',') if c.strip().startswith('CVE-')]

                # Get QoD
                qod_elem = result_elem.find('qod')
                if qod_elem is not None:
                    qod_text = qod_elem.findtext('value', '0')
                    try:
                        qod_value = float(qod_text)
                    except (ValueError, TypeError):
                        qod_value = 0

            severity = self.SEVERITY_MAP.get(severity_text, 'INFO')

            description = result_elem.findtext('description', '')
            solution = ''
            if nvt is not None:
                solution = nvt.findtext('solution', '') or nvt.findtext('fix', '')

            return {
                'title': name,
                'severity': severity,
                'description': description,
                'affected_host': host,
                'affected_port': port,
                'cvss_score': cvss,
                'cve_ids': cve_ids,
                'qod': qod_value,
                'oid': oid,
                'remediation': solution,
                'tool': 'openvas',
            }

        except Exception as e:
            self.scan_logger.warning(f"Error parsing OpenVAS result: {e}")
            return None

    def _record_finding(self, finding: Dict):
        """Record an imported finding using the standard add_finding method."""
        self.add_finding(
            severity=finding['severity'],
            title=finding['title'],
            description=finding.get('description', ''),
            affected_asset=finding.get('affected_host', ''),
            finding_type='cve_vulnerability' if finding.get('cve_ids') else 'openvas_finding',
            cvss_score=finding.get('cvss_score', 0.0),
            cve_ids=finding.get('cve_ids', []),
            remediation=finding.get('remediation', ''),
            raw_data=finding,
            detection_method='openvas_import'
        )

    def _enrich_findings(self, findings: List[Dict]):
        """Enrich OpenVAS findings with KEV/EPSS data."""
        if not get_threat_intel:
            return

        try:
            ti = get_threat_intel()

            # Collect all CVEs
            all_cves = []
            for f in findings:
                all_cves.extend(f.get('cve_ids', []))

            if all_cves:
                enrichments = ti.enrich_findings_batch(list(set(all_cves)))

                for finding in findings:
                    for cve_id in finding.get('cve_ids', []):
                        if cve_id in enrichments:
                            e = enrichments[cve_id]
                            finding['kev_status'] = e.get('kev_status', False)
                            finding['epss_score'] = max(
                                finding.get('epss_score', 0),
                                e.get('epss_score', 0)
                            )
                            finding['epss_percentile'] = max(
                                finding.get('epss_percentile', 0),
                                e.get('epss_percentile', 0)
                            )

                self.scan_logger.info(f"Enriched {len(findings)} findings with KEV/EPSS data")

        except Exception as e:
            self.scan_logger.warning(f"Enrichment error: {e}")

    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate scan summary."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        kev_count = 0
        hosts = set()
        cves = set()

        for f in findings:
            sev = f.get('severity', 'INFO').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            hosts.add(f.get('affected_host', ''))
            for cve in f.get('cve_ids', []):
                cves.add(cve)
            if f.get('kev_status'):
                kev_count += 1

        return {
            'total_findings': len(findings),
            'by_severity': severity_counts,
            'unique_cves': len(cves),
            'hosts_affected': len(hosts),
            'kev_findings': kev_count,
            'mode': self.gvm_mode,
        }

    def sync_findings(self):
        """Two-way sync between our DB and OpenVAS (placeholder for GMP mode)."""
        if self.gvm_mode != 'gmp':
            self.scan_logger.info("Sync only available in GMP mode")
            return

        self.scan_logger.info("Syncing findings with OpenVAS...")
        # Implementation would pull latest results from GVM and update our DB


if __name__ == '__main__':
    scanner = OpenVASScanner()
    print(f"OpenVAS Scanner initialized")
    print(f"GVM available: {scanner.gvm_available}")
    print(f"Mode: {scanner.gvm_mode}")

    import sys
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        print(f"\nImporting report: {report_path}")
        findings = scanner.import_openvas_report(report_path)
        print(f"Imported {len(findings)} findings")
