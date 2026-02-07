#!/usr/bin/env python3
"""
Purple Team Portable - Assessment Orchestrator
Coordinates full security assessments with human-paced execution.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'scanners'))

from paths import paths
from config import config
from evidence import get_evidence_manager
from logger import get_logger
from network import get_scan_targets

from network_scanner import NetworkScanner
from vulnerability_scanner import VulnerabilityScanner
from web_scanner import WebScanner
from ssl_scanner import SSLScanner
from compliance_scanner import ComplianceScanner

try:
    from asset_manager import get_asset_manager
except ImportError:
    get_asset_manager = None

try:
    from credential_scanner import CredentialScanner
    from credential_manager import get_credential_manager
except ImportError:
    CredentialScanner = None
    get_credential_manager = None

try:
    from openvas_scanner import OpenVASScanner
except ImportError:
    OpenVASScanner = None


class AssessmentOrchestrator:
    """Orchestrates complete security assessments."""

    def __init__(self):
        self.paths = paths
        self.config = config
        self.evidence = get_evidence_manager()
        self.logger = get_logger('orchestrator')
        self.session_id: Optional[str] = None

    def run_full_assessment(self, targets: List[str] = None,
                            assessment_type: str = 'standard',
                            frameworks: List[str] = None) -> Dict:
        """
        Run a complete security assessment.

        Args:
            targets: Networks/hosts to assess (auto-detect if not provided)
            assessment_type: 'quick', 'standard', or 'deep'
            frameworks: Compliance frameworks to assess

        Returns:
            Complete assessment results
        """
        # Get targets
        if not targets:
            targets = get_scan_targets()
            if not targets:
                self.logger.error("No targets configured or detected")
                return {'error': 'No targets available'}

        # Get frameworks
        if not frameworks:
            frameworks = self.config.get_frameworks()

        # Start session
        self.session_id = self.evidence.start_session(
            scan_type=f'full_assessment_{assessment_type}',
            target_networks=targets,
            metadata={
                'assessment_type': assessment_type,
                'frameworks': frameworks,
                'started_by': 'orchestrator'
            }
        )

        self.logger.info(f"Starting {assessment_type} assessment")
        self.logger.info(f"Session: {self.session_id}")
        self.logger.info(f"Targets: {targets}")
        self.logger.info(f"Frameworks: {frameworks}")

        results = {
            'session_id': self.session_id,
            'assessment_type': assessment_type,
            'targets': targets,
            'frameworks': frameworks,
            'start_time': datetime.utcnow().isoformat(),
            'phases': {},
            'summary': {}
        }

        try:
            # Phase 1: Network Discovery and Port Scanning
            self.logger.info("=" * 50)
            self.logger.info("PHASE 1: Network Discovery and Port Scanning")
            self.logger.info("=" * 50)

            network_scanner = NetworkScanner(self.session_id)
            results['phases']['network'] = network_scanner.scan(
                targets=targets,
                scan_type=assessment_type
            )
            results['phases']['network']['summary'] = network_scanner.get_summary()

            # Get discovered hosts for next phases
            discovered_hosts = [
                h['ip'] for h in results['phases']['network'].get('hosts', [])
            ]

            if not discovered_hosts:
                self.logger.warning("No hosts discovered, using original targets")
                discovered_hosts = targets

            # Register assets in inventory
            if get_asset_manager is not None:
                try:
                    am = get_asset_manager()
                    am.update_from_scan(
                        self.session_id,
                        results['phases']['network']
                    )
                    inventory = am.get_inventory_summary()
                    results['asset_inventory'] = inventory
                    self.logger.info(f"Asset inventory: {inventory.get('total_assets', 0)} assets")
                except Exception as e:
                    self.logger.warning(f"Asset registration error: {e}")

            # Phase 1.5: Credentialed Scanning (if credentials configured)
            if CredentialScanner is not None and get_credential_manager is not None:
                try:
                    cm = get_credential_manager()
                    cred_targets = [h for h in discovered_hosts if cm.has_credentials_for(h)]
                    if cred_targets:
                        self.logger.info("=" * 50)
                        self.logger.info("PHASE 1.5: Credentialed Scanning")
                        self.logger.info("=" * 50)

                        cred_scanner = CredentialScanner(self.session_id)
                        results['phases']['credential'] = cred_scanner.scan(
                            targets=cred_targets,
                            scan_type=assessment_type
                        )
                        results['phases']['credential']['summary'] = cred_scanner.get_summary()
                except Exception as e:
                    self.logger.warning(f"Credentialed scanning skipped: {e}")

            # Phase 2: Vulnerability Assessment
            self.logger.info("=" * 50)
            self.logger.info("PHASE 2: Vulnerability Assessment")
            self.logger.info("=" * 50)

            vuln_scanner = VulnerabilityScanner(self.session_id)
            results['phases']['vulnerability'] = vuln_scanner.scan(
                targets=discovered_hosts,
                scan_type=assessment_type
            )
            results['phases']['vulnerability']['summary'] = vuln_scanner.get_summary()

            # Phase 2.5: OpenVAS Integration (if available)
            if OpenVASScanner is not None:
                try:
                    openvas = OpenVASScanner(self.session_id)
                    if openvas.gvm_available and openvas.gvm_mode in ('gmp', 'cli'):
                        self.logger.info("=" * 50)
                        self.logger.info("PHASE 2.5: OpenVAS/GVM Scanning")
                        self.logger.info("=" * 50)

                        results['phases']['openvas'] = openvas.scan(
                            targets=discovered_hosts,
                            scan_type=assessment_type
                        )
                        results['phases']['openvas']['summary'] = openvas.get_summary()
                except Exception as e:
                    self.logger.warning(f"OpenVAS scanning skipped: {e}")

            # Phase 3: Web Application Scanning
            self.logger.info("=" * 50)
            self.logger.info("PHASE 3: Web Application Scanning")
            self.logger.info("=" * 50)

            web_scanner = WebScanner(self.session_id)
            results['phases']['web'] = web_scanner.scan(
                targets=discovered_hosts,
                scan_type=assessment_type
            )
            results['phases']['web']['summary'] = web_scanner.get_summary()

            # Phase 4: SSL/TLS Assessment
            self.logger.info("=" * 50)
            self.logger.info("PHASE 4: SSL/TLS Assessment")
            self.logger.info("=" * 50)

            ssl_scanner = SSLScanner(self.session_id)
            results['phases']['ssl'] = ssl_scanner.scan(
                targets=discovered_hosts,
                scan_type=assessment_type
            )
            results['phases']['ssl']['summary'] = ssl_scanner.get_summary()

            # Phase 5: Compliance Assessment
            self.logger.info("=" * 50)
            self.logger.info("PHASE 5: Compliance Assessment")
            self.logger.info("=" * 50)

            compliance_scanner = ComplianceScanner(self.session_id)
            results['phases']['compliance'] = compliance_scanner.scan(
                frameworks=frameworks
            )
            results['phases']['compliance']['summary'] = compliance_scanner.get_summary()

            # Generate overall summary
            results['end_time'] = datetime.utcnow().isoformat()
            results['summary'] = self._generate_overall_summary(results)

            # End session
            self.evidence.end_session(self.session_id, results['summary'])

            self.logger.info("=" * 50)
            self.logger.info("ASSESSMENT COMPLETE")
            self.logger.info("=" * 50)
            self.logger.info(f"Session: {self.session_id}")
            self.logger.info(f"Total findings: {results['summary']['total_findings']}")

        except Exception as e:
            self.logger.error(f"Assessment failed: {e}")
            results['error'] = str(e)
            results['end_time'] = datetime.utcnow().isoformat()
            self.evidence.end_session(self.session_id, {'error': str(e)})

        return results

    def _generate_overall_summary(self, results: Dict) -> Dict:
        """Generate overall assessment summary."""
        summary = {
            'total_hosts_scanned': 0,
            'total_ports_found': 0,
            'total_findings': 0,
            'findings_by_severity': {
                'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
            },
            'compliance_rate': 0.0,
            'phases_completed': len(results.get('phases', {}))
        }

        # Aggregate from phases
        for phase_name, phase_data in results.get('phases', {}).items():
            phase_summary = phase_data.get('summary', {})

            if phase_name == 'network':
                summary['total_hosts_scanned'] = phase_summary.get('total_hosts', 0)
                summary['total_ports_found'] = phase_summary.get('total_ports', 0)

            # Aggregate findings
            findings_count = phase_summary.get('findings_count', 0)
            summary['total_findings'] += findings_count

            for sev, count in phase_summary.get('findings_by_severity', {}).items():
                summary['findings_by_severity'][sev] = summary['findings_by_severity'].get(sev, 0) + count

            if phase_name == 'compliance':
                summary['compliance_rate'] = phase_data.get('summary', {}).get('overall_compliance_rate', 0)

        return summary

    def run_quick_scan(self, targets: List[str] = None) -> Dict:
        """Run a quick security scan."""
        return self.run_full_assessment(targets, 'quick')

    def run_deep_assessment(self, targets: List[str] = None,
                             frameworks: List[str] = None) -> Dict:
        """Run a comprehensive deep assessment."""
        return self.run_full_assessment(targets, 'deep', frameworks)


def run_assessment(assessment_type: str = 'standard', targets: List[str] = None,
                   frameworks: List[str] = None) -> Dict:
    """Convenience function to run an assessment."""
    orchestrator = AssessmentOrchestrator()
    return orchestrator.run_full_assessment(targets, assessment_type, frameworks)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Run security assessment')
    parser.add_argument('--type', choices=['quick', 'standard', 'deep'],
                       default='standard', help='Assessment type')
    parser.add_argument('--targets', nargs='+', help='Target networks/hosts')
    parser.add_argument('--frameworks', nargs='+', help='Compliance frameworks')

    args = parser.parse_args()

    orchestrator = AssessmentOrchestrator()
    results = orchestrator.run_full_assessment(
        targets=args.targets,
        assessment_type=args.type,
        frameworks=args.frameworks
    )

    print(f"\nAssessment complete!")
    print(f"Session: {results.get('session_id')}")
    print(f"Summary: {results.get('summary')}")
