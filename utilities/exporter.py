#!/usr/bin/env python3
"""
Purple Team Portable - Compliance Exporter
Exports compliance data in formats compatible with GRC platforms.
Supports OSCAL, CSV, JSON, and platform-specific formats.
"""

import json
import csv
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from paths import paths
from config import config
from evidence import get_evidence_manager
from compliance import get_compliance_mapper
from logger import get_logger


class ComplianceExporter:
    """Exports compliance data for various GRC platforms."""

    def __init__(self):
        self.paths = paths
        self.config = config
        self.evidence = get_evidence_manager()
        self.compliance = get_compliance_mapper()
        self.logger = get_logger('exporter')

    def export_oscal(self, framework: str, output_path: Path = None) -> Path:
        """
        Export in OSCAL (Open Security Controls Assessment Language) format.
        Federal/NIST standard for compliance automation.
        """
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"oscal_{framework}_{timestamp}.json"

        summary = self.compliance.generate_compliance_summary(self.evidence, framework)

        oscal_doc = {
            "assessment-results": {
                "uuid": f"ar-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                "metadata": {
                    "title": f"{framework} Assessment Results",
                    "last-modified": datetime.utcnow().isoformat() + "Z",
                    "version": "1.0.0",
                    "oscal-version": "1.1.2"
                },
                "import-ap": {
                    "href": f"#{framework.lower()}-assessment-plan"
                },
                "local-definitions": {
                    "assessment-assets": {
                        "components": []
                    }
                },
                "results": [
                    {
                        "uuid": f"result-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                        "title": f"{framework} Assessment",
                        "description": f"Automated assessment of {framework} controls",
                        "start": datetime.utcnow().isoformat() + "Z",
                        "reviewed-controls": {
                            "control-selections": [
                                {
                                    "include-all": {}
                                }
                            ]
                        },
                        "findings": [],
                        "observations": []
                    }
                ]
            }
        }

        # Add findings
        for control in summary.get('control_details', []):
            finding = {
                "uuid": f"finding-{control['control_id'].lower().replace('.', '-')}",
                "title": f"{control['control_id']}: {control['control_name']}",
                "description": f"Assessment of {control['control_id']}",
                "target": {
                    "type": "control-id",
                    "target-id": control['control_id'],
                    "status": {
                        "state": "satisfied" if control['has_evidence'] else "not-satisfied"
                    }
                }
            }
            oscal_doc["assessment-results"]["results"][0]["findings"].append(finding)

            # Add observation for evidence
            if control['has_evidence']:
                observation = {
                    "uuid": f"obs-{control['control_id'].lower().replace('.', '-')}",
                    "description": f"Evidence collected for {control['control_id']}",
                    "methods": ["EXAMINE", "TEST"],
                    "collected": datetime.utcnow().isoformat() + "Z"
                }
                oscal_doc["assessment-results"]["results"][0]["observations"].append(observation)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(oscal_doc, f, indent=2)

        self.logger.info(f"OSCAL export saved to {output_path}")
        return output_path

    def export_csv_grc(self, framework: str, output_path: Path = None) -> Path:
        """
        Export in CSV format compatible with common GRC platforms
        (ServiceNow, RSA Archer, OneTrust, etc.)
        """
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"grc_import_{framework}_{timestamp}.csv"

        summary = self.compliance.generate_compliance_summary(self.evidence, framework)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header row
            writer.writerow([
                'Framework',
                'Control ID',
                'Control Name',
                'Control Family',
                'Assessment Date',
                'Evidence Count',
                'Compliance Status',
                'Gap',
                'Notes'
            ])

            # Data rows
            for control in summary.get('control_details', []):
                writer.writerow([
                    framework,
                    control['control_id'],
                    control['control_name'],
                    control['family'],
                    datetime.utcnow().strftime('%Y-%m-%d'),
                    control['evidence_count'],
                    'Compliant' if control['has_evidence'] else 'Non-Compliant',
                    'No' if control['has_evidence'] else 'Yes',
                    f"Automated assessment via Purple Team Portable"
                ])

        self.logger.info(f"GRC CSV export saved to {output_path}")
        return output_path

    def export_drata(self, framework: str, output_path: Path = None) -> Path:
        """Export in Drata-compatible JSON format."""
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"drata_{framework}_{timestamp}.json"

        summary = self.compliance.generate_compliance_summary(self.evidence, framework)

        drata_export = {
            "exportVersion": "1.0",
            "exportDate": datetime.utcnow().isoformat(),
            "framework": framework,
            "controls": []
        }

        for control in summary.get('control_details', []):
            drata_export["controls"].append({
                "controlId": control['control_id'],
                "controlName": control['control_name'],
                "category": control['family'],
                "status": "PASSING" if control['has_evidence'] else "FAILING",
                "evidenceCount": control['evidence_count'],
                "lastTested": datetime.utcnow().isoformat(),
                "automated": True
            })

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(drata_export, f, indent=2)

        self.logger.info(f"Drata export saved to {output_path}")
        return output_path

    def export_vanta(self, framework: str, output_path: Path = None) -> Path:
        """Export in Vanta-compatible JSON format."""
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"vanta_{framework}_{timestamp}.json"

        summary = self.compliance.generate_compliance_summary(self.evidence, framework)

        vanta_export = {
            "version": "1.0",
            "timestamp": datetime.utcnow().isoformat(),
            "framework": framework,
            "complianceScore": summary.get('controls_with_evidence', 0) / max(summary.get('total_controls', 1), 1) * 100,
            "tests": []
        }

        for control in summary.get('control_details', []):
            vanta_export["tests"].append({
                "testId": control['control_id'],
                "testName": control['control_name'],
                "category": control['family'],
                "result": "PASS" if control['has_evidence'] else "FAIL",
                "evidence": control['evidence_count'],
                "timestamp": datetime.utcnow().isoformat()
            })

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(vanta_export, f, indent=2)

        self.logger.info(f"Vanta export saved to {output_path}")
        return output_path

    def export_all_formats(self, framework: str) -> Dict[str, Path]:
        """Export in all supported formats."""
        exports = {}

        exports['oscal'] = self.export_oscal(framework)
        exports['csv_grc'] = self.export_csv_grc(framework)
        exports['drata'] = self.export_drata(framework)
        exports['vanta'] = self.export_vanta(framework)

        self.logger.info(f"Exported {len(exports)} formats for {framework}")
        return exports

    def export_evidence_package(self, framework: str,
                                 output_path: Path = None) -> Path:
        """Create a complete evidence package for auditors."""
        import tarfile
        import tempfile
        import shutil

        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.archives / f"evidence_package_{framework}_{timestamp}.tar.gz"

        # Create temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = Path(tmpdir) / f"evidence_{framework}"
            pkg_dir.mkdir()

            # Export compliance data
            self.evidence.export_for_framework(framework, pkg_dir / 'compliance_evidence.json')

            # Generate reports
            from .reporter import ReportGenerator
            reporter = ReportGenerator()
            reporter.generate_compliance_report(framework, pkg_dir / 'compliance_report.html')

            # Export in all formats
            self.export_csv_grc(framework, pkg_dir / 'grc_import.csv')
            self.export_oscal(framework, pkg_dir / 'oscal_results.json')

            # Create manifest
            manifest = {
                'package_version': '1.0',
                'created': datetime.utcnow().isoformat(),
                'framework': framework,
                'contents': [
                    'compliance_evidence.json - Raw evidence data',
                    'compliance_report.html - Human-readable report',
                    'grc_import.csv - GRC platform import file',
                    'oscal_results.json - OSCAL format for federal compliance'
                ]
            }
            with open(pkg_dir / 'MANIFEST.json', 'w') as f:
                json.dump(manifest, f, indent=2)

            # Create tarball
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(output_path, 'w:gz') as tar:
                tar.add(pkg_dir, arcname=pkg_dir.name)

        self.logger.info(f"Evidence package saved to {output_path}")
        return output_path


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Export compliance data')
    parser.add_argument('framework', help='Compliance framework to export')
    parser.add_argument('--format', choices=['oscal', 'csv', 'drata', 'vanta', 'all', 'package'],
                       default='all', help='Export format')

    args = parser.parse_args()

    exporter = ComplianceExporter()

    if args.format == 'package':
        path = exporter.export_evidence_package(args.framework)
        print(f"Evidence package: {path}")
    elif args.format == 'all':
        paths = exporter.export_all_formats(args.framework)
        for fmt, path in paths.items():
            print(f"{fmt}: {path}")
    else:
        method = getattr(exporter, f'export_{args.format}')
        path = method(args.framework)
        print(f"Exported: {path}")
