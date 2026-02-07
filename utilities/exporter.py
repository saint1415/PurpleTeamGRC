#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Compliance & Integration Exporter
Exports compliance data in OSCAL, CSV, SARIF, and platform-specific formats.
Integrations: Jira, ServiceNow, Slack, Teams webhooks.
"""

import json
import csv
import sys
import urllib.request
import urllib.error
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


    def export_sarif(self, findings: List[Dict], output_path: Path = None) -> Path:
        """Export findings in SARIF v2.1.0 format (GitHub Security tab compatible)."""
        if not output_path:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_path = self.paths.reports / f"results_{timestamp}.sarif"

        # Map severity to SARIF level
        severity_map = {
            'CRITICAL': 'error', 'HIGH': 'error',
            'MEDIUM': 'warning', 'LOW': 'note', 'INFO': 'note',
        }

        rules = []
        results = []
        rule_ids_seen = set()

        for finding in findings:
            rule_id = finding.get('finding_id', f"purple-{len(rules)}")
            severity = finding.get('severity', 'INFO').upper()
            title = finding.get('title', 'Unknown Finding')
            description = finding.get('description', '')
            asset = finding.get('affected_asset', 'unknown')
            remediation = finding.get('remediation', '')
            cvss = finding.get('cvss_score', 0)
            cves = finding.get('cve_ids', [])
            if isinstance(cves, str):
                try:
                    cves = json.loads(cves)
                except (json.JSONDecodeError, TypeError):
                    cves = []

            # Build unique rule ID from title
            short_id = title.lower().replace(' ', '-')[:50]
            if short_id not in rule_ids_seen:
                rule_ids_seen.add(short_id)
                rule = {
                    "id": short_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": description[:1000] if description else title},
                    "defaultConfiguration": {"level": severity_map.get(severity, 'note')},
                    "properties": {"tags": ["security"]}
                }
                if remediation:
                    rule["help"] = {"text": remediation}
                if cvss:
                    rule["properties"]["security-severity"] = str(cvss)
                rules.append(rule)

            result = {
                "ruleId": short_id,
                "level": severity_map.get(severity, 'note'),
                "message": {"text": f"{title}: {description[:500]}" if description else title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": asset},
                        "region": {"startLine": 1}
                    }
                }]
            }
            if cves:
                result["properties"] = {"cve": cves}
            results.append(result)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Purple Team Platform",
                        "version": "7.0",
                        "informationUri": "https://github.com/saint1415/PurpleTeamGRC",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(sarif_doc, f, indent=2)

        self.logger.info(f"SARIF export saved to {output_path}")
        return output_path

    def create_jira_tickets(self, findings: List[Dict], jira_url: str,
                             project_key: str, api_token: str,
                             email: str, max_tickets: int = 10) -> List[Dict]:
        """Create Jira tickets for findings via REST API."""
        created = []
        severity_priority = {
            'CRITICAL': 'Highest', 'HIGH': 'High',
            'MEDIUM': 'Medium', 'LOW': 'Low', 'INFO': 'Lowest',
        }

        for finding in findings[:max_tickets]:
            title = finding.get('title', 'Security Finding')
            severity = finding.get('severity', 'MEDIUM')
            description = finding.get('description', '')
            asset = finding.get('affected_asset', '')
            remediation = finding.get('remediation', '')

            issue_data = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": f"[{severity}] {title}",
                    "description": (
                        f"*Security Finding*\n\n"
                        f"*Severity:* {severity}\n"
                        f"*Asset:* {asset}\n"
                        f"*CVSS:* {finding.get('cvss_score', 'N/A')}\n\n"
                        f"*Description:*\n{description}\n\n"
                        f"*Remediation:*\n{remediation}\n\n"
                        f"_Created by Purple Team Platform v7.0_"
                    ),
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": severity_priority.get(severity, 'Medium')},
                    "labels": ["security", "purple-team", severity.lower()],
                }
            }

            try:
                import base64
                credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
                req = urllib.request.Request(
                    f"{jira_url.rstrip('/')}/rest/api/2/issue",
                    data=json.dumps(issue_data).encode(),
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f'Basic {credentials}',
                    }
                )
                resp = urllib.request.urlopen(req, timeout=15)
                result = json.loads(resp.read().decode())
                created.append({
                    'finding': title,
                    'ticket': result.get('key', 'unknown'),
                    'url': f"{jira_url}/browse/{result.get('key', '')}",
                })
                self.logger.info(f"Created Jira ticket: {result.get('key')}")
            except Exception as e:
                self.logger.warning(f"Failed to create Jira ticket for '{title}': {e}")

        return created

    def create_servicenow_incidents(self, findings: List[Dict], instance_url: str,
                                     username: str, password: str,
                                     max_incidents: int = 10) -> List[Dict]:
        """Create ServiceNow incidents via REST API."""
        created = []
        severity_map = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}

        for finding in findings[:max_incidents]:
            title = finding.get('title', 'Security Finding')
            severity = finding.get('severity', 'MEDIUM')

            incident = {
                "short_description": f"[Security] {title}",
                "description": (
                    f"Security finding from Purple Team Platform\n\n"
                    f"Severity: {severity}\n"
                    f"Asset: {finding.get('affected_asset', 'N/A')}\n"
                    f"CVSS: {finding.get('cvss_score', 'N/A')}\n\n"
                    f"{finding.get('description', '')}\n\n"
                    f"Remediation: {finding.get('remediation', '')}"
                ),
                "urgency": severity_map.get(severity, 3),
                "impact": severity_map.get(severity, 3),
                "category": "Security",
            }

            try:
                import base64
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                req = urllib.request.Request(
                    f"{instance_url.rstrip('/')}/api/now/table/incident",
                    data=json.dumps(incident).encode(),
                    headers={
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'Authorization': f'Basic {credentials}',
                    }
                )
                resp = urllib.request.urlopen(req, timeout=15)
                result = json.loads(resp.read().decode())
                record = result.get('result', {})
                created.append({
                    'finding': title,
                    'number': record.get('number', 'unknown'),
                    'sys_id': record.get('sys_id', ''),
                })
                self.logger.info(f"Created ServiceNow incident: {record.get('number')}")
            except Exception as e:
                self.logger.warning(f"Failed to create ServiceNow incident for '{title}': {e}")

        return created

    def send_slack_notification(self, webhook_url: str, summary: Dict,
                                 findings: List[Dict] = None) -> bool:
        """Send scan results to Slack via webhook."""
        total = summary.get('total_findings', 0)
        by_sev = summary.get('findings_by_severity', {})
        critical = by_sev.get('CRITICAL', 0)
        high = by_sev.get('HIGH', 0)

        color = '#dc3545' if critical > 0 else '#fd7e14' if high > 0 else '#28a745'

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Purple Team Security Scan Results"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Findings:* {total}"},
                    {"type": "mrkdwn", "text": f"*Critical:* {critical}"},
                    {"type": "mrkdwn", "text": f"*High:* {high}"},
                    {"type": "mrkdwn", "text": f"*Medium:* {by_sev.get('MEDIUM', 0)}"},
                ]
            }
        ]

        if findings:
            top_text = "\n".join(
                f"- [{f.get('severity', '?')}] {f.get('title', '?')}"
                for f in findings[:5]
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{top_text}"}
            })

        payload = {"blocks": blocks}

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode(),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=10)
            self.logger.info("Slack notification sent")
            return True
        except Exception as e:
            self.logger.warning(f"Slack notification failed: {e}")
            return False

    def send_teams_notification(self, webhook_url: str, summary: Dict,
                                  findings: List[Dict] = None) -> bool:
        """Send scan results to Microsoft Teams via webhook."""
        total = summary.get('total_findings', 0)
        by_sev = summary.get('findings_by_severity', {})
        critical = by_sev.get('CRITICAL', 0)
        high = by_sev.get('HIGH', 0)

        color = 'dc3545' if critical > 0 else 'fd7e14' if high > 0 else '28a745'

        facts = [
            {"name": "Total Findings", "value": str(total)},
            {"name": "Critical", "value": str(critical)},
            {"name": "High", "value": str(high)},
            {"name": "Medium", "value": str(by_sev.get('MEDIUM', 0))},
            {"name": "Low", "value": str(by_sev.get('LOW', 0))},
        ]

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Purple Team Scan: {total} findings",
            "sections": [{
                "activityTitle": "Purple Team Security Scan Results",
                "activitySubtitle": f"Completed {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                "facts": facts,
                "markdown": True,
            }]
        }

        if findings:
            top_text = "\n\n".join(
                f"**[{f.get('severity', '?')}]** {f.get('title', '?')} on {f.get('affected_asset', '?')}"
                for f in findings[:5]
            )
            card["sections"].append({
                "activityTitle": "Top Findings",
                "text": top_text,
            })

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(card).encode(),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=10)
            self.logger.info("Teams notification sent")
            return True
        except Exception as e:
            self.logger.warning(f"Teams notification failed: {e}")
            return False


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Export compliance data')
    parser.add_argument('framework', nargs='?', default='NIST-800-53',
                       help='Compliance framework to export')
    parser.add_argument('--format',
                       choices=['oscal', 'csv', 'drata', 'vanta', 'sarif', 'all', 'package'],
                       default='all', help='Export format')

    args = parser.parse_args()

    exporter = ComplianceExporter()

    if args.format == 'sarif':
        # Demo SARIF export
        sample = [
            {'finding_id': 'FND-001', 'severity': 'CRITICAL', 'title': 'SQL Injection',
             'description': 'SQL injection in login', 'affected_asset': '10.0.0.1',
             'cvss_score': 9.8, 'cve_ids': ['CVE-2024-1234'], 'remediation': 'Use parameterized queries'},
        ]
        path = exporter.export_sarif(sample)
        print(f"SARIF: {path}")
    elif args.format == 'package':
        path = exporter.export_evidence_package(args.framework)
        print(f"Evidence package: {path}")
    elif args.format == 'all':
        export_paths = exporter.export_all_formats(args.framework)
        for fmt, path in export_paths.items():
            print(f"{fmt}: {path}")
    else:
        method = getattr(exporter, f'export_{args.format}')
        path = method(args.framework)
        print(f"Exported: {path}")
