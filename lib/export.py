#!/usr/bin/env python3
"""
Purple Team GRC - Data Export Module
Exports scan findings and vulnerability data to major security platforms.

Supported formats:
  1. CEF (Common Event Format) - ArcSight, QRadar, Splunk
  2. STIX 2.1 - CrowdStrike, Stellar AI, Sentinel, ThreatLocker
  3. Splunk HEC JSON - Native Splunk HTTP Event Collector
  4. Microsoft Sentinel / Azure Log Analytics - Custom log tables
  5. QRadar LEEF - Log Event Extended Format
  6. ServiceNow / Jira CSV - Ticket/incident import
  7. Qualys XML - QualysGuard-compatible report format
  8. SARIF 2.1.0 - GitHub, Azure DevOps
  9. Syslog RFC 5424 - Universal SIEM format
  10. JSON Lines (.jsonl) - Generic line-delimited JSON
"""

import os
import sys
import json
import csv
import socket
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET
from xml.dom import minidom

# Add lib to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from evidence import get_evidence_manager
    from paths import paths
except ImportError:
    get_evidence_manager = None
    paths = None


class ExportManager:
    """
    Manages export of Purple Team GRC findings to various security platforms.
    Uses ONLY Python stdlib - no external dependencies.
    """

    VERSION = "7.0"
    VENDOR = "PurpleTeamGRC"
    PRODUCT = "Scanner"

    # Severity mappings
    SEVERITY_TO_CEF = {
        'CRITICAL': 10,
        'HIGH': 8,
        'MEDIUM': 5,
        'LOW': 3,
        'INFO': 1
    }

    SEVERITY_TO_SARIF = {
        'CRITICAL': 'error',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'note',
        'INFO': 'none'
    }

    SEVERITY_TO_SYSLOG = {
        'CRITICAL': 2,  # Critical
        'HIGH': 3,      # Error
        'MEDIUM': 4,    # Warning
        'LOW': 5,       # Notice
        'INFO': 6       # Informational
    }

    def __init__(self):
        """Initialize export manager."""
        self.hostname = socket.gethostname()
        self.evidence_manager = get_evidence_manager() if get_evidence_manager else None

    def get_supported_formats(self) -> Dict[str, str]:
        """Return all supported export formats with descriptions."""
        return {
            'cef': 'CEF (Common Event Format) - ArcSight, QRadar, Splunk via syslog',
            'stix': 'STIX 2.1 JSON - CrowdStrike, Stellar AI, Sentinel, ThreatLocker',
            'splunk_hec': 'Splunk HEC JSON - Native HTTP Event Collector format',
            'sentinel': 'Microsoft Sentinel / Azure Log Analytics - Custom log tables',
            'leef': 'QRadar LEEF (Log Event Extended Format)',
            'csv': 'ServiceNow / Jira CSV - Ticket/incident import',
            'servicenow_json': 'ServiceNow JSON - API import format',
            'qualys_xml': 'Qualys-compatible XML - Basic QualysGuard report format',
            'sarif': 'SARIF 2.1.0 - GitHub, Azure DevOps security scanning',
            'syslog': 'Syslog RFC 5424 - Universal SIEM format',
            'jsonl': 'JSON Lines (.jsonl) - Generic line-delimited JSON'
        }

    def export_all(self, session_id: str, output_dir: Optional[Path] = None,
                   formats: Optional[List[str]] = None) -> Dict[str, Path]:
        """
        Export session findings to all (or selected) formats.

        Args:
            session_id: Session ID to export
            output_dir: Output directory (default: session exports/)
            formats: List of format names to export (default: all)

        Returns:
            Dictionary mapping format name to output file path
        """
        if not self.evidence_manager:
            raise RuntimeError("Evidence manager not available")

        # Get findings for session
        findings = self.evidence_manager.get_findings_for_session(session_id)
        if not findings:
            raise ValueError(f"No findings found for session {session_id}")

        # Determine output directory
        if output_dir is None:
            if paths:
                session_dir = paths.session_dir(session_id)
                output_dir = session_dir / 'exports'
            else:
                output_dir = Path(f'./results/{session_id}/exports')

        output_dir.mkdir(parents=True, exist_ok=True)

        # Determine formats to export
        if formats is None:
            formats = list(self.get_supported_formats().keys())

        results = {}
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Export each format
        for fmt in formats:
            try:
                if fmt == 'cef':
                    output = output_dir / f'findings_{timestamp}.cef'
                    self.export_cef(findings, output)
                    results[fmt] = output

                elif fmt == 'stix':
                    output = output_dir / f'findings_{timestamp}.stix.json'
                    self.export_stix(findings, output)
                    results[fmt] = output

                elif fmt == 'splunk_hec':
                    output = output_dir / f'findings_{timestamp}.splunk.json'
                    self.export_splunk_hec(findings, output)
                    results[fmt] = output

                elif fmt == 'sentinel':
                    output = output_dir / f'findings_{timestamp}.sentinel.json'
                    self.export_sentinel(findings, output)
                    results[fmt] = output

                elif fmt == 'leef':
                    output = output_dir / f'findings_{timestamp}.leef'
                    self.export_leef(findings, output)
                    results[fmt] = output

                elif fmt == 'csv':
                    output = output_dir / f'findings_{timestamp}.csv'
                    self.export_csv(findings, output)
                    results[fmt] = output

                elif fmt == 'servicenow_json':
                    output = output_dir / f'findings_{timestamp}.servicenow.json'
                    self.export_servicenow_json(findings, output)
                    results[fmt] = output

                elif fmt == 'qualys_xml':
                    output = output_dir / f'findings_{timestamp}.qualys.xml'
                    self.export_qualys_xml(findings, output)
                    results[fmt] = output

                elif fmt == 'sarif':
                    output = output_dir / f'findings_{timestamp}.sarif.json'
                    self.export_sarif(findings, output)
                    results[fmt] = output

                elif fmt == 'syslog':
                    output = output_dir / f'findings_{timestamp}.syslog'
                    self.export_syslog(findings, output)
                    results[fmt] = output

                elif fmt == 'jsonl':
                    output = output_dir / f'findings_{timestamp}.jsonl'
                    self.export_jsonl(findings, output)
                    results[fmt] = output

            except Exception as e:
                print(f"Warning: Failed to export {fmt}: {e}")
                continue

        return results

    def export_cef(self, findings: List[Dict], output_path: Path):
        """
        Export findings to CEF (Common Event Format).
        Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

        Used by: ArcSight, QRadar, Splunk
        """
        lines = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            # Build CEF line
            severity_num = self.SEVERITY_TO_CEF.get(finding.get('severity', 'INFO').upper(), 5)
            finding_type = metadata.get('finding_type', 'unknown')
            title = self._escape_cef(finding.get('title', 'Unknown Finding'))

            # Build extensions
            extensions = []

            # Source/Destination
            asset = finding.get('affected_asset', '')
            if asset:
                extensions.append(f"dst={asset}")
                extensions.append(f"src={self.hostname}")

            # CVE
            if cve_ids:
                cve_str = self._escape_cef(','.join(cve_ids))
                extensions.append(f"cs1={cve_str}")
                extensions.append(f"cs1Label=CVE")

            # Compliance controls (from metadata)
            compliance = metadata.get('compliance_controls', [])
            if compliance:
                compliance_str = self._escape_cef(','.join(compliance))
                extensions.append(f"cs2={compliance_str}")
                extensions.append(f"cs2Label=ComplianceControls")

            # CWE (from metadata)
            cwe = metadata.get('cwe_id', '')
            if cwe:
                extensions.append(f"cs3={cwe}")
                extensions.append(f"cs3Label=CWE")

            # CVSS
            cvss = finding.get('cvss_score', 0.0)
            if cvss:
                extensions.append(f"cn1={cvss}")
                extensions.append(f"cn1Label=CVSS")

            # Remediation
            remediation = finding.get('remediation', '')
            if remediation:
                rem_escaped = self._escape_cef(remediation[:200])  # Limit length
                extensions.append(f"cs4={rem_escaped}")
                extensions.append(f"cs4Label=Remediation")

            # Additional fields
            extensions.append(f"cat={finding_type}")

            timestamp = finding.get('timestamp', datetime.utcnow().isoformat())
            extensions.append(f"rt={self._to_cef_timestamp(timestamp)}")

            # Construct CEF line
            extension_str = ' '.join(extensions)
            cef_line = f"CEF:0|{self.VENDOR}|{self.PRODUCT}|{self.VERSION}|{finding_type}|{title}|{severity_num}|{extension_str}"
            lines.append(cef_line)

        # Write to file with UTF-8 encoding
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def export_stix(self, findings: List[Dict], output_path: Path):
        """
        Export findings to STIX 2.1 JSON format.

        Used by: CrowdStrike, Stellar AI, Microsoft Sentinel, ThreatLocker
        """
        stix_objects = []

        # Create identity object
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{self._generate_uuid()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": "PurpleTeamGRC Scanner",
            "identity_class": "system"
        }
        stix_objects.append(identity)

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            timestamp = self._parse_timestamp(finding.get('timestamp'))

            # Create vulnerability object for each CVE
            for cve_id in cve_ids:
                vuln = {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": f"vulnerability--{self._generate_uuid()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "name": cve_id,
                    "external_references": [
                        {
                            "source_name": "cve",
                            "external_id": cve_id
                        }
                    ]
                }
                stix_objects.append(vuln)

            # Create indicator object for the finding
            pattern_parts = []
            asset = finding.get('affected_asset', '')
            if asset:
                pattern_parts.append(f"[ipv4-addr:value = '{asset}']")
            else:
                pattern_parts.append("[x-scanner:finding = 'true']")

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{self._generate_uuid()}",
                "created": timestamp,
                "modified": timestamp,
                "name": finding.get('title', 'Unknown Finding'),
                "description": finding.get('description', ''),
                "pattern": ' AND '.join(pattern_parts) if pattern_parts else "[x-scanner:finding = 'true']",
                "pattern_type": "stix",
                "valid_from": timestamp,
                "indicator_types": ["compromised", "malicious-activity"],
                "labels": [
                    finding.get('severity', 'INFO').lower(),
                    metadata.get('finding_type', 'unknown')
                ]
            }

            # Add custom properties
            if finding.get('cvss_score'):
                indicator['x_cvss_score'] = finding['cvss_score']

            if finding.get('remediation'):
                indicator['x_remediation'] = finding['remediation']

            stix_objects.append(indicator)

            # Create relationships between indicators and vulnerabilities
            for cve_id in cve_ids:
                relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{self._generate_uuid()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "relationship_type": "indicates",
                    "source_ref": indicator["id"],
                    "target_ref": f"vulnerability--{self._generate_uuid()}"
                }
                stix_objects.append(relationship)

        # Create STIX bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "objects": stix_objects
        }

        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)

    def export_splunk_hec(self, findings: List[Dict], output_path: Path):
        """
        Export findings to Splunk HTTP Event Collector JSON format.
        Each finding becomes a separate JSON object.
        """
        events = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            # Convert timestamp to epoch
            timestamp = self._parse_timestamp(finding.get('timestamp'))
            epoch = int(datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp())

            # Build event object
            event = {
                "time": epoch,
                "source": "purpleteam",
                "sourcetype": "purpleteam:finding",
                "event": {
                    "finding_id": finding.get('finding_id', ''),
                    "session_id": finding.get('session_id', ''),
                    "severity": finding.get('severity', 'INFO'),
                    "title": finding.get('title', ''),
                    "description": finding.get('description', ''),
                    "affected_asset": finding.get('affected_asset', ''),
                    "cvss_score": finding.get('cvss_score', 0.0),
                    "cve_ids": cve_ids,
                    "remediation": finding.get('remediation', ''),
                    "status": finding.get('status', 'open'),
                    "finding_type": metadata.get('finding_type', 'unknown'),
                    "scanner_name": finding.get('scanner_name', 'unknown'),
                    "detection_source": finding.get('detection_source', ''),
                    "kev_status": finding.get('kev_status', ''),
                    "epss_score": finding.get('epss_score', 0.0),
                    "effective_priority": finding.get('effective_priority', 0.0),
                    "quality_of_detection": finding.get('quality_of_detection', 0.0),
                    "false_positive": finding.get('false_positive', 0),
                    "timestamp": finding.get('timestamp', '')
                }
            }

            events.append(event)

        # Write to file (one event per line for HEC bulk ingestion)
        with open(output_path, 'w', encoding='utf-8') as f:
            for event in events:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')

    def export_sentinel(self, findings: List[Dict], output_path: Path):
        """
        Export findings to Microsoft Sentinel / Azure Log Analytics format.
        Compatible with Azure Monitor Data Collection Rules.
        """
        events = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            # Build flat event (Sentinel requires flat schema)
            event = {
                "TimeGenerated": finding.get('timestamp', datetime.utcnow().isoformat()),
                "FindingId": finding.get('finding_id', ''),
                "SessionId": finding.get('session_id', ''),
                "Severity": finding.get('severity', 'INFO'),
                "Title": finding.get('title', ''),
                "Description": finding.get('description', ''),
                "AffectedAsset": finding.get('affected_asset', ''),
                "CVSSScore": finding.get('cvss_score', 0.0),
                "CVEIds": ','.join(cve_ids),
                "Remediation": finding.get('remediation', ''),
                "Status": finding.get('status', 'open'),
                "FindingType": metadata.get('finding_type', 'unknown'),
                "ScannerName": finding.get('scanner_name', 'unknown'),
                "DetectionSource": finding.get('detection_source', ''),
                "KEVStatus": finding.get('kev_status', ''),
                "EPSSScore": finding.get('epss_score', 0.0),
                "EffectivePriority": finding.get('effective_priority', 0.0),
                "QualityOfDetection": finding.get('quality_of_detection', 0.0),
                "FalsePositive": finding.get('false_positive', 0)
            }

            events.append(event)

        # Write as JSON array
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    def export_leef(self, findings: List[Dict], output_path: Path):
        """
        Export findings to QRadar LEEF (Log Event Extended Format).
        Format: LEEF:2.0|Vendor|Product|Version|EventID|Attributes
        Tab-delimited attributes.
        """
        lines = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            event_id = finding.get('finding_id', 'unknown')

            # Build attributes (tab-delimited key=value pairs)
            attributes = []
            attributes.append(f"sev={finding.get('severity', 'INFO')}")
            attributes.append(f"title={self._escape_leef(finding.get('title', ''))}")
            attributes.append(f"desc={self._escape_leef(finding.get('description', ''))}")

            asset = finding.get('affected_asset', '')
            if asset:
                attributes.append(f"dst={asset}")

            attributes.append(f"devTime={self._to_leef_timestamp(finding.get('timestamp'))}")

            if cve_ids:
                attributes.append(f"identSrc=CVE")
                attributes.append(f"identHostName={','.join(cve_ids)}")

            cvss = finding.get('cvss_score', 0.0)
            if cvss:
                attributes.append(f"cvss={cvss}")

            finding_type = metadata.get('finding_type', 'unknown')
            attributes.append(f"cat={finding_type}")

            # Construct LEEF line
            attr_str = '\t'.join(attributes)
            leef_line = f"LEEF:2.0|{self.VENDOR}|{self.PRODUCT}|{self.VERSION}|{event_id}\t{attr_str}"
            lines.append(leef_line)

        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def export_csv(self, findings: List[Dict], output_path: Path):
        """
        Export findings to CSV format for ServiceNow / Jira import.
        Columns: Title, Severity, Description, CVE, CVSS, CWE, Remediation,
                 ComplianceControls, Asset, ScanDate
        """
        fieldnames = [
            'Title', 'Severity', 'Description', 'CVE', 'CVSS', 'CWE',
            'Remediation', 'ComplianceControls', 'Asset', 'ScanDate',
            'Status', 'FindingType', 'Scanner', 'KEVStatus', 'EPSSScore',
            'Priority', 'FalsePositive'
        ]

        rows = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            row = {
                'Title': finding.get('title', ''),
                'Severity': finding.get('severity', 'INFO'),
                'Description': finding.get('description', ''),
                'CVE': ','.join(cve_ids),
                'CVSS': finding.get('cvss_score', 0.0),
                'CWE': metadata.get('cwe_id', ''),
                'Remediation': finding.get('remediation', ''),
                'ComplianceControls': ','.join(metadata.get('compliance_controls', [])),
                'Asset': finding.get('affected_asset', ''),
                'ScanDate': finding.get('timestamp', ''),
                'Status': finding.get('status', 'open'),
                'FindingType': metadata.get('finding_type', 'unknown'),
                'Scanner': finding.get('scanner_name', 'unknown'),
                'KEVStatus': finding.get('kev_status', ''),
                'EPSSScore': finding.get('epss_score', 0.0),
                'Priority': finding.get('effective_priority', 0.0),
                'FalsePositive': 'Yes' if finding.get('false_positive', 0) else 'No'
            }

            rows.append(row)

        # Write CSV with UTF-8 BOM for Excel compatibility
        with open(output_path, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def export_servicenow_json(self, findings: List[Dict], output_path: Path):
        """
        Export findings to ServiceNow API import JSON format.
        JSON array of incident records.
        """
        incidents = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            # Map severity to ServiceNow impact/urgency
            severity = finding.get('severity', 'INFO').upper()
            impact = '1' if severity == 'CRITICAL' else ('2' if severity == 'HIGH' else '3')
            urgency = impact

            incident = {
                "short_description": finding.get('title', ''),
                "description": finding.get('description', ''),
                "impact": impact,
                "urgency": urgency,
                "category": "Security",
                "subcategory": metadata.get('finding_type', 'Vulnerability'),
                "assignment_group": "Security Operations",
                "u_affected_asset": finding.get('affected_asset', ''),
                "u_cve_ids": ','.join(cve_ids),
                "u_cvss_score": str(finding.get('cvss_score', 0.0)),
                "u_remediation": finding.get('remediation', ''),
                "u_scanner": finding.get('scanner_name', 'PurpleTeamGRC'),
                "u_finding_id": finding.get('finding_id', ''),
                "u_session_id": finding.get('session_id', ''),
                "u_kev_status": finding.get('kev_status', ''),
                "u_epss_score": str(finding.get('epss_score', 0.0)),
                "state": "1"  # New
            }

            incidents.append(incident)

        # Write as JSON array
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(incidents, f, indent=2, ensure_ascii=False)

    def export_qualys_xml(self, findings: List[Dict], output_path: Path):
        """
        Export findings to Qualys-compatible XML report format.
        Basic QualysGuard-style structure for import tools.
        """
        # Create root element
        root = ET.Element('SCAN')

        # Add header
        header = ET.SubElement(root, 'HEADER')
        ET.SubElement(header, 'DATETIME').text = datetime.utcnow().isoformat()
        ET.SubElement(header, 'TITLE').text = 'PurpleTeamGRC Security Scan'

        # Add IP list
        ip_set = set()
        for finding in findings:
            asset = finding.get('affected_asset', '')
            if asset:
                ip_set.add(asset)

        ip_list = ET.SubElement(root, 'IP_LIST')
        for ip in sorted(ip_set):
            ip_elem = ET.SubElement(ip_list, 'IP')
            ET.SubElement(ip_elem, 'VALUE').text = ip

            # Add vulnerabilities for this IP
            vulns = ET.SubElement(ip_elem, 'VULNS')

            for finding in findings:
                if finding.get('affected_asset', '') == ip:
                    vuln = ET.SubElement(vulns, 'VULN')

                    # QID (use finding_id hash)
                    qid = str(abs(hash(finding.get('finding_id', ''))) % 1000000)
                    ET.SubElement(vuln, 'QID').text = qid
                    ET.SubElement(vuln, 'TITLE').text = finding.get('title', '')

                    # Severity (1-5 scale)
                    sev_map = {'CRITICAL': '5', 'HIGH': '4', 'MEDIUM': '3', 'LOW': '2', 'INFO': '1'}
                    severity = sev_map.get(finding.get('severity', 'INFO').upper(), '3')
                    ET.SubElement(vuln, 'SEVERITY').text = severity

                    # CVSS
                    cvss = finding.get('cvss_score', 0.0)
                    if cvss:
                        ET.SubElement(vuln, 'CVSS_BASE').text = str(cvss)

                    # CVE IDs
                    try:
                        cve_ids = json.loads(finding.get('cve_ids', '[]'))
                        if cve_ids:
                            cve_list = ET.SubElement(vuln, 'CVE_ID_LIST')
                            for cve_id in cve_ids:
                                ET.SubElement(cve_list, 'CVE_ID').text = cve_id
                    except (json.JSONDecodeError, TypeError):
                        pass

                    # Diagnosis
                    ET.SubElement(vuln, 'DIAGNOSIS').text = finding.get('description', '')

                    # Solution
                    remediation = finding.get('remediation', '')
                    if remediation:
                        ET.SubElement(vuln, 'SOLUTION').text = remediation

        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root, encoding='utf-8')).toprettyxml(indent='  ')

        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_str)

    def export_sarif(self, findings: List[Dict], output_path: Path):
        """
        Export findings to SARIF 2.1.0 format.

        Used by: GitHub Advanced Security, Azure DevOps, GitLab
        """
        # Build SARIF structure
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PurpleTeamGRC",
                            "version": self.VERSION,
                            "informationUri": "https://github.com/purpleteamgrc",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }

        run = sarif["runs"][0]
        rules_dict = {}

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            # Create rule if not exists
            finding_type = metadata.get('finding_type', 'unknown')
            rule_id = finding_type

            if rule_id not in rules_dict:
                rule = {
                    "id": rule_id,
                    "name": finding_type.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": finding.get('title', '')
                    },
                    "fullDescription": {
                        "text": finding.get('description', '')
                    },
                    "help": {
                        "text": finding.get('remediation', '')
                    },
                    "properties": {
                        "tags": [finding.get('severity', 'INFO').lower()]
                    }
                }

                if cve_ids:
                    rule["properties"]["cve"] = cve_ids

                rules_dict[rule_id] = rule
                run["tool"]["driver"]["rules"].append(rule)

            # Create result
            result = {
                "ruleId": rule_id,
                "message": {
                    "text": finding.get('description', '')
                },
                "level": self.SEVERITY_TO_SARIF.get(finding.get('severity', 'INFO').upper(), 'warning'),
                "properties": {
                    "cvss": finding.get('cvss_score', 0.0),
                    "affected_asset": finding.get('affected_asset', ''),
                    "finding_id": finding.get('finding_id', ''),
                    "scanner": finding.get('scanner_name', 'unknown')
                }
            }

            # Add CVE information
            if cve_ids:
                result["properties"]["cve_ids"] = cve_ids

            # Add KEV/EPSS if available
            if finding.get('kev_status'):
                result["properties"]["kev_status"] = finding['kev_status']

            if finding.get('epss_score'):
                result["properties"]["epss_score"] = finding['epss_score']

            # Add location if asset is available
            asset = finding.get('affected_asset', '')
            if asset:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "address": {
                                "fullyQualifiedName": asset
                            }
                        }
                    }
                ]

            run["results"].append(result)

        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

    def export_syslog(self, findings: List[Dict], output_path: Path):
        """
        Export findings to Syslog RFC 5424 format.
        Universal format for any SIEM.
        """
        lines = []

        for finding in findings:
            # Parse metadata
            try:
                metadata = json.loads(finding.get('metadata', '{}'))
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            # Parse CVE IDs
            try:
                cve_ids = json.loads(finding.get('cve_ids', '[]'))
            except (json.JSONDecodeError, TypeError):
                cve_ids = []

            # Calculate priority (facility * 8 + severity)
            # Facility 16 = local0 (security)
            # Severity based on finding severity
            facility = 16
            severity_num = self.SEVERITY_TO_SYSLOG.get(finding.get('severity', 'INFO').upper(), 6)
            priority = facility * 8 + severity_num

            # Timestamp in RFC 3339 format
            timestamp = self._parse_timestamp(finding.get('timestamp'))

            # Build structured data
            sd_elements = []

            # Finding data
            finding_sd = [
                f'finding_id="{finding.get("finding_id", "")}"',
                f'severity="{finding.get("severity", "INFO")}"',
                f'cvss="{finding.get("cvss_score", 0.0)}"',
                f'asset="{finding.get("affected_asset", "")}"',
                f'finding_type="{metadata.get("finding_type", "unknown")}"'
            ]

            if cve_ids:
                finding_sd.append(f'cve="{",".join(cve_ids)}"')

            sd_elements.append(f'[finding@32473 {" ".join(finding_sd)}]')

            # Message
            title = finding.get('title', 'Security Finding')
            msg = f"{finding.get('severity', 'INFO')}: {title}"

            # Construct RFC 5424 syslog message
            # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
            syslog_line = f"<{priority}>1 {timestamp} {self.hostname} PurpleTeamGRC {os.getpid()} - {' '.join(sd_elements)} {msg}"

            lines.append(syslog_line)

        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def export_jsonl(self, findings: List[Dict], output_path: Path):
        """
        Export findings to JSON Lines format (.jsonl).
        One JSON object per line - generic format for any platform.
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            for finding in findings:
                # Parse metadata
                try:
                    metadata = json.loads(finding.get('metadata', '{}'))
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

                # Parse CVE IDs
                try:
                    cve_ids = json.loads(finding.get('cve_ids', '[]'))
                except (json.JSONDecodeError, TypeError):
                    cve_ids = []

                # Build complete finding object
                finding_obj = {
                    "finding_id": finding.get('finding_id', ''),
                    "session_id": finding.get('session_id', ''),
                    "timestamp": finding.get('timestamp', ''),
                    "severity": finding.get('severity', 'INFO'),
                    "title": finding.get('title', ''),
                    "description": finding.get('description', ''),
                    "affected_asset": finding.get('affected_asset', ''),
                    "cvss_score": finding.get('cvss_score', 0.0),
                    "cve_ids": cve_ids,
                    "remediation": finding.get('remediation', ''),
                    "status": finding.get('status', 'open'),
                    "finding_type": metadata.get('finding_type', 'unknown'),
                    "scanner_name": finding.get('scanner_name', 'unknown'),
                    "detection_source": finding.get('detection_source', ''),
                    "kev_status": finding.get('kev_status', ''),
                    "epss_score": finding.get('epss_score', 0.0),
                    "epss_percentile": finding.get('epss_percentile', 0.0),
                    "effective_priority": finding.get('effective_priority', 0.0),
                    "quality_of_detection": finding.get('quality_of_detection', 0.0),
                    "false_positive": finding.get('false_positive', 0),
                    "fp_reason": finding.get('fp_reason', ''),
                    "metadata": metadata
                }

                # Write as single line
                f.write(json.dumps(finding_obj, ensure_ascii=False) + '\n')

    # Helper methods

    def _escape_cef(self, text: str) -> str:
        """Escape text for CEF format."""
        if not text:
            return ''
        # Escape pipe, equals, backslash, newline, carriage return
        text = str(text)
        text = text.replace('\\', '\\\\')
        text = text.replace('|', '\\|')
        text = text.replace('=', '\\=')
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        return text

    def _escape_leef(self, text: str) -> str:
        """Escape text for LEEF format."""
        if not text:
            return ''
        # Escape tab, newline, carriage return
        text = str(text)
        text = text.replace('\t', ' ')
        text = text.replace('\n', ' ')
        text = text.replace('\r', ' ')
        return text

    def _to_cef_timestamp(self, timestamp: str) -> str:
        """Convert ISO timestamp to CEF format (milliseconds since epoch)."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return str(int(dt.timestamp() * 1000))
        except (ValueError, AttributeError):
            return str(int(datetime.utcnow().timestamp() * 1000))

    def _to_leef_timestamp(self, timestamp: str) -> str:
        """Convert ISO timestamp to LEEF format (ISO 8601)."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        except (ValueError, AttributeError):
            return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    def _parse_timestamp(self, timestamp: str) -> str:
        """Parse and normalize timestamp to ISO 8601 with timezone."""
        if not timestamp:
            return datetime.now(timezone.utc).isoformat()

        try:
            # Try parsing as ISO format
            if 'Z' in timestamp:
                return timestamp
            elif '+' in timestamp or timestamp.count('-') > 2:
                return timestamp
            else:
                # Add UTC timezone
                dt = datetime.fromisoformat(timestamp)
                return dt.replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc).isoformat()

    def _generate_uuid(self) -> str:
        """Generate a UUID-like string using hashlib (no uuid module needed)."""
        # Use timestamp + random data for uniqueness
        import random
        data = f"{datetime.utcnow().isoformat()}{random.random()}{os.getpid()}"
        hash_obj = hashlib.sha256(data.encode())
        hex_str = hash_obj.hexdigest()

        # Format as UUID
        return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


def main():
    """CLI interface for export module."""
    import argparse

    parser = argparse.ArgumentParser(description='Export Purple Team GRC findings')
    parser.add_argument('session_id', help='Session ID to export')
    parser.add_argument('-f', '--formats', nargs='+',
                       help='Export formats (default: all)')
    parser.add_argument('-o', '--output', type=Path,
                       help='Output directory (default: session exports/)')
    parser.add_argument('-l', '--list', action='store_true',
                       help='List supported formats and exit')

    args = parser.parse_args()

    exporter = ExportManager()

    if args.list:
        print("Supported Export Formats:")
        print()
        for fmt, desc in exporter.get_supported_formats().items():
            print(f"  {fmt:20s} - {desc}")
        return

    # Export
    try:
        results = exporter.export_all(args.session_id, args.output, args.formats)
        print(f"Exported {len(results)} formats:")
        for fmt, path in results.items():
            print(f"  {fmt}: {path}")
    except Exception as e:
        print(f"Export failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
