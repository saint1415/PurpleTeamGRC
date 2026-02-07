#!/usr/bin/env python3
"""
Purple Team Portable - Base Scanner Class
Provides common functionality for all scanner modules.
"""

import os
import sys
import json
import time
import random
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from paths import paths, get_paths
from config import config, get_config
from evidence import get_evidence_manager
from compliance import get_compliance_mapper
from logger import get_logger, get_scan_logger

try:
    from threat_intel import get_threat_intel
except ImportError:
    get_threat_intel = None

try:
    from qod import get_qod_scorer
except ImportError:
    get_qod_scorer = None


class BaseScanner(ABC):
    """Base class for all scanners."""

    SCANNER_NAME = "base"
    SCANNER_DESCRIPTION = "Base scanner class"

    def __init__(self, session_id: Optional[str] = None):
        self.paths = get_paths()
        self.config = get_config()
        self.evidence = get_evidence_manager()
        self.compliance = get_compliance_mapper()

        self.session_id = session_id
        self.logger = get_logger(self.SCANNER_NAME)

        if session_id:
            self.scan_logger = get_scan_logger(session_id)
        else:
            self.scan_logger = self.logger

        self.results: List[Dict] = []
        self.findings: List[Dict] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    @abstractmethod
    def scan(self, targets: List[str], **kwargs) -> Dict:
        """Execute the scan. Must be implemented by subclasses."""
        pass

    def human_delay(self):
        """Add human-like delay between operations."""
        min_delay, max_delay = self.config.get_scan_delay()
        delay = random.uniform(min_delay, max_delay)
        self.scan_logger.debug(f"Human delay: {delay:.1f} seconds")
        time.sleep(delay)

    def run_tool(self, command: List[str], timeout: int = 300,
                  description: str = "") -> subprocess.CompletedProcess:
        """Run an external tool with logging."""
        self.scan_logger.info(f"Running: {' '.join(command[:3])}...")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            self.scan_logger.warning(f"Command timed out: {description}")
            raise
        except Exception as e:
            self.scan_logger.error(f"Command failed: {e}")
            raise

    def add_result(self, result_type: str, data: Dict, target: str = ""):
        """Add a scan result."""
        result = {
            'type': result_type,
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'scanner': self.SCANNER_NAME,
            'data': data
        }
        self.results.append(result)
        self.scan_logger.debug(f"Result: {result_type} for {target}")

    def add_finding(self, severity: str, title: str, description: str,
                    affected_asset: str, finding_type: str,
                    cvss_score: float = 0.0, cve_ids: List[str] = None,
                    remediation: str = "", raw_data: Any = None,
                    detection_method: str = ""):
        """Add a security finding with enrichment, QoD, and override checking."""
        finding = {
            'severity': severity,
            'title': title,
            'description': description,
            'affected_asset': affected_asset,
            'finding_type': finding_type,
            'cvss_score': cvss_score,
            'cve_ids': cve_ids or [],
            'remediation': remediation,
            'timestamp': datetime.utcnow().isoformat(),
            'scanner': self.SCANNER_NAME,
            'detection_method': detection_method,
        }

        # Check overrides before recording
        override = self.evidence.check_overrides(finding)
        if override:
            if override['action'] == 'false_positive':
                finding['false_positive'] = 1
                finding['fp_reason'] = override.get('reason', 'Override rule')
                self.scan_logger.info(f"Finding marked FP by override: {title}")
            elif override['action'] == 'severity_change' and override.get('new_severity'):
                finding['original_severity'] = severity
                severity = override['new_severity']
                finding['severity'] = severity
            elif override['action'] == 'accepted_risk':
                finding['status'] = 'accepted_risk'

        self.findings.append(finding)
        self.scan_logger.info(f"Finding [{severity}]: {title} on {affected_asset}")

        # If we have a session, record in evidence database
        if self.session_id:
            # Add evidence
            evidence_id = self.evidence.add_evidence(
                session_id=self.session_id,
                evidence_type='finding',
                title=title,
                description=description,
                source_tool=self.SCANNER_NAME,
                raw_data=raw_data or finding,
                metadata={'severity': severity, 'cvss': cvss_score}
            )

            # Add finding to database
            finding_id = self.evidence.add_finding(
                session_id=self.session_id,
                severity=severity,
                title=title,
                description=description,
                affected_asset=affected_asset,
                cvss_score=cvss_score,
                cve_ids=cve_ids,
                remediation=remediation,
                evidence_id=evidence_id,
                metadata={'finding_type': finding_type}
            )

            # Assign QoD score
            qod_score = None
            if get_qod_scorer is not None:
                try:
                    qod = get_qod_scorer()
                    qod_score = qod.assign_qod(
                        self.SCANNER_NAME, detection_method
                    )
                except Exception:
                    pass

            # Enrich with threat intelligence (KEV + EPSS)
            kev_status = None
            epss_score = None
            epss_percentile = None
            effective_priority = None

            if get_threat_intel is not None and cve_ids:
                try:
                    ti = get_threat_intel()
                    for cve_id in (cve_ids or []):
                        enrichment = ti.enrich_finding(cve_id)
                        if enrichment.get('kev_status'):
                            kev_status = 'true'
                        if enrichment.get('epss_score', 0) > (epss_score or 0):
                            epss_score = enrichment['epss_score']
                            epss_percentile = enrichment['epss_percentile']

                    is_kev = kev_status == 'true'
                    effective_priority = ti.calculate_effective_priority(
                        cvss_score, epss_score or 0.0, is_kev
                    )
                except Exception as e:
                    self.scan_logger.debug(f"Threat intel enrichment error: {e}")

            # Update finding with enrichment data
            self.evidence.update_finding_enrichment(
                finding_id,
                kev_status=kev_status,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                effective_priority=effective_priority,
                quality_of_detection=qod_score,
                detection_source=detection_method or self.SCANNER_NAME,
                false_positive=finding.get('false_positive'),
                fp_reason=finding.get('fp_reason'),
                scanner_name=self.SCANNER_NAME,
            )

            # Map to compliance controls
            frameworks = self.config.get_frameworks()
            self.compliance.map_finding_to_controls(
                finding_type, evidence_id, self.evidence, frameworks
            )

    def save_results(self, filename: str = None) -> Path:
        """Save scan results to file."""
        if not filename:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.SCANNER_NAME}_{timestamp}.json"

        if self.session_id:
            output_dir = self.paths.session_dir(self.session_id)
        else:
            output_dir = self.paths.results

        output_path = output_dir / filename

        output_data = {
            'scanner': self.SCANNER_NAME,
            'session_id': self.session_id,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else None,
            'results_count': len(self.results),
            'findings_count': len(self.findings),
            'findings_by_severity': self._count_by_severity(),
            'results': self.results,
            'findings': self.findings
        }

        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)

        self.scan_logger.info(f"Results saved to {output_path}")
        return output_path

    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in self.findings:
            sev = finding.get('severity', 'INFO').upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    def get_summary(self) -> Dict:
        """Get scan summary."""
        return {
            'scanner': self.SCANNER_NAME,
            'session_id': self.session_id,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': str(self.end_time - self.start_time) if self.end_time and self.start_time else None,
            'results_count': len(self.results),
            'findings_count': len(self.findings),
            'findings_by_severity': self._count_by_severity()
        }

    def check_tool(self, tool_name: str) -> bool:
        """Check if an external tool is available."""
        tool_path = self.paths.find_tool(tool_name)
        if tool_path:
            self.scan_logger.debug(f"Found {tool_name} at {tool_path}")
            return True
        self.scan_logger.warning(f"Tool not found: {tool_name}")
        return False

    def require_tool(self, tool_name: str) -> Path:
        """Require an external tool, raise error if not found."""
        return self.paths.require_tool(tool_name)
