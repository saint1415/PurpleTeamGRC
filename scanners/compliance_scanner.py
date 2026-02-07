#!/usr/bin/env python3
"""
Purple Team Portable - Compliance Scanner
Automated compliance checking against multiple frameworks.
Maps technical findings to compliance controls.
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

from compliance import get_compliance_mapper, Framework


class ComplianceScanner(BaseScanner):
    """Compliance assessment scanner."""

    SCANNER_NAME = "compliance"
    SCANNER_DESCRIPTION = "Multi-framework compliance assessment"

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.mapper = get_compliance_mapper()

    def scan(self, frameworks: List[str] = None, **kwargs) -> Dict:
        """
        Execute compliance assessment.

        Args:
            frameworks: List of frameworks to assess (default: all configured)
        """
        self.start_time = datetime.utcnow()

        # Get frameworks to assess
        if not frameworks:
            frameworks = self.config.get_frameworks()

        self.scan_logger.info(f"Starting compliance assessment for: {frameworks}")

        results = {
            'frameworks': {},
            'summary': {},
            'gaps': [],
            'recommendations': []
        }

        for framework in frameworks:
            self.scan_logger.info(f"Assessing {framework}")

            try:
                assessment = self._assess_framework(framework)
                results['frameworks'][framework] = assessment

                # Collect gaps
                for gap in assessment.get('gaps', []):
                    results['gaps'].append({
                        'framework': framework,
                        **gap
                    })

            except Exception as e:
                self.scan_logger.error(f"Error assessing {framework}: {e}")

            self.human_delay()

        # Generate overall summary
        results['summary'] = self._generate_summary(results)

        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)

        self.end_time = datetime.utcnow()
        self.save_results()

        # Add compliance evidence
        self._add_compliance_evidence(results)

        return results

    def _assess_framework(self, framework: str) -> Dict:
        """Assess compliance for a specific framework."""
        controls = self.mapper.get_all_controls_for_framework(framework)

        if not controls:
            return {'error': f'Framework {framework} not supported'}

        assessment = {
            'framework': framework,
            'total_controls': len(controls),
            'controls_with_evidence': 0,
            'controls_without_evidence': 0,
            'compliance_rate': 0.0,
            'control_status': [],
            'gaps': []
        }

        for control_id, control in controls.items():
            # Check for existing evidence
            evidence = self.evidence.get_evidence_for_control(framework, control_id)

            status = {
                'control_id': control_id,
                'control_name': control.control_name,
                'family': control.family,
                'evidence_count': len(evidence),
                'has_evidence': len(evidence) > 0,
                'audit_procedures': control.audit_procedures,
                'evidence_types': control.evidence_types
            }

            assessment['control_status'].append(status)

            if evidence:
                assessment['controls_with_evidence'] += 1
            else:
                assessment['controls_without_evidence'] += 1
                assessment['gaps'].append({
                    'control_id': control_id,
                    'control_name': control.control_name,
                    'family': control.family,
                    'required_evidence': control.evidence_types,
                    'audit_procedures': control.audit_procedures
                })

                # Record gap as finding with detection_method
                self.add_finding(
                    severity='MEDIUM',
                    title=f"Compliance gap: {framework}/{control_id}",
                    description=f"No evidence found for {control.control_name} ({control.family})",
                    affected_asset=framework,
                    finding_type='compliance_gap',
                    remediation=f"Collect evidence for {control_id}: {', '.join(control.evidence_types[:3])}",
                    detection_method='evidence_review'
                )

        # Calculate compliance rate
        if assessment['total_controls'] > 0:
            assessment['compliance_rate'] = round(
                (assessment['controls_with_evidence'] / assessment['total_controls']) * 100, 2
            )

        return assessment

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate overall compliance summary."""
        summary = {
            'frameworks_assessed': len(results['frameworks']),
            'total_controls': 0,
            'total_with_evidence': 0,
            'total_gaps': len(results['gaps']),
            'overall_compliance_rate': 0.0,
            'by_framework': {}
        }

        for framework, assessment in results['frameworks'].items():
            if 'error' not in assessment:
                summary['total_controls'] += assessment['total_controls']
                summary['total_with_evidence'] += assessment['controls_with_evidence']
                summary['by_framework'][framework] = {
                    'compliance_rate': assessment['compliance_rate'],
                    'gaps': assessment['controls_without_evidence']
                }

        if summary['total_controls'] > 0:
            summary['overall_compliance_rate'] = round(
                (summary['total_with_evidence'] / summary['total_controls']) * 100, 2
            )

        return summary

    def _generate_recommendations(self, results: Dict) -> List[Dict]:
        """Generate prioritized remediation recommendations."""
        recommendations = []

        # Group gaps by control family
        gaps_by_family = {}
        for gap in results['gaps']:
            family = gap.get('family', 'Other')
            if family not in gaps_by_family:
                gaps_by_family[family] = []
            gaps_by_family[family].append(gap)

        # Generate recommendations per family
        priority = 1
        for family, gaps in sorted(gaps_by_family.items(), key=lambda x: -len(x[1])):
            # Determine priority based on family type
            if any(term in family.lower() for term in ['access', 'auth', 'identity']):
                rec_priority = 'HIGH'
            elif any(term in family.lower() for term in ['risk', 'vuln', 'security']):
                rec_priority = 'HIGH'
            elif any(term in family.lower() for term in ['audit', 'log', 'monitor']):
                rec_priority = 'MEDIUM'
            else:
                rec_priority = 'MEDIUM'

            # Collect affected frameworks
            affected_frameworks = list(set(g['framework'] for g in gaps))

            recommendation = {
                'priority': priority,
                'priority_level': rec_priority,
                'control_family': family,
                'gap_count': len(gaps),
                'affected_frameworks': affected_frameworks,
                'controls': [g['control_id'] for g in gaps],
                'recommendation': self._get_family_recommendation(family),
                'evidence_needed': list(set(
                    ev for g in gaps for ev in g.get('required_evidence', [])
                ))
            }
            recommendations.append(recommendation)
            priority += 1

        return recommendations

    def _get_family_recommendation(self, family: str) -> str:
        """Get recommendation for a control family."""
        recommendations = {
            'Access Control': 'Implement and document access control policies. Conduct regular access reviews.',
            'Audit and Accountability': 'Enable comprehensive logging. Implement log review processes.',
            'Configuration Management': 'Establish and maintain configuration baselines. Document all changes.',
            'Identification': 'Implement strong authentication. Document identity management procedures.',
            'Risk Assessment': 'Conduct and document periodic risk assessments.',
            'System and Communications': 'Document network architecture. Implement encryption for data in transit.',
            'System and Information Integrity': 'Implement vulnerability management. Document patch procedures.',
            'Logical Access': 'Document access provisioning and review processes.',
            'System Operations': 'Document operational procedures. Implement monitoring.',
            'Change Management': 'Document change management processes. Maintain change logs.',
            'IT General Controls': 'Strengthen IT general controls across access, change, and operations.',
            'Administrative': 'Document administrative policies and procedures.',
            'Technical': 'Implement and document technical security controls.',
            'Physical': 'Document physical security controls.',
            'Organizational': 'Document organizational security policies.',
            'Technological': 'Implement and document technological controls.'
        }

        for key, rec in recommendations.items():
            if key.lower() in family.lower():
                return rec

        return f'Review and implement controls for {family}. Document procedures and maintain evidence.'

    def _add_compliance_evidence(self, results: Dict):
        """Add compliance assessment as evidence."""
        if not self.session_id:
            return

        evidence_id = self.evidence.add_evidence(
            session_id=self.session_id,
            evidence_type='compliance_assessment',
            title='Multi-Framework Compliance Assessment',
            description=f"Assessed {len(results['frameworks'])} frameworks. "
                       f"Overall compliance rate: {results['summary']['overall_compliance_rate']}%",
            source_tool='compliance_scanner',
            raw_data=results['summary']
        )

        # Map to each framework's risk assessment control
        for framework in results['frameworks'].keys():
            self.evidence.map_to_control(
                evidence_id, framework,
                'RA-3' if 'NIST' in framework else 'CC3.2',
                'Risk Assessment', 'Risk Assessment'
            )

    def generate_attestation(self, framework: str, control_id: str,
                             period_start: datetime, period_end: datetime,
                             status: str, attester: str) -> str:
        """Generate a control attestation."""
        # Get evidence for this control
        evidence = self.evidence.get_evidence_for_control(framework, control_id)
        evidence_ids = [e['evidence_id'] for e in evidence]

        attestation_id = self.evidence.create_attestation(
            framework=framework,
            control_id=control_id,
            period_start=period_start,
            period_end=period_end,
            status=status,
            evidence_ids=evidence_ids,
            attester=attester
        )

        self.scan_logger.info(f"Created attestation {attestation_id} for {framework}/{control_id}")
        return attestation_id


if __name__ == '__main__':
    scanner = ComplianceScanner()
    print(f"Compliance Scanner initialized")
    print(f"Supported frameworks: {scanner.mapper.get_supported_frameworks()}")
