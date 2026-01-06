#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detection
Integrated GRC Scanner
Processes scan results with automatic evidence management, risk scoring, and control citations
"""

import json
import yaml
import logging
import sys
from datetime import datetime
from pathlib import Path
import importlib.util

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

# Paths

# Import our GRC modules
def import_module_from_file(module_name, file_path):
    """Import a module from a file path"""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

# Try to import GRC modules
# FIX: Changed BASE_DIR / 'scripts' to BASE_DIR / 'utilities'
try:
    evidence_module = import_module_from_file('evidence_manager', BASE_DIR / 'utilities' / 'evidence_manager.py')
    risk_module = import_module_from_file('risk_scorer', BASE_DIR / 'utilities' / 'risk_scorer.py')
    EvidenceManager = evidence_module.EvidenceManager
    RiskScorer = risk_module.RiskScorer
except Exception as e:
    logger.warning(f"Could not import GRC modules: {e}")
    EvidenceManager = None
    RiskScorer = None

# Control mappings for automatic citation
FINDING_TO_CONTROLS = {
    'weak_password': [
        ('SOC2', 'CC6.1'),
        ('NIST', 'AC-2'),
        ('ISO27001', 'A.9.4.3'),
        ('HIPAA', '164.312(a)(1)')
    ],
    'unpatched_system': [
        ('SOC2', 'CC6.7'),
        ('NIST', 'SI-2'),
        ('ISO27001', 'A.12.6.1'),
        ('HIPAA', '164.308(a)(1)(ii)(A)')
    ],
    'open_port': [
        ('SOC2', 'CC6.1'),
        ('NIST', 'SC-7'),
        ('ISO27001', 'A.13.1.1')
    ],
    'ssl_vulnerability': [
        ('NIST', 'SC-8'),
        ('ISO27001', 'A.13.1.1'),
        ('HIPAA', '164.312(e)(1)')
    ],
    'missing_encryption': [
        ('HIPAA', '164.312(e)(1)'),
        ('ISO27001', 'A.10.1.1'),
        ('SOC2', 'CC6.1')
    ],
    'logging_disabled': [
        ('SOC2', 'CC7.1'),
        ('NIST', 'SI-4'),
        ('ISO27001', 'A.12.4.1'),
        ('HIPAA', '164.312(b)')
    ],
    'unauthorized_access': [
        ('SOC2', 'CC6.1'),
        ('NIST', 'AC-3'),
        ('HIPAA', '164.312(a)(1)'),
        ('ISO27001', 'A.9.4.1')
    ],
}

# Threat intelligence for likelihood assessment
THREAT_INTEL = {
    'ransomware': 'very_high',  # Active ransomware targeting healthcare
    'sql_injection': 'high',  # Common web attack
    'weak_password': 'very_high',  # Credential stuffing attacks common
    'unpatched_critical': 'very_high',  # Actively exploited vulnerabilities
    'ssl_tls_weak': 'medium',  # Legacy protocol issues
    'information_disclosure': 'medium',  # Passive reconnaissance
}

class GRCIntegratedScanner:
    """Integrated scanner with GRC capabilities"""
    
    def __init__(self):
        self.evidence_manager = EvidenceManager() if EvidenceManager else None
        self.risk_scorer = RiskScorer() if RiskScorer else None
        
        if not self.evidence_manager or not self.risk_scorer:
            logger.warning("GRC modules not available, running in basic mode")
    
    def process_scan_results(self, scan_file: Path, scan_type: str):
        """Process scan results with GRC integration"""
        
        logger.info(f"Processing {scan_type} scan: {scan_file}")
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        # Add evidence to repository
        if self.evidence_manager:
            evidence_id = self.evidence_manager.add_evidence(
                evidence_type=scan_type,
                title=f"{scan_type.replace('_', ' ').title()} - {scan_data.get('scan_id', 'Unknown')}",
                file_path=str(scan_file),
                description=f"Automated {scan_type} scan results",
                metadata={
                    'scan_id': scan_data.get('scan_id'),
                    'scan_date': scan_data.get('start_time'),
                    'summary': scan_data.get('summary', {})
                }
            )
            logger.info(f"Added to evidence repository: {evidence_id}")
        
        # Process findings with citations and risk scoring
        if scan_type == 'vulnerability_scan':
            self._process_vulnerability_findings(scan_data, evidence_id if self.evidence_manager else None)
        elif scan_type == 'network_scan':
            self._process_network_findings(scan_data, evidence_id if self.evidence_manager else None)
        elif scan_type == 'compliance_check':
            self._process_compliance_findings(scan_data, evidence_id if self.evidence_manager else None)
    
    def _process_vulnerability_findings(self, scan_data: dict, evidence_id: str = None):
        """Process vulnerability findings with risk scoring"""
        
        findings = scan_data.get('findings', [])
        logger.info(f"Processing {len(findings)} vulnerability findings")
        
        for finding in findings:
            # Determine finding category
            category = self._categorize_finding(finding)
            
            # Get applicable controls
            controls = FINDING_TO_CONTROLS.get(category, [])
            
            # Add control citations to finding
            finding['control_citations'] = [
                {
                    'framework': fw,
                    'control_id': ctrl,
                    'test_result': 'fail',  # Vulnerability found = control failed
                    'test_date': datetime.now().isoformat()
                }
                for fw, ctrl in controls
            ]
            
            # Link evidence to controls
            if self.evidence_manager and evidence_id and controls:
                self.evidence_manager.link_to_controls(evidence_id, finding['control_citations'])
            
            # Risk scoring
            if self.risk_scorer:
                # Get or create asset
                host = finding.get('host', 'unknown')
                asset_id = f"ASSET_{host.replace('.', '_')}"
                
                # Register asset if needed (simplified)
                try:
                    self.risk_scorer.register_asset(
                        asset_name=host,
                        ip_address=host,
                        business_function='Unknown',
                        business_impact='medium'  # Default, should be classified
                    )
                except:
                    pass  # Asset might already exist
                
                # Assess vulnerability risk
                cvss_score = self._extract_cvss_score(finding)
                threat_likelihood = self._determine_threat_likelihood(finding, category)
                
                risk_id = self.risk_scorer.assess_vulnerability(
                    asset_id=asset_id,
                    vulnerability_id=finding.get('title', 'Unknown')[:50],
                    finding_title=finding.get('title', 'Unknown'),
                    cvss_score=cvss_score,
                    threat_likelihood=threat_likelihood,
                    notes=finding.get('description', '')
                )
                
                # Create remediation task for high/critical risks
                if risk_id:
                    finding['risk_id'] = risk_id
                    
                    risk_info = self.risk_scorer.calculate_risk_score(
                        cvss_score, 'medium', threat_likelihood
                    )
                    
                    if risk_info['risk_level'] in ['critical', 'high']:
                        task_id = self.risk_scorer.create_remediation_task(
                            risk_id=risk_id,
                            verification_method='rescan'
                        )
                        finding['remediation_task_id'] = task_id
                        logger.info(f"Created remediation task: {task_id}")
        
        # Update scan file with enhanced data
        scan_data['findings'] = findings
        scan_file = Path(scan_data.get('_source_file', RESULTS_DIR / 'vulnerability-scans' / 'latest.json'))
        
        with open(scan_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        logger.info("Enhanced vulnerability findings with control citations and risk scores")
    
    def _process_network_findings(self, scan_data: dict, evidence_id: str = None):
        """Process network scan findings"""
        
        hosts = scan_data.get('hosts', [])
        logger.info(f"Processing {len(hosts)} discovered hosts")
        
        # Link to network security controls
        if self.evidence_manager and evidence_id:
            controls = [
                {'framework': 'NIST', 'control_id': 'SC-7', 'test_result': 'pass'},
                {'framework': 'ISO27001', 'control_id': 'A.13.1.1', 'test_result': 'pass'},
                {'framework': 'SOC2', 'control_id': 'CC6.1', 'test_result': 'pass'}
            ]
            self.evidence_manager.link_to_controls(evidence_id, controls)
        
        # Register assets in risk database
        if self.risk_scorer:
            for host in hosts:
                try:
                    self.risk_scorer.register_asset(
                        asset_name=host.get('hostname', host.get('ip')),
                        ip_address=host.get('ip'),
                        business_function='Discovered via network scan'
                    )
                except Exception as e:
                    logger.debug(f"Asset registration note: {e}")
    
    def _process_compliance_findings(self, scan_data: dict, evidence_id: str = None):
        """Process compliance check findings"""
        
        frameworks = scan_data.get('frameworks', {})
        logger.info(f"Processing compliance for {len(frameworks)} frameworks")
        
        # Link evidence to all tested controls
        if self.evidence_manager and evidence_id:
            all_controls = []
            
            for framework, data in frameworks.items():
                for control_id, control_data in data.get('controls', {}).items():
                    all_controls.append({
                        'framework': framework,
                        'control_id': control_id,
                        'test_result': 'pass' if control_data['status'] == 'Compliant' else 'fail',
                        'effectiveness': 'effective' if control_data['status'] == 'Compliant' else 'ineffective',
                        'notes': f"{len(control_data.get('findings', []))} findings"
                    })
            
            if all_controls:
                self.evidence_manager.link_to_controls(evidence_id, all_controls)
                logger.info(f"Linked compliance evidence to {len(all_controls)} controls")
    
    def _categorize_finding(self, finding: dict) -> str:
        """Categorize finding for control mapping"""
        
        title_lower = finding.get('title', '').lower()
        desc_lower = finding.get('description', '').lower()
        combined = title_lower + ' ' + desc_lower
        
        if 'password' in combined or 'credential' in combined:
            return 'weak_password'
        elif 'patch' in combined or 'update' in combined or 'cve' in combined:
            return 'unpatched_system'
        elif 'port' in combined or 'open service' in combined:
            return 'open_port'
        elif 'ssl' in combined or 'tls' in combined or 'certificate' in combined:
            return 'ssl_vulnerability'
        elif 'encrypt' in combined:
            return 'missing_encryption'
        elif 'log' in combined or 'audit' in combined:
            return 'logging_disabled'
        elif 'access' in combined or 'authorization' in combined:
            return 'unauthorized_access'
        else:
            return 'general_finding'
    
    def _extract_cvss_score(self, finding: dict) -> float:
        """Extract or estimate CVSS score"""
        
        # Check if CVSS score is provided
        if 'cvss_score' in finding:
            return float(finding['cvss_score'])
        
        # Estimate based on severity
        severity = finding.get('severity', 'medium').lower()
        severity_to_cvss = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        
        return severity_to_cvss.get(severity, 5.0)
    
    def _determine_threat_likelihood(self, finding: dict, category: str) -> str:
        """Determine threat likelihood"""
        
        # Check threat intelligence
        for threat_type, likelihood in THREAT_INTEL.items():
            if threat_type in finding.get('title', '').lower():
                return likelihood
        
        # Default based on severity
        severity = finding.get('severity', 'medium').lower()
        if severity == 'critical':
            return 'high'
        elif severity == 'high':
            return 'medium'
        else:
            return 'low'
    
    def generate_citation_report(self, scan_file: Path, output_file: Path = None):
        """Generate report with full control citations"""
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        if not output_file:
            output_file = scan_file.parent / f"{scan_file.stem}_with_citations.html"
        
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Scan Results with Control Citations</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 3px solid #667eea; }}
        .finding {{ background: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #667eea; }}
        .citations {{ background: #e7f3fe; padding: 10px; margin-top: 10px; }}
        .citation-tag {{ display: inline-block; background: #4CAF50; color: white; 
                        padding: 4px 8px; margin: 2px; border-radius: 3px; font-size: 12px; }}
        .risk-score {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
        .critical {{ color: #f44336; }}
        .high {{ color: #ff9800; }}
        .medium {{ color: #ffeb3b; color: #333; }}
        .low {{ color: #4caf50; }}
    </style>
</head>
<body>
    <h1>Security Scan Results with Control Citations</h1>
    <p><strong>Scan Date:</strong> {scan_data.get('start_time', 'Unknown')}</p>
    <p><strong>Scan ID:</strong> {scan_data.get('scan_id', 'Unknown')}</p>
'''
        
        findings = scan_data.get('findings', [])
        for idx, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'medium')
            citations = finding.get('control_citations', [])
            risk_id = finding.get('risk_id', '')
            
            html += f'''
    <div class="finding">
        <h3>Finding #{idx}: {finding.get('title', 'Unknown')}</h3>
        <p><strong>Severity:</strong> <span class="{severity}">{severity.upper()}</span></p>
        <p><strong>Host:</strong> {finding.get('host', 'N/A')}</p>
        <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
'''
            
            if risk_id:
                html += f'<p><strong>Risk ID:</strong> {risk_id}</p>'
            
            if citations:
                html += '<div class="citations"><strong>Control Citations:</strong><br>'
                for citation in citations:
                    html += f'<span class="citation-tag">{citation["framework"]} {citation["control_id"]}</span> '
                html += '</div>'
            
            html += '</div>'
        
        html += '''
</body>
</html>
'''
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Generated citation report: {output_file}")
        return str(output_file)

def main():
    """Main entry point"""
    
    scanner = GRCIntegratedScanner()
    
    # Process latest scans
    scan_types = [
        ('vulnerability-scans', 'vulnerability_scan'),
        ('network-scans', 'network_scan'),
        ('compliance-checks', 'compliance_check')
    ]
    
    for scan_dir, scan_type in scan_types:
        scan_path = RESULTS_DIR / scan_dir
        if scan_path.exists():
            json_files = sorted(scan_path.glob('*.json'), reverse=True)
            if json_files:
                latest = json_files[0]
                scanner.process_scan_results(latest, scan_type)
                
                # Generate citation report
                if scan_type == 'vulnerability_scan':
                    scanner.generate_citation_report(latest)

if __name__ == '__main__':
    main()
