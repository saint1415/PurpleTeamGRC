#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detection
Evidence Manager Module
Centralized audit evidence repository with control citations and metadata management
FIX: Changed EVIDENCE_DIR to use RESULTS_DIR instead of BASE_DIR for write permissions
"""

import json
import yaml
import logging
import hashlib
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import sqlite3

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

# CRITICAL FIX: Evidence directory must be in RESULTS_DIR (writable user space)
# NOT in BASE_DIR (read-only system installation)
EVIDENCE_DIR = RESULTS_DIR / 'evidence'
DB_FILE = EVIDENCE_DIR / 'evidence.db'

# Control Framework Citations
CONTROL_CITATIONS = {
    'SOC2': {
        'CC6.1': 'Logical and Physical Access Controls - The entity implements logical access security software, infrastructure, and architectures over protected information assets',
        'CC6.6': 'Logical and Physical Access Controls - The entity implements logical access security measures to protect against threats from sources outside its system boundaries',
        'CC6.7': 'System Operations - The entity restricts the transmission, movement, and removal of information to authorized internal and external users',
        'CC7.1': 'System Monitoring - The entity identifies, selects, and develops risk mitigation activities',
        'CC7.2': 'System Monitoring - The entity implements detection policies, procedures, and tools',
    },
    'NIST': {
        'AC-2': 'Account Management - The organization manages information system accounts',
        'AC-3': 'Access Enforcement - The information system enforces approved authorizations',
        'RA-5': 'Vulnerability Scanning - The organization scans for vulnerabilities in the information system',
        'SC-7': 'Boundary Protection - The information system monitors and controls communications at external boundaries',
        'SI-2': 'Flaw Remediation - The organization identifies, reports, and corrects information system flaws',
        'SI-4': 'Information System Monitoring - The organization monitors the information system to detect attacks and indicators of potential attacks',
    },
    'ISO27001': {
        'A.9.2.1': 'User registration and de-registration - A formal user registration and de-registration process shall be implemented',
        'A.9.4.1': 'Information access restriction - Access to information and application system functions shall be restricted',
        'A.12.6.1': 'Management of technical vulnerabilities - Information about technical vulnerabilities shall be obtained in a timely fashion',
        'A.13.1.1': 'Network controls - Networks shall be managed and controlled to protect information',
        'A.14.2.8': 'System security testing - Testing of security functionality shall be carried out during development',
    },
    'HIPAA': {
        '164.308(a)(1)(ii)(A)': 'Risk Analysis - Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to ePHI',
        '164.308(a)(5)(ii)(B)': 'Protection from Malicious Software - Procedures for guarding against, detecting, and reporting malicious software',
        '164.312(a)(1)': 'Access Control - Implement technical policies and procedures for electronic information systems',
        '164.312(b)': 'Audit Controls - Implement hardware, software, and/or procedural mechanisms that record and examine activity',
        '164.312(e)(1)': 'Transmission Security - Implement technical security measures to guard against unauthorized access to ePHI',
    },
    'SOX': {
        'ITGC-Access': 'IT General Controls - Access to Programs and Data',
        'ITGC-Change': 'IT General Controls - Program Changes',
        'ITGC-Operations': 'IT General Controls - Computer Operations',
    }
}

class EvidenceManager:
    """Manages audit evidence with control citations and metadata"""
    
    def __init__(self):
        self.config = self.load_config()
        self.init_database()
        self.ensure_directories()
    
    def load_config(self):
        """Load configuration"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def ensure_directories(self):
        """Create evidence directory structure"""
        directories = [
            EVIDENCE_DIR,
            EVIDENCE_DIR / 'scans',
            EVIDENCE_DIR / 'controls',
            EVIDENCE_DIR / 'remediation',
            EVIDENCE_DIR / 'audit-packages',
            EVIDENCE_DIR / 'exports',
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def init_database(self):
        """Initialize SQLite database for evidence tracking"""
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Evidence items table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT UNIQUE NOT NULL,
                evidence_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                file_hash TEXT,
                created_date TEXT NOT NULL,
                collection_method TEXT,
                collector TEXT,
                status TEXT DEFAULT 'active',
                metadata TEXT
            )
        ''')
        
        # Control citations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS control_citations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                control_id TEXT NOT NULL,
                control_description TEXT,
                test_result TEXT,
                effectiveness TEXT,
                test_date TEXT,
                tester TEXT,
                notes TEXT,
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
            )
        ''')
        
        # Audit packages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id TEXT UNIQUE NOT NULL,
                package_name TEXT NOT NULL,
                framework TEXT NOT NULL,
                audit_period_start TEXT,
                audit_period_end TEXT,
                created_date TEXT NOT NULL,
                created_by TEXT,
                file_path TEXT,
                status TEXT DEFAULT 'draft',
                metadata TEXT
            )
        ''')
        
        # Package evidence mapping
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS package_evidence (
                package_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                included_date TEXT NOT NULL,
                PRIMARY KEY (package_id, evidence_id),
                FOREIGN KEY (package_id) REFERENCES audit_packages(package_id),
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Evidence database initialized")
    
    def add_evidence(self, evidence_type: str, title: str, file_path: str,
                    description: str = "", collection_method: str = "automated",
                    collector: str = "purple-team-scanner",
                    metadata: Dict = None) -> str:
        """Add evidence item to repository"""
        
        evidence_id = f"{evidence_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)
        
        # Copy file to evidence repository
        dest_path = EVIDENCE_DIR / 'scans' / Path(file_path).name
        shutil.copy2(file_path, dest_path)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence (
                evidence_id, evidence_type, title, description,
                file_path, file_hash, created_date, collection_method,
                collector, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence_id,
            evidence_type,
            title,
            description,
            str(dest_path),
            file_hash,
            datetime.now().isoformat(),
            collection_method,
            collector,
            json.dumps(metadata) if metadata else None
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Added evidence: {evidence_id}")
        return evidence_id
    
    def link_to_controls(self, evidence_id: str, controls: List[Dict]):
        """Link evidence to compliance controls"""
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        for control in controls:
            framework = control.get('framework')
            control_id = control.get('control_id')
            
            # Get control description from citations
            control_desc = None
            if framework in CONTROL_CITATIONS and control_id in CONTROL_CITATIONS[framework]:
                control_desc = CONTROL_CITATIONS[framework][control_id]
            
            cursor.execute('''
                INSERT INTO control_citations (
                    evidence_id, framework, control_id, control_description,
                    test_result, effectiveness, test_date, tester, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence_id,
                framework,
                control_id,
                control_desc,
                control.get('test_result'),
                control.get('effectiveness'),
                control.get('test_date', datetime.now().isoformat()),
                control.get('tester', 'purple-team-scanner'),
                control.get('notes')
            ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Linked evidence {evidence_id} to {len(controls)} controls")
    
    def create_audit_package(self, package_name: str, framework: str,
                           evidence_ids: List[str],
                           audit_period_start: str = None,
                           audit_period_end: str = None,
                           created_by: str = "purple-team-scanner") -> str:
        """Create an audit evidence package"""
        
        package_id = f"PKG_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create package record
        cursor.execute('''
            INSERT INTO audit_packages (
                package_id, package_name, framework,
                audit_period_start, audit_period_end,
                created_date, created_by, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            package_id,
            package_name,
            framework,
            audit_period_start,
            audit_period_end,
            datetime.now().isoformat(),
            created_by,
            'draft'
        ))
        
        # Link evidence to package
        for evidence_id in evidence_ids:
            cursor.execute('''
                INSERT INTO package_evidence (package_id, evidence_id, included_date)
                VALUES (?, ?, ?)
            ''', (package_id, evidence_id, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created audit package: {package_id} with {len(evidence_ids)} evidence items")
        return package_id
    
    def export_audit_package(self, package_id: str, output_dir: str = None):
        """Export audit package with all evidence and index"""
        
        if output_dir is None:
            output_dir = EVIDENCE_DIR / 'audit-packages' / package_id
        else:
            output_dir = Path(output_dir)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get package info
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM audit_packages WHERE package_id = ?', (package_id,))
        package = dict(cursor.fetchone())
        
        # Get all evidence in package
        cursor.execute('''
            SELECT e.*
            FROM evidence e
            JOIN package_evidence pe ON e.evidence_id = pe.evidence_id
            WHERE pe.package_id = ?
        ''', (package_id,))
        
        evidence_list = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        # Copy evidence files
        evidence_dir = output_dir / 'evidence'
        evidence_dir.mkdir(exist_ok=True)
        
        for evidence in evidence_list:
            source_file = Path(evidence['file_path'])
            if source_file.exists():
                dest_file = evidence_dir / source_file.name
                shutil.copy2(source_file, dest_file)
        
        # Generate index
        self._generate_package_index(package, evidence_list, output_dir)
        
        # Update package status
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE audit_packages
            SET status = 'exported', file_path = ?
            WHERE package_id = ?
        ''', (str(output_dir), package_id))
        conn.commit()
        conn.close()
        
        logger.info(f"Exported audit package to: {output_dir}")
        return str(output_dir)
    
    def _generate_package_index(self, package: Dict, evidence_list: List[Dict], package_dir: Path):
        """Generate HTML index for audit package"""
        
        package_id = package['package_id']
        package_name = package['package_name']
        framework = package['framework']
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Audit Package - {package_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .metadata {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; }}
        .control-tag {{ background-color: #e74c3c; color: white; padding: 3px 8px;
                       border-radius: 3px; margin: 2px; display: inline-block; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Audit Evidence Package</h1>
    <div class="metadata">
        <p><strong>Package ID:</strong> {package_id}</p>
        <p><strong>Package Name:</strong> {package_name}</p>
        <p><strong>Framework:</strong> {framework}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Evidence Items:</strong> {len(evidence_list)}</p>
    </div>
    
    <h2>Evidence Inventory</h2>
    <table>
        <tr>
            <th>Evidence ID</th>
            <th>Title</th>
            <th>Type</th>
            <th>Date Collected</th>
            <th>File</th>
            <th>Controls</th>
        </tr>
'''
        
        # Get control mappings for each evidence
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        for evidence in evidence_list:
            cursor.execute('''
                SELECT framework, control_id, test_result
                FROM control_citations
                WHERE evidence_id = ?
            ''', (evidence['evidence_id'],))
            
            controls = cursor.fetchall()
            control_tags = ''.join([
                f'<span class="control-tag">{c["framework"]} {c["control_id"]}</span>'
                for c in controls
            ])
            
            html += f'''
        <tr>
            <td>{evidence['evidence_id']}</td>
            <td>{evidence['title']}</td>
            <td>{evidence['evidence_type']}</td>
            <td>{evidence['created_date'][:10]}</td>
            <td>{Path(evidence['file_path']).name}</td>
            <td>{control_tags}</td>
        </tr>
'''
        
        conn.close()
        
        html += '''
    </table>
    
    <h2>Control Coverage Summary</h2>
    <p>This package provides evidence for the following controls:</p>
'''
        
        # Generate control summary
        control_summary = self._generate_control_summary(evidence_list)
        html += '<ul>'
        for framework, controls in control_summary.items():
            html += f'<li><strong>{framework}:</strong> '
            html += ', '.join([f'{c["control_id"]} ({c["count"]} items)' for c in controls])
            html += '</li>'
        html += '</ul>'
        
        html += '''
    <h2>Instructions</h2>
    <p>This package contains all evidence collected during the audit period. Each evidence item has been:</p>
    <ul>
        <li>Collected using automated security scanning tools</li>
        <li>Linked to specific control requirements</li>
        <li>Validated for integrity (file hash recorded)</li>
        <li>Organized for auditor review</li>
    </ul>
    <p>For questions or additional information, please contact the security team.</p>
</body>
</html>
'''
        
        with open(package_dir / 'INDEX.html', 'w') as f:
            f.write(html)
        
        logger.info(f"Generated package index: {package_dir / 'INDEX.html'}")
    
    def _generate_control_summary(self, evidence_list: List[Dict]) -> Dict:
        """Generate summary of control coverage"""
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        summary = {}
        
        for evidence in evidence_list:
            cursor.execute('''
                SELECT framework, control_id, COUNT(*) as count
                FROM control_citations
                WHERE evidence_id = ?
                GROUP BY framework, control_id
            ''', (evidence['evidence_id'],))
            
            for row in cursor.fetchall():
                framework, control_id, count = row
                if framework not in summary:
                    summary[framework] = []
                
                # Check if control already in summary
                existing = next((c for c in summary[framework] if c['control_id'] == control_id), None)
                if existing:
                    existing['count'] += count
                else:
                    summary[framework].append({'control_id': control_id, 'count': count})
        
        conn.close()
        return summary
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_evidence_by_control(self, framework: str, control_id: str) -> List[Dict]:
        """Get all evidence for a specific control"""
        
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT e.*, cc.test_result, cc.effectiveness, cc.test_date
            FROM evidence e
            JOIN control_citations cc ON e.evidence_id = cc.evidence_id
            WHERE cc.framework = ? AND cc.control_id = ?
            AND e.status = 'active'
            ORDER BY e.created_date DESC
        ''', (framework, control_id))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def export_evidence_log(self, output_path: str, framework: str = None):
        """Export evidence log to CSV"""
        import csv
        
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if framework:
            cursor.execute('''
                SELECT DISTINCT e.*, cc.framework, cc.control_id
                FROM evidence e
                JOIN control_citations cc ON e.evidence_id = cc.evidence_id
                WHERE cc.framework = ?
                ORDER BY e.created_date DESC
            ''', (framework,))
        else:
            cursor.execute('''
                SELECT e.*, cc.framework, cc.control_id
                FROM evidence e
                LEFT JOIN control_citations cc ON e.evidence_id = cc.evidence_id
                ORDER BY e.created_date DESC
            ''')
        
        results = cursor.fetchall()
        conn.close()
        
        with open(output_path, 'w', newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                for row in results:
                    writer.writerow(dict(row))
        
        logger.info(f"Exported evidence log to {output_path}")

def main():
    """Main entry point for testing"""
    manager = EvidenceManager()
    logger.info("Evidence Manager initialized")
    
    # Example: Add evidence from a scan
    # evidence_id = manager.add_evidence(
    #     evidence_type="vulnerability_scan",
    #     title="Weekly Vulnerability Scan - 2024-12-31",
    #     file_path="/opt/purple-team/results/vulnerability-scans/latest.json",
    #     description="Automated vulnerability scan of internal network"
    # )
    
    # Example: Link to controls
    # manager.link_to_controls(evidence_id, [
    #     {'framework': 'SOC2', 'control_id': 'CC6.7', 'test_result': 'pass'},
    #     {'framework': 'NIST', 'control_id': 'RA-5', 'test_result': 'pass'},
    # ])

if __name__ == '__main__':
    main()
