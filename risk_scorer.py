#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detection
Risk Scoring Engine
Calculate risk scores combining CVSS, business impact, and threat likelihood
"""

import json
import yaml
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import math

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
# Specific results directory
RISK_SCORES_DIR = RESULTS_DIR / 'risk-scores'

# Paths

RISK_DIR = RESULTS_DIR / 'risk'
DB_FILE = RISK_DIR / 'risk.db'

# Business Impact Ratings
BUSINESS_IMPACT = {
    'critical': {
        'score': 10,
        'description': 'Affects core business operations, regulatory compliance, or ePHI',
        'examples': ['EMR system', 'Claims processing', 'Patient portal']
    },
    'high': {
        'score': 7,
        'description': 'Affects important business functions or contains sensitive data',
        'examples': ['HR system', 'Financial systems', 'Internal applications']
    },
    'medium': {
        'score': 4,
        'description': 'Affects non-critical business functions',
        'examples': ['Internal wikis', 'Development servers', 'Test environments']
    },
    'low': {
        'score': 1,
        'description': 'Minimal business impact',
        'examples': ['Demo systems', 'Isolated test instances']
    }
}

# Threat Likelihood
THREAT_LIKELIHOOD = {
    'very_high': {
        'score': 1.0,
        'description': 'Active exploitation observed in the wild, known ransomware targeting',
        'indicators': ['Active ransomware campaigns', 'APT targeting healthcare/insurance']
    },
    'high': {
        'score': 0.8,
        'description': 'Exploit code publicly available, sector-specific threats',
        'indicators': ['Public exploits', 'Healthcare sector threats']
    },
    'medium': {
        'score': 0.5,
        'description': 'Theoretical exploit possible, generic threats',
        'indicators': ['Proof of concept exists', 'Generic attack vectors']
    },
    'low': {
        'score': 0.2,
        'description': 'Difficult to exploit, requires specific conditions',
        'indicators': ['Complex exploitation', 'Specific prerequisites']
    },
    'very_low': {
        'score': 0.1,
        'description': 'Theoretical only, no known exploits',
        'indicators': ['No exploitation path', 'Theoretical vulnerability']
    }
}

class RiskScorer:
    """Calculate comprehensive risk scores"""
    
    def __init__(self):
        self.config = self.load_config()
        self.init_database()
        RISK_DIR.mkdir(parents=True, exist_ok=True)
    
    def load_config(self):
        """Load configuration"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def init_database(self):
        """Initialize risk database"""
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Asset inventory
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                asset_name TEXT NOT NULL,
                asset_type TEXT,
                ip_address TEXT,
                hostname TEXT,
                business_function TEXT,
                data_classification TEXT,
                business_impact TEXT DEFAULT 'medium',
                criticality_score INTEGER DEFAULT 4,
                owner TEXT,
                created_date TEXT,
                last_updated TEXT,
                metadata TEXT
            )
        ''')
        
        # Risk assessments
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_assessments (
                risk_id TEXT PRIMARY KEY,
                asset_id TEXT,
                vulnerability_id TEXT,
                finding_title TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                business_impact_score INTEGER,
                threat_likelihood_score REAL,
                composite_risk_score REAL,
                risk_level TEXT,
                assessment_date TEXT,
                assessor TEXT,
                status TEXT DEFAULT 'open',
                remediation_deadline TEXT,
                notes TEXT,
                FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
            )
        ''')
        
        # Remediation tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                task_id TEXT PRIMARY KEY,
                risk_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                assigned_to TEXT,
                priority TEXT,
                status TEXT DEFAULT 'open',
                created_date TEXT,
                due_date TEXT,
                completed_date TEXT,
                verification_method TEXT,
                verification_date TEXT,
                verified_by TEXT,
                notes TEXT,
                FOREIGN KEY (risk_id) REFERENCES risk_assessments(risk_id)
            )
        ''')
        
        # Risk history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk_id TEXT,
                event_type TEXT,
                event_date TEXT,
                previous_status TEXT,
                new_status TEXT,
                previous_score REAL,
                new_score REAL,
                changed_by TEXT,
                notes TEXT,
                FOREIGN KEY (risk_id) REFERENCES risk_assessments(risk_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Risk database initialized")
    
    def register_asset(self, asset_name: str, ip_address: str = None,
                      business_function: str = None, data_classification: str = None,
                      business_impact: str = 'medium', owner: str = None) -> str:
        """Register an asset in the inventory"""
        
        asset_id = f"ASSET_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{ip_address or asset_name}"
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        impact_score = BUSINESS_IMPACT.get(business_impact, BUSINESS_IMPACT['medium'])['score']
        
        cursor.execute('''
            INSERT OR REPLACE INTO assets (
                asset_id, asset_name, ip_address, business_function,
                data_classification, business_impact, criticality_score,
                owner, created_date, last_updated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            asset_id, asset_name, ip_address, business_function,
            data_classification, business_impact, impact_score,
            owner, datetime.now().isoformat(), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Registered asset: {asset_id}")
        return asset_id
    
    def calculate_risk_score(self, cvss_score: float, business_impact: str,
                            threat_likelihood: str = 'medium',
                            exploitability: float = None) -> Dict:
        """Calculate comprehensive risk score"""
        
        # Get business impact score
        impact_score = BUSINESS_IMPACT.get(business_impact, BUSINESS_IMPACT['medium'])['score']
        
        # Get threat likelihood multiplier
        likelihood_mult = THREAT_LIKELIHOOD.get(threat_likelihood, THREAT_LIKELIHOOD['medium'])['score']
        
        # Composite score calculation
        # Formula: (CVSS Ãƒâ€” Business Impact Ãƒâ€” Threat Likelihood) / 10
        # This gives us a 0-100 scale
        composite_score = (cvss_score * impact_score * likelihood_mult)
        
        # Determine risk level
        if composite_score >= 70:
            risk_level = 'critical'
        elif composite_score >= 40:
            risk_level = 'high'
        elif composite_score >= 20:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Calculate SLA based on risk level
        sla_days = {
            'critical': 7,
            'high': 30,
            'medium': 90,
            'low': 180
        }
        
        return {
            'cvss_score': cvss_score,
            'business_impact_score': impact_score,
            'threat_likelihood_score': likelihood_mult,
            'composite_risk_score': round(composite_score, 2),
            'risk_level': risk_level,
            'remediation_sla_days': sla_days[risk_level]
        }
    
    def assess_vulnerability(self, asset_id: str, vulnerability_id: str,
                           finding_title: str, cvss_score: float,
                           cvss_vector: str = None, threat_likelihood: str = 'medium',
                           notes: str = None) -> str:
        """Create risk assessment for a vulnerability"""
        
        # Get asset details
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM assets WHERE asset_id = ?', (asset_id,))
        asset = cursor.fetchone()
        
        if not asset:
            logger.error(f"Asset not found: {asset_id}")
            conn.close()
            return None
        
        asset_dict = dict(asset)
        business_impact = asset_dict['business_impact']
        
        # Calculate risk score
        risk_calc = self.calculate_risk_score(
            cvss_score, business_impact, threat_likelihood
        )
        
        # Create risk assessment
        risk_id = f"RISK_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{vulnerability_id}"
        
        # Calculate remediation deadline
        from datetime import timedelta
        deadline = (datetime.now() + timedelta(days=risk_calc['remediation_sla_days'])).isoformat()
        
        cursor.execute('''
            INSERT INTO risk_assessments (
                risk_id, asset_id, vulnerability_id, finding_title,
                cvss_score, cvss_vector, business_impact_score,
                threat_likelihood_score, composite_risk_score, risk_level,
                assessment_date, assessor, remediation_deadline, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            risk_id, asset_id, vulnerability_id, finding_title,
            cvss_score, cvss_vector, risk_calc['business_impact_score'],
            risk_calc['threat_likelihood_score'], risk_calc['composite_risk_score'],
            risk_calc['risk_level'], datetime.now().isoformat(),
            'purple-team-scanner', deadline, notes
        ))
        
        # Log to history
        cursor.execute('''
            INSERT INTO risk_history (
                risk_id, event_type, event_date, new_status,
                new_score, changed_by, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            risk_id, 'created', datetime.now().isoformat(), 'open',
            risk_calc['composite_risk_score'], 'purple-team-scanner',
            f"Risk assessment created with {risk_calc['risk_level']} severity"
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created risk assessment: {risk_id} (Score: {risk_calc['composite_risk_score']}, Level: {risk_calc['risk_level']})")
        return risk_id
    
    def create_remediation_task(self, risk_id: str, title: str = None,
                               description: str = None, assigned_to: str = None,
                               verification_method: str = None) -> str:
        """Create remediation task"""
        
        # Get risk details
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM risk_assessments WHERE risk_id = ?', (risk_id,))
        risk = cursor.fetchone()
        
        if not risk:
            logger.error(f"Risk not found: {risk_id}")
            conn.close()
            return None
        
        risk_dict = dict(risk)
        
        # Default title from finding
        if not title:
            title = f"Remediate: {risk_dict['finding_title']}"
        
        task_id = f"TASK_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Priority based on risk level
        priority_map = {
            'critical': 'P1',
            'high': 'P2',
            'medium': 'P3',
            'low': 'P4'
        }
        priority = priority_map.get(risk_dict['risk_level'], 'P3')
        
        cursor.execute('''
            INSERT INTO remediation_tasks (
                task_id, risk_id, title, description, assigned_to,
                priority, status, created_date, due_date, verification_method
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task_id, risk_id, title, description, assigned_to,
            priority, 'open', datetime.now().isoformat(),
            risk_dict['remediation_deadline'], verification_method
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created remediation task: {task_id}")
        return task_id
    
    def update_task_status(self, task_id: str, status: str, notes: str = None):
        """Update remediation task status"""
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        update_fields = ['status = ?', 'notes = COALESCE(notes || char(10) || ?, ?)']
        values = [status, notes, notes]
        
        if status == 'completed':
            update_fields.append('completed_date = ?')
            values.append(datetime.now().isoformat())
        
        query = f"UPDATE remediation_tasks SET {', '.join(update_fields)} WHERE task_id = ?"
        values.append(task_id)
        
        cursor.execute(query, values)
        conn.commit()
        conn.close()
        
        logger.info(f"Updated task {task_id} status to {status}")
    
    def verify_remediation(self, task_id: str, verified_by: str, success: bool, notes: str = None):
        """Verify remediation completion"""
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE remediation_tasks
            SET verification_date = ?, verified_by = ?,
                status = ?, notes = COALESCE(notes || char(10) || ?, ?)
            WHERE task_id = ?
        ''', (
            datetime.now().isoformat(), verified_by,
            'verified' if success else 'failed_verification',
            notes, notes, task_id
        ))
        
        # If verified, close the associated risk
        if success:
            cursor.execute('''
                UPDATE risk_assessments
                SET status = 'closed'
                WHERE risk_id = (SELECT risk_id FROM remediation_tasks WHERE task_id = ?)
            ''', (task_id,))
            
            # Log to history
            cursor.execute('''
                INSERT INTO risk_history (
                    risk_id, event_type, event_date, new_status, changed_by, notes
                )
                SELECT risk_id, 'remediated', ?, 'closed', ?, ?
                FROM remediation_tasks WHERE task_id = ?
            ''', (datetime.now().isoformat(), verified_by, notes, task_id))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Verified remediation for task {task_id}: {'Success' if success else 'Failed'}")
    
    def get_risk_summary(self) -> Dict:
        """Get summary of current risks"""
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        summary = {
            'total_risks': 0,
            'by_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_status': {},
            'overdue_tasks': 0,
            'avg_remediation_time': 0
        }
        
        # Total risks
        cursor.execute('SELECT COUNT(*) FROM risk_assessments WHERE status = "open"')
        summary['total_risks'] = cursor.fetchone()[0]
        
        # By risk level
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count
            FROM risk_assessments
            WHERE status = 'open'
            GROUP BY risk_level
        ''')
        for row in cursor.fetchall():
            summary['by_level'][row[0]] = row[1]
        
        # By status
        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM risk_assessments
            GROUP BY status
        ''')
        summary['by_status'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Overdue tasks
        cursor.execute('''
            SELECT COUNT(*) FROM remediation_tasks
            WHERE status NOT IN ('completed', 'verified')
            AND due_date < ?
        ''', (datetime.now().isoformat(),))
        summary['overdue_tasks'] = cursor.fetchone()[0]
        
        conn.close()
        return summary
    
    def generate_risk_report(self, output_path: str = None) -> str:
        """Generate comprehensive risk report"""
        
        if not output_path:
            output_path = RISK_DIR / f'Risk_Report_{datetime.now().strftime("%Y%m%d")}.html'
        
        summary = self.get_risk_summary()
        
        # Get detailed risks
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, a.asset_name, a.business_function
            FROM risk_assessments r
            JOIN assets a ON r.asset_id = a.asset_id
            WHERE r.status = 'open'
            ORDER BY r.composite_risk_score DESC
        ''')
        risks = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        html = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Risk Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 3px solid #667eea; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; color: #667eea; }}
        .critical {{ color: #f44336; }}
        .high {{ color: #ff9800; }}
        .medium {{ color: #ffeb3b; }}
        .low {{ color: #4caf50; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #667eea; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Risk Assessment Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Open Risks</h3>
            <div class="value">{summary['total_risks']}</div>
        </div>
        <div class="summary-card">
            <h3>Critical Risks</h3>
            <div class="value critical">{summary['by_level']['critical']}</div>
        </div>
        <div class="summary-card">
            <h3>High Risks</h3>
            <div class="value high">{summary['by_level']['high']}</div>
        </div>
        <div class="summary-card">
            <h3>Overdue Tasks</h3>
            <div class="value">{summary['overdue_tasks']}</div>
        </div>
    </div>
    
    <h2>Top Risks</h2>
    <table>
        <tr>
            <th>Risk Score</th>
            <th>Level</th>
            <th>Asset</th>
            <th>Finding</th>
            <th>CVSS</th>
            <th>Due Date</th>
        </tr>
'''
        
        for risk in risks[:20]:  # Top 20 risks
            due_date = risk['remediation_deadline'][:10] if risk['remediation_deadline'] else 'N/A'
            
            html += f'''
        <tr>
            <td>{risk['composite_risk_score']}</td>
            <td><span class="{risk['risk_level']}">{risk['risk_level'].upper()}</span></td>
            <td>{risk['asset_name']}</td>
            <td>{risk['finding_title']}</td>
            <td>{risk['cvss_score']}</td>
            <td>{due_date}</td>
        </tr>
'''
        
        html += '''
    </table>
</body>
</html>
'''
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        logger.info(f"Generated risk report: {output_path}")
        return str(output_path)

def main():
    """Main entry point"""
    scorer = RiskScorer()
    logger.info("Risk Scorer initialized")
    
    # Generate risk report
    report = scorer.generate_risk_report()
    logger.info(f"Risk report: {report}")

if __name__ == '__main__':
    main()
