#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

# Flask app paths
TEMPLATE_DIR = BASE_DIR / 'dashboard' / 'templates'
STATIC_DIR = BASE_DIR / 'dashboard' / 'static'
"""
Purple Team Dashboard
Web interface for viewing scan results and managing scans
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import yaml
from pathlib import Path
from datetime import datetime
import subprocess
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Paths

# Flask app
app = Flask(__name__, 
            template_folder=str(TEMPLATE_DIR),
            static_folder=str(STATIC_DIR))
CORS(app)

# Load configuration
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

config = load_config()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/scans/latest')
def get_latest_scans():
    """Get latest scan results for each type"""
    results = {}
    
    scan_types = ['vulnerability-scans', 'network-scans', 'compliance-checks']
    
    for scan_type in scan_types:
        scan_dir = RESULTS_DIR / scan_type
        if scan_dir.exists():
            json_files = sorted(scan_dir.glob('*.json'), reverse=True)
            if json_files:
                with open(json_files[0], 'r') as f:
                    results[scan_type] = json.load(f)
    
    return jsonify(results)

@app.route('/api/scans/<scan_type>')
def get_scans(scan_type):
    """Get all scans of a specific type"""
    scan_dir = RESULTS_DIR / scan_type
    scans = []
    
    if scan_dir.exists():
        for json_file in sorted(scan_dir.glob('*.json'), reverse=True):
            with open(json_file, 'r') as f:
                data = json.load(f)
                scans.append({
                    'id': data.get('scan_id'),
                    'type': scan_type,
                    'start_time': data.get('start_time'),
                    'file': json_file.name
                })
    
    return jsonify(scans)

@app.route('/api/scans/<scan_type>/<scan_id>')
def get_scan_details(scan_type, scan_id):
    """Get details of a specific scan"""
    scan_dir = RESULTS_DIR / scan_type
    
    for json_file in scan_dir.glob(f'*{scan_id}*.json'):
        with open(json_file, 'r') as f:
            return jsonify(json.load(f))
    
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get summary statistics for dashboard"""
    stats = {
        'total_scans': 0,
        'last_scan': None,
        'vulnerabilities': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'live_hosts': 0,
        'compliance_rate': 0
    }
    
    # Get latest vulnerability scan
    vuln_dir = RESULTS_DIR / 'vulnerability-scans'
    if vuln_dir.exists():
        vuln_files = sorted(vuln_dir.glob('*.json'), reverse=True)
        if vuln_files:
            with open(vuln_files[0], 'r') as f:
                vuln_data = json.load(f)
                stats['vulnerabilities'] = vuln_data.get('summary', {})
                stats['last_scan'] = vuln_data.get('start_time')
    
    # Get latest network scan
    net_dir = RESULTS_DIR / 'network-scans'
    if net_dir.exists():
        net_files = sorted(net_dir.glob('*.json'), reverse=True)
        if net_files:
            with open(net_files[0], 'r') as f:
                net_data = json.load(f)
                stats['live_hosts'] = len(net_data.get('hosts', []))
    
    # Get latest compliance check
    comp_dir = RESULTS_DIR / 'compliance-checks'
    if comp_dir.exists():
        comp_files = sorted(comp_dir.glob('*.json'), reverse=True)
        if comp_files:
            with open(comp_files[0], 'r') as f:
                comp_data = json.load(f)
                # Calculate average compliance rate
                frameworks = comp_data.get('frameworks', {})
                if frameworks:
                    total_rate = 0
                    for fw_data in frameworks.values():
                        if fw_data['total'] > 0:
                            total_rate += (fw_data['compliant'] / fw_data['total'] * 100)
                    stats['compliance_rate'] = total_rate / len(frameworks)
    
    # Count total scans
    for scan_type in ['vulnerability-scans', 'network-scans', 'compliance-checks']:
        scan_dir = RESULTS_DIR / scan_type
        if scan_dir.exists():
            stats['total_scans'] += len(list(scan_dir.glob('*.json')))
    
    return jsonify(stats)

@app.route('/api/scans/run/<scan_type>', methods=['POST'])
def run_scan(scan_type):
    """Trigger a scan manually"""
    scanner_map = {
        'vulnerability': 'vulnerability_scanner.py',
        'network': 'network_scanner.py',
        'compliance': 'compliance_checker.py'
    }
    
    if scan_type not in scanner_map:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    scanner_path = BASE_DIR / 'scanners' / scanner_map[scan_type]
    
    try:
        # Run scanner in background
        subprocess.Popen(['/opt/purple-team/venv/bin/python3', str(scanner_path)])
        return jsonify({'status': 'started', 'message': f'{scan_type} scan started'})
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config')
def get_config():
    """Get current configuration"""
    return jsonify(config)

@app.route('/api/config', methods=['PUT'])
def update_config():
    """Update configuration"""
    try:
        new_config = request.json
        
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(new_config, f)
        
        global config
        config = new_config
        
        return jsonify({'status': 'success', 'message': 'Configuration updated'})
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<scan_type>/<filename>')
def download_report(scan_type, filename):
    """Download report file"""
    scan_dir = RESULTS_DIR / scan_type
    return send_from_directory(scan_dir, filename)

@app.route('/api/schedule')
def get_schedule():
    """Get current scan schedule"""
    return jsonify(config.get('schedule', {}))

@app.route('/api/schedule', methods=['PUT'])
def update_schedule():
    """Update scan schedule"""
    try:
        new_schedule = request.json
        config['schedule'] = new_schedule
        
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(config, f)
        
        # Restart scheduler service
        subprocess.run(['systemctl', 'restart', 'purple-team-scheduler'])
        
        return jsonify({'status': 'success', 'message': 'Schedule updated'})
    except Exception as e:
        logger.error(f"Error updating schedule: {e}")
        return jsonify({'error': str(e)}), 500

def main():
    """Run the dashboard"""
    dashboard_config = config.get('dashboard', {})
    host = dashboard_config.get('host', '127.0.0.1')
    port = dashboard_config.get('port', 5000)
    debug = dashboard_config.get('debug', False)
    
    logger.info(f"Starting dashboard on {host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()
