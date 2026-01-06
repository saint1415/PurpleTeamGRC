#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

BASELINE_FILE = RESULTS_DIR / 'baselines' / 'port_baseline.json'
"""
Port Change Detector
Monitors for unexpected port changes across the network

Alerts when:
- New ports open
- Services stop listening
- Port changes on critical systems
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Baseline file path defined at top of file (line 11)

class PortChangeDetector:
    """Detect changes in open ports"""
    
    def __init__(self):
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    def scan_ports(self, target):
        """Quick port scan of target"""
        try:
            result = subprocess.run(
                ['nmap', '-Pn', '-T4', '--top-ports', '1000', target],
                capture_output=True, text=True, timeout=300
            )
            
            ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        ports.append({
                            'port': parts[0].split('/')[0],
                            'service': parts[2]
                        })
            return ports
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return []
    
    def create_baseline(self, hosts):
        """Create baseline of current port states"""
        baseline = {
            'created': datetime.now().isoformat(),
            'hosts': {}
        }
        
        for host in hosts:
            logger.info(f"Scanning {host}...")
            ports = self.scan_ports(host)
            baseline['hosts'][host] = ports
        
        with open(BASELINE_FILE, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        logger.info(f"Baseline created: {BASELINE_FILE}")
        return baseline
    
    def load_baseline(self):
        """Load existing baseline"""
        if BASELINE_FILE.exists():
            with open(BASELINE_FILE, 'r') as f:
                return json.load(f)
        return None
    
    def detect_changes(self, hosts):
        """Detect port changes from baseline"""
        baseline = self.load_baseline()
        
        if not baseline:
            logger.warning("No baseline found - creating one")
            return self.create_baseline(hosts)
        
        changes = {
            'scan_time': datetime.now().isoformat(),
            'baseline_time': baseline['created'],
            'hosts': {}
        }
        
        for host in hosts:
            logger.info(f"Checking {host}...")
            current_ports = self.scan_ports(host)
            baseline_ports = baseline['hosts'].get(host, [])
            
            # Convert to sets for comparison
            current_set = {p['port'] for p in current_ports}
            baseline_set = {p['port'] for p in baseline_ports}
            
            new_ports = current_set - baseline_set
            closed_ports = baseline_set - current_set
            
            if new_ports or closed_ports:
                changes['hosts'][host] = {
                    'new_ports': [p for p in current_ports if p['port'] in new_ports],
                    'closed_ports': list(closed_ports),
                    'status': 'CHANGED'
                }
            else:
                changes['hosts'][host] = {
                    'new_ports': [],
                    'closed_ports': [],
                    'status': 'UNCHANGED'
                }
        
        return changes
    
    def print_changes(self, changes):
        """Print change report"""
        print("\n" + "="*70)
        print("PORT CHANGE DETECTION REPORT")
        print("="*70)
        print(f"Scan Time: {changes['scan_time']}")
        print(f"Baseline: {changes['baseline_time']}")
        print()
        
        has_changes = False
        for host, data in changes['hosts'].items():
            if data['status'] == 'CHANGED':
                has_changes = True
                print(f"Ã°Å¸Å¡Â¨ CHANGES DETECTED: {host}")
                
                if data['new_ports']:
                    print("  New Ports:")
                    for port in data['new_ports']:
                        print(f"    + {port['port']}/{port['service']}")
                
                if data['closed_ports']:
                    print("  Closed Ports:")
                    for port in data['closed_ports']:
                        print(f"    - {port}")
                print()
        
        if not has_changes:
            print("Ã¢Å“â€œ No port changes detected\n")
        
        print("="*70 + "\n")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Port Change Detector')
    parser.add_argument('--baseline', action='store_true', help='Create new baseline')
    parser.add_argument('--hosts', nargs='+', help='Hosts to monitor')
    parser.add_argument('--check', action='store_true', help='Check for changes')
    
    args = parser.parse_args()
    
    detector = PortChangeDetector()
    
    if args.baseline and args.hosts:
        detector.create_baseline(args.hosts)
    elif args.check and args.hosts:
        changes = detector.detect_changes(args.hosts)
        detector.print_changes(changes)
        
        # Exit code if changes
        has_changes = any(h['status'] == 'CHANGED' for h in changes['hosts'].values())
        exit(1 if has_changes else 0)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
