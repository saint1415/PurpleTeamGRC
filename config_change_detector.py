#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

CONFIG_TRACKING_DIR = RESULTS_DIR / 'config-tracking'
CONFIG_TRACKING_DIR.mkdir(parents=True, exist_ok=True)
"""Config Change Detector - Detect drift from baseline configuration"""
import hashlib, json, subprocess
from pathlib import Path
from datetime import datetime

# Directory already created on line 12


class ConfigChangeDetector:
    def hash_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except: return None
    
    def hash_command_output(self, command):
        try:
            result = subprocess.run(command.split(), capture_output=True, timeout=30)
            return hashlib.sha256(result.stdout).hexdigest()
        except: return None
    
    def create_baseline(self, config_items):
        baseline = {'created': datetime.now().isoformat(), 'items': []}
        for item in config_items:
            if item['type'] == 'file':
                hash_val = self.hash_file(item['path'])
            elif item['type'] == 'command':
                hash_val = self.hash_command_output(item['command'])
            baseline['items'].append({**item, 'hash': hash_val})
        
        with open(BASE_DIR / 'baseline.json', 'w') as f:
            json.dump(baseline, f, indent=2)
        return baseline
    
    def check_drift(self, config_items):
        baseline_file = BASE_DIR / 'baseline.json'
        if not baseline_file.exists():
            return self.create_baseline(config_items)
        
        with open(baseline_file) as f:
            baseline = json.load(f)
        
        changes = []
        for item in config_items:
            baseline_item = next((b for b in baseline['items'] if b.get('name') == item.get('name')), None)
            if not baseline_item: continue
            
            if item['type'] == 'file':
                current_hash = self.hash_file(item['path'])
            elif item['type'] == 'command':
                current_hash = self.hash_command_output(item['command'])
            
            if current_hash != baseline_item['hash']:
                changes.append({'name': item['name'], 'status': 'CHANGED'})
        
        return changes
    
    def print_report(self, changes):
        print("\n" + "="*70)
        print("CONFIGURATION DRIFT REPORT")
        print("="*70)
        if changes:
            for change in changes:
                print(f"Ã°Å¸Å¡Â¨ CHANGED: {change['name']}")
        else:
            print("Ã¢Å“â€œ No configuration drift detected")
        print("="*70 + "\n")

if __name__ == '__main__':
    configs = [
        {'name': 'Purple Team Config', 'type': 'file', 'path': '/opt/purple-team/config/config.yaml'},
        {'name': 'SSH Config', 'type': 'file', 'path': '/etc/ssh/sshd_config'},
        {'name': 'Firewall Rules', 'type': 'command', 'command': 'ufw status numbered'},
    ]
    detector = ConfigChangeDetector()
    changes = detector.check_drift(configs)
    detector.print_report(changes)
