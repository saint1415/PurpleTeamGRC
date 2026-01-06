#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

AVAILABILITY_DIR = RESULTS_DIR / 'availability'
AVAILABILITY_DIR.mkdir(parents=True, exist_ok=True)
"""Service Availability Monitor - Track uptime of critical services"""
import requests, socket, json, subprocess
from pathlib import Path
from datetime import datetime

# Directory already created on line 12


class ServiceMonitor:
    def check_http(self, url, timeout=10):
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            return {'status': 'up', 'code': r.status_code, 'time': r.elapsed.total_seconds()}
        except: return {'status': 'down', 'error': 'connection_failed'}
    
    def check_port(self, host, port, timeout=5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, int(port)))
            s.close()
            return {'status': 'up'}
        except: return {'status': 'down'}
    
    def check_ping(self, host):
        result = subprocess.run(['ping', '-c', '1', '-W', '2', host], capture_output=True)
        return {'status': 'up' if result.returncode == 0 else 'down'}
    
    def monitor_services(self, services):
        results = {'time': datetime.now().isoformat(), 'services': []}
        for svc in services:
            if svc['type'] == 'http':
                status = self.check_http(svc['url'])
            elif svc['type'] == 'port':
                status = self.check_port(svc['host'], svc['port'])
            elif svc['type'] == 'ping':
                status = self.check_ping(svc['host'])
            results['services'].append({**svc, **status})
        return results
    
    def print_status(self, results):
        print("\n" + "="*70)
        print("SERVICE AVAILABILITY REPORT")
        print("="*70)
        for svc in results['services']:
            status = "Ã¢Å“â€œ UP" if svc['status'] == 'up' else "Ã¢Å“â€” DOWN"
            print(f"{status:8s} {svc['name']}")
        print("="*70 + "\n")

if __name__ == '__main__':
    services = [
        {'name': 'Dashboard', 'type': 'http', 'url': 'http://localhost:5000'},
        {'name': 'SSH', 'type': 'port', 'host': 'localhost', 'port': 22},
    ]
    monitor = ServiceMonitor()
    results = monitor.monitor_services(services)
    monitor.print_status(results)
