#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

DB_FILE = RESULTS_DIR / 'assets' / 'inventory.db'
DB_FILE.parent.mkdir(parents=True, exist_ok=True)
"""Asset Inventory Tracker - Maintain asset database with auto-discovery"""
import sqlite3, subprocess, json
from pathlib import Path
from datetime import datetime

# Directory already created on line 12


class AssetInventory:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        self.init_db()
    
    def init_db(self):
        self.conn.execute('''CREATE TABLE IF NOT EXISTS assets (
            ip TEXT PRIMARY KEY, hostname TEXT, mac TEXT, os TEXT,
            device_type TEXT, criticality TEXT, last_seen TEXT, ports TEXT
        )''')
        self.conn.commit()
    
    def add_asset(self, ip, **kwargs):
        self.conn.execute('''INSERT OR REPLACE INTO assets 
            (ip, hostname, mac, os, device_type, criticality, last_seen, ports)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (ip, kwargs.get('hostname'), kwargs.get('mac'), kwargs.get('os'),
             kwargs.get('device_type'), kwargs.get('criticality'),
             datetime.now().isoformat(), json.dumps(kwargs.get('ports', []))))
        self.conn.commit()
    
    def discover_assets(self, network):
        """Auto-discover assets on network"""
        print(f"Discovering assets on {network}...")
        result = subprocess.run(['nmap', '-sn', '-T4', network], 
                              capture_output=True, text=True, timeout=300)
        
        for line in result.stdout.split('\n'):
            if 'Nmap scan report for' in line:
                ip = line.split()[-1].strip('()')
                hostname = line.split('for')[1].split('(')[0].strip() if '(' in line else ip
                self.add_asset(ip, hostname=hostname, device_type='discovered')
        print(f"Ã¢Å“â€œ Discovery complete")
    
    def list_assets(self):
        cursor = self.conn.execute('SELECT * FROM assets ORDER BY last_seen DESC')
        assets = cursor.fetchall()
        
        print("\n" + "="*70)
        print("ASSET INVENTORY")
        print("="*70)
        for asset in assets:
            ip, hostname, mac, os, dtype, crit, seen, ports = asset
            print(f"{ip:15s} {hostname or 'Unknown':20s} {dtype or 'Unknown':15s}")
        print(f"\nTotal Assets: {len(assets)}")
        print("="*70 + "\n")
        return assets
    
    def export_csv(self, filename='assets.csv'):
        cursor = self.conn.execute('SELECT * FROM assets')
        with open(filename, 'w') as f:
            f.write("IP,Hostname,MAC,OS,Type,Criticality,LastSeen,Ports\n")
            for row in cursor.fetchall():
                f.write(','.join(str(x or '') for x in row) + '\n')
        print(f"Ã¢Å“â€œ Exported to {filename}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Asset Inventory Tracker')
    parser.add_argument('--discover', help='Network to discover (e.g., 10.0.1.0/24)')
    parser.add_argument('--list', action='store_true', help='List all assets')
    parser.add_argument('--export', help='Export to CSV file')
    
    args = parser.parse_args()
    inventory = AssetInventory()
    
    if args.discover:
        inventory.discover_assets(args.discover)
    if args.list or not any([args.discover, args.export]):
        inventory.list_assets()
    if args.export:
        inventory.export_csv(args.export)
