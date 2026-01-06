#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detection
Network Scanner Module
Performs stealthy network reconnaissance and mapping
"""

import sys
import nmap
import json
import yaml
import logging
import random
import time
from datetime import datetime
from pathlib import Path
import ipaddress
import subprocess

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
NETWORK_SCANS_DIR = RESULTS_DIR / 'network-scans'

# Paths

class NetworkScanner:
    """Stealthy network scanner"""
    
    def __init__(self):
        self.config = self.load_config()
        self.nm = nmap.PortScanner()
        self.results = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'scan_type': 'network_discovery',
            'start_time': datetime.now().isoformat(),
            'targets': [],
            'hosts': [],
            'summary': {}
        }
    
    def load_config(self):
        """Load configuration"""
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    
    def get_target_ranges(self):
        """Get target IP ranges excluding blacklisted IPs"""
        # Support both 'ranges' and 'target_ranges' for compatibility
        network_config = self.config.get('network', {})
        targets = network_config.get('ranges') or network_config.get('target_ranges', [])
        
        if not targets:
            logging.error("No network ranges configured. Run network discovery first (option 1).")
            print("\n⚠️  No network ranges configured!")
            print("Please run 'Network Discovery & Auto-Detection' (option 1) first.")
            sys.exit(1)
        
        exclusions = set(network_config.get('exclusions', []))
        
        all_ips = []
        for target_range in targets:
            network = ipaddress.ip_network(target_range, strict=False)
            for ip in network.hosts():
                if str(ip) not in exclusions:
                    all_ips.append(str(ip))
        
        return all_ips
    
    def calculate_delay(self):
        """Calculate random delay for stealth"""
        scanning_config = self.config.get('scanning', {})
        min_delay = scanning_config.get('random_delay_min', 0.5)
        max_delay = scanning_config.get('random_delay_max', 2.0)
        return random.uniform(min_delay, max_delay)
    
    def perform_host_discovery(self, targets):
        """Discover live hosts on network"""
        logger.info(f"Starting host discovery for {len(targets)} targets")
        
        # Get scanning config with defaults
        scanning_config = self.config.get('scanning', {})
        timing = scanning_config.get('timing_template', 'T3')
        stealth_level = scanning_config.get('stealth_level', 3)
        max_rate = scanning_config.get('max_rate', 100)
        
        # Adjust scan based on stealth level
        if stealth_level >= 4:
            # Extract timing value (T3 -> 3)
            timing_val = timing[1] if len(timing) > 1 else '3'
            scan_args = f'-sn -T{timing_val} --max-rate {max_rate}'
        elif stealth_level >= 3:
            timing_val = timing[1] if len(timing) > 1 else '3'
            scan_args = f'-sn -T{timing_val}'
        else:
            scan_args = '-sn -T3'
        
        live_hosts = []
        
        # Scan in chunks to avoid overwhelming the network
        chunk_size = 256
        for i in range(0, len(targets), chunk_size):
            chunk = targets[i:i+chunk_size]
            target_spec = ' '.join(chunk)
            
            try:
                logger.info(f"Scanning chunk {i//chunk_size + 1}/{(len(targets)//chunk_size) + 1}")
                self.nm.scan(hosts=target_spec, arguments=scan_args)
                
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        live_hosts.append(host)
                        logger.info(f"Found live host: {host}")
                
                # Random delay between chunks
                if i + chunk_size < len(targets):
                    delay = self.calculate_delay()
                    logger.info(f"Sleeping for {delay:.2f} seconds (stealth)")
                    time.sleep(delay)
                    
            except Exception as e:
                logger.error(f"Error scanning chunk: {e}")
                continue
        
        return live_hosts
    
    def port_scan_host(self, host):
        """Perform port scan on a single host"""
        logger.info(f"Port scanning {host}")
        
        # Get scanning config with defaults
        scanning_config = self.config.get('scanning', {})
        timing = scanning_config.get('timing_template', 'T3')
        max_rate = scanning_config.get('max_rate', 100)
        
        # Common ports for initial scan
        ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443'
        
        try:
            # Extract timing value (T3 -> 3)
            timing_val = timing[1] if len(timing) > 1 else '3'
            
            self.nm.scan(
                hosts=host,
                ports=ports,
                arguments=f'-sV -T{timing_val} --max-rate {max_rate}'
            )
            
            host_info = {
                'ip': host,
                'hostname': '',
                'state': self.nm[host].state(),
                'ports': []
            }
            
            # Get hostname if available
            if 'hostnames' in self.nm[host]:
                hostnames = self.nm[host]['hostnames']
                if hostnames:
                    host_info['hostname'] = hostnames[0].get('name', '')
            
            # Get open ports
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    port_info = self.nm[host][proto][port]
                    if port_info['state'] == 'open':
                        host_info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
            
            return host_info
            
        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")
            return None
    
    def scan_network(self):
        """Main network scanning function"""
        logger.info("Starting network scan")
        
        # Get targets
        targets = self.get_target_ranges()
        self.results['targets'] = targets
        logger.info(f"Total targets: {len(targets)}")
        
        # Discover live hosts
        live_hosts = self.perform_host_discovery(targets)
        logger.info(f"Found {len(live_hosts)} live hosts")
        
        # Port scan each live host
        for idx, host in enumerate(live_hosts, 1):
            logger.info(f"Scanning host {idx}/{len(live_hosts)}: {host}")
            
            host_info = self.port_scan_host(host)
            if host_info:
                self.results['hosts'].append(host_info)
            
            # Random delay between host scans
            if idx < len(live_hosts):
                delay = self.calculate_delay()
                logger.info(f"Sleeping for {delay:.2f} seconds (stealth)")
                time.sleep(delay)
        
        # Generate summary
        self.results['end_time'] = datetime.now().isoformat()
        self.results['summary'] = {
            'total_targets': len(targets),
            'live_hosts': len(live_hosts),
            'hosts_scanned': len(self.results['hosts']),
            'total_open_ports': sum(len(h['ports']) for h in self.results['hosts'])
        }
        
        logger.info("Network scan completed")
        return self.results
    
    def save_results(self):
        """Save scan results to file"""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_NetworkScan_Results.json"
        filepath = RESULTS_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Results saved to {filepath}")
        
        # Also create HTML report
        self.create_html_report(filepath.with_suffix('.html'))
    
    def create_html_report(self, filepath):
        """Create HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report - {self.results['scan_id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .summary {{ background-color: #e7f3fe; padding: 15px; border-left: 6px solid #2196F3; }}
    </style>
</head>
<body>
    <h1>Network Scan Report</h1>
    <p><strong>Scan ID:</strong> {self.results['scan_id']}</p>
    <p><strong>Start Time:</strong> {self.results['start_time']}</p>
    <p><strong>End Time:</strong> {self.results['end_time']}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Targets:</strong> {self.results['summary']['total_targets']}</p>
        <p><strong>Live Hosts:</strong> {self.results['summary']['live_hosts']}</p>
        <p><strong>Total Open Ports:</strong> {self.results['summary']['total_open_ports']}</p>
    </div>
    
    <h2>Discovered Hosts</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>Open Ports</th>
            <th>Services</th>
        </tr>
"""
        
        for host in self.results['hosts']:
            ports_str = ', '.join([f"{p['port']}/{p['protocol']}" for p in host['ports']])
            services_str = ', '.join([f"{p['service']}" for p in host['ports']])
            
            html += f"""
        <tr>
            <td>{host['ip']}</td>
            <td>{host['hostname']}</td>
            <td>{ports_str}</td>
            <td>{services_str}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        logger.info(f"HTML report saved to {filepath}")

def main():
    """Main entry point"""
    try:
        scanner = NetworkScanner()
        results = scanner.scan_network()
        scanner.save_results()
        logger.info("Network scanning completed successfully")
    except Exception as e:
        logger.error(f"Network scanning failed: {e}")
        raise

if __name__ == '__main__':
    main()
