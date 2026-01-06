#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

CONFIG_DIR = RESULTS_DIR / 'discovered_configs'
"""
Zero-Configuration Network Discovery
Automatically discovers and maps networks without prior configuration
Makes the platform truly industry-agnostic
"""

import socket
import netifaces
import ipaddress
import nmap
import logging
import yaml
import json
from datetime import datetime
from pathlib import Path
import subprocess
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths already defined at top of file (line 11)


class ZeroConfigDiscovery:
    """Intelligent zero-configuration network discovery"""
    
    def __init__(self):
        self.discovered_networks = []
        self.discovered_hosts = []
        self.network_topology = {}
        self.nm = nmap.PortScanner()
    
    def discover_local_interfaces(self):
        """Discover all local network interfaces and their networks"""
        logger.info("Discovering local network interfaces...")
        interfaces = []
        
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        
                        # Skip loopback
                        if ip and netmask and not ip.startswith('127.'):
                            network = ipaddress.ip_network(
                                f"{ip}/{netmask}", 
                                strict=False
                            )
                            
                            interfaces.append({
                                'interface': iface,
                                'ip': ip,
                                'netmask': netmask,
                                'network': str(network),
                                'network_obj': network
                            })
                            logger.info(f"  Found: {iface} - {ip}/{netmask} ({network})")
            except Exception as e:
                logger.debug(f"Error processing interface {iface}: {e}")
        
        return interfaces
    
    def discover_gateway(self):
        """Discover default gateway"""
        try:
            gws = netifaces.gateways()
            default_gw = gws.get('default', {}).get(netifaces.AF_INET)
            if default_gw:
                gateway_ip = default_gw[0]
                logger.info(f"Discovered gateway: {gateway_ip}")
                return gateway_ip
        except Exception as e:
            logger.error(f"Error discovering gateway: {e}")
        return None
    
    def discover_dns_servers(self):
        """Discover DNS servers from system configuration"""
        dns_servers = []
        
        # Try multiple methods
        try:
            # Method 1: Read /etc/resolv.conf
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_ip = line.split()[1]
                        dns_servers.append(dns_ip)
        except:
            pass
        
        # Method 2: Use nmcli if available
        try:
            result = subprocess.run(['nmcli', 'dev', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'DNS' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        dns_ip = parts[1].strip()
                        if dns_ip and dns_ip not in dns_servers:
                            dns_servers.append(dns_ip)
        except:
            pass
        
        if dns_servers:
            logger.info(f"Discovered DNS servers: {', '.join(dns_servers)}")
        else:
            logger.warning("No DNS servers discovered")
        
        return dns_servers
    
    def ping_sweep(self, network):
        """Fast ping sweep to find live hosts"""
        logger.info(f"Performing ping sweep on {network}...")
        
        live_hosts = []
        
        try:
            # Use nmap for fast ping sweep
            self.nm.scan(hosts=str(network), arguments='-sn -T4 --min-rate 1000')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hostname = self.nm[host].hostname() or ''
                    mac = ''
                    
                    # Try to get MAC address
                    if 'mac' in self.nm[host].get('addresses', {}):
                        mac = self.nm[host]['addresses']['mac']
                    
                    live_hosts.append({
                        'ip': host,
                        'hostname': hostname,
                        'mac': mac,
                        'state': 'up'
                    })
                    logger.debug(f"  Live host: {host} ({hostname})")
            
            logger.info(f"  Found {len(live_hosts)} live hosts")
        except Exception as e:
            logger.error(f"Error during ping sweep: {e}")
        
        return live_hosts
    
    def fingerprint_device(self, host_ip):
        """Identify device type and criticality"""
        logger.debug(f"Fingerprinting {host_ip}...")
        
        device_info = {
            'ip': host_ip,
            'device_type': 'unknown',
            'os': 'unknown',
            'open_ports': [],
            'services': [],
            'criticality': 'low'
        }
        
        try:
            # Quick port scan on common ports
            common_ports = '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5900,8080,8443'
            self.nm.scan(host_ip, common_ports, arguments='-sV --version-intensity 2 -T3')
            
            if host_ip in self.nm.all_hosts():
                host_data = self.nm[host_ip]
                
                # Get open ports and services
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            device_info['open_ports'].append(port)
                            service = port_data.get('name', 'unknown')
                            device_info['services'].append({
                                'port': port,
                                'service': service,
                                'version': port_data.get('version', '')
                            })
                
                # OS detection
                if 'osmatch' in host_data and host_data['osmatch']:
                    os_match = host_data['osmatch'][0]
                    device_info['os'] = os_match.get('name', 'unknown')
                
                # Determine device type based on open ports and OS
                device_info['device_type'] = self._classify_device_type(
                    device_info['open_ports'], 
                    device_info['os'],
                    device_info['services']
                )
                
                # Determine criticality
                device_info['criticality'] = self._assess_criticality(device_info)
        
        except Exception as e:
            logger.error(f"Error fingerprinting {host_ip}: {e}")
        
        return device_info
    
    def _classify_device_type(self, open_ports, os_info, services):
        """Classify device based on fingerprinting data"""
        
        os_lower = os_info.lower()
        
        # Network infrastructure
        if any(keyword in os_lower for keyword in ['cisco', 'juniper', 'router', 'switch', 'fortinet', 'palo alto']):
            if 'firewall' in os_lower or 'fortinet' in os_lower or 'palo alto' in os_lower:
                return 'firewall'
            elif 'switch' in os_lower:
                return 'switch'
            else:
                return 'router'
        
        # Domain Controller (ports 88, 389, 636)
        if any(port in open_ports for port in [88, 389, 636]):
            return 'domain_controller'
        
        # Database servers
        if any(port in open_ports for port in [1433, 3306, 5432, 27017, 1521]):
            return 'database_server'
        
        # Web servers
        if any(port in open_ports for port in [80, 443, 8080, 8443]):
            # Check if it's JUST a web server or more
            if 1433 in open_ports or 3306 in open_ports:
                return 'application_server'  # Web + DB = app server
            return 'web_server'
        
        # Mail servers
        if any(port in open_ports for port in [25, 110, 143, 993, 995]):
            return 'mail_server'
        
        # Windows workstation/server
        if 'windows' in os_lower:
            if 3389 in open_ports:  # RDP
                if 445 in open_ports and 135 in open_ports:
                    return 'windows_server'
                return 'windows_workstation'
        
        # Linux server
        if 'linux' in os_lower:
            if 22 in open_ports:  # SSH
                return 'linux_server'
        
        # Virtualization
        if any(keyword in os_lower for keyword in ['vmware', 'esx', 'hypervisor']):
            return 'hypervisor'
        
        # Default
        if open_ports:
            return 'server'
        else:
            return 'workstation'
    
    def _assess_criticality(self, device_info):
        """Automatically assess device criticality"""
        
        criticality_score = 0
        
        # Device type scoring
        critical_types = {
            'domain_controller': 10,
            'firewall': 10,
            'router': 9,
            'database_server': 9,
            'mail_server': 7,
            'application_server': 7,
            'hypervisor': 8,
            'switch': 8,
            'web_server': 6,
            'windows_server': 5,
            'linux_server': 5,
            'server': 4,
            'workstation': 2
        }
        
        criticality_score += critical_types.get(device_info['device_type'], 0)
        
        # Port-based scoring
        critical_ports = {
            88: 5,   # Kerberos - indicates DC
            389: 5,  # LDAP - indicates DC
            636: 5,  # LDAPS - indicates DC
            1433: 4, # SQL Server
            3306: 4, # MySQL
            5432: 4, # PostgreSQL
            25: 3,   # SMTP
            443: 2,  # HTTPS
        }
        
        for port in device_info['open_ports']:
            criticality_score += critical_ports.get(port, 0)
        
        # Hostname analysis
        hostname = device_info.get('hostname', '').lower()
        critical_keywords = ['prod', 'production', 'dc', 'domain', 'sql', 'db', 'mail', 'exchange']
        if any(keyword in hostname for keyword in critical_keywords):
            criticality_score += 5
        
        # Map score to criticality level
        if criticality_score >= 15:
            return 'critical'
        elif criticality_score >= 10:
            return 'high'
        elif criticality_score >= 5:
            return 'medium'
        else:
            return 'low'
    
    def generate_exclusions(self):
        """Auto-generate list of systems that should be excluded from aggressive scanning"""
        
        logger.info("Generating automatic exclusion list...")
        exclusions = []
        reasons = {}
        
        # Always exclude gateway
        gateway = self.discover_gateway()
        if gateway:
            exclusions.append(gateway)
            reasons[gateway] = "Default gateway"
        
        # Exclude DNS servers
        dns_servers = self.discover_dns_servers()
        for dns in dns_servers:
            if dns not in exclusions:
                exclusions.append(dns)
                reasons[dns] = "DNS server"
        
        # Exclude critical infrastructure based on fingerprinting
        for host in self.discovered_hosts:
            if host.get('device_type') in ['router', 'switch', 'firewall', 'domain_controller']:
                if host['ip'] not in exclusions:
                    exclusions.append(host['ip'])
                    reasons[host['ip']] = f"Critical infrastructure ({host['device_type']})"
        
        logger.info(f"Generated {len(exclusions)} automatic exclusions:")
        for ip in exclusions:
            logger.info(f"  {ip}: {reasons.get(ip, 'Unknown reason')}")
        
        return exclusions, reasons
    
    def classify_network_purpose(self, network, hosts):
        """Determine what a network segment is used for"""
        
        if not hosts:
            return 'empty'
        
        device_types = {}
        for host in hosts:
            dtype = host.get('device_type', 'unknown')
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        total_hosts = len(hosts)
        
        # Database network
        if device_types.get('database_server', 0) / total_hosts > 0.5:
            return 'database_tier'
        
        # Web tier
        if device_types.get('web_server', 0) / total_hosts > 0.5:
            return 'web_tier'
        
        # Application tier
        if device_types.get('application_server', 0) / total_hosts > 0.5:
            return 'application_tier'
        
        # Workstation network
        if device_types.get('workstation', 0) / total_hosts > 0.6:
            return 'workstation_network'
        
        # Infrastructure
        if sum(device_types.get(t, 0) for t in ['router', 'switch', 'firewall']) / total_hosts > 0.5:
            return 'infrastructure'
        
        # Mixed/General
        return 'general_purpose'
    
    def full_discovery(self, quick_mode=False):
        """
        Complete network discovery workflow
        
        Args:
            quick_mode: If True, only ping sweep (no fingerprinting)
        """
        
        logger.info("=" * 60)
        logger.info("Starting Zero-Configuration Network Discovery")
        logger.info("=" * 60)
        
        # Step 1: Discover local interfaces
        logger.info("\n[1/6] Discovering local network interfaces...")
        interfaces = self.discover_local_interfaces()
        
        if not interfaces:
            logger.error("No network interfaces found!")
            return None
        
        # Step 2: Discover gateway and DNS
        logger.info("\n[2/6] Discovering network infrastructure...")
        gateway = self.discover_gateway()
        dns_servers = self.discover_dns_servers()
        
        # Step 3: Discover hosts on each network
        logger.info("\n[3/6] Discovering live hosts...")
        for iface in interfaces:
            network = iface['network_obj']
            logger.info(f"  Scanning network: {network}")
            
            hosts = self.ping_sweep(network)
            
            if not quick_mode and hosts:
                # Step 4: Fingerprint devices
                logger.info(f"\n[4/6] Fingerprinting {len(hosts)} hosts on {network}...")
                fingerprinted_hosts = []
                
                for idx, host in enumerate(hosts, 1):
                    logger.info(f"  [{idx}/{len(hosts)}] Fingerprinting {host['ip']}...")
                    device_info = self.fingerprint_device(host['ip'])
                    
                    # Merge discovered info
                    host.update(device_info)
                    fingerprinted_hosts.append(host)
                    
                    # Small delay to be polite
                    time.sleep(0.5)
                
                hosts = fingerprinted_hosts
            
            self.discovered_hosts.extend(hosts)
            self.discovered_networks.append({
                'network': str(network),
                'interface': iface['interface'],
                'hosts': hosts,
                'total_hosts': len(hosts),
                'purpose': self.classify_network_purpose(network, hosts) if not quick_mode else 'unknown'
            })
        
        # Step 5: Generate exclusions
        logger.info("\n[5/6] Generating exclusion list...")
        exclusions, exclusion_reasons = self.generate_exclusions()
        
        # Step 6: Generate configuration
        logger.info("\n[6/6] Generating configuration...")
        config = self._generate_config(interfaces, gateway, dns_servers, exclusions, exclusion_reasons)
        
        # Save configuration
        self._save_config(config)
        
        # Generate summary report
        self._generate_summary_report(config)
        
        logger.info("\n" + "=" * 60)
        logger.info("Network Discovery Complete!")
        logger.info("=" * 60)
        
        return config
    
    def _generate_config(self, interfaces, gateway, dns_servers, exclusions, exclusion_reasons):
        """Generate complete configuration"""
        
        return {
            'discovery': {
                'timestamp': datetime.now().isoformat(),
                'discovery_mode': 'automatic',
                'version': '2.0'
            },
            'network': {
                'target_ranges': [net['network'] for net in self.discovered_networks],
                'exclusions': exclusions,
                'exclusion_reasons': exclusion_reasons,
                'dns_servers': dns_servers,
                'gateway': gateway
            },
            'discovered_assets': self.discovered_hosts,
            'network_topology': self.discovered_networks,
            'statistics': {
                'total_networks': len(self.discovered_networks),
                'total_hosts': len(self.discovered_hosts),
                'total_exclusions': len(exclusions),
                'criticality_breakdown': self._calculate_criticality_breakdown()
            }
        }
    
    def _calculate_criticality_breakdown(self):
        """Calculate breakdown of assets by criticality"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for host in self.discovered_hosts:
            crit = host.get('criticality', 'low')
            breakdown[crit] = breakdown.get(crit, 0) + 1
        
        return breakdown
    
    def _save_config(self, config):
        """Save configuration to file"""
        
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Save as YAML
        yaml_file = CONFIG_DIR / 'discovered_config.yaml'
        with open(yaml_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.info(f"Configuration saved to: {yaml_file}")
        
        # Save as JSON (for programmatic access)
        json_file = CONFIG_DIR / 'discovered_config.json'
        with open(json_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Configuration also saved to: {json_file}")
    
    def _generate_summary_report(self, config):
        """Generate human-readable summary report"""
        
        report_file = CONFIG_DIR / f'discovery_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        
        with open(report_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("ZERO-CONFIGURATION NETWORK DISCOVERY REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Discovery Time: {config['discovery']['timestamp']}\n")
            f.write(f"Discovery Mode: {config['discovery']['discovery_mode']}\n\n")
            
            f.write("SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"Networks Discovered: {config['statistics']['total_networks']}\n")
            f.write(f"Total Hosts Found: {config['statistics']['total_hosts']}\n")
            f.write(f"Auto-Generated Exclusions: {config['statistics']['total_exclusions']}\n\n")
            
            f.write("CRITICALITY BREAKDOWN\n")
            f.write("-" * 70 + "\n")
            for level, count in config['statistics']['criticality_breakdown'].items():
                f.write(f"{level.capitalize():10s}: {count:3d} hosts\n")
            f.write("\n")
            
            f.write("DISCOVERED NETWORKS\n")
            f.write("-" * 70 + "\n")
            for net in config['network_topology']:
                f.write(f"\nNetwork: {net['network']}\n")
                f.write(f"  Interface: {net['interface']}\n")
                f.write(f"  Purpose: {net['purpose']}\n")
                f.write(f"  Live Hosts: {net['total_hosts']}\n")
            f.write("\n")
            
            f.write("EXCLUSIONS (Will NOT be aggressively scanned)\n")
            f.write("-" * 70 + "\n")
            for ip in config['network']['exclusions']:
                reason = config['network']['exclusion_reasons'].get(ip, 'Unknown')
                f.write(f"{ip:15s} - {reason}\n")
            f.write("\n")
            
            f.write("CRITICAL ASSETS DISCOVERED\n")
            f.write("-" * 70 + "\n")
            critical_assets = [h for h in config['discovered_assets'] 
                             if h.get('criticality') in ['critical', 'high']]
            
            for asset in critical_assets:
                f.write(f"\n{asset['ip']:15s} ({asset.get('hostname', 'No hostname')})\n")
                f.write(f"  Device Type: {asset.get('device_type', 'unknown')}\n")
                f.write(f"  Criticality: {asset.get('criticality', 'unknown')}\n")
                if asset.get('open_ports'):
                    f.write(f"  Open Ports: {', '.join(map(str, asset['open_ports']))}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("Next Steps:\n")
            f.write("1. Review the discovered_config.yaml file\n")
            f.write("2. Verify exclusion list is complete\n")
            f.write("3. Update /opt/purple-team/config/config.yaml with these settings\n")
            f.write("4. Begin security scanning with discovered configuration\n")
            f.write("=" * 70 + "\n")
        
        logger.info(f"Summary report saved to: {report_file}")

def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Zero-Configuration Network Discovery')
    parser.add_argument('--quick', action='store_true', 
                       help='Quick mode (ping sweep only, no fingerprinting)')
    parser.add_argument('--output', type=str, 
                       help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Create discovery instance
    discovery = ZeroConfigDiscovery()
    
    # Run discovery
    config = discovery.full_discovery(quick_mode=args.quick)
    
    if config:
        print("\n" + "=" * 70)
        print("DISCOVERY SUMMARY")
        print("=" * 70)
        print(f"Networks Discovered: {config['statistics']['total_networks']}")
        print(f"Total Hosts: {config['statistics']['total_hosts']}")
        print(f"Critical/High Assets: {config['statistics']['criticality_breakdown']['critical'] + config['statistics']['criticality_breakdown']['high']}")
        print(f"Auto-Exclusions: {config['statistics']['total_exclusions']}")
        print("\nConfiguration files created:")
        print(f"  - {CONFIG_DIR}/discovered_config.yaml")
        print(f"  - {CONFIG_DIR}/discovered_config.json")
        print(f"  - {CONFIG_DIR}/discovery_report_*.txt")
        print("\nNext step: Review and apply configuration to config.yaml")
        print("=" * 70)

if __name__ == '__main__':
    main()
