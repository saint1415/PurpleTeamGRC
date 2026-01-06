#!/usr/bin/env python3
"""
Purple Team GRC Platform v3.0 - Network Auto-Detector
Automatically detects network interfaces and RFC1918 private network ranges

Features:
- Detects all active network interfaces (wired + wireless)
- Identifies RFC1918 private network ranges
- Multi-network support (can scan both wired and wireless separately)
- Interactive prompts for network selection
- Safe exclusion list generation for critical infrastructure
- Automatic config.yaml update

Usage:
    sudo python3 network-detector.py [--force] [--verbose]
"""

import subprocess
import ipaddress
import yaml
import sys
import socket
from pathlib import Path
from datetime import datetime

# Add utils to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.path_helper import CONFIG_FILE, REPORTS_DIR

# Colors for terminal output
class Colors:
    BLUE = '\033[0;34m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'


def print_header():
    """Print application header"""
    print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}")
    print(f"{Colors.BLUE}Purple Team v3.0 - Network Discovery & Auto-Detection{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}")
    print()


def get_active_interfaces():
    """
    Detect all active network interfaces with IP addresses.
    
    Returns:
        list: List of interface dictionaries
    """
    interfaces = []
    
    try:
        # Get all interfaces with IP addresses
        result = subprocess.run(
            ['ip', '-o', 'addr', 'show'],
            capture_output=True,
            text=True,
            check=True
        )
        
        for line in result.stdout.split('\n'):
            if 'inet ' in line and '127.0.0.1' not in line:
                parts = line.split()
                
                # Extract interface name (format: "2: eth0")
                iface_name = parts[1].rstrip(':')
                
                # Extract IP/CIDR
                ip_cidr = parts[3]
                ip_addr = ip_cidr.split('/')[0]
                
                # Determine interface type
                if iface_name.startswith(('eth', 'ens', 'enp')):
                    iface_type = 'wired'
                elif iface_name.startswith(('wlan', 'wlp')):
                    iface_type = 'wireless'
                else:
                    iface_type = 'other'
                
                # Get network info
                network = ipaddress.IPv4Network(ip_cidr, strict=False)
                
                # Get gateway
                gateway = get_gateway(iface_name)
                
                interface = {
                    'name': iface_name,
                    'type': iface_type,
                    'ip': ip_addr,
                    'cidr': ip_cidr,
                    'network': str(network),
                    'gateway': gateway,
                    'is_rfc1918': ipaddress.IPv4Address(ip_addr).is_private
                }
                
                interfaces.append(interface)
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error detecting interfaces: {e}{Colors.NC}")
    
    return interfaces


def get_gateway(interface):
    """
    Get default gateway for an interface.
    
    Args:
        interface: Interface name
        
    Returns:
        str: Gateway IP or None
    """
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'dev', interface],
            capture_output=True,
            text=True,
            check=True
        )
        
        for line in result.stdout.split('\n'):
            if 'default via' in line:
                parts = line.split()
                return parts[2]  # Gateway IP
        
    except subprocess.CalledProcessError:
        pass
    
    return None


def get_dns_servers():
    """
    Get configured DNS servers.
    
    Returns:
        list: List of DNS server IPs
    """
    dns_servers = []
    
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.strip().startswith('nameserver'):
                    dns_servers.append(line.split()[1])
    except FileNotFoundError:
        pass
    
    return dns_servers


def discover_rfc1918_ranges(interfaces):
    """
    Discover all RFC1918 network ranges from active interfaces.
    
    Args:
        interfaces: List of interface dictionaries
        
    Returns:
        list: List of RFC1918 network ranges
    """
    ranges = set()
    
    for iface in interfaces:
        if iface['is_rfc1918']:
            # Get the full RFC1918 range this network belongs to
            ip = ipaddress.IPv4Address(iface['ip'])
            
            # Determine which RFC1918 range this belongs to
            if ip in ipaddress.IPv4Network('10.0.0.0/8'):
                # For 10.x networks, use the /16 by default
                network = ipaddress.IPv4Network(f"{iface['ip']}/16", strict=False)
            elif ip in ipaddress.IPv4Network('172.16.0.0/12'):
                # For 172.16-31 networks, use /16
                network = ipaddress.IPv4Network(f"{iface['ip']}/16", strict=False)
            elif ip in ipaddress.IPv4Network('192.168.0.0/16'):
                # For 192.168 networks, use /24
                network = ipaddress.IPv4Network(f"{iface['ip']}/24", strict=False)
            else:
                continue
            
            ranges.add(str(network))
    
    return sorted(list(ranges))


def quick_ping_sweep(network, max_hosts=10):
    """
    Perform a quick ping sweep to find live hosts.
    
    Args:
        network: Network range (CIDR)
        max_hosts: Maximum hosts to ping (for quick scan)
        
    Returns:
        list: List of live host IPs
    """
    print(f"Performing quick discovery sweep on {network}...")
    
    live_hosts = []
    net = ipaddress.IPv4Network(network)
    
    # Ping a sample of hosts (first 10, last 10, and a few random)
    hosts_to_ping = []
    all_hosts = list(net.hosts())
    
    if len(all_hosts) <= max_hosts:
        hosts_to_ping = all_hosts
    else:
        # First 5, last 5
        hosts_to_ping.extend(all_hosts[:5])
        hosts_to_ping.extend(all_hosts[-5:])
    
    for host in hosts_to_ping:
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(host)],
                capture_output=True,
                timeout=2
            )
            
            if result.returncode == 0:
                live_hosts.append(str(host))
                print(f"  Found: {host}")
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
    
    print(f"Quick sweep complete: {len(live_hosts)} hosts found")
    return live_hosts


def identify_critical_systems(live_hosts):
    """
    Identify critical systems that should be excluded from scans.
    
    Args:
        live_hosts: List of live host IPs
        
    Returns:
        dict: Critical systems identified
    """
    critical = {}
    
    for host in live_hosts:
        # Check common critical ports
        services = check_services(host)
        
        if services:
            critical[host] = services
    
    return critical


def check_services(host):
    """
    Check what services are running on a host.
    
    Args:
        host: Host IP address
        
    Returns:
        list: List of identified services
    """
    services = []
    
    # Common critical ports
    ports_to_check = {
        53: 'DNS',
        88: 'Kerberos (Domain Controller)',
        389: 'LDAP (Domain Controller)',
        636: 'LDAPS (Domain Controller)',
        3268: 'Global Catalog (Domain Controller)',
        25: 'SMTP',
        3306: 'MySQL/MariaDB',
        5432: 'PostgreSQL',
        1433: 'MSSQL'
    }
    
    for port, service in ports_to_check.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                services.append(service)
        except:
            pass
        finally:
            sock.close()
    
    return services


def display_interface_info(interfaces):
    """Display detected network interfaces"""
    print(f"{Colors.BOLD}Active Interfaces Detected:{Colors.NC}")
    print("─" * 70)
    
    for iface in interfaces:
        icon = "📡" if iface['type'] == 'wireless' else "🔌"
        rfc1918 = " (RFC 1918)" if iface['is_rfc1918'] else ""
        
        print(f"{icon} Interface: {iface['name']} ({iface['type']})")
        print(f"  Status: {Colors.GREEN}Connected{Colors.NC}")
        print(f"  IP Address: {iface['ip']}")
        print(f"  Network Range: {iface['network']}{rfc1918}")
        if iface['gateway']:
            print(f"  Gateway: {iface['gateway']}")
        print()


def select_network(interfaces):
    """
    Interactive network selection if multiple networks detected.
    
    Args:
        interfaces: List of interfaces
        
    Returns:
        list: Selected network ranges
    """
    # Filter RFC1918 interfaces
    rfc1918_interfaces = [i for i in interfaces if i['is_rfc1918']]
    
    if len(rfc1918_interfaces) == 0:
        print(f"{Colors.RED}No RFC1918 private networks detected!{Colors.NC}")
        return []
    
    if len(rfc1918_interfaces) == 1:
        print(f"{Colors.GREEN}Single network detected. Auto-selecting.{Colors.NC}")
        return [rfc1918_interfaces[0]['network']]
    
    # Multiple networks - prompt user
    print(f"\n{Colors.YELLOW}Multiple networks detected!{Colors.NC}")
    print("Which network do you want to scan?\n")
    
    for idx, iface in enumerate(rfc1918_interfaces, 1):
        net_type = "Corporate Ethernet" if iface['type'] == 'wired' else "WiFi"
        print(f"{idx}) {iface['network']} ({net_type} - {iface['name']})")
    
    print(f"{len(rfc1918_interfaces) + 1}) Scan all networks separately")
    print(f"{len(rfc1918_interfaces) + 2}) Enter custom range manually")
    
    while True:
        try:
            choice = input(f"\n{Colors.BOLD}Select option [1-{len(rfc1918_interfaces) + 2}]: {Colors.NC}")
            choice = int(choice)
            
            if 1 <= choice <= len(rfc1918_interfaces):
                return [rfc1918_interfaces[choice - 1]['network']]
            elif choice == len(rfc1918_interfaces) + 1:
                return [i['network'] for i in rfc1918_interfaces]
            elif choice == len(rfc1918_interfaces) + 2:
                custom = input("Enter custom CIDR range (e.g., 10.0.0.0/24): ")
                try:
                    ipaddress.IPv4Network(custom)
                    return [custom]
                except ValueError:
                    print(f"{Colors.RED}Invalid CIDR format!{Colors.NC}")
            else:
                print(f"{Colors.RED}Invalid choice!{Colors.NC}")
        except (ValueError, KeyboardInterrupt):
            print(f"\n{Colors.RED}Invalid input!{Colors.NC}")


def generate_config(networks, exclusions, interfaces):
    """
    Generate or update configuration file.
    
    Args:
        networks: List of network ranges
        exclusions: List of IPs to exclude
        interfaces: List of interfaces
    """
    config = {}
    
    # Load existing config if it exists
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f) or {}
    
    # Update network section
    config['network'] = config.get('network', {})
    config['network']['auto_detect'] = True
    config['network']['ranges'] = networks
    config['network']['exclusions'] = exclusions
    
    # Add detected DNS servers
    dns_servers = get_dns_servers()
    if dns_servers:
        config['network']['dns_servers'] = dns_servers
    
    # Add interface preference
    has_wired = any(i['type'] == 'wired' for i in interfaces)
    config['network']['prefer_wired'] = has_wired
    config['network']['scan_all_interfaces'] = len(interfaces) > 1
    
    # Save config
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    print(f"{Colors.GREEN}✓ Configuration updated: {CONFIG_FILE}{Colors.NC}")


def generate_report(interfaces, networks, exclusions):
    """Generate discovery report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORTS_DIR / f"network_discovery_{timestamp}.txt"
    
    with open(report_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("Purple Team v3.0 - Network Discovery Report\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("Detected Interfaces:\n")
        f.write("-" * 70 + "\n")
        for iface in interfaces:
            f.write(f"Interface: {iface['name']} ({iface['type']})\n")
            f.write(f"  IP: {iface['ip']}\n")
            f.write(f"  Network: {iface['network']}\n")
            if iface['gateway']:
                f.write(f"  Gateway: {iface['gateway']}\n")
            f.write("\n")
        
        f.write("\nDiscovered Network Ranges:\n")
        f.write("-" * 70 + "\n")
        for net in networks:
            f.write(f"  • {net}\n")
        
        if exclusions:
            f.write("\nRecommended Exclusions:\n")
            f.write("-" * 70 + "\n")
            for exc in exclusions:
                f.write(f"  • {exc}\n")
    
    print(f"{Colors.GREEN}✓ Report saved: {report_file}{Colors.NC}")


def main():
    """Main execution"""
    print_header()
    
    # Detect interfaces
    print("Scanning network interfaces...\n")
    interfaces = get_active_interfaces()
    
    if not interfaces:
        print(f"{Colors.RED}No active network interfaces detected!{Colors.NC}")
        sys.exit(1)
    
    # Display interface info
    display_interface_info(interfaces)
    
    # Get RFC1918 ranges
    rfc1918_ranges = discover_rfc1918_ranges(interfaces)
    
    if not rfc1918_ranges:
        print(f"{Colors.RED}No RFC1918 private networks detected!{Colors.NC}")
        print("This tool only works with private networks (10.x, 172.16-31.x, 192.168.x)")
        sys.exit(1)
    
    print(f"{Colors.BOLD}RFC 1918 Private Network Ranges Detected:{Colors.NC}")
    print("─" * 70)
    for net_range in rfc1918_ranges:
        print(f"  • {net_range}")
    print()
    
    # Select networks
    selected_networks = select_network(interfaces)
    
    if not selected_networks:
        print(f"{Colors.RED}No networks selected!{Colors.NC}")
        sys.exit(1)
    
    # Generate exclusions
    print(f"\n{Colors.BOLD}Generating recommended exclusions...{Colors.NC}\n")
    exclusions = []
    
    # Always exclude gateways
    for iface in interfaces:
        if iface['gateway'] and iface['is_rfc1918']:
            exclusions.append(iface['gateway'])
            print(f"  → Excluding gateway: {iface['gateway']}")
    
    # Quick discovery for critical systems
    for network in selected_networks:
        live_hosts = quick_ping_sweep(network, max_hosts=10)
        critical = identify_critical_systems(live_hosts)
        
        for host, services in critical.items():
            if host not in exclusions:
                exclusions.append(host)
                print(f"  → Excluding {host}: {', '.join(services)}")
    
    # Update configuration
    print(f"\n{Colors.BOLD}Updating configuration...{Colors.NC}")
    generate_config(selected_networks, exclusions, interfaces)
    
    # Generate report
    generate_report(interfaces, selected_networks, exclusions)
    
    # Summary
    print(f"\n{Colors.GREEN}{'=' * 70}{Colors.NC}")
    print(f"{Colors.GREEN}Network Discovery Complete!{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 70}{Colors.NC}")
    print(f"\nSelected Networks: {', '.join(selected_networks)}")
    print(f"Exclusions: {len(exclusions)} critical systems")
    print(f"\n{Colors.BOLD}Ready to scan!{Colors.NC}")
    print(f"Next step: Run purple-team-launcher and select scan type\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Cancelled by user{Colors.NC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.NC}")
        sys.exit(1)
