#!/usr/bin/env python3
"""
Purple Team Portable - Network Utilities
Auto-detects networks, RFC1918 ranges, and provides network scanning utilities.
"""

import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address, ip_network, ip_address
from typing import List, Optional, Tuple, Dict

try:
    from .paths import paths
    from .config import config
    from .logger import get_logger
except ImportError:
    from paths import paths
    from config import config
    from logger import get_logger

logger = get_logger('network')


@dataclass
class NetworkInterface:
    """Represents a network interface."""
    name: str
    ip_address: str
    netmask: str
    network: str
    broadcast: Optional[str]
    is_private: bool


@dataclass
class DiscoveredHost:
    """Represents a discovered host."""
    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]
    is_up: bool
    ports: List[int]


class NetworkDiscovery:
    """Network discovery and enumeration utilities."""

    # RFC1918 private address ranges
    PRIVATE_RANGES = [
        IPv4Network('10.0.0.0/8'),
        IPv4Network('172.16.0.0/12'),
        IPv4Network('192.168.0.0/16')
    ]

    # Link-local range
    LINK_LOCAL = IPv4Network('169.254.0.0/16')

    # Loopback
    LOOPBACK = IPv4Network('127.0.0.0/8')

    def __init__(self):
        self.nmap_path = paths.find_tool('nmap')

    def get_local_interfaces(self) -> List[NetworkInterface]:
        """Get all local network interfaces with their configuration.
        Cross-platform: Linux (ip), Windows (ipconfig), fallback (pure Python).
        """
        interfaces = []
        import sys as _sys

        if _sys.platform == 'win32':
            interfaces = self._get_interfaces_windows()
        else:
            interfaces = self._get_interfaces_linux()

        # Fallback: pure Python socket approach
        if not interfaces:
            interfaces = self._get_interfaces_fallback()

        return interfaces

    def _get_interfaces_linux(self) -> List[NetworkInterface]:
        """Get interfaces on Linux using ip command."""
        interfaces = []
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show'],
                capture_output=True, text=True, timeout=10
            )

            current_iface = None
            for line in result.stdout.split('\n'):
                if re.match(r'^\d+:', line):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_iface = parts[1].strip().split('@')[0]

                elif 'inet ' in line and current_iface:
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if match:
                        ip = match.group(1)
                        prefix = int(match.group(2))
                        try:
                            network = ip_network(f"{ip}/{prefix}", strict=False)
                            netmask = str(network.netmask)
                            network_addr = str(network.network_address)
                            broadcast = str(network.broadcast_address)
                            ip_obj = ip_address(ip)
                            is_private = any(ip_obj in r for r in self.PRIVATE_RANGES)
                            interfaces.append(NetworkInterface(
                                name=current_iface,
                                ip_address=ip, netmask=netmask,
                                network=f"{network_addr}/{prefix}",
                                broadcast=broadcast, is_private=is_private
                            ))
                        except Exception as e:
                            logger.warning(f"Error parsing interface {current_iface}: {e}")
        except Exception as e:
            logger.error(f"Error getting Linux interfaces: {e}")
        return interfaces

    def _get_interfaces_windows(self) -> List[NetworkInterface]:
        """Get interfaces on Windows using ipconfig."""
        interfaces = []
        try:
            result = subprocess.run(
                ['ipconfig', '/all'],
                capture_output=True, text=True, timeout=10
            )

            current_iface = None
            for line in result.stdout.split('\n'):
                line = line.rstrip()
                # Adapter header
                if line and not line.startswith(' ') and ':' in line:
                    current_iface = line.split(':')[0].strip()
                # IPv4 Address
                elif 'IPv4 Address' in line and current_iface:
                    match = re.search(r':\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        # Look for subnet mask in next lines
                        netmask = '255.255.255.0'  # default
                elif 'Subnet Mask' in line and current_iface:
                    match = re.search(r':\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        netmask = match.group(1)
                        try:
                            prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                            network = ip_network(f"{ip}/{prefix}", strict=False)
                            ip_obj = ip_address(ip)
                            is_private = any(ip_obj in r for r in self.PRIVATE_RANGES)
                            interfaces.append(NetworkInterface(
                                name=current_iface,
                                ip_address=ip, netmask=netmask,
                                network=f"{network.network_address}/{prefix}",
                                broadcast=str(network.broadcast_address),
                                is_private=is_private
                            ))
                        except Exception as e:
                            logger.warning(f"Error parsing Windows interface: {e}")
        except Exception as e:
            logger.error(f"Error getting Windows interfaces: {e}")
        return interfaces

    def _get_interfaces_fallback(self) -> List[NetworkInterface]:
        """Fallback: pure Python socket-based detection."""
        interfaces = []
        try:
            hostname = socket.gethostname()
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            seen = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip in seen or ip.startswith('127.'):
                    continue
                seen.add(ip)
                ip_obj = ip_address(ip)
                is_private = any(ip_obj in r for r in self.PRIVATE_RANGES)
                network = ip_network(f"{ip}/24", strict=False)
                interfaces.append(NetworkInterface(
                    name='unknown',
                    ip_address=ip,
                    netmask='255.255.255.0',
                    network=f"{network.network_address}/24",
                    broadcast=str(network.broadcast_address),
                    is_private=is_private
                ))
        except Exception as e:
            logger.error(f"Fallback interface detection error: {e}")
        return interfaces

    def get_private_networks(self) -> List[str]:
        """Get all private (RFC1918) networks from local interfaces."""
        interfaces = self.get_local_interfaces()
        networks = []

        for iface in interfaces:
            if iface.is_private and iface.name != 'lo':
                networks.append(iface.network)

        return list(set(networks))

    def get_scan_targets(self) -> List[str]:
        """Get networks to scan based on configuration."""
        # Check if specific ranges configured
        configured_ranges = config.get('network.scan_ranges', [])
        if configured_ranges:
            return configured_ranges

        # Auto-detect if enabled
        if config.get('network.auto_detect', True):
            return self.get_private_networks()

        return []

    def get_excluded_ranges(self) -> List[str]:
        """Get networks to exclude from scanning."""
        return config.get('network.exclude_ranges', ['127.0.0.0/8'])

    def is_host_in_scope(self, host: str, target_networks: List[str],
                          excluded_ranges: List[str]) -> bool:
        """Check if a host is within scan scope."""
        try:
            host_ip = ip_address(host)

            # Check exclusions first
            for excluded in excluded_ranges:
                if host_ip in ip_network(excluded, strict=False):
                    return False

            # Check if in target networks
            for target in target_networks:
                if host_ip in ip_network(target, strict=False):
                    return True

            return False
        except Exception:
            return False

    def discover_hosts(self, network: str, scan_type: str = 'ping') -> List[DiscoveredHost]:
        """Discover live hosts on a network."""
        if not self.nmap_path:
            logger.error("nmap not found - cannot perform host discovery")
            return []

        hosts = []
        logger.info(f"Discovering hosts on {network}")

        try:
            # Build nmap command based on scan type
            if scan_type == 'ping':
                cmd = [str(self.nmap_path), '-sn', '-PE', '-PP', '-PM', network]
            elif scan_type == 'arp':
                cmd = [str(self.nmap_path), '-sn', '-PR', network]
            elif scan_type == 'syn':
                cmd = [str(self.nmap_path), '-sn', '-PS22,80,443,3389', network]
            else:
                cmd = [str(self.nmap_path), '-sn', network]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )

            # Parse nmap output
            current_host = None
            for line in result.stdout.split('\n'):
                # Host line
                if 'Nmap scan report for' in line:
                    # Extract IP and optionally hostname
                    match = re.search(r'for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        hostname = match.group(1)
                        ip = match.group(2)
                        current_host = DiscoveredHost(
                            ip=ip,
                            hostname=hostname,
                            mac=None,
                            vendor=None,
                            is_up=True,
                            ports=[]
                        )

                # MAC address line
                elif 'MAC Address:' in line and current_host:
                    match = re.search(r'MAC Address:\s+([0-9A-F:]+)\s*\(([^)]+)\)?', line)
                    if match:
                        current_host.mac = match.group(1)
                        current_host.vendor = match.group(2) if match.group(2) else None
                    hosts.append(current_host)
                    current_host = None

                # Host status (for hosts without MAC - i.e., local host)
                elif 'Host is up' in line and current_host:
                    hosts.append(current_host)
                    current_host = None

        except subprocess.TimeoutExpired:
            logger.warning(f"Host discovery timed out for {network}")
        except Exception as e:
            logger.error(f"Error during host discovery: {e}")

        logger.info(f"Discovered {len(hosts)} hosts on {network}")
        return hosts

    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP address to hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return None

    def get_network_summary(self) -> Dict:
        """Get summary of local network configuration."""
        interfaces = self.get_local_interfaces()
        private_nets = self.get_private_networks()
        targets = self.get_scan_targets()
        excluded = self.get_excluded_ranges()

        return {
            'interfaces': [
                {
                    'name': iface.name,
                    'ip': iface.ip_address,
                    'network': iface.network,
                    'private': iface.is_private
                }
                for iface in interfaces
            ],
            'private_networks': private_nets,
            'scan_targets': targets,
            'excluded_ranges': excluded,
            'total_interfaces': len(interfaces),
            'private_interfaces': sum(1 for i in interfaces if i.is_private)
        }


# Singleton
_discovery: Optional[NetworkDiscovery] = None


def get_network_discovery() -> NetworkDiscovery:
    """Get the network discovery singleton."""
    global _discovery
    if _discovery is None:
        _discovery = NetworkDiscovery()
    return _discovery


def get_scan_targets() -> List[str]:
    """Convenience function to get scan targets."""
    return get_network_discovery().get_scan_targets()


def discover_hosts(network: str) -> List[DiscoveredHost]:
    """Convenience function to discover hosts."""
    return get_network_discovery().discover_hosts(network)


if __name__ == '__main__':
    # Self-test
    nd = get_network_discovery()

    print("Network Summary:")
    summary = nd.get_network_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")

    print("\nScan Targets:")
    for target in nd.get_scan_targets():
        print(f"  {target}")
