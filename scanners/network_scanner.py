#!/usr/bin/env python3
"""
Purple Team Portable - Network Scanner
Comprehensive network discovery and port scanning with human-paced execution.
"""

import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Add lib to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

# Import from lib/network.py (renamed import to avoid confusion)
from network import get_network_discovery, get_scan_targets

try:
    from asset_manager import get_asset_manager
except ImportError:
    get_asset_manager = None


class NetworkScanner(BaseScanner):
    """Network discovery and port scanning."""

    SCANNER_NAME = "network"
    SCANNER_DESCRIPTION = "Network discovery and port scanning"

    # Common ports for quick scans
    QUICK_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"

    # Top 1000 ports (nmap default)
    DEFAULT_PORTS = "--top-ports 1000"

    # Full port range
    FULL_PORTS = "1-65535"

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.network_discovery = get_network_discovery()
        self.nmap_path = None

    def scan(self, targets: List[str] = None, scan_type: str = 'standard',
             port_range: str = None, **kwargs) -> Dict:
        """
        Execute network scan.

        Args:
            targets: List of networks/hosts to scan. Auto-detects if not provided.
            scan_type: 'quick', 'standard', 'deep', or 'stealth'
            port_range: Custom port range (default based on scan_type)
        """
        self.start_time = datetime.utcnow()
        self.nmap_path = self.require_tool('nmap')

        # Get targets if not provided
        if not targets:
            targets = get_scan_targets()
            if not targets:
                self.scan_logger.error("No scan targets found or configured")
                return {'error': 'No targets available'}

        self.scan_logger.info(f"Starting {scan_type} network scan")
        self.scan_logger.info(f"Targets: {targets}")

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'hosts': [],
            'services': [],
            'summary': {}
        }

        # Phase 1: Host discovery
        self.scan_logger.info("Phase 1: Host Discovery")
        live_hosts = []
        for target in targets:
            discovered = self._discover_hosts(target)
            live_hosts.extend(discovered)
            self.human_delay()

        self.scan_logger.info(f"Discovered {len(live_hosts)} live hosts")
        results['hosts'] = live_hosts

        # Phase 2: Port scanning
        self.scan_logger.info("Phase 2: Port Scanning")
        for host in live_hosts:
            host_ip = host['ip']
            ports = self._scan_ports(host_ip, scan_type, port_range)
            host['ports'] = ports

            # Add service findings
            for port in ports:
                self._process_port_finding(host_ip, port)

            self.human_delay()

        # Phase 3: Service detection (for standard and deep scans)
        if scan_type in ['standard', 'deep']:
            self.scan_logger.info("Phase 3: Service Detection")
            for host in live_hosts:
                if host.get('ports'):
                    services = self._detect_services(host['ip'], host['ports'])
                    host['services'] = services
                    results['services'].extend(services)
                    self.human_delay()

        # Generate summary
        results['summary'] = {
            'total_hosts': len(live_hosts),
            'total_ports': sum(len(h.get('ports', [])) for h in live_hosts),
            'total_services': len(results['services'])
        }

        # Register assets in inventory
        if get_asset_manager is not None:
            try:
                am = get_asset_manager()
                for host in live_hosts:
                    am.register_asset(
                        ip=host['ip'],
                        hostname=host.get('hostname'),
                        mac=host.get('mac'),
                        vendor=host.get('vendor'),
                    )
                    if host.get('ports'):
                        am.update_ports(host['ip'], host['ports'])
                self.scan_logger.info(f"Registered {len(live_hosts)} assets in inventory")
            except Exception as e:
                self.scan_logger.warning(f"Asset registration error: {e}")

        self.end_time = datetime.utcnow()

        # Save results and add to evidence
        self.save_results()
        self._add_network_evidence(results)

        return results

    def _discover_hosts(self, network: str) -> List[Dict]:
        """Discover live hosts on a network."""
        self.scan_logger.info(f"Discovering hosts on {network}")

        cmd = [
            str(self.nmap_path),
            '-sn',  # Ping scan
            '-PE', '-PP', '-PM',  # ICMP echo, timestamp, netmask
            '-PS22,80,443',  # TCP SYN to common ports
            '--max-retries', '2',
            network
        ]

        result = self.run_tool(cmd, timeout=300, description=f"Host discovery on {network}")
        hosts = self._parse_host_discovery(result.stdout)

        for host in hosts:
            self.add_result('host_discovery', host, host['ip'])

        return hosts

    def _parse_host_discovery(self, output: str) -> List[Dict]:
        """Parse nmap host discovery output."""
        hosts = []
        current_host = None

        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                match = re.search(r'for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_host = {
                        'hostname': match.group(1),
                        'ip': match.group(2),
                        'is_up': True,
                        'mac': None,
                        'vendor': None
                    }

            elif 'MAC Address:' in line and current_host:
                match = re.search(r'MAC Address:\s+([0-9A-F:]+)\s*(?:\(([^)]+)\))?', line)
                if match:
                    current_host['mac'] = match.group(1)
                    current_host['vendor'] = match.group(2)
                hosts.append(current_host)
                current_host = None

            elif 'Host is up' in line and current_host:
                hosts.append(current_host)
                current_host = None

        return hosts

    def _scan_ports(self, host: str, scan_type: str, custom_ports: str = None) -> List[Dict]:
        """Scan ports on a host."""
        self.scan_logger.info(f"Scanning ports on {host}")

        # Determine port range and scan options
        if custom_ports:
            port_arg = f"-p{custom_ports}"
        elif scan_type == 'quick':
            port_arg = f"-p{self.QUICK_PORTS}"
        elif scan_type == 'deep':
            port_arg = "-p-"  # All ports
        else:
            port_arg = self.DEFAULT_PORTS

        # Build command based on scan type
        if scan_type == 'stealth':
            scan_flags = ['-sS', '-T2']  # SYN scan, slower timing
        elif scan_type == 'deep':
            scan_flags = ['-sS', '-sV', '-T3']  # SYN + version
        else:
            scan_flags = ['-sS', '-T3']  # Standard SYN scan

        cmd = [
            str(self.nmap_path),
            *scan_flags,
            port_arg,
            '--max-retries', '2',
            '--host-timeout', '5m',
            host
        ]

        result = self.run_tool(cmd, timeout=600, description=f"Port scan on {host}")
        return self._parse_port_scan(result.stdout, host)

    def _parse_port_scan(self, output: str, host: str) -> List[Dict]:
        """Parse nmap port scan output."""
        ports = []

        for line in output.split('\n'):
            # Match port lines: "22/tcp   open  ssh"
            match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)?', line)
            if match:
                port_info = {
                    'port': int(match.group(1)),
                    'protocol': match.group(2),
                    'state': match.group(3),
                    'service': match.group(4) if match.group(4) else 'unknown',
                    'host': host
                }
                ports.append(port_info)

        return ports

    def _detect_services(self, host: str, ports: List[Dict]) -> List[Dict]:
        """Detect service versions on open ports."""
        if not ports:
            return []

        open_ports = [str(p['port']) for p in ports if p['state'] == 'open']
        if not open_ports:
            return []

        self.scan_logger.info(f"Detecting services on {host}")

        cmd = [
            str(self.nmap_path),
            '-sV',
            '--version-intensity', '5',
            '-p', ','.join(open_ports),
            host
        ]

        result = self.run_tool(cmd, timeout=300, description=f"Service detection on {host}")
        return self._parse_service_detection(result.stdout, host)

    def _parse_service_detection(self, output: str, host: str) -> List[Dict]:
        """Parse nmap service detection output."""
        services = []

        for line in output.split('\n'):
            # Match service lines with version info
            match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)?$', line)
            if match:
                service = {
                    'host': host,
                    'port': int(match.group(1)),
                    'protocol': match.group(2),
                    'state': match.group(3),
                    'service': match.group(4),
                    'version': match.group(5).strip() if match.group(5) else ''
                }
                services.append(service)

                self.add_result('service', service, f"{host}:{service['port']}")

        return services

    def _process_port_finding(self, host: str, port_info: Dict):
        """Process an open port as a finding."""
        if port_info['state'] != 'open':
            return

        port = port_info['port']
        service = port_info['service']

        # Determine severity based on service risk
        high_risk_ports = {21, 23, 135, 139, 445, 1433, 3389, 5432, 5900}
        medium_risk_ports = {22, 25, 53, 110, 143, 993, 995, 3306}

        if port in high_risk_ports:
            severity = 'MEDIUM'
            remediation = f"Review if port {port} ({service}) is necessary. Consider restricting access."
        elif port in medium_risk_ports:
            severity = 'LOW'
            remediation = f"Ensure port {port} ({service}) is properly secured."
        else:
            severity = 'INFO'
            remediation = "Document this service in the asset inventory."

        self.add_finding(
            severity=severity,
            title=f"Open Port: {port}/{port_info['protocol']} ({service})",
            description=f"Port {port} is open and running {service} on host {host}",
            affected_asset=host,
            finding_type='open_port',
            remediation=remediation,
            raw_data=port_info,
            detection_method='port_scan'
        )

    def _add_network_evidence(self, results: Dict):
        """Add network scan results as evidence."""
        if not self.session_id:
            return

        # Add overall scan evidence
        evidence_id = self.evidence.add_evidence(
            session_id=self.session_id,
            evidence_type='network_scan',
            title=f"Network Scan - {results['scan_type']}",
            description=f"Network scan of {len(results['targets'])} networks, "
                       f"found {results['summary']['total_hosts']} hosts, "
                       f"{results['summary']['total_ports']} open ports",
            source_tool='nmap',
            raw_data=results['summary']
        )

        # Map to compliance controls
        frameworks = self.config.get_frameworks()
        self.compliance.map_finding_to_controls(
            'network_service', evidence_id, self.evidence, frameworks
        )


if __name__ == '__main__':
    # Self-test
    scanner = NetworkScanner()
    print(f"Network Scanner initialized")
    print(f"Nmap available: {scanner.check_tool('nmap')}")

    targets = get_scan_targets()
    print(f"Auto-detected targets: {targets}")
