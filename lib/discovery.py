#!/usr/bin/env python3
"""
Purple Team GRC Platform - Network Discovery Engine
Finds and fingerprints live hosts on the network using multiple discovery
methods (ARP, ICMP, TCP connect, DNS, Active Directory, cloud CLI).
Results are persisted in a SQLite database for tracking over time.

Stdlib-only. No third-party dependencies required.
"""

import json
import os
import platform
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import uuid
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

try:
    from .network import get_network_discovery
except ImportError:
    try:
        from network import get_network_discovery
    except ImportError:
        get_network_discovery = None

try:
    from .asset_inventory import get_asset_inventory
except ImportError:
    try:
        from asset_inventory import get_asset_inventory
    except ImportError:
        get_asset_inventory = None

logger = get_logger('discovery')


class DiscoveryEngine:
    """
    Network Discovery Engine.

    Discovers live hosts on local or specified subnets using a combination
    of ARP, ICMP ping sweep, TCP connect scanning, reverse DNS, Active
    Directory enumeration, and cloud CLI queries.  Results are stored in
    ``data/discovery.db`` and can be promoted to the main asset inventory.
    """

    _instance: Optional['DiscoveryEngine'] = None

    # Default ports for TCP connect scan
    DEFAULT_PORTS = [22, 80, 135, 443, 445, 3389, 8080]

    # Well-known service names mapped by port
    PORT_SERVICE_MAP = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind',
        135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
        161: 'snmp', 389: 'ldap', 443: 'https', 445: 'smb',
        465: 'smtps', 514: 'syslog', 587: 'submission',
        636: 'ldaps', 993: 'imaps', 995: 'pop3s',
        1433: 'mssql', 1521: 'oracle', 2049: 'nfs',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        5900: 'vnc', 5985: 'winrm-http', 5986: 'winrm-https',
        6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
        8888: 'http-alt', 9090: 'prometheus', 27017: 'mongodb',
    }

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_path = paths.data / 'discovery.db'
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS discovered_hosts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id         TEXT UNIQUE NOT NULL,
                    ip_address      TEXT NOT NULL,
                    hostname        TEXT,
                    mac_address     TEXT,
                    os_guess        TEXT DEFAULT 'unknown',
                    os_confidence   INTEGER DEFAULT 0,
                    open_ports      TEXT DEFAULT '[]',
                    services        TEXT DEFAULT '{}',
                    discovery_method TEXT,
                    first_seen      TEXT NOT NULL,
                    last_seen       TEXT NOT NULL,
                    status          TEXT DEFAULT 'live',
                    auto_registered INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_dh_ip
                    ON discovered_hosts(ip_address);
                CREATE INDEX IF NOT EXISTS idx_dh_status
                    ON discovered_hosts(status);
                CREATE INDEX IF NOT EXISTS idx_dh_os
                    ON discovered_hosts(os_guess);
                CREATE INDEX IF NOT EXISTS idx_dh_last_seen
                    ON discovered_hosts(last_seen);
            ''')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    def _generate_id(self) -> str:
        return f"HOST-{uuid.uuid4().hex[:12].upper()}"

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a Row to a plain dict, deserialising JSON fields."""
        d = dict(row)
        for jf in ('open_ports', 'services'):
            if jf in d and isinstance(d[jf], str):
                try:
                    d[jf] = json.loads(d[jf])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Convert auto_registered int to bool
        if 'auto_registered' in d:
            d['auto_registered'] = bool(d['auto_registered'])
        return d

    def _upsert_host(self, ip_address: str, discovery_method: str,
                     hostname: str = None, mac_address: str = None,
                     os_guess: str = 'unknown', os_confidence: int = 0,
                     open_ports: List[int] = None,
                     services: Dict[str, str] = None) -> str:
        """Insert or update a discovered host. Returns host_id."""
        now = self._now()
        ports_json = json.dumps(open_ports or [])
        services_json = json.dumps(services or {})

        with self._conn() as conn:
            existing = conn.execute(
                'SELECT host_id, open_ports, services, os_guess, os_confidence '
                'FROM discovered_hosts WHERE ip_address = ?',
                (ip_address,)
            ).fetchone()

            if existing:
                host_id = existing['host_id']
                # Merge open ports
                try:
                    prev_ports = json.loads(existing['open_ports'] or '[]')
                except (json.JSONDecodeError, TypeError):
                    prev_ports = []
                merged_ports = sorted(set(prev_ports + (open_ports or [])))

                # Merge services
                try:
                    prev_services = json.loads(existing['services'] or '{}')
                except (json.JSONDecodeError, TypeError):
                    prev_services = {}
                merged_services = {**prev_services, **(services or {})}

                # Keep higher-confidence OS guess
                prev_confidence = existing['os_confidence'] or 0
                if os_confidence > prev_confidence:
                    new_os = os_guess
                    new_conf = os_confidence
                else:
                    new_os = existing['os_guess']
                    new_conf = prev_confidence

                updates = {
                    'last_seen': now,
                    'status': 'live',
                    'discovery_method': discovery_method,
                    'open_ports': json.dumps(merged_ports),
                    'services': json.dumps(merged_services),
                    'os_guess': new_os,
                    'os_confidence': new_conf,
                }
                if hostname:
                    updates['hostname'] = hostname
                if mac_address:
                    updates['mac_address'] = mac_address

                set_clause = ', '.join(f"{k} = ?" for k in updates)
                values = list(updates.values()) + [host_id]
                conn.execute(
                    f"UPDATE discovered_hosts SET {set_clause} WHERE host_id = ?",
                    values
                )
                logger.debug(f"Updated host {host_id} ({ip_address})")
                return host_id

            host_id = self._generate_id()
            conn.execute(
                "INSERT INTO discovered_hosts "
                "(host_id, ip_address, hostname, mac_address, os_guess, "
                "os_confidence, open_ports, services, discovery_method, "
                "first_seen, last_seen, status, auto_registered) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'live', 0)",
                (host_id, ip_address, hostname, mac_address, os_guess,
                 os_confidence, ports_json, services_json, discovery_method,
                 now, now)
            )
            logger.info(f"Discovered new host {host_id} ({ip_address})")
            return host_id

    # ------------------------------------------------------------------
    # Subnet auto-detection
    # ------------------------------------------------------------------
    def _detect_local_subnet(self) -> str:
        """Auto-detect the local subnet CIDR."""
        # Try using the existing network module first
        if get_network_discovery is not None:
            try:
                nd = get_network_discovery()
                networks = nd.get_private_networks()
                if networks:
                    logger.info(f"Auto-detected subnet: {networks[0]}")
                    return networks[0]
            except Exception as e:
                logger.debug(f"Network module detection failed: {e}")

        # Fallback: platform-specific detection
        if sys.platform == 'win32':
            return self._detect_subnet_windows()
        else:
            return self._detect_subnet_linux()

    def _detect_subnet_windows(self) -> str:
        """Detect local subnet on Windows via ipconfig."""
        try:
            result = subprocess.run(
                ['ipconfig'], capture_output=True, text=True, timeout=10
            )
            ip_addr = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'IPv4 Address' in line:
                    match = re.search(r':\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        candidate = match.group(1)
                        if not candidate.startswith('127.'):
                            ip_addr = candidate
                elif 'Subnet Mask' in line and ip_addr:
                    match = re.search(r':\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        mask = match.group(1)
                        prefix = sum(bin(int(x)).count('1') for x in mask.split('.'))
                        network = ip_network(f"{ip_addr}/{prefix}", strict=False)
                        cidr = str(network)
                        logger.info(f"Windows auto-detected subnet: {cidr}")
                        return cidr
        except Exception as e:
            logger.warning(f"Windows subnet detection failed: {e}")

        # Fallback: assume /24 on default gateway network
        return self._detect_subnet_fallback()

    def _detect_subnet_linux(self) -> str:
        """Detect local subnet on Linux via ip command."""
        try:
            result = subprocess.run(
                ['ip', '-4', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=10
            )
            # Parse default route to find interface
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                iface = match.group(1)
                result2 = subprocess.run(
                    ['ip', '-4', 'addr', 'show', iface],
                    capture_output=True, text=True, timeout=10
                )
                match2 = re.search(
                    r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', result2.stdout
                )
                if match2:
                    ip_addr = match2.group(1)
                    prefix = match2.group(2)
                    network = ip_network(f"{ip_addr}/{prefix}", strict=False)
                    cidr = str(network)
                    logger.info(f"Linux auto-detected subnet: {cidr}")
                    return cidr
        except Exception as e:
            logger.warning(f"Linux subnet detection failed: {e}")

        return self._detect_subnet_fallback()

    def _detect_subnet_fallback(self) -> str:
        """Fallback subnet detection using socket."""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip.startswith('127.'):
                # Try connecting to external host to get real IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(('8.8.8.8', 80))
                    local_ip = s.getsockname()[0]
                finally:
                    s.close()
            network = ip_network(f"{local_ip}/24", strict=False)
            cidr = str(network)
            logger.info(f"Fallback auto-detected subnet: {cidr}")
            return cidr
        except Exception as e:
            logger.error(f"Subnet fallback detection failed: {e}")
            return '192.168.1.0/24'

    # ------------------------------------------------------------------
    # Discovery methods
    # ------------------------------------------------------------------
    def discover_network(self, cidr: str = 'auto',
                         methods: List[str] = None) -> List[Dict]:
        """
        Main entry point. Discover live hosts on a network.

        Args:
            cidr: Network CIDR notation, or 'auto' to detect local subnet.
            methods: List of discovery methods to use. Options:
                     'arp', 'icmp', 'tcp', 'dns'.
                     Defaults to ['arp', 'icmp', 'tcp'].

        Returns:
            List of discovered host dicts.
        """
        if cidr == 'auto':
            cidr = self._detect_local_subnet()

        if methods is None:
            methods = ['arp', 'icmp', 'tcp']

        logger.info(f"Starting network discovery on {cidr} with methods: {methods}")

        discovered_ips = {}  # ip -> partial host dict

        # Phase 1: Host discovery (ARP + ICMP)
        if 'arp' in methods:
            try:
                arp_hosts = self._discover_arp(cidr)
                for h in arp_hosts:
                    ip = h['ip_address']
                    discovered_ips.setdefault(ip, {}).update(h)
            except Exception as e:
                logger.warning(f"ARP discovery failed: {e}")

        if 'icmp' in methods:
            try:
                icmp_hosts = self._discover_icmp(cidr)
                for h in icmp_hosts:
                    ip = h['ip_address']
                    discovered_ips.setdefault(ip, {}).update(h)
            except Exception as e:
                logger.warning(f"ICMP discovery failed: {e}")

        # Phase 2: Port scanning on discovered hosts
        if 'tcp' in methods:
            # Also try TCP on all IPs if no hosts found yet
            if not discovered_ips:
                try:
                    network = ip_network(cidr, strict=False)
                    # Only enumerate small subnets to avoid very long scans
                    if network.num_addresses <= 256:
                        for ip_obj in network.hosts():
                            ip_str = str(ip_obj)
                            open_ports = self._discover_tcp(ip_str)
                            if open_ports:
                                discovered_ips.setdefault(ip_str, {}).update({
                                    'ip_address': ip_str,
                                    'open_ports': open_ports,
                                })
                except Exception as e:
                    logger.warning(f"TCP subnet sweep failed: {e}")
            else:
                for ip_str in list(discovered_ips.keys()):
                    try:
                        open_ports = self._discover_tcp(ip_str)
                        if open_ports:
                            discovered_ips[ip_str].setdefault(
                                'open_ports', []
                            )
                            existing = discovered_ips[ip_str]['open_ports']
                            discovered_ips[ip_str]['open_ports'] = sorted(
                                set(existing + open_ports)
                            )
                    except Exception as e:
                        logger.debug(f"TCP scan failed for {ip_str}: {e}")

        # Phase 3: DNS resolution
        if 'dns' in methods:
            for ip_str in list(discovered_ips.keys()):
                if not discovered_ips[ip_str].get('hostname'):
                    hostname = self._resolve_hostname(ip_str)
                    if hostname:
                        discovered_ips[ip_str]['hostname'] = hostname

        # Phase 4: OS fingerprinting and service identification
        results = []
        for ip_str, host_data in discovered_ips.items():
            open_ports = host_data.get('open_ports', [])
            services = {}
            for port in open_ports:
                svc = self.PORT_SERVICE_MAP.get(port, f'unknown-{port}')
                services[str(port)] = svc

            os_guess, os_confidence = self._fingerprint_os(ip_str, open_ports)

            host_id = self._upsert_host(
                ip_address=ip_str,
                discovery_method=','.join(methods),
                hostname=host_data.get('hostname'),
                mac_address=host_data.get('mac_address'),
                os_guess=os_guess,
                os_confidence=os_confidence,
                open_ports=open_ports,
                services=services,
            )

            host_dict = {
                'host_id': host_id,
                'ip_address': ip_str,
                'hostname': host_data.get('hostname'),
                'mac_address': host_data.get('mac_address'),
                'os_guess': os_guess,
                'os_confidence': os_confidence,
                'open_ports': open_ports,
                'services': services,
                'discovery_method': ','.join(methods),
                'status': 'live',
            }
            results.append(host_dict)

        logger.info(
            f"Discovery complete: {len(results)} live hosts found on {cidr}"
        )
        return results

    def _discover_arp(self, cidr: str) -> List[Dict]:
        """
        ARP-based discovery.
        Uses ``arp -a`` on Windows or ``ip neigh`` on Linux.
        Optionally attempts ``nmap -sn`` if available.
        """
        hosts: List[Dict] = []
        network = ip_network(cidr, strict=False)

        if sys.platform == 'win32':
            hosts = self._arp_windows(network)
        else:
            hosts = self._arp_linux(network)

        # Supplement with nmap -sn if available
        try:
            nmap_path = paths.find_tool('nmap')
            if nmap_path:
                result = subprocess.run(
                    [str(nmap_path), '-sn', '-PR', cidr],
                    capture_output=True, text=True, timeout=120
                )
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        match = re.search(
                            r'(\d+\.\d+\.\d+\.\d+)', line
                        )
                        if match:
                            ip_str = match.group(1)
                            if ip_address(ip_str) in network:
                                existing = [
                                    h for h in hosts
                                    if h['ip_address'] == ip_str
                                ]
                                if not existing:
                                    hosts.append({
                                        'ip_address': ip_str,
                                        'discovery_method': 'arp_nmap',
                                    })
                    elif 'MAC Address:' in line:
                        mac_match = re.search(
                            r'MAC Address:\s+([0-9A-Fa-f:]+)', line
                        )
                        if mac_match and hosts:
                            hosts[-1]['mac_address'] = mac_match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Nmap ARP scan not available: {e}")
        except Exception as e:
            logger.debug(f"Nmap ARP scan error: {e}")

        logger.info(f"ARP discovery found {len(hosts)} hosts")
        return hosts

    def _arp_windows(self, network: IPv4Network) -> List[Dict]:
        """Parse Windows ``arp -a`` output."""
        hosts = []
        try:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                match = re.match(
                    r'\s*(\d+\.\d+\.\d+\.\d+)\s+'
                    r'([0-9a-fA-F-]+)\s+'
                    r'(dynamic|static)',
                    line.strip()
                )
                if match:
                    ip_str = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    try:
                        if ip_address(ip_str) in network:
                            hosts.append({
                                'ip_address': ip_str,
                                'mac_address': mac,
                                'discovery_method': 'arp',
                            })
                    except ValueError:
                        pass
        except Exception as e:
            logger.warning(f"Windows ARP scan failed: {e}")
        return hosts

    def _arp_linux(self, network: IPv4Network) -> List[Dict]:
        """Parse Linux ``ip neigh`` output."""
        hosts = []
        try:
            result = subprocess.run(
                ['ip', 'neigh'], capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip_str = parts[0]
                    try:
                        if ip_address(ip_str) in network:
                            mac = None
                            for i, p in enumerate(parts):
                                if p == 'lladdr' and i + 1 < len(parts):
                                    mac = parts[i + 1].upper()
                                    break
                            state = parts[-1] if parts else ''
                            if state not in ('FAILED',):
                                hosts.append({
                                    'ip_address': ip_str,
                                    'mac_address': mac,
                                    'discovery_method': 'arp',
                                })
                    except ValueError:
                        pass
        except FileNotFoundError:
            # Fallback to arp command
            try:
                result = subprocess.run(
                    ['arp', '-an'], capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.split('\n'):
                    match = re.search(
                        r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)',
                        line
                    )
                    if match:
                        ip_str = match.group(1)
                        mac = match.group(2).upper()
                        try:
                            if ip_address(ip_str) in network:
                                hosts.append({
                                    'ip_address': ip_str,
                                    'mac_address': mac,
                                    'discovery_method': 'arp',
                                })
                        except ValueError:
                            pass
            except Exception as e2:
                logger.warning(f"Linux ARP fallback failed: {e2}")
        except Exception as e:
            logger.warning(f"Linux ARP scan failed: {e}")
        return hosts

    def _discover_icmp(self, cidr: str) -> List[Dict]:
        """
        ICMP ping sweep.
        Pings each host in the subnet using subprocess ping.
        Only attempts subnets of /24 or smaller to avoid very long sweeps.
        """
        hosts = []
        network = ip_network(cidr, strict=False)

        if network.num_addresses > 256:
            logger.warning(
                f"ICMP sweep skipped for {cidr}: subnet too large "
                f"({network.num_addresses} addresses). Use /24 or smaller."
            )
            return hosts

        ping_flag = '-n' if sys.platform == 'win32' else '-c'
        timeout_flag = '-w' if sys.platform == 'win32' else '-W'
        # Windows -w is in milliseconds, Linux -W is in seconds
        timeout_val = '500' if sys.platform == 'win32' else '1'

        for ip_obj in network.hosts():
            ip_str = str(ip_obj)
            try:
                cmd = ['ping', ping_flag, '1', timeout_flag, timeout_val, ip_str]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    ttl = self._extract_ttl(result.stdout)
                    hosts.append({
                        'ip_address': ip_str,
                        'ttl': ttl,
                        'discovery_method': 'icmp',
                    })
            except (subprocess.TimeoutExpired, Exception):
                pass

        logger.info(f"ICMP sweep found {len(hosts)} hosts on {cidr}")
        return hosts

    def _extract_ttl(self, ping_output: str) -> Optional[int]:
        """Extract TTL value from ping output."""
        match = re.search(r'[Tt][Tt][Ll][=: ]+(\d+)', ping_output)
        if match:
            return int(match.group(1))
        return None

    def _discover_tcp(self, ip: str,
                      ports: List[int] = None) -> List[int]:
        """
        TCP connect scan on common ports for a single IP.

        Args:
            ip: Target IP address.
            ports: List of ports to scan. Defaults to DEFAULT_PORTS.

        Returns:
            List of open port numbers.
        """
        if ports is None:
            ports = self.DEFAULT_PORTS

        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except (socket.timeout, socket.error, OSError):
                pass

        if open_ports:
            logger.debug(f"TCP scan {ip}: open ports {open_ports}")
        return open_ports

    def _fingerprint_os(self, ip: str,
                        open_ports: List[int]) -> Tuple[str, int]:
        """
        Guess operating system from open ports and TTL.

        Heuristics:
        - Port 135 or 445 open + TTL ~128 -> Windows (90%)
        - Port 135 or 445 open (no TTL) -> Windows (80%)
        - Port 22 open + TTL ~64 -> Linux (85%)
        - Port 22 open (no TTL) -> Linux (75%)
        - Port 161 open + no 22/135 -> Network device (70%)
        - Only port 80/443 -> Unknown (40%)
        - No data -> Unknown (0%)

        Returns:
            Tuple of (os_guess, confidence_percentage)
        """
        if not open_ports:
            return ('unknown', 0)

        # Try to get TTL from a quick ping
        ttl = None
        try:
            ping_flag = '-n' if sys.platform == 'win32' else '-c'
            timeout_flag = '-w' if sys.platform == 'win32' else '-W'
            timeout_val = '500' if sys.platform == 'win32' else '1'
            result = subprocess.run(
                ['ping', ping_flag, '1', timeout_flag, timeout_val, ip],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ttl = self._extract_ttl(result.stdout)
        except Exception:
            pass

        has_smb = 135 in open_ports or 445 in open_ports
        has_rdp = 3389 in open_ports
        has_ssh = 22 in open_ports
        has_snmp = 161 in open_ports
        has_winrm = 5985 in open_ports or 5986 in open_ports

        # Windows indicators
        if has_smb or has_rdp or has_winrm:
            if ttl is not None and 100 <= ttl <= 128:
                return ('windows', 95)
            if ttl is not None and ttl > 128:
                return ('windows', 90)
            return ('windows', 80)

        # Linux indicators
        if has_ssh:
            if ttl is not None and 50 <= ttl <= 64:
                return ('linux', 90)
            if ttl is not None and ttl <= 64:
                return ('linux', 85)
            return ('linux', 75)

        # Network device indicators
        if has_snmp and not has_ssh and not has_smb:
            return ('network_device', 70)

        # SNMP + SSH could be a managed Linux/network device
        if has_snmp and has_ssh:
            return ('network_device', 55)

        # TTL-only heuristic
        if ttl is not None:
            if 100 <= ttl <= 128:
                return ('windows', 50)
            elif 50 <= ttl <= 64:
                return ('linux', 50)
            elif ttl <= 32:
                return ('network_device', 40)

        return ('unknown', 20)

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup for an IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _discover_ad_hosts(self) -> List[Dict]:
        """
        Discover hosts from Active Directory via PowerShell Get-ADComputer.
        Only works on Windows domain-joined machines.

        Returns:
            List of host dicts with hostname, ip_address, os info.
        """
        hosts = []

        if sys.platform != 'win32':
            logger.debug("AD discovery skipped: not on Windows")
            return hosts

        try:
            ps_cmd = (
                "Get-ADComputer -Filter * -Properties "
                "Name,IPv4Address,OperatingSystem,Enabled | "
                "Where-Object { $_.Enabled -eq $true } | "
                "Select-Object Name,IPv4Address,OperatingSystem | "
                "ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for entry in data:
                    name = entry.get('Name', '')
                    ip_addr = entry.get('IPv4Address', '')
                    os_name = (entry.get('OperatingSystem') or '').lower()

                    if not ip_addr:
                        # Try to resolve hostname
                        try:
                            ip_addr = socket.gethostbyname(name)
                        except (socket.gaierror, OSError):
                            continue

                    os_guess = 'unknown'
                    if 'windows' in os_name:
                        os_guess = 'windows'
                    elif 'linux' in os_name or 'ubuntu' in os_name:
                        os_guess = 'linux'

                    hosts.append({
                        'ip_address': ip_addr,
                        'hostname': name,
                        'os_guess': os_guess,
                        'os_confidence': 85,
                        'discovery_method': 'ad',
                    })

            logger.info(f"AD discovery found {len(hosts)} hosts")
        except FileNotFoundError:
            logger.debug("PowerShell not available for AD discovery")
        except json.JSONDecodeError as e:
            logger.warning(f"AD discovery JSON parse error: {e}")
        except subprocess.TimeoutExpired:
            logger.warning("AD discovery timed out")
        except Exception as e:
            logger.warning(f"AD discovery failed: {e}")

        return hosts

    def _discover_cloud_instances(self) -> List[Dict]:
        """
        Discover cloud instances via CLI tools (AWS, Azure, GCloud).
        Tries each provider and collects what it can.

        Returns:
            List of host dicts.
        """
        hosts = []

        # --- AWS ---
        hosts.extend(self._discover_aws())

        # --- Azure ---
        hosts.extend(self._discover_azure())

        # --- GCP ---
        hosts.extend(self._discover_gcp())

        logger.info(f"Cloud discovery found {len(hosts)} instances total")
        return hosts

    def _discover_aws(self) -> List[Dict]:
        """Discover AWS EC2 instances via aws CLI."""
        hosts = []
        try:
            result = subprocess.run(
                ['aws', 'ec2', 'describe-instances',
                 '--query',
                 'Reservations[].Instances[].{'
                 'IP:PrivateIpAddress,Name:Tags[?Key==`Name`].Value|[0],'
                 'OS:Platform,State:State.Name}',
                 '--output', 'json'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                instances = json.loads(result.stdout)
                for inst in instances:
                    if inst.get('State') != 'running':
                        continue
                    ip_addr = inst.get('IP', '')
                    if not ip_addr:
                        continue
                    os_guess = 'windows' if inst.get('OS') == 'windows' else 'linux'
                    hosts.append({
                        'ip_address': ip_addr,
                        'hostname': inst.get('Name', ''),
                        'os_guess': os_guess,
                        'os_confidence': 80,
                        'discovery_method': 'cloud_aws',
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.debug(f"AWS discovery error: {e}")
        return hosts

    def _discover_azure(self) -> List[Dict]:
        """Discover Azure VMs via az CLI."""
        hosts = []
        try:
            result = subprocess.run(
                ['az', 'vm', 'list', '-d', '--output', 'json'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                vms = json.loads(result.stdout)
                for vm in vms:
                    if vm.get('powerState') != 'VM running':
                        continue
                    ip_addr = vm.get('privateIps', '').split(',')[0].strip()
                    if not ip_addr:
                        continue
                    os_type = (vm.get('storageProfile', {})
                               .get('osDisk', {})
                               .get('osType', '')).lower()
                    os_guess = os_type if os_type in ('windows', 'linux') else 'unknown'
                    hosts.append({
                        'ip_address': ip_addr,
                        'hostname': vm.get('name', ''),
                        'os_guess': os_guess,
                        'os_confidence': 80,
                        'discovery_method': 'cloud_azure',
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.debug(f"Azure discovery error: {e}")
        return hosts

    def _discover_gcp(self) -> List[Dict]:
        """Discover GCP instances via gcloud CLI."""
        hosts = []
        try:
            result = subprocess.run(
                ['gcloud', 'compute', 'instances', 'list',
                 '--format=json'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                instances = json.loads(result.stdout)
                for inst in instances:
                    if inst.get('status') != 'RUNNING':
                        continue
                    nics = inst.get('networkInterfaces', [])
                    ip_addr = nics[0].get('networkIP', '') if nics else ''
                    if not ip_addr:
                        continue
                    hosts.append({
                        'ip_address': ip_addr,
                        'hostname': inst.get('name', ''),
                        'os_guess': 'unknown',
                        'os_confidence': 30,
                        'discovery_method': 'cloud_gcp',
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logger.debug(f"GCP discovery error: {e}")
        return hosts

    # ------------------------------------------------------------------
    # Registration and queries
    # ------------------------------------------------------------------
    def register_to_inventory(self, host_ids: List[str] = None):
        """
        Push discovered hosts to the asset inventory.
        If host_ids is None, registers all non-registered live hosts.
        """
        if get_asset_inventory is None:
            logger.warning("Asset inventory module not available")
            return

        inventory = get_asset_inventory()

        with self._conn() as conn:
            if host_ids:
                placeholders = ','.join('?' for _ in host_ids)
                rows = conn.execute(
                    f"SELECT * FROM discovered_hosts "
                    f"WHERE host_id IN ({placeholders})",
                    host_ids
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM discovered_hosts "
                    "WHERE status = 'live' AND auto_registered = 0"
                ).fetchall()

            registered = 0
            for row in rows:
                host = self._row_to_dict(row)
                try:
                    os_type_map = {
                        'windows': 'windows',
                        'linux': 'linux',
                        'network_device': 'network',
                        'unknown': 'other',
                    }
                    asset_type_map = {
                        'windows': 'server',
                        'linux': 'server',
                        'network_device': 'network_device',
                        'unknown': 'server',
                    }

                    inventory.add_asset(
                        hostname=host.get('hostname') or host['ip_address'],
                        ip_address=host['ip_address'],
                        mac_address=host.get('mac_address', ''),
                        os_type=os_type_map.get(
                            host.get('os_guess', 'unknown'), 'other'
                        ),
                        asset_type=asset_type_map.get(
                            host.get('os_guess', 'unknown'), 'server'
                        ),
                        metadata={
                            'discovered_by': 'discovery_engine',
                            'discovery_method': host.get('discovery_method'),
                            'os_confidence': host.get('os_confidence', 0),
                            'open_ports': host.get('open_ports', []),
                        },
                    )

                    conn.execute(
                        "UPDATE discovered_hosts SET auto_registered = 1 "
                        "WHERE host_id = ?",
                        (host['host_id'],)
                    )
                    registered += 1
                except Exception as e:
                    logger.warning(
                        f"Failed to register host {host['host_id']}: {e}"
                    )

        logger.info(f"Registered {registered} hosts to asset inventory")

    def get_discovered_hosts(self, status: str = None,
                             os_guess: str = None) -> List[Dict]:
        """
        Retrieve discovered hosts with optional filters.

        Args:
            status: Filter by status ('live', 'unreachable').
            os_guess: Filter by OS guess ('windows', 'linux',
                      'network_device', 'unknown').

        Returns:
            List of host dicts.
        """
        clauses = []
        params = []

        if status:
            clauses.append("status = ?")
            params.append(status)
        if os_guess:
            clauses.append("os_guess = ?")
            params.append(os_guess)

        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        sql = f"SELECT * FROM discovered_hosts{where} ORDER BY last_seen DESC"

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def rescan(self, host_id: str) -> Dict:
        """
        Rescan a specific previously-discovered host.

        Args:
            host_id: The host_id to rescan.

        Returns:
            Updated host dict, or empty dict if not found.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM discovered_hosts WHERE host_id = ?",
                (host_id,)
            ).fetchone()

        if not row:
            logger.warning(f"Host {host_id} not found for rescan")
            return {}

        host = self._row_to_dict(row)
        ip_str = host['ip_address']

        # TCP scan
        open_ports = self._discover_tcp(ip_str)

        # Hostname resolution
        hostname = self._resolve_hostname(ip_str) or host.get('hostname')

        # OS fingerprint
        os_guess, os_confidence = self._fingerprint_os(ip_str, open_ports)

        # Build services
        services = {}
        for port in open_ports:
            services[str(port)] = self.PORT_SERVICE_MAP.get(
                port, f'unknown-{port}'
            )

        # Check if host is live (we got open ports or can ping it)
        status = 'live' if open_ports else 'unreachable'
        if not open_ports:
            # Try a quick ping
            try:
                ping_flag = '-n' if sys.platform == 'win32' else '-c'
                timeout_flag = '-w' if sys.platform == 'win32' else '-W'
                timeout_val = '500' if sys.platform == 'win32' else '1'
                result = subprocess.run(
                    ['ping', ping_flag, '1', timeout_flag, timeout_val, ip_str],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    status = 'live'
            except Exception:
                pass

        # Update database
        self._upsert_host(
            ip_address=ip_str,
            discovery_method='rescan',
            hostname=hostname,
            mac_address=host.get('mac_address'),
            os_guess=os_guess,
            os_confidence=os_confidence,
            open_ports=open_ports,
            services=services,
        )

        # Update status
        with self._conn() as conn:
            conn.execute(
                "UPDATE discovered_hosts SET status = ? WHERE host_id = ?",
                (status, host_id)
            )

        # Return updated host
        with self._conn() as conn:
            updated = conn.execute(
                "SELECT * FROM discovered_hosts WHERE host_id = ?",
                (host_id,)
            ).fetchone()
            return self._row_to_dict(updated) if updated else {}

    def get_statistics(self) -> Dict:
        """
        Return comprehensive discovery statistics.

        Returns:
            Dict with total hosts, status breakdown, OS breakdown, etc.
        """
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM discovered_hosts"
            ).fetchone()[0]

            live = conn.execute(
                "SELECT COUNT(*) FROM discovered_hosts WHERE status = 'live'"
            ).fetchone()[0]

            unreachable = conn.execute(
                "SELECT COUNT(*) FROM discovered_hosts "
                "WHERE status = 'unreachable'"
            ).fetchone()[0]

            registered = conn.execute(
                "SELECT COUNT(*) FROM discovered_hosts "
                "WHERE auto_registered = 1"
            ).fetchone()[0]

            # OS breakdown
            os_rows = conn.execute(
                "SELECT os_guess, COUNT(*) AS cnt FROM discovered_hosts "
                "GROUP BY os_guess"
            ).fetchall()
            by_os = {r['os_guess']: r['cnt'] for r in os_rows}

            # Discovery method breakdown
            method_rows = conn.execute(
                "SELECT discovery_method, COUNT(*) AS cnt "
                "FROM discovered_hosts GROUP BY discovery_method"
            ).fetchall()
            by_method = {r['discovery_method']: r['cnt'] for r in method_rows}

            # Recently discovered (last 24h)
            cutoff = (
                datetime.utcnow() - timedelta(hours=24)
            ).isoformat()
            recent = conn.execute(
                "SELECT COUNT(*) FROM discovered_hosts "
                "WHERE first_seen >= ?",
                (cutoff,)
            ).fetchone()[0]

            # Average OS confidence
            avg_conf_row = conn.execute(
                "SELECT AVG(os_confidence) FROM discovered_hosts "
                "WHERE os_confidence > 0"
            ).fetchone()
            avg_confidence = round(avg_conf_row[0], 1) if avg_conf_row[0] else 0

        return {
            'total_hosts': total,
            'live': live,
            'unreachable': unreachable,
            'registered_to_inventory': registered,
            'by_os': by_os,
            'by_discovery_method': by_method,
            'discovered_last_24h': recent,
            'avg_os_confidence': avg_confidence,
        }

    def scan_subnet(self, cidr: str) -> Dict:
        """
        Convenience method: discover, fingerprint, and return summary.

        Args:
            cidr: Network CIDR to scan.

        Returns:
            Dict with hosts list and summary statistics.
        """
        hosts = self.discover_network(
            cidr=cidr, methods=['arp', 'icmp', 'tcp', 'dns']
        )
        stats = self.get_statistics()

        return {
            'cidr': cidr,
            'hosts_found': len(hosts),
            'hosts': hosts,
            'statistics': stats,
        }


# ======================================================================
# Singleton accessor
# ======================================================================
_discovery_engine: Optional[DiscoveryEngine] = None


def get_discovery_engine() -> DiscoveryEngine:
    """Get the DiscoveryEngine singleton."""
    global _discovery_engine
    if _discovery_engine is None:
        _discovery_engine = DiscoveryEngine()
    return _discovery_engine


# ======================================================================
# Self-test
# ======================================================================
if __name__ == '__main__':
    engine = get_discovery_engine()
    print(f"Discovery DB: {engine.db_path}")
    print(f"DB exists: {engine.db_path.exists()}")

    # Detect local subnet
    subnet = engine._detect_local_subnet()
    print(f"Detected subnet: {subnet}")

    # Quick TCP scan of localhost
    local_ports = engine._discover_tcp('127.0.0.1')
    print(f"Localhost open ports: {local_ports}")

    # Get statistics
    stats = engine.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
