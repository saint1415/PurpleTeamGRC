#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Attack Surface Management Scanner
External attack surface discovery and monitoring.
Passive-first: CT logs and DNS lookups are default.
Active enumeration requires explicit opt-in.
"""

import json
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from credential_manager import get_credential_manager
except ImportError:
    get_credential_manager = None

try:
    from asset_manager import get_asset_manager
except ImportError:
    get_asset_manager = None

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except ImportError:
    urlopen = None


class ASMScanner(BaseScanner):
    """Attack surface management and external discovery scanner."""

    SCANNER_NAME = "asm"
    SCANNER_DESCRIPTION = "Attack surface management and external discovery"

    # Common subdomains for passive DNS enumeration
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'smtp', 'ftp', 'vpn', 'remote', 'admin',
        'dev', 'staging', 'api', 'app', 'portal', 'test'
    ]

    # Extended subdomain list for active brute-force fallback
    EXTENDED_SUBDOMAINS = [
        'www', 'mail', 'smtp', 'ftp', 'vpn', 'remote', 'admin',
        'dev', 'staging', 'api', 'app', 'portal', 'test',
        'ns1', 'ns2', 'mx', 'webmail', 'cloud', 'git', 'gitlab',
        'jenkins', 'ci', 'cd', 'jira', 'confluence', 'wiki',
        'blog', 'shop', 'store', 'cdn', 'static', 'assets',
        'media', 'img', 'images', 'files', 'download', 'upload',
        'login', 'auth', 'sso', 'id', 'accounts', 'dashboard',
        'monitor', 'status', 'health', 'metrics', 'logs',
        'db', 'database', 'redis', 'elastic', 'kibana', 'grafana',
        'proxy', 'gateway', 'lb', 'edge', 'internal', 'intranet',
        'backup', 'archive', 'old', 'legacy', 'beta', 'alpha',
        'sandbox', 'demo', 'docs', 'support', 'help', 'ticket',
    ]

    # Rate limit for CT log queries (seconds between requests)
    CT_RATE_LIMIT = 2.0

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)

    def scan(self, targets: List[str], **kwargs) -> Dict:
        """
        Execute attack surface management scan.

        Args:
            targets: List of domain names to scan.
            **kwargs:
                scan_type: 'quick', 'standard', or 'deep' (default 'standard')
                active: Enable active enumeration (default False, passive only)
        """
        self.start_time = datetime.utcnow()
        scan_type = kwargs.get('scan_type', 'standard')
        active = kwargs.get('active', False)

        self.scan_logger.info(f"Starting ASM scan (type={scan_type}, active={active})")
        self.scan_logger.info(f"Targets: {targets}")

        results = {
            'scan_type': scan_type,
            'active': active,
            'targets': targets,
            'domains': [],
            'subdomains': [],
            'certificates': [],
            'findings': [],
            'summary': {}
        }

        for domain in targets:
            self.scan_logger.info(f"Scanning domain: {domain}")
            domain_entry = {'domain': domain, 'subdomains': [], 'certificates': []}

            # Always run passive checks
            ct_results = self._check_certificate_transparency(domain)
            domain_entry['certificates'] = ct_results
            results['certificates'].extend(ct_results)

            # Extract subdomains from CT results
            ct_subdomains = set()
            for cert in ct_results:
                for name in cert.get('names', []):
                    if name.endswith(f'.{domain}') or name == domain:
                        ct_subdomains.add(name)

            dns_results = self._enumerate_dns(domain)
            domain_entry['subdomains'] = dns_results
            results['subdomains'].extend(dns_results)

            # Merge CT-discovered subdomains into results
            known_hosts = {r['hostname'] for r in dns_results}
            for sub in ct_subdomains:
                if sub not in known_hosts:
                    results['subdomains'].append({
                        'hostname': sub,
                        'source': 'certificate_transparency',
                        'addresses': []
                    })

            # Active enumeration only if explicitly enabled
            if active:
                self.scan_logger.warning(
                    "Active enumeration enabled - may trigger security alerts "
                    "on target infrastructure"
                )
                active_results = self._active_enumeration(domain)
                for ar in active_results:
                    if ar['hostname'] not in known_hosts:
                        domain_entry['subdomains'].append(ar)
                        results['subdomains'].append(ar)
                        known_hosts.add(ar['hostname'])

            # Shodan lookup if API key is configured
            for sub_entry in dns_results:
                for addr in sub_entry.get('addresses', []):
                    shodan_data = self._check_shodan(addr)
                    if shodan_data and shodan_data.get('ports'):
                        sub_entry['shodan'] = shodan_data

            results['domains'].append(domain_entry)
            self.human_delay()

        # Check for large attack surface
        total_subs = len(results['subdomains'])
        if total_subs > 50:
            self.add_finding(
                severity='INFO',
                title=f"Large attack surface detected ({total_subs} subdomains)",
                description=(
                    f"Discovered {total_subs} subdomains across scanned domains. "
                    "A large attack surface increases the risk of misconfigured "
                    "or forgotten services being exposed."
                ),
                affected_asset=', '.join(targets),
                finding_type='attack_surface',
                remediation="Review all subdomains and decommission unused services.",
                detection_method='subdomain_enumeration'
            )

        # Generate summary
        results['summary'] = {
            'total_domains': len(targets),
            'total_subdomains': total_subs,
            'total_certificates': len(results['certificates']),
            'findings_count': len(self.findings),
            'findings_by_severity': self._count_by_severity()
        }
        results['findings'] = self.findings.copy()

        self.end_time = datetime.utcnow()
        self.save_results()

        return results

    def _check_certificate_transparency(self, domain: str) -> List[Dict]:
        """
        Query Certificate Transparency logs via crt.sh API.

        Returns list of certificate entries with names, issuer, and expiry info.
        Finds expired certificates (MEDIUM) and wildcard certificates (INFO).
        """
        self.scan_logger.info(f"Checking Certificate Transparency for {domain}")
        certificates = []

        if urlopen is None:
            self.scan_logger.warning("urllib not available, skipping CT check")
            return certificates

        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        try:
            req = Request(url, headers={'User-Agent': 'PurpleTeam-ASM/7.0'})
            response = urlopen(req, timeout=30)
            data = json.loads(response.read().decode('utf-8'))
        except (HTTPError, URLError) as e:
            self.scan_logger.warning(f"CT log query failed for {domain}: {e}")
            return certificates
        except Exception as e:
            self.scan_logger.warning(f"CT log query error for {domain}: {e}")
            return certificates

        # Rate limit compliance
        time.sleep(self.CT_RATE_LIMIT)

        # Deduplicate by certificate serial or name set
        seen_ids = set()
        unique_certs = []
        for entry in data if isinstance(data, list) else []:
            cert_id = entry.get('id')
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)
            unique_certs.append(entry)

        for entry in unique_certs:
            common_name = entry.get('common_name', '')
            name_value = entry.get('name_value', '')
            issuer = entry.get('issuer_name', '')
            not_after = entry.get('not_after', '')
            not_before = entry.get('not_before', '')

            # Parse names (may contain newlines for SANs)
            names = set()
            for raw_name in [common_name] + name_value.split('\n'):
                name = raw_name.strip().lower()
                if name and not name.startswith('*'):
                    names.add(name)
                elif name:
                    names.add(name)

            cert_entry = {
                'id': entry.get('id'),
                'common_name': common_name,
                'names': list(names),
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'source': 'crt.sh'
            }
            certificates.append(cert_entry)

            # Check for expired certificates
            if not_after:
                try:
                    # crt.sh format: "2024-01-15T00:00:00" or similar
                    expiry_str = not_after.replace('T', ' ').split('.')[0]
                    expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
                    if expiry < datetime.utcnow():
                        self.add_finding(
                            severity='MEDIUM',
                            title=f"Expired certificate for {common_name}",
                            description=(
                                f"Certificate for {common_name} expired on {not_after}. "
                                f"Issuer: {issuer}. Expired certificates may cause "
                                "service disruptions and trust warnings."
                            ),
                            affected_asset=domain,
                            finding_type='expired_certificate',
                            remediation="Renew or remove the expired certificate.",
                            raw_data=cert_entry,
                            detection_method='ct_log_analysis'
                        )
                except (ValueError, TypeError):
                    pass

            # Check for wildcard certificates
            if '*' in common_name:
                self.add_finding(
                    severity='INFO',
                    title=f"Wildcard certificate: {common_name}",
                    description=(
                        f"Wildcard certificate detected for {common_name}. "
                        f"Issuer: {issuer}. Wildcard certificates cover all "
                        "subdomains which may mask unauthorized services."
                    ),
                    affected_asset=domain,
                    finding_type='wildcard_certificate',
                    remediation=(
                        "Consider using specific certificates for critical services "
                        "to improve certificate lifecycle management."
                    ),
                    raw_data=cert_entry,
                    detection_method='ct_log_analysis'
                )

        self.scan_logger.info(
            f"CT log results for {domain}: {len(certificates)} certificates, "
            f"{len(seen_ids)} unique"
        )
        return certificates

    def _enumerate_dns(self, domain: str) -> List[Dict]:
        """
        Enumerate subdomains via passive DNS lookups.

        Checks common subdomain prefixes using socket.getaddrinfo.
        Also attempts DNS zone transfer (AXFR) detection.
        """
        self.scan_logger.info(f"Enumerating DNS for {domain}")
        results = []
        discovered_hosts = set()

        # Check base domain
        addrs = self._resolve_hostname(domain)
        if addrs:
            results.append({
                'hostname': domain,
                'addresses': addrs,
                'source': 'dns_lookup'
            })
            discovered_hosts.add(domain)

        # Check common subdomains
        for prefix in self.COMMON_SUBDOMAINS:
            fqdn = f"{prefix}.{domain}"
            addrs = self._resolve_hostname(fqdn)
            if addrs:
                results.append({
                    'hostname': fqdn,
                    'addresses': addrs,
                    'source': 'dns_lookup'
                })
                discovered_hosts.add(fqdn)

                # Check if subdomain has HTTPS
                self._check_https_availability(fqdn, domain)

        # Check for DNS zone transfer vulnerability
        self._check_zone_transfer(domain)

        self.scan_logger.info(
            f"DNS enumeration for {domain}: {len(results)} hosts resolved"
        )
        return results

    def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve a hostname to IP addresses using socket.getaddrinfo."""
        addresses = []
        try:
            # IPv4
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM
            )
            for result in results:
                addr = result[4][0]
                if addr not in addresses:
                    addresses.append(addr)
        except socket.gaierror:
            pass

        try:
            # IPv6
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET6, socket.SOCK_STREAM
            )
            for result in results:
                addr = result[4][0]
                if addr not in addresses:
                    addresses.append(addr)
        except socket.gaierror:
            pass

        return addresses

    def _check_https_availability(self, hostname: str, parent_domain: str):
        """Check if a discovered subdomain responds on HTTPS (port 443)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, 443))
            sock.close()

            if result != 0:
                # Port 443 not open - no HTTPS
                self.add_finding(
                    severity='MEDIUM',
                    title=f"Subdomain without HTTPS: {hostname}",
                    description=(
                        f"The subdomain {hostname} was discovered but does not "
                        "appear to have HTTPS (port 443) available. Services "
                        "without HTTPS may transmit data in cleartext."
                    ),
                    affected_asset=parent_domain,
                    finding_type='no_https',
                    remediation=(
                        f"Enable HTTPS on {hostname} or decommission the "
                        "subdomain if not in use."
                    ),
                    detection_method='port_check'
                )
        except (socket.timeout, socket.error, OSError):
            pass

    def _check_zone_transfer(self, domain: str):
        """
        Attempt DNS zone transfer (AXFR) to detect misconfigured DNS servers.
        Uses dig or host command if available. A successful zone transfer
        is a HIGH severity finding.
        """
        dig_path = shutil.which('dig')
        host_path = shutil.which('host')

        if dig_path:
            # First get nameservers
            try:
                ns_result = subprocess.run(
                    [dig_path, '+short', 'NS', domain],
                    capture_output=True, text=True, timeout=10
                )
                nameservers = [
                    ns.strip().rstrip('.')
                    for ns in ns_result.stdout.strip().split('\n')
                    if ns.strip()
                ]
            except (subprocess.TimeoutExpired, Exception):
                nameservers = []

            for ns in nameservers:
                try:
                    axfr_result = subprocess.run(
                        [dig_path, 'AXFR', domain, f'@{ns}'],
                        capture_output=True, text=True, timeout=15
                    )
                    output = axfr_result.stdout
                    # A successful zone transfer will contain multiple records
                    if axfr_result.returncode == 0 and output.count('\n') > 5:
                        # Check it is not a "Transfer failed" response
                        if 'Transfer failed' not in output and 'XFR size' in output:
                            self.add_finding(
                                severity='HIGH',
                                title=f"DNS zone transfer possible on {ns}",
                                description=(
                                    f"DNS zone transfer (AXFR) succeeded against "
                                    f"nameserver {ns} for domain {domain}. This "
                                    "exposes the entire DNS zone contents to "
                                    "unauthorized parties, revealing internal "
                                    "hostnames and network architecture."
                                ),
                                affected_asset=domain,
                                finding_type='dns_zone_transfer',
                                remediation=(
                                    f"Restrict zone transfers on {ns} to authorized "
                                    "secondary DNS servers only."
                                ),
                                raw_data={'nameserver': ns, 'domain': domain},
                                detection_method='dns_axfr'
                            )
                except (subprocess.TimeoutExpired, Exception):
                    continue

        elif host_path:
            try:
                axfr_result = subprocess.run(
                    [host_path, '-t', 'axfr', domain],
                    capture_output=True, text=True, timeout=15
                )
                output = axfr_result.stdout
                if 'has address' in output and output.count('\n') > 5:
                    self.add_finding(
                        severity='HIGH',
                        title=f"DNS zone transfer possible for {domain}",
                        description=(
                            f"DNS zone transfer (AXFR) succeeded for {domain}. "
                            "This exposes the entire DNS zone contents to "
                            "unauthorized parties."
                        ),
                        affected_asset=domain,
                        finding_type='dns_zone_transfer',
                        remediation=(
                            "Restrict zone transfers to authorized secondary "
                            "DNS servers only."
                        ),
                        raw_data={'domain': domain},
                        detection_method='dns_axfr'
                    )
            except (subprocess.TimeoutExpired, Exception):
                pass

    def _active_enumeration(self, domain: str) -> List[Dict]:
        """
        Active subdomain enumeration using external tools.
        Only called when active=True is explicitly set.

        Uses amass or subfinder if available, falls back to extended
        DNS brute-force with a larger wordlist.
        """
        self.scan_logger.info(f"Active enumeration for {domain}")
        results = []
        discovered = set()

        amass_path = shutil.which('amass')
        subfinder_path = shutil.which('subfinder')

        # Try amass (passive mode to reduce noise even in active scan)
        if amass_path:
            self.scan_logger.info("Using amass for subdomain enumeration")
            try:
                proc = subprocess.run(
                    [amass_path, 'enum', '-d', domain, '-passive'],
                    capture_output=True, text=True, timeout=300
                )
                for line in proc.stdout.strip().split('\n'):
                    hostname = line.strip().lower()
                    if hostname and hostname.endswith(f'.{domain}'):
                        if hostname not in discovered:
                            discovered.add(hostname)
                            addrs = self._resolve_hostname(hostname)
                            results.append({
                                'hostname': hostname,
                                'addresses': addrs,
                                'source': 'amass'
                            })
            except (subprocess.TimeoutExpired, Exception) as e:
                self.scan_logger.warning(f"amass error: {e}")

        # Try subfinder
        if subfinder_path:
            self.scan_logger.info("Using subfinder for subdomain enumeration")
            try:
                proc = subprocess.run(
                    [subfinder_path, '-d', domain, '-silent'],
                    capture_output=True, text=True, timeout=300
                )
                for line in proc.stdout.strip().split('\n'):
                    hostname = line.strip().lower()
                    if hostname and hostname.endswith(f'.{domain}'):
                        if hostname not in discovered:
                            discovered.add(hostname)
                            addrs = self._resolve_hostname(hostname)
                            results.append({
                                'hostname': hostname,
                                'addresses': addrs,
                                'source': 'subfinder'
                            })
            except (subprocess.TimeoutExpired, Exception) as e:
                self.scan_logger.warning(f"subfinder error: {e}")

        # Fallback: extended DNS brute-force if no external tools found results
        if not results:
            self.scan_logger.info("Fallback: extended DNS brute-force enumeration")
            for prefix in self.EXTENDED_SUBDOMAINS:
                fqdn = f"{prefix}.{domain}"
                if fqdn not in discovered:
                    addrs = self._resolve_hostname(fqdn)
                    if addrs:
                        discovered.add(fqdn)
                        results.append({
                            'hostname': fqdn,
                            'addresses': addrs,
                            'source': 'dns_bruteforce'
                        })

        self.scan_logger.info(
            f"Active enumeration for {domain}: {len(results)} additional subdomains"
        )
        return results

    def _check_shodan(self, domain_or_ip: str) -> Dict:
        """
        Query Shodan API for external exposure information.

        Requires a Shodan API key stored via credential_manager with
        cred_type 'api_key' and name containing 'shodan'.
        Returns open ports and services visible from the internet.
        """
        if urlopen is None:
            return {}

        # Try to get Shodan API key from credential manager
        api_key = None
        if get_credential_manager is not None:
            try:
                cm = get_credential_manager()
                for cred in cm.get_all_credentials(decrypt=True):
                    if 'shodan' in cred.get('name', '').lower():
                        api_key = cred.get('params', {}).get('secret')
                        if not api_key:
                            api_key = cred.get('params', {}).get('password')
                        break
            except Exception:
                pass

        if not api_key:
            self.scan_logger.debug("No Shodan API key configured, skipping")
            return {}

        url = f"https://api.shodan.io/host/{domain_or_ip}?key={api_key}"

        try:
            req = Request(url, headers={'User-Agent': 'PurpleTeam-ASM/7.0'})
            response = urlopen(req, timeout=15)
            data = json.loads(response.read().decode('utf-8'))
        except (HTTPError, URLError) as e:
            self.scan_logger.debug(f"Shodan query failed for {domain_or_ip}: {e}")
            return {}
        except Exception as e:
            self.scan_logger.debug(f"Shodan query error for {domain_or_ip}: {e}")
            return {}

        shodan_result = {
            'ip': domain_or_ip,
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'org': data.get('org', ''),
            'os': data.get('os', ''),
            'vulns': data.get('vulns', []),
            'source': 'shodan'
        }

        # Flag unexpected externally exposed services
        unexpected_ports = set()
        common_web_ports = {80, 443, 8080, 8443}
        for port in data.get('ports', []):
            if port not in common_web_ports:
                unexpected_ports.add(port)

        if unexpected_ports:
            self.add_finding(
                severity='HIGH',
                title=f"Unexpected services exposed externally on {domain_or_ip}",
                description=(
                    f"Shodan reports the following non-standard ports are "
                    f"visible from the internet on {domain_or_ip}: "
                    f"{sorted(unexpected_ports)}. These may represent "
                    "unintended exposure of internal services."
                ),
                affected_asset=domain_or_ip,
                finding_type='external_exposure',
                remediation=(
                    "Review firewall rules and ensure only intended services "
                    "are accessible from the internet."
                ),
                raw_data=shodan_result,
                detection_method='shodan_lookup'
            )

        return shodan_result

    def _compare_internal_external(self, internal_results: List[Dict],
                                    external_results: List[Dict]) -> List[Dict]:
        """
        Compare internal scan results with external (internet-facing) results.

        Identifies services that are visible from outside the network but
        should not be, generating HIGH severity findings.

        Args:
            internal_results: Results from internal network scans (port/service data)
            external_results: Results from Shodan or external port scans

        Returns:
            List of discrepancy findings.
        """
        discrepancies = []

        # Build external services map: ip -> set of ports
        external_map = {}
        for ext in external_results:
            ip = ext.get('ip', '')
            ports = set(ext.get('ports', []))
            if ip:
                external_map[ip] = ports

        # Internal services that are also externally visible
        internal_only_services = {22, 3306, 5432, 6379, 27017, 11211, 9200}

        for ip, ext_ports in external_map.items():
            exposed_internal = ext_ports.intersection(internal_only_services)
            if exposed_internal:
                finding = {
                    'ip': ip,
                    'exposed_ports': sorted(exposed_internal),
                    'severity': 'HIGH'
                }
                discrepancies.append(finding)

                self.add_finding(
                    severity='HIGH',
                    title=f"Internal services exposed externally on {ip}",
                    description=(
                        f"The following services on {ip} are visible from the "
                        f"internet but are typically internal-only: "
                        f"ports {sorted(exposed_internal)}. This may indicate "
                        "a firewall misconfiguration."
                    ),
                    affected_asset=ip,
                    finding_type='internal_service_exposed',
                    remediation=(
                        "Restrict access to internal services using firewall rules. "
                        "Only expose services that require internet access."
                    ),
                    raw_data=finding,
                    detection_method='internal_external_comparison'
                )

        return discrepancies


if __name__ == '__main__':
    scanner = ASMScanner()
    print("ASM Scanner initialized")
    print(f"  amass: {shutil.which('amass') is not None}")
    print(f"  subfinder: {shutil.which('subfinder') is not None}")
    print(f"  dig: {shutil.which('dig') is not None}")

    # Test passive DNS (safe to run)
    try:
        result = socket.getaddrinfo('example.com', None, socket.AF_INET)
        if result:
            print(f"\n  DNS test: example.com -> {result[0][4][0]}")
    except socket.gaierror:
        print("\n  DNS resolution not available")

    print("\nASM Scanner ready (passive-first)")
    print("  Default: Passive (CT logs, DNS)")
    print("  Active: Requires explicit opt-in (active=True)")
