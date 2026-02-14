#!/usr/bin/env python3
"""
Purple Team GRC Platform - Lightweight Scanner Agent
====================================================

Self-contained scanner agent designed to run on remote Windows or Linux
hosts. Requires only Python 3.6+ standard library -- no third-party
packages.

Features:
    - Detects OS and runs appropriate security checks
    - Stores results as JSON in a local directory
    - Can push results to a central server via HTTPS POST
    - Can write results to a shared filesystem path (air-gapped mode)
    - Configurable via JSON config file or environment variables
    - Runs as: scheduled task (Windows), systemd service (Linux),
      or one-shot via ``--once``

Usage:
    python scanner_agent.py --config /opt/purpleteam/agent_config.json
    python scanner_agent.py --once --output ./results
    python scanner_agent.py --config agent_config.json --push
"""

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import textwrap
import time

try:
    from datetime import datetime, timezone
except ImportError:
    from datetime import datetime
    timezone = None

try:
    from pathlib import Path
except ImportError:
    Path = None

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

try:
    import ssl
    HAS_SSL = True
except ImportError:
    HAS_SSL = False

# ======================================================================
# Version and constants
# ======================================================================
AGENT_VERSION = '1.0.0'
DEFAULT_OUTPUT_DIR = '.'
DEFAULT_SCAN_INTERVAL = 14400  # 4 hours in seconds

# Known AI-related process names (for unauthorized AI detection)
KNOWN_AI_PROCESSES = [
    'ollama', 'llama', 'chatgpt', 'copilot', 'bard',
    'localai', 'text-generation', 'lm-studio', 'lmstudio',
    'koboldcpp', 'oobabooga', 'mlc-chat', 'gpt4all',
    'jan', 'anything-llm', 'privateGPT', 'h2ogpt',
    'vllm', 'triton', 'tgi',
]


def _utcnow_iso():
    """Return current UTC time as ISO-8601 string (compatible with 3.6+)."""
    if timezone is not None:
        return datetime.now(timezone.utc).isoformat()
    return datetime.utcnow().isoformat() + 'Z'


def _run_cmd(cmd, timeout=30, shell=False):
    """
    Run a subprocess command and return (returncode, stdout, stderr).
    Safe wrapper that never raises.
    """
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=shell
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, '', 'timeout'
    except FileNotFoundError:
        return -2, '', 'command not found'
    except Exception as e:
        return -3, '', str(e)


def _is_windows():
    return platform.system().lower() == 'windows'


def _is_linux():
    return platform.system().lower() == 'linux'


# ======================================================================
# Configuration
# ======================================================================
class AgentConfig:
    """Agent configuration loaded from file, env vars, or defaults."""

    def __init__(self, config_path=None):
        self.agent_id = ''
        self.central_url = ''
        self.api_key = ''
        self.scan_schedule = '0 */4 * * *'
        self.scan_type = 'quick'
        self.output_dir = DEFAULT_OUTPUT_DIR
        self.shared_path = None

        # Load from file
        if config_path and os.path.isfile(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for key, val in data.items():
                    if hasattr(self, key):
                        setattr(self, key, val)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[WARN] Config file error: {e}", file=sys.stderr)

        # Override from environment variables
        env_map = {
            'PURPLETEAM_AGENT_ID': 'agent_id',
            'PURPLETEAM_CENTRAL_URL': 'central_url',
            'PURPLETEAM_API_KEY': 'api_key',
            'PURPLETEAM_SCAN_TYPE': 'scan_type',
            'PURPLETEAM_OUTPUT_DIR': 'output_dir',
            'PURPLETEAM_SHARED_PATH': 'shared_path',
        }
        for env_key, attr in env_map.items():
            val = os.environ.get(env_key)
            if val:
                setattr(self, attr, val)

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)


# ======================================================================
# Security checks
# ======================================================================
def check_os_info():
    """Gather basic OS information."""
    info = {
        'check': 'os_info',
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
    }

    # Get IPs
    try:
        hostname = socket.gethostname()
        info['ip_addresses'] = socket.gethostbyname_ex(hostname)[2]
    except Exception:
        info['ip_addresses'] = []

    # Uptime (best-effort)
    if _is_linux():
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                info['uptime_hours'] = round(uptime_seconds / 3600, 1)
        except Exception:
            pass
    elif _is_windows():
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime'],
            timeout=10
        )
        if rc == 0 and out:
            info['last_boot'] = out

    info['severity'] = 'INFO'
    info['status'] = 'collected'
    return info


def check_listening_ports():
    """Check listening TCP/UDP ports."""
    finding = {
        'check': 'listening_ports',
        'tcp_ports': [],
        'udp_ports': [],
        'severity': 'INFO',
        'status': 'ok',
    }

    if _is_windows():
        rc, out, _ = _run_cmd(['netstat', '-an'], timeout=15)
        if rc == 0:
            for line in out.split('\n'):
                line = line.strip()
                if 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = parts[1]
                        if ':' in addr:
                            port = addr.rsplit(':', 1)[-1]
                            try:
                                finding['tcp_ports'].append(int(port))
                            except ValueError:
                                pass
                elif 'UDP' in line.upper() and '*:*' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = parts[1]
                        if ':' in addr:
                            port = addr.rsplit(':', 1)[-1]
                            try:
                                finding['udp_ports'].append(int(port))
                            except ValueError:
                                pass
    else:
        # Try ss first, fall back to netstat
        rc, out, _ = _run_cmd(['ss', '-tuln'], timeout=15)
        if rc != 0:
            rc, out, _ = _run_cmd(['netstat', '-tuln'], timeout=15)

        if rc == 0:
            for line in out.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part:
                            port_str = part.rsplit(':', 1)[-1]
                            try:
                                port = int(port_str)
                                finding['tcp_ports'].append(port)
                                break
                            except ValueError:
                                pass
                elif line.strip().startswith('udp'):
                    parts = line.split()
                    for part in parts:
                        if ':' in part:
                            port_str = part.rsplit(':', 1)[-1]
                            try:
                                port = int(port_str)
                                finding['udp_ports'].append(port)
                                break
                            except ValueError:
                                pass

    finding['tcp_ports'] = sorted(set(finding['tcp_ports']))
    finding['udp_ports'] = sorted(set(finding['udp_ports']))

    # Flag high-risk ports
    high_risk = {21, 23, 69, 111, 135, 139, 161, 445, 512, 513, 514, 1099}
    exposed = [p for p in finding['tcp_ports'] if p in high_risk]
    if exposed:
        finding['severity'] = 'MEDIUM'
        finding['status'] = 'warning'
        finding['high_risk_ports'] = exposed
        finding['message'] = f"High-risk ports open: {exposed}"

    return finding


def check_running_services():
    """Enumerate running services."""
    finding = {
        'check': 'running_services',
        'services': [],
        'severity': 'INFO',
        'status': 'collected',
    }

    if _is_windows():
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-Service | Where-Object {$_.Status -eq "Running"} | '
             'Select-Object Name, DisplayName | ConvertTo-Json -Compress'],
            timeout=20
        )
        if rc == 0 and out:
            try:
                services = json.loads(out)
                if isinstance(services, dict):
                    services = [services]
                finding['services'] = [
                    {'name': s.get('Name', ''),
                     'display': s.get('DisplayName', '')}
                    for s in services
                ]
            except json.JSONDecodeError:
                pass
    else:
        rc, out, _ = _run_cmd(
            ['systemctl', 'list-units', '--type=service',
             '--state=running', '--no-pager', '--no-legend'],
            timeout=15
        )
        if rc == 0:
            for line in out.split('\n'):
                parts = line.strip().split()
                if parts:
                    finding['services'].append({
                        'name': parts[0].replace('.service', ''),
                    })

    finding['service_count'] = len(finding['services'])
    return finding


def check_user_accounts():
    """Check local user accounts for security issues."""
    finding = {
        'check': 'user_accounts',
        'users': [],
        'local_admins': [],
        'issues': [],
        'severity': 'INFO',
        'status': 'ok',
    }

    if _is_windows():
        # Get local users
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-LocalUser | Select-Object Name, Enabled, '
             'PasswordRequired, LastLogon | ConvertTo-Json -Compress'],
            timeout=15
        )
        if rc == 0 and out:
            try:
                users = json.loads(out)
                if isinstance(users, dict):
                    users = [users]
                for u in users:
                    finding['users'].append(u.get('Name', ''))
                    if u.get('Enabled') and not u.get('PasswordRequired'):
                        finding['issues'].append(
                            f"User '{u.get('Name')}' has no password required"
                        )
            except json.JSONDecodeError:
                pass

        # Get local admins
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-LocalGroupMember -Group "Administrators" | '
             'Select-Object -ExpandProperty Name'],
            timeout=15
        )
        if rc == 0 and out:
            finding['local_admins'] = [
                a.strip() for a in out.split('\n') if a.strip()
            ]

    else:
        # Get users from /etc/passwd
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2]) if parts[2].isdigit() else -1
                        shell = parts[6]
                        if uid >= 1000 or uid == 0:
                            finding['users'].append(username)
                        if uid == 0:
                            finding['local_admins'].append(username)
                        # Check for users with no shell restriction
                        if (uid >= 1000 and
                                shell not in ('/usr/sbin/nologin',
                                              '/bin/false', '/sbin/nologin')):
                            pass  # Normal interactive user
        except IOError:
            pass

        # Check for passwordless accounts in shadow
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        passwd_hash = parts[1]
                        if passwd_hash in ('', '!', '*'):
                            continue  # Locked or system
                        if passwd_hash == '!!':
                            finding['issues'].append(
                                f"User '{username}' has no password set"
                            )
        except (IOError, PermissionError):
            pass  # Need root to read shadow

        # Check sudo group
        rc, out, _ = _run_cmd(['getent', 'group', 'sudo'], timeout=5)
        if rc == 0 and ':' in out:
            members = out.split(':')[-1]
            if members:
                finding['local_admins'].extend(
                    m.strip() for m in members.split(',') if m.strip()
                )
        # Also check wheel group
        rc, out, _ = _run_cmd(['getent', 'group', 'wheel'], timeout=5)
        if rc == 0 and ':' in out:
            members = out.split(':')[-1]
            if members:
                finding['local_admins'].extend(
                    m.strip() for m in members.split(',') if m.strip()
                )

    finding['local_admins'] = list(set(finding['local_admins']))

    if finding['issues']:
        finding['severity'] = 'HIGH'
        finding['status'] = 'warning'
    if len(finding['local_admins']) > 3:
        finding['issues'].append(
            f"Excessive local admins: {len(finding['local_admins'])}"
        )
        if finding['severity'] == 'INFO':
            finding['severity'] = 'MEDIUM'
            finding['status'] = 'warning'

    return finding


def check_patch_status():
    """Check last patch/update date."""
    finding = {
        'check': 'patch_status',
        'last_update': None,
        'days_since_update': None,
        'severity': 'INFO',
        'status': 'ok',
    }

    if _is_windows():
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             '(Get-HotFix | Sort-Object InstalledOn -Descending | '
             'Select-Object -First 1).InstalledOn.ToString("yyyy-MM-dd")'],
            timeout=20
        )
        if rc == 0 and out:
            finding['last_update'] = out.strip()
    else:
        # Check various package manager logs
        update_files = [
            '/var/log/apt/history.log',    # Debian/Ubuntu
            '/var/log/dnf.log',            # Fedora/RHEL 8+
            '/var/log/yum.log',            # RHEL 7/CentOS
        ]
        for fpath in update_files:
            try:
                stat = os.stat(fpath)
                mtime = datetime.utcfromtimestamp(stat.st_mtime)
                finding['last_update'] = mtime.strftime('%Y-%m-%d')
                break
            except (OSError, IOError):
                continue

    # Calculate days since last update
    if finding['last_update']:
        try:
            last = datetime.strptime(finding['last_update'], '%Y-%m-%d')
            delta = datetime.utcnow() - last
            finding['days_since_update'] = delta.days

            if delta.days > 90:
                finding['severity'] = 'HIGH'
                finding['status'] = 'critical'
                finding['message'] = (
                    f"System not patched in {delta.days} days"
                )
            elif delta.days > 30:
                finding['severity'] = 'MEDIUM'
                finding['status'] = 'warning'
                finding['message'] = (
                    f"System not patched in {delta.days} days"
                )
        except ValueError:
            pass
    else:
        finding['severity'] = 'MEDIUM'
        finding['status'] = 'unknown'
        finding['message'] = 'Unable to determine last patch date'

    return finding


def check_firewall_status():
    """Check if host firewall is enabled."""
    finding = {
        'check': 'firewall_status',
        'enabled': False,
        'severity': 'INFO',
        'status': 'ok',
    }

    if _is_windows():
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-NetFirewallProfile | Select-Object Name, Enabled | '
             'ConvertTo-Json -Compress'],
            timeout=15
        )
        if rc == 0 and out:
            try:
                profiles = json.loads(out)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                all_enabled = all(
                    p.get('Enabled', False) for p in profiles
                )
                finding['enabled'] = all_enabled
                finding['profiles'] = profiles
                if not all_enabled:
                    disabled = [
                        p.get('Name', '?') for p in profiles
                        if not p.get('Enabled')
                    ]
                    finding['severity'] = 'HIGH'
                    finding['status'] = 'critical'
                    finding['message'] = (
                        f"Firewall disabled for profiles: {disabled}"
                    )
            except json.JSONDecodeError:
                pass
    else:
        # Check iptables/nftables/ufw/firewalld
        checks = [
            (['ufw', 'status'], 'active'),
            (['firewall-cmd', '--state'], 'running'),
            (['iptables', '-L', '-n'], 'Chain'),
            (['nft', 'list', 'ruleset'], 'table'),
        ]
        for cmd, success_marker in checks:
            rc, out, _ = _run_cmd(cmd, timeout=10)
            if rc == 0 and success_marker in out:
                finding['enabled'] = True
                finding['firewall_tool'] = cmd[0]
                break

        if not finding['enabled']:
            finding['severity'] = 'HIGH'
            finding['status'] = 'critical'
            finding['message'] = 'No active firewall detected'

    return finding


def check_disk_encryption():
    """Check if disk encryption is enabled."""
    finding = {
        'check': 'disk_encryption',
        'encrypted': False,
        'severity': 'INFO',
        'status': 'ok',
    }

    if _is_windows():
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-BitLockerVolume -MountPoint C: -ErrorAction '
             'SilentlyContinue | Select-Object MountPoint, '
             'ProtectionStatus, EncryptionPercentage | '
             'ConvertTo-Json -Compress'],
            timeout=15
        )
        if rc == 0 and out:
            try:
                data = json.loads(out)
                if data.get('ProtectionStatus') == 1:
                    finding['encrypted'] = True
                    finding['method'] = 'BitLocker'
                    finding['percentage'] = data.get(
                        'EncryptionPercentage', 0
                    )
                else:
                    finding['severity'] = 'MEDIUM'
                    finding['status'] = 'warning'
                    finding['message'] = 'BitLocker not enabled on C:'
            except json.JSONDecodeError:
                pass
        else:
            finding['severity'] = 'MEDIUM'
            finding['status'] = 'unknown'
            finding['message'] = 'Unable to check BitLocker status'
    else:
        # Check LUKS / dm-crypt
        rc, out, _ = _run_cmd(['lsblk', '-o', 'NAME,TYPE'], timeout=10)
        if rc == 0 and 'crypt' in out:
            finding['encrypted'] = True
            finding['method'] = 'LUKS/dm-crypt'
        else:
            # Check for encrypted volumes in fstab or dmsetup
            rc2, out2, _ = _run_cmd(['dmsetup', 'status'], timeout=10)
            if rc2 == 0 and 'crypt' in out2:
                finding['encrypted'] = True
                finding['method'] = 'dm-crypt'
            else:
                finding['severity'] = 'MEDIUM'
                finding['status'] = 'warning'
                finding['message'] = 'No disk encryption detected'

    return finding


def check_ai_processes():
    """Scan running processes for known AI/LLM tools."""
    finding = {
        'check': 'unauthorized_ai_detection',
        'detected': [],
        'severity': 'INFO',
        'status': 'ok',
    }

    process_list = []

    if _is_windows():
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             'Get-Process | Select-Object -ExpandProperty ProcessName'],
            timeout=15
        )
        if rc == 0:
            process_list = [p.strip().lower() for p in out.split('\n')]
    else:
        rc, out, _ = _run_cmd(['ps', '-eo', 'comm'], timeout=10)
        if rc == 0:
            process_list = [p.strip().lower() for p in out.split('\n')]

    for proc_name in process_list:
        if not proc_name:
            continue
        for ai_name in KNOWN_AI_PROCESSES:
            if ai_name.lower() in proc_name:
                finding['detected'].append({
                    'process': proc_name,
                    'matched_rule': ai_name,
                })
                break

    if finding['detected']:
        finding['severity'] = 'MEDIUM'
        finding['status'] = 'warning'
        finding['message'] = (
            f"Detected {len(finding['detected'])} potential AI tool(s) "
            f"running"
        )

    return finding


def check_basic_hardening():
    """Run basic OS hardening checks."""
    finding = {
        'check': 'basic_hardening',
        'issues': [],
        'passed': [],
        'severity': 'INFO',
        'status': 'ok',
    }

    if _is_windows():
        # Check if automatic login is enabled
        rc, out, _ = _run_cmd(
            ['reg', 'query',
             r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
             '/v', 'AutoAdminLogon'],
            timeout=10
        )
        if rc == 0 and '1' in out:
            finding['issues'].append('Automatic login is enabled')
        else:
            finding['passed'].append('Automatic login is disabled')

        # Check if Remote Desktop is enabled
        rc, out, _ = _run_cmd(
            ['reg', 'query',
             r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
             '/v', 'fDenyTSConnections'],
            timeout=10
        )
        if rc == 0 and '0x0' in out:
            finding['issues'].append(
                'Remote Desktop is enabled (verify if needed)'
            )

        # Check if Windows Defender is running
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             '(Get-MpComputerStatus).AntivirusEnabled'],
            timeout=15
        )
        if rc == 0 and 'True' in out:
            finding['passed'].append('Windows Defender antivirus is enabled')
        elif rc == 0:
            finding['issues'].append('Windows Defender antivirus is disabled')

        # Check UAC
        rc, out, _ = _run_cmd(
            ['reg', 'query',
             r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
             '/v', 'EnableLUA'],
            timeout=10
        )
        if rc == 0 and '0x1' in out:
            finding['passed'].append('UAC is enabled')
        elif rc == 0:
            finding['issues'].append('UAC is disabled')

        # Check SMBv1
        rc, out, _ = _run_cmd(
            ['powershell', '-NoProfile', '-Command',
             '(Get-SmbServerConfiguration).EnableSMB1Protocol'],
            timeout=15
        )
        if rc == 0 and 'True' in out:
            finding['issues'].append('SMBv1 is enabled (security risk)')
        elif rc == 0:
            finding['passed'].append('SMBv1 is disabled')

    else:
        # Check SSH root login
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                sshd_config = f.read()
                if re.search(
                    r'^\s*PermitRootLogin\s+yes',
                    sshd_config, re.MULTILINE
                ):
                    finding['issues'].append(
                        'SSH root login is permitted'
                    )
                else:
                    finding['passed'].append(
                        'SSH root login is restricted'
                    )

                if re.search(
                    r'^\s*PasswordAuthentication\s+yes',
                    sshd_config, re.MULTILINE
                ):
                    finding['issues'].append(
                        'SSH password authentication is enabled'
                    )
                else:
                    finding['passed'].append(
                        'SSH password authentication is disabled'
                    )
        except (IOError, PermissionError):
            pass

        # Check if SELinux/AppArmor is active
        rc, out, _ = _run_cmd(['getenforce'], timeout=5)
        if rc == 0:
            if 'Enforcing' in out:
                finding['passed'].append('SELinux is enforcing')
            elif 'Permissive' in out:
                finding['issues'].append('SELinux is in permissive mode')
            else:
                finding['issues'].append('SELinux is disabled')
        else:
            # Check AppArmor
            rc2, out2, _ = _run_cmd(['aa-status', '--enabled'], timeout=5)
            if rc2 == 0:
                finding['passed'].append('AppArmor is enabled')
            else:
                finding['issues'].append(
                    'No MAC (SELinux/AppArmor) detected'
                )

        # Check core dumps
        rc, out, _ = _run_cmd(
            ['sysctl', 'fs.suid_dumpable'], timeout=5
        )
        if rc == 0 and '= 0' in out:
            finding['passed'].append('SUID core dumps are disabled')
        elif rc == 0:
            finding['issues'].append('SUID core dumps are enabled')

        # Check /tmp noexec
        rc, out, _ = _run_cmd(['mount'], timeout=5)
        if rc == 0:
            for line in out.split('\n'):
                if ' /tmp ' in line:
                    if 'noexec' in line:
                        finding['passed'].append(
                            '/tmp is mounted with noexec'
                        )
                    else:
                        finding['issues'].append(
                            '/tmp is not mounted with noexec'
                        )
                    break

    if finding['issues']:
        # Set severity based on number of issues
        if len(finding['issues']) >= 3:
            finding['severity'] = 'HIGH'
        else:
            finding['severity'] = 'MEDIUM'
        finding['status'] = 'warning'

    finding['passed_count'] = len(finding['passed'])
    finding['issue_count'] = len(finding['issues'])
    return finding


# ======================================================================
# Main scan orchestrator
# ======================================================================
def run_scan(config):
    """
    Execute all security checks and compile results.

    Args:
        config: AgentConfig instance.

    Returns:
        Dict with full scan results.
    """
    hostname = socket.gethostname()
    scan_start = _utcnow_iso()

    print(f"[{scan_start}] Starting scan on {hostname}")

    findings = []
    checks = [
        ('os_info', check_os_info),
        ('listening_ports', check_listening_ports),
        ('running_services', check_running_services),
        ('user_accounts', check_user_accounts),
        ('patch_status', check_patch_status),
        ('firewall_status', check_firewall_status),
        ('disk_encryption', check_disk_encryption),
        ('unauthorized_ai', check_ai_processes),
        ('basic_hardening', check_basic_hardening),
    ]

    for check_name, check_fn in checks:
        try:
            print(f"  Running check: {check_name}")
            result = check_fn()
            findings.append(result)
        except Exception as e:
            findings.append({
                'check': check_name,
                'severity': 'INFO',
                'status': 'error',
                'error': str(e),
            })

    scan_end = _utcnow_iso()

    # Count severities
    severity_counts = {}
    for f in findings:
        sev = f.get('severity', 'INFO')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    results = {
        'agent_id': config.agent_id,
        'agent_version': AGENT_VERSION,
        'hostname': hostname,
        'platform': platform.platform(),
        'scan_start': scan_start,
        'scan_end': scan_end,
        'scan_type': config.scan_type,
        'findings_count': len(findings),
        'severity_summary': severity_counts,
        'findings': findings,
    }

    print(
        f"[{scan_end}] Scan complete: {len(findings)} checks, "
        f"severities: {severity_counts}"
    )

    return results


def save_results(results, config):
    """Save scan results to JSON file in the output directory."""
    hostname = results.get('hostname', 'unknown')
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_{hostname}_{timestamp}.json"
    filepath = os.path.join(config.output_dir, filename)

    os.makedirs(config.output_dir, exist_ok=True)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"  Results saved to: {filepath}")
    except IOError as e:
        print(f"  [ERROR] Failed to save results: {e}", file=sys.stderr)
        return None

    # Copy to shared path if configured
    if config.shared_path:
        try:
            os.makedirs(config.shared_path, exist_ok=True)
            shared_file = os.path.join(config.shared_path, filename)
            with open(shared_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"  Results copied to shared path: {shared_file}")
        except IOError as e:
            print(
                f"  [WARN] Failed to copy to shared path: {e}",
                file=sys.stderr
            )

    return filepath


def push_results(results, config):
    """Push scan results to central server via HTTPS POST."""
    if not config.central_url:
        print("  No central URL configured; skipping push")
        return False

    if not HAS_URLLIB:
        print("  [WARN] urllib not available; cannot push results",
              file=sys.stderr)
        return False

    url = config.central_url
    data = json.dumps(results, default=str).encode('utf-8')

    headers = {
        'Content-Type': 'application/json',
        'X-Agent-ID': config.agent_id or '',
        'X-API-Key': config.api_key or '',
        'User-Agent': f'PurpleTeamAgent/{AGENT_VERSION}',
    }

    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        req.method = 'POST'

        # Create SSL context (allow self-signed certs in agent mode)
        if HAS_SSL:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = None

        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        status = resp.getcode()
        if 200 <= status < 300:
            print(f"  Results pushed to {url} (HTTP {status})")
            return True
        else:
            print(
                f"  [WARN] Push returned HTTP {status}",
                file=sys.stderr
            )
            return False

    except urllib.error.URLError as e:
        print(f"  [ERROR] Push failed: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  [ERROR] Push error: {e}", file=sys.stderr)
        return False


def parse_cron_interval(cron_expr):
    """
    Parse a simple cron expression to get the interval in seconds.
    Supports: '0 */N * * *' (every N hours).
    Falls back to DEFAULT_SCAN_INTERVAL for complex expressions.
    """
    try:
        parts = cron_expr.strip().split()
        if len(parts) >= 5:
            hour_part = parts[1]
            if hour_part.startswith('*/'):
                hours = int(hour_part[2:])
                return hours * 3600
    except (ValueError, IndexError):
        pass
    return DEFAULT_SCAN_INTERVAL


# ======================================================================
# Entry point
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description='Purple Team GRC - Lightweight Scanner Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              %(prog)s --config /opt/purpleteam/agent_config.json
              %(prog)s --once --output ./results
              %(prog)s --config config.json --push --once
        '''),
    )
    parser.add_argument(
        '--config', metavar='PATH',
        help='Path to JSON configuration file'
    )
    parser.add_argument(
        '--once', action='store_true',
        help='Run a single scan and exit (do not loop)'
    )
    parser.add_argument(
        '--output', metavar='PATH',
        help='Output directory for scan results'
    )
    parser.add_argument(
        '--push', action='store_true',
        help='Push results to central URL after scan'
    )

    args = parser.parse_args()

    # Load configuration
    config = AgentConfig(config_path=args.config)

    # Override output dir from CLI
    if args.output:
        config.output_dir = args.output
        os.makedirs(config.output_dir, exist_ok=True)

    print(f"Purple Team GRC Scanner Agent v{AGENT_VERSION}")
    print(f"  Agent ID:   {config.agent_id or '(not set)'}")
    print(f"  Output dir: {config.output_dir}")
    print(f"  Central URL: {config.central_url or '(not set)'}")
    print(f"  Mode: {'one-shot' if args.once else 'continuous'}")
    print()

    if args.once:
        # Single scan
        results = run_scan(config)
        save_results(results, config)
        if args.push:
            push_results(results, config)
        return

    # Continuous loop
    interval = parse_cron_interval(config.scan_schedule)
    print(f"  Scan interval: {interval} seconds ({interval/3600:.1f} hours)")
    print()

    while True:
        try:
            results = run_scan(config)
            save_results(results, config)
            if args.push or config.central_url:
                push_results(results, config)
        except KeyboardInterrupt:
            print("\nAgent stopped by user.")
            break
        except Exception as e:
            print(f"[ERROR] Scan cycle failed: {e}", file=sys.stderr)

        try:
            print(f"\nSleeping {interval} seconds until next scan...")
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nAgent stopped by user.")
            break


if __name__ == '__main__':
    main()
