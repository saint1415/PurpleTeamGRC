#!/usr/bin/env python3
"""
Purple Team Platform v6.0 - Credentialed/Authenticated Scanner
SSH-based authenticated checks for deep vulnerability assessment.
Maps to QoD 97% (authenticated version checks).
"""

import re
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from credential_manager import get_credential_manager
except ImportError:
    get_credential_manager = None


class CredentialScanner(BaseScanner):
    """Authenticated scanning via SSH for deep vulnerability assessment."""

    SCANNER_NAME = "credential"
    SCANNER_DESCRIPTION = "Authenticated vulnerability assessment via SSH"

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.cred_manager = None
        if get_credential_manager:
            try:
                self.cred_manager = get_credential_manager()
            except Exception:
                pass

    def scan(self, targets: List[str], scan_type: str = 'standard', **kwargs) -> Dict:
        """Execute authenticated scan on targets with configured credentials."""
        self.start_time = datetime.utcnow()

        if not self.cred_manager:
            self.scan_logger.warning("Credential manager not available")
            return {'error': 'Credential manager not available', 'targets': targets}

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'authenticated_hosts': [],
            'skipped_hosts': [],
            'checks': [],
            'summary': {}
        }

        for target in targets:
            cred = self.cred_manager.get_credential_for_target(target)

            if not cred:
                results['skipped_hosts'].append({
                    'host': target,
                    'reason': 'No credentials configured'
                })
                continue

            if cred.get('type') not in ('ssh_password', 'ssh_key'):
                results['skipped_hosts'].append({
                    'host': target,
                    'reason': f"Unsupported credential type: {cred.get('type')}"
                })
                continue

            self.scan_logger.info(f"Authenticated scan on {target} as {cred['params'].get('username', 'unknown')}")

            try:
                host_results = self._scan_host(target, cred, scan_type)
                results['authenticated_hosts'].append(target)
                results['checks'].extend(host_results)
            except Exception as e:
                self.scan_logger.error(f"Error scanning {target}: {e}")
                results['skipped_hosts'].append({
                    'host': target,
                    'reason': str(e)
                })

            self.human_delay()

        results['summary'] = {
            'authenticated_hosts': len(results['authenticated_hosts']),
            'skipped_hosts': len(results['skipped_hosts']),
            'total_checks': len(results['checks']),
        }

        self.end_time = datetime.utcnow()
        self.save_results()
        return results

    def _get_ssh_client(self, target: str, cred: Dict):
        """Get an SSH connection to the target."""
        params = cred.get('params', {})
        username = params.get('username', 'root')

        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if cred.get('type') == 'ssh_key':
                key_path = params.get('key_path', '')
                passphrase = params.get('key_passphrase')
                client.connect(
                    target, username=username,
                    key_filename=key_path,
                    passphrase=passphrase,
                    timeout=15
                )
            else:
                client.connect(
                    target, username=username,
                    password=params.get('password', ''),
                    timeout=15
                )
            return client

        except ImportError:
            # Fallback: use subprocess ssh
            return None

    def _ssh_exec(self, client, command: str, target: str, cred: Dict) -> str:
        """Execute a command via SSH."""
        if client is not None:
            # paramiko client
            _, stdout, stderr = client.exec_command(command, timeout=30)
            return stdout.read().decode('utf-8', errors='replace')
        else:
            # subprocess fallback
            import subprocess
            params = cred.get('params', {})
            username = params.get('username', 'root')
            cmd = [
                'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=no',
                f'{username}@{target}', command
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return result.stdout
            except Exception:
                return ''

    def _detect_remote_os(self, client, target: str, cred: Dict) -> str:
        """Detect the remote host OS. Returns 'linux', 'windows', or 'unknown'."""
        # Try uname first (Linux/macOS)
        output = self._ssh_exec(client, 'uname -s 2>/dev/null', target, cred).strip().lower()
        if 'linux' in output:
            return 'linux'
        if 'darwin' in output:
            return 'macos'
        # Try Windows detection (PowerShell over SSH)
        output = self._ssh_exec(
            client, 'echo %OS% 2>nul || echo unknown', target, cred
        ).strip().lower()
        if 'windows' in output:
            return 'windows'
        return 'linux'  # default assumption for SSH targets

    def _scan_host(self, target: str, cred: Dict, scan_type: str) -> List[Dict]:
        """Run authenticated checks on a single host."""
        checks = []
        client = self._get_ssh_client(target, cred)

        try:
            remote_os = self._detect_remote_os(client, target, cred)

            if remote_os == 'windows':
                checks.extend(self._check_windows_host(client, target, cred, scan_type))
            else:
                # Linux/macOS checks
                # Package version audit
                checks.extend(self._check_packages(client, target, cred))

                # Running services audit
                checks.extend(self._check_services(client, target, cred))

                # SSH configuration
                checks.extend(self._check_ssh_config(client, target, cred))

                # User account audit
                checks.extend(self._check_users(client, target, cred))

                if scan_type in ('standard', 'deep'):
                    # PAM configuration
                    checks.extend(self._check_pam_config(client, target, cred))

                    # File permissions
                    checks.extend(self._check_file_permissions(client, target, cred))

                if scan_type == 'deep':
                    # Patch level
                    checks.extend(self._check_patch_level(client, target, cred))

        finally:
            if client and hasattr(client, 'close'):
                client.close()

        return checks

    def _check_windows_host(self, client, target: str, cred: Dict,
                             scan_type: str) -> List[Dict]:
        """Run authenticated checks on a Windows host via SSH/PowerShell."""
        checks = []

        # Installed software audit (Windows equivalent of package check)
        output = self._ssh_exec(
            client,
            'powershell -Command "Get-WmiObject -Class Win32_Product | '
            'Select-Object Name,Version | Format-Table -AutoSize" 2>nul',
            target, cred
        )
        if output.strip():
            lines = [l for l in output.strip().split('\n') if l.strip()]
            checks.append({
                'host': target, 'check': 'package_audit',
                'result': f'{len(lines)} software entries found',
                'status': 'info'
            })

        # Running services audit
        output = self._ssh_exec(
            client,
            'powershell -Command "Get-Service | Where-Object {$_.Status -eq '
            '\'Running\'} | Select-Object Name,DisplayName | Format-Table -AutoSize" 2>nul',
            target, cred
        )
        if output.strip():
            risky_services = ['telnet', 'ftp', 'tftp', 'RemoteRegistry']
            for service in risky_services:
                if service.lower() in output.lower():
                    self.add_finding(
                        severity='HIGH',
                        title=f"[Auth] Insecure service running: {service} on {target}",
                        description=f"The insecure service '{service}' is running on {target}",
                        affected_asset=target,
                        finding_type='insecure_service',
                        remediation=f'Disable {service} via services.msc or Stop-Service',
                        detection_method='service_audit'
                    )
                    checks.append({
                        'host': target, 'check': 'insecure_service',
                        'result': f'{service} running', 'status': 'HIGH'
                    })

        # User account audit
        output = self._ssh_exec(
            client,
            'powershell -Command "Get-LocalUser | Select-Object Name,Enabled,'
            'LastLogon | Format-Table -AutoSize" 2>nul || net user 2>nul',
            target, cred
        )
        if output.strip():
            checks.append({
                'host': target, 'check': 'user_audit',
                'result': 'User enumeration complete',
                'status': 'info'
            })

        if scan_type == 'deep':
            # Windows patch level
            output = self._ssh_exec(
                client,
                'powershell -Command "(Get-HotFix | Measure-Object).Count" 2>nul',
                target, cred
            ).strip()
            if output:
                checks.append({
                    'host': target, 'check': 'patch_level',
                    'result': f'{output} hotfixes installed',
                    'status': 'info'
                })

        return checks

    def _check_packages(self, client, target: str, cred: Dict) -> List[Dict]:
        """Audit installed packages for known vulnerabilities."""
        checks = []

        # Try dpkg (Debian/Ubuntu)
        output = self._ssh_exec(client, 'dpkg -l 2>/dev/null | tail -n +6', target, cred)
        if not output.strip():
            # Try rpm (RHEL/CentOS)
            output = self._ssh_exec(client, 'rpm -qa --queryformat "%{NAME} %{VERSION}-%{RELEASE}\n" 2>/dev/null', target, cred)

        if output.strip():
            pkg_count = len(output.strip().split('\n'))
            checks.append({
                'host': target, 'check': 'package_audit',
                'result': f'{pkg_count} packages installed',
                'status': 'info'
            })

            # Check for outdated/vulnerable patterns
            vuln_patterns = [
                (r'openssl.*1\.[01]\.[01]', 'Outdated OpenSSL detected', 'HIGH'),
                (r'apache2?\s+2\.[24]\.[0-9]\b', 'Potentially outdated Apache', 'MEDIUM'),
                (r'openssh.*[67]\.[0-4]', 'Outdated OpenSSH version', 'MEDIUM'),
            ]

            for pattern, title, severity in vuln_patterns:
                if re.search(pattern, output, re.IGNORECASE):
                    self.add_finding(
                        severity=severity,
                        title=f"[Auth] {title} on {target}",
                        description=f"Authenticated package audit found: {title}",
                        affected_asset=target,
                        finding_type='outdated_software',
                        remediation='Update the affected package to the latest version',
                        detection_method='package_audit'
                    )
                    checks.append({
                        'host': target, 'check': 'package_vulnerability',
                        'result': title, 'status': severity
                    })

        return checks

    def _check_services(self, client, target: str, cred: Dict) -> List[Dict]:
        """Audit running services."""
        checks = []
        output = self._ssh_exec(
            client,
            'systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null',
            target, cred
        )

        if output.strip():
            risky_services = ['telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 'tftp']
            for service in risky_services:
                if service in output.lower():
                    self.add_finding(
                        severity='HIGH',
                        title=f"[Auth] Insecure service running: {service} on {target}",
                        description=f"The insecure service '{service}' is running on {target}",
                        affected_asset=target,
                        finding_type='insecure_service',
                        remediation=f'Disable {service} and use secure alternatives (e.g., SSH, SFTP)',
                        detection_method='service_audit'
                    )
                    checks.append({
                        'host': target, 'check': 'insecure_service',
                        'result': f'{service} running', 'status': 'HIGH'
                    })

        return checks

    def _check_ssh_config(self, client, target: str, cred: Dict) -> List[Dict]:
        """Check SSH server configuration."""
        checks = []
        output = self._ssh_exec(client, 'cat /etc/ssh/sshd_config 2>/dev/null', target, cred)

        if not output.strip():
            return checks

        # Check for insecure settings
        ssh_checks = [
            ('PermitRootLogin yes', 'SSH root login enabled', 'MEDIUM'),
            ('PasswordAuthentication yes', 'SSH password authentication enabled', 'LOW'),
            ('PermitEmptyPasswords yes', 'SSH empty passwords permitted', 'CRITICAL'),
            ('Protocol 1', 'SSH Protocol 1 enabled', 'CRITICAL'),
            ('X11Forwarding yes', 'SSH X11 forwarding enabled', 'LOW'),
        ]

        for pattern, title, severity in ssh_checks:
            # Simple check - look for uncommented directive
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('#'):
                    continue
                if pattern.lower().replace(' ', '') in line.lower().replace(' ', '').replace('\t', ''):
                    self.add_finding(
                        severity=severity,
                        title=f"[Auth] {title} on {target}",
                        description=f"SSH config issue: {line.strip()}",
                        affected_asset=target,
                        finding_type='insecure_configuration',
                        remediation=f'Update /etc/ssh/sshd_config to address: {title}',
                        detection_method='config_check'
                    )
                    checks.append({
                        'host': target, 'check': 'ssh_config',
                        'result': title, 'status': severity
                    })
                    break

        return checks

    def _check_users(self, client, target: str, cred: Dict) -> List[Dict]:
        """Audit user accounts."""
        checks = []

        # Check /etc/passwd for suspicious accounts
        output = self._ssh_exec(client, 'cat /etc/passwd 2>/dev/null', target, cred)
        if output.strip():
            uid_0_users = []
            for line in output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 4 and parts[2] == '0' and parts[0] != 'root':
                    uid_0_users.append(parts[0])

            if uid_0_users:
                self.add_finding(
                    severity='CRITICAL',
                    title=f"[Auth] Non-root UID 0 accounts on {target}",
                    description=f"Users with UID 0 (besides root): {', '.join(uid_0_users)}",
                    affected_asset=target,
                    finding_type='privilege_escalation',
                    remediation='Remove or change UID for non-root accounts with UID 0',
                    detection_method='user_audit'
                )

        # Check /etc/shadow permissions
        shadow_perms = self._ssh_exec(
            client, 'stat -c "%a" /etc/shadow 2>/dev/null', target, cred
        ).strip()
        if shadow_perms and shadow_perms not in ('600', '640', '000'):
            self.add_finding(
                severity='HIGH',
                title=f"[Auth] Weak /etc/shadow permissions on {target}",
                description=f"/etc/shadow has permissions {shadow_perms} (should be 600 or 640)",
                affected_asset=target,
                finding_type='file_permission',
                remediation='chmod 640 /etc/shadow',
                detection_method='user_audit'
            )

        return checks

    def _check_pam_config(self, client, target: str, cred: Dict) -> List[Dict]:
        """Check PAM configuration for security issues."""
        checks = []
        output = self._ssh_exec(
            client, 'cat /etc/pam.d/common-auth 2>/dev/null || cat /etc/pam.d/system-auth 2>/dev/null',
            target, cred
        )

        if output.strip():
            # Check for password complexity
            if 'pam_pwquality' not in output and 'pam_cracklib' not in output:
                self.add_finding(
                    severity='MEDIUM',
                    title=f"[Auth] No password complexity enforcement on {target}",
                    description='PAM is not configured with pam_pwquality or pam_cracklib',
                    affected_asset=target,
                    finding_type='insecure_configuration',
                    remediation='Install and configure pam_pwquality for password complexity',
                    detection_method='config_check'
                )

            # Check for account lockout
            if 'pam_tally' not in output and 'pam_faillock' not in output:
                self.add_finding(
                    severity='MEDIUM',
                    title=f"[Auth] No account lockout policy on {target}",
                    description='PAM is not configured with account lockout (pam_tally2/pam_faillock)',
                    affected_asset=target,
                    finding_type='insecure_configuration',
                    remediation='Configure pam_faillock for account lockout after failed attempts',
                    detection_method='config_check'
                )

        return checks

    def _check_file_permissions(self, client, target: str, cred: Dict) -> List[Dict]:
        """Check critical file permissions."""
        checks = []

        critical_files = [
            ('/etc/passwd', '644', 'MEDIUM'),
            ('/etc/shadow', '640', 'HIGH'),
            ('/etc/group', '644', 'MEDIUM'),
            ('/etc/gshadow', '640', 'HIGH'),
            ('/etc/crontab', '644', 'MEDIUM'),
        ]

        for filepath, expected_max, severity in critical_files:
            perms = self._ssh_exec(
                client, f'stat -c "%a" {filepath} 2>/dev/null', target, cred
            ).strip()

            if perms and int(perms, 8) > int(expected_max, 8):
                self.add_finding(
                    severity=severity,
                    title=f"[Auth] Weak permissions on {filepath} ({target})",
                    description=f"{filepath} has permissions {perms} (expected max {expected_max})",
                    affected_asset=target,
                    finding_type='file_permission',
                    remediation=f'chmod {expected_max} {filepath}',
                    detection_method='file_integrity'
                )

        return checks

    def _check_patch_level(self, client, target: str, cred: Dict) -> List[Dict]:
        """Assess system patch level."""
        checks = []

        # Check for available updates
        output = self._ssh_exec(
            client,
            'apt list --upgradable 2>/dev/null | wc -l || yum check-update 2>/dev/null | wc -l',
            target, cred
        ).strip()

        try:
            update_count = int(output) - 1  # subtract header line
            if update_count > 50:
                severity = 'HIGH'
            elif update_count > 10:
                severity = 'MEDIUM'
            elif update_count > 0:
                severity = 'LOW'
            else:
                severity = 'INFO'

            if update_count > 0:
                self.add_finding(
                    severity=severity,
                    title=f"[Auth] {update_count} pending updates on {target}",
                    description=f"System has {update_count} packages awaiting update",
                    affected_asset=target,
                    finding_type='missing_patch',
                    remediation='Apply pending security updates',
                    detection_method='patch_level'
                )
        except (ValueError, TypeError):
            pass

        # Check kernel version
        kernel = self._ssh_exec(client, 'uname -r 2>/dev/null', target, cred).strip()
        if kernel:
            checks.append({
                'host': target, 'check': 'kernel_version',
                'result': kernel, 'status': 'info'
            })

        return checks


if __name__ == '__main__':
    scanner = CredentialScanner()
    print("Credential Scanner initialized")
    if scanner.cred_manager:
        creds = scanner.cred_manager.get_all_credentials()
        print(f"Configured credentials: {len(creds)}")
    else:
        print("No credential manager available")
