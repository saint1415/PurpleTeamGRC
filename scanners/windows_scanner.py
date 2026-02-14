#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Windows Security Scanner
Local Windows security assessment using only built-in tools.
Works without admin, internet, or external tool installs.

Performs 10 security checks covering:
  1. Defender / Antivirus status
  2. BitLocker disk encryption
  3. Audit policy and password policy
  4. Windows Firewall profiles
  5. Network listening ports
  6. System hardening (SMBv1, local admins, password-less users)
  7. Patch / hotfix status
  8. Certificate expiration
  9. Registry security settings (auto-logon, UAC, RDP, SMB signing)
 10. Security event log analysis

Scan types:
  quick    - checks 1-6 only
  standard - all 10 checks
  deep     - all 10 checks with expanded depth
"""

import sys
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# ---------------------------------------------------------------------------
# Path bootstrap - ensure lib/ is importable regardless of launch directory
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


# ===========================================================================
# WindowsScanner
# ===========================================================================

class WindowsScanner(BaseScanner):
    """Windows security assessment using built-in tools."""

    SCANNER_NAME = "windows"
    SCANNER_DESCRIPTION = "Windows security assessment using built-in tools"

    # Ports considered dangerous when listening on all interfaces
    DANGEROUS_PORTS: Dict[int, str] = {
        21: 'FTP',
        23: 'Telnet',
        445: 'SMB',
        3389: 'RDP',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL',
    }

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.is_admin: bool = False

    # -----------------------------------------------------------------------
    # Core helpers
    # -----------------------------------------------------------------------

    def _run_ps(self, script: str, timeout: int = 60) -> Optional[str]:
        """Execute a PowerShell command and return stdout.

        Returns *None* on any error (non-zero exit, timeout, exception) so
        callers can simply test ``if result is None``.
        """
        cmd = [
            'powershell.exe',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-Command', script,
        ]
        self.scan_logger.debug(f"PS> {script[:120]}{'...' if len(script) > 120 else ''}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                stderr = (proc.stderr or '').strip()
                if 'access is denied' in stderr.lower() or 'not recognized' in stderr.lower():
                    self.scan_logger.debug(f"PS access denied / not recognized: {stderr[:200]}")
                else:
                    self.scan_logger.debug(f"PS non-zero exit ({proc.returncode}): {stderr[:200]}")
                return None
            return (proc.stdout or '').strip() or None
        except subprocess.TimeoutExpired:
            self.scan_logger.warning(f"PS command timed out ({timeout}s): {script[:80]}")
            return None
        except FileNotFoundError:
            self.scan_logger.error("powershell.exe not found on PATH")
            return None
        except Exception as exc:
            self.scan_logger.warning(f"PS execution error: {exc}")
            return None

    def _run_ps_json(self, script: str, timeout: int = 60) -> Optional[Any]:
        """Execute a PowerShell command, convert output to JSON, and parse it.

        The helper automatically appends ``| ConvertTo-Json`` so callers should
        *not* include that in *script*.  Returns a Python list/dict or *None*.
        """
        full_script = f"{script} | ConvertTo-Json -Depth 3 -Compress"
        raw = self._run_ps(full_script, timeout=timeout)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            # PowerShell emits a bare object (not wrapped in []) for single
            # results.  Normalise to a list when the caller likely expects one.
            return data
        except (json.JSONDecodeError, ValueError) as exc:
            self.scan_logger.debug(f"JSON parse error: {exc}")
            return None

    def _check_admin(self) -> bool:
        """Return *True* if the current process has local-admin privileges."""
        script = (
            "[bool]([System.Security.Principal.WindowsPrincipal]"
            "[System.Security.Principal.WindowsIdentity]::GetCurrent()"
            ").IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)"
        )
        result = self._run_ps(script, timeout=15)
        if result is not None and result.strip().lower() == 'true':
            return True
        return False

    # -----------------------------------------------------------------------
    # Helper: ensure a PS result is always a list
    # -----------------------------------------------------------------------

    @staticmethod
    def _ensure_list(data: Any) -> list:
        """Wrap a single dict in a list; pass through lists unchanged."""
        if data is None:
            return []
        if isinstance(data, list):
            return data
        return [data]

    # -----------------------------------------------------------------------
    # scan()
    # -----------------------------------------------------------------------

    def scan(self, targets=None, scan_type: str = 'standard', **kwargs) -> Dict:
        """Run the Windows security assessment.

        Parameters
        ----------
        targets : ignored
            Present for API compatibility; this scanner always assesses the
            local machine.
        scan_type : str
            ``'quick'`` runs checks 1-6, ``'standard'`` runs all 10,
            ``'deep'`` runs all 10 with additional depth.
        """
        self.start_time = datetime.utcnow()
        self.is_admin = self._check_admin()

        hostname = (subprocess.getoutput('hostname') or 'localhost').strip()

        self.scan_logger.info(
            f"Starting Windows {scan_type} scan on {hostname} "
            f"(admin={self.is_admin})"
        )

        results: Dict[str, Any] = {
            'scanner': self.SCANNER_NAME,
            'hostname': hostname,
            'is_admin': self.is_admin,
            'scan_type': scan_type,
            'checks_completed': 0,
            'checks_skipped': 0,
        }

        # Ordered list of checks ------------------------------------------------
        checks = [
            ('Defender/Antivirus',   self._check_defender),
            ('BitLocker Encryption', self._check_bitlocker),
            ('Audit Policy',         self._check_audit_policy),
            ('Firewall',             self._check_firewall),
            ('Network',              self._check_network),
            ('System Hardening',     self._check_hardening),
        ]

        if scan_type in ('standard', 'deep'):
            checks.extend([
                ('Patch Status',      self._check_patches),
                ('Certificates',      self._check_certificates),
                ('Registry Security', self._check_registry),
                ('Event Logs',        self._check_event_logs),
                ('Unauthorized AI',   self._check_unauthorized_ai),
            ])

        # Execute each check -----------------------------------------------------
        for name, check_fn in checks:
            try:
                self.scan_logger.info(f"Checking: {name}")
                check_fn(hostname, scan_type)
                results['checks_completed'] += 1
            except PermissionError:
                results['checks_skipped'] += 1
                self.scan_logger.info(f"Skipped {name}: requires admin privileges")
                self.add_finding(
                    severity='INFO',
                    title=f'{name}: Skipped (admin required)',
                    description=(
                        f'The {name} check requires administrator privileges. '
                        f'Re-run the scanner from an elevated prompt for full coverage.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    detection_method='powershell_cmdlet',
                )
            except Exception as exc:
                results['checks_skipped'] += 1
                self.scan_logger.warning(f"{name} check failed: {exc}")

        # Wrap up -----------------------------------------------------------------
        self.end_time = datetime.utcnow()
        results['summary'] = self.get_summary()
        self.save_results()
        return results

    # ===================================================================== #
    #  CHECK 1 - Defender / Antivirus                                       #
    # ===================================================================== #

    def _check_defender(self, hostname: str, scan_type: str) -> None:
        """Assess Windows Defender / antivirus posture."""

        status = self._run_ps_json(
            "Get-MpComputerStatus | Select-Object "
            "AMServiceEnabled, AntivirusEnabled, AntispywareEnabled, "
            "BehaviorMonitorEnabled, RealTimeProtectionEnabled, "
            "IoavProtectionEnabled, NISEnabled, "
            "AntivirusSignatureAge, AntispywareSignatureAge, "
            "AntivirusSignatureLastUpdated, "
            "QuickScanAge, FullScanAge"
        )

        if status is None:
            # Non-admin often cannot access Get-MpComputerStatus; fall back to
            # the service check so we can at least report whether Defender is
            # running at all.
            svc = self._run_ps_json(
                "Get-Service WinDefend -ErrorAction SilentlyContinue "
                "| Select-Object Status, DisplayName"
            )
            if svc is None:
                self.add_finding(
                    severity='MEDIUM',
                    title='Defender status: unable to query',
                    description=(
                        'Could not query Windows Defender status.  '
                        'Get-MpComputerStatus and Get-Service WinDefend both '
                        'failed.  This may indicate Defender is not installed '
                        'or the WinDefend service is missing.'
                    ),
                    affected_asset=hostname,
                    finding_type='endpoint_protection',
                    cvss_score=5.0,
                    remediation='Run the scanner as administrator or verify that Windows Defender is installed.',
                    detection_method='powershell_cmdlet',
                )
                return

            svc_data = svc if isinstance(svc, dict) else (svc[0] if svc else {})
            svc_status = str(svc_data.get('Status', '')).strip()
            # Status 4 == Running (enum value)
            if svc_status not in ('Running', '4'):
                self.add_finding(
                    severity='CRITICAL',
                    title='Windows Defender service is not running',
                    description=(
                        f'The WinDefend service status is "{svc_status}".  '
                        'Without an active antimalware service the system has '
                        'no real-time protection against malware.'
                    ),
                    affected_asset=hostname,
                    finding_type='endpoint_protection',
                    cvss_score=9.0,
                    remediation='Start the Windows Defender service: Start-Service WinDefend',
                    detection_method='powershell_cmdlet',
                )
            else:
                self.add_finding(
                    severity='INFO',
                    title='Windows Defender service is running (limited detail)',
                    description=(
                        'The WinDefend service is running but detailed status '
                        'could not be retrieved without admin privileges.'
                    ),
                    affected_asset=hostname,
                    finding_type='endpoint_protection',
                    detection_method='powershell_cmdlet',
                )
            return

        # Full status available ---------------------------------------------------
        status_data: dict = status if isinstance(status, dict) else (status[0] if status else {})

        # Real-time protection
        if not status_data.get('RealTimeProtectionEnabled', True):
            self.add_finding(
                severity='CRITICAL',
                title='Real-time protection is disabled',
                description=(
                    'Windows Defender real-time protection is turned off.  '
                    'The system is unprotected against new malware execution.'
                ),
                affected_asset=hostname,
                finding_type='endpoint_protection',
                cvss_score=9.0,
                remediation='Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring $false',
                raw_data=status_data,
                detection_method='powershell_cmdlet',
            )

        # Signature age
        sig_age = status_data.get('AntivirusSignatureAge')
        if sig_age is not None:
            try:
                sig_age_int = int(sig_age)
            except (ValueError, TypeError):
                sig_age_int = 0
            if sig_age_int > 7:
                self.add_finding(
                    severity='HIGH',
                    title=f'Antivirus signatures are {sig_age_int} days old',
                    description=(
                        f'Defender antivirus definitions have not been updated '
                        f'in {sig_age_int} days (threshold: 7).  New threats '
                        f'may not be detected.'
                    ),
                    affected_asset=hostname,
                    finding_type='endpoint_protection',
                    cvss_score=7.0,
                    remediation='Update signatures: Update-MpSignature',
                    raw_data=status_data,
                    detection_method='powershell_cmdlet',
                )

        # Behavior monitor
        if not status_data.get('BehaviorMonitorEnabled', True):
            self.add_finding(
                severity='MEDIUM',
                title='Behavior monitoring is disabled',
                description=(
                    'Defender behavior monitoring is disabled, reducing the '
                    'ability to detect suspicious process activity.'
                ),
                affected_asset=hostname,
                finding_type='endpoint_protection',
                cvss_score=5.5,
                remediation='Enable: Set-MpPreference -DisableBehaviorMonitoring $false',
                raw_data=status_data,
                detection_method='powershell_cmdlet',
            )

        # --- Exclusions (Get-MpPreference) ---
        prefs = self._run_ps_json(
            "Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess"
        )
        if prefs is not None:
            prefs_data: dict = prefs if isinstance(prefs, dict) else (prefs[0] if prefs else {})
            excl_paths = prefs_data.get('ExclusionPath') or []
            if isinstance(excl_paths, str):
                excl_paths = [excl_paths]

            if excl_paths:
                # Flag broad / dangerous exclusions
                dangerous_roots = {'C:\\', 'C:\\Windows', 'C:\\Windows\\System32',
                                   'C:\\Program Files', 'C:\\ProgramData'}
                dangerous_found = [
                    p for p in excl_paths
                    if any(p.upper().rstrip('\\') == d.upper() for d in dangerous_roots)
                ]
                if dangerous_found:
                    self.add_finding(
                        severity='HIGH',
                        title='Broad Defender exclusion paths detected',
                        description=(
                            f'The following broad exclusion paths are configured: '
                            f'{", ".join(dangerous_found)}.  Malware placed in '
                            f'excluded locations will not be scanned.'
                        ),
                        affected_asset=hostname,
                        finding_type='endpoint_protection',
                        cvss_score=7.5,
                        remediation='Review and remove unnecessary exclusions: Get-MpPreference | Select ExclusionPath',
                        raw_data={'exclusion_paths': excl_paths},
                        detection_method='powershell_cmdlet',
                    )
                elif len(excl_paths) > 5:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'{len(excl_paths)} Defender exclusion paths configured',
                        description=(
                            f'There are {len(excl_paths)} exclusion paths '
                            f'configured for Defender scanning.  Each exclusion '
                            f'increases the attack surface.'
                        ),
                        affected_asset=hostname,
                        finding_type='endpoint_protection',
                        cvss_score=4.0,
                        remediation='Audit exclusion paths and remove any that are no longer needed.',
                        raw_data={'exclusion_paths': excl_paths},
                        detection_method='powershell_cmdlet',
                    )

    # ===================================================================== #
    #  CHECK 2 - BitLocker Encryption                                       #
    # ===================================================================== #

    def _check_bitlocker(self, hostname: str, scan_type: str) -> None:
        """Assess BitLocker disk encryption status."""

        volumes = self._run_ps_json(
            "Get-BitLockerVolume | Select-Object "
            "MountPoint, VolumeStatus, ProtectionStatus, "
            "EncryptionMethod, EncryptionPercentage, VolumeType"
        )

        if volumes is None:
            # Get-BitLockerVolume requires admin privileges
            raise PermissionError("Get-BitLockerVolume requires administrator privileges")

        volumes_list = self._ensure_list(volumes)

        if not volumes_list:
            self.add_finding(
                severity='HIGH',
                title='No BitLocker volumes detected',
                description=(
                    'Get-BitLockerVolume returned no results.  This may mean '
                    'BitLocker is not enabled on any volume.'
                ),
                affected_asset=hostname,
                finding_type='disk_encryption',
                cvss_score=7.5,
                remediation='Enable BitLocker: manage-bde -on C:',
                detection_method='powershell_cmdlet',
            )
            return

        for vol in volumes_list:
            mount = vol.get('MountPoint', '?')
            protection = str(vol.get('ProtectionStatus', ''))
            volume_type = str(vol.get('VolumeType', '')).lower()
            enc_pct = vol.get('EncryptionPercentage', 0)
            enc_method = vol.get('EncryptionMethod', 'Unknown')

            # ProtectionStatus: 0=Off, 1=On, 2=Unknown
            # The string representation is 'On' / 'Off'
            is_protected = protection in ('On', '1')

            if is_protected:
                self.add_finding(
                    severity='INFO',
                    title=f'BitLocker active on {mount}',
                    description=(
                        f'Volume {mount} is encrypted '
                        f'({enc_pct}% complete, method: {enc_method}).'
                    ),
                    affected_asset=hostname,
                    finding_type='disk_encryption',
                    raw_data=vol,
                    detection_method='powershell_cmdlet',
                )
                continue

            # Not protected
            is_os_drive = (
                volume_type in ('operatingsystem', '1')
                or str(mount).upper().startswith('C:')
            )

            if is_os_drive:
                self.add_finding(
                    severity='CRITICAL',
                    title=f'OS drive {mount} is NOT encrypted',
                    description=(
                        f'The operating-system volume {mount} does not have '
                        f'BitLocker protection enabled.  If the device is lost '
                        f'or stolen, all data on this volume is accessible.'
                    ),
                    affected_asset=hostname,
                    finding_type='disk_encryption',
                    cvss_score=9.0,
                    remediation=f'Enable BitLocker on the OS drive: manage-bde -on {mount}',
                    raw_data=vol,
                    detection_method='powershell_cmdlet',
                )
            else:
                self.add_finding(
                    severity='HIGH',
                    title=f'Data drive {mount} is NOT encrypted',
                    description=(
                        f'Data volume {mount} does not have BitLocker '
                        f'protection.  Sensitive data on this volume could be '
                        f'exposed if the disk is physically accessed.'
                    ),
                    affected_asset=hostname,
                    finding_type='disk_encryption',
                    cvss_score=7.5,
                    remediation=f'Enable BitLocker: manage-bde -on {mount}',
                    raw_data=vol,
                    detection_method='powershell_cmdlet',
                )

    # ===================================================================== #
    #  CHECK 3 - Audit Policy & Password Policy                             #
    # ===================================================================== #

    def _check_audit_policy(self, hostname: str, scan_type: str) -> None:
        """Check audit policy, password policy, and guest account status."""

        # --- Audit policy (CSV output) ---
        audit_raw = self._run_ps("auditpol /get /category:* /r", timeout=30)

        if audit_raw is not None:
            self._parse_audit_policy(audit_raw, hostname)
        else:
            self.scan_logger.debug("auditpol returned no data (may need admin)")

        # --- Password policy via 'net accounts' ---
        net_raw = self._run_ps("net accounts", timeout=15)
        if net_raw is not None:
            self._parse_password_policy(net_raw, hostname)

        # --- Guest account ---
        self._check_guest_account(hostname)

    def _parse_audit_policy(self, csv_text: str, hostname: str) -> None:
        """Parse auditpol /r CSV and flag weak categories."""
        # CSV columns: Machine Name,Policy Target,Subcategory,Subcategory GUID,
        #              Inclusion Setting,Exclusion Setting
        lines = csv_text.strip().splitlines()
        if len(lines) < 2:
            return

        critical_categories = {
            'Logon':           ('HIGH', 7.0, 'Logon events are not audited'),
            'Logoff':          ('HIGH', 7.0, 'Logoff events are not audited'),
            'Special Logon':   ('HIGH', 7.0, 'Special logon events are not audited'),
            'Privilege Use':   ('HIGH', 6.5, 'Privilege use is not audited'),
            'Sensitive Privilege Use': ('HIGH', 6.5, 'Sensitive privilege use is not audited'),
            'Other Object Access Events': ('MEDIUM', 5.0, 'Object access is not audited'),
            'File System':     ('MEDIUM', 5.0, 'File system auditing is not enabled'),
            'Security State Change': ('MEDIUM', 5.5, 'Security state changes are not audited'),
            'Process Creation': ('MEDIUM', 5.5, 'Process creation events are not audited'),
        }

        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) < 5:
                continue
            subcategory = parts[2].strip()
            setting = parts[4].strip()

            if setting == 'No Auditing' and subcategory in critical_categories:
                sev, cvss, desc_suffix = critical_categories[subcategory]
                self.add_finding(
                    severity=sev,
                    title=f'Audit policy: {subcategory} not audited',
                    description=(
                        f'The audit subcategory "{subcategory}" is set to '
                        f'"No Auditing".  {desc_suffix}, reducing visibility '
                        f'into security-relevant activity.'
                    ),
                    affected_asset=hostname,
                    finding_type='audit_policy',
                    cvss_score=cvss,
                    remediation=f'Enable auditing: auditpol /set /subcategory:"{subcategory}" /success:enable /failure:enable',
                    raw_data={'subcategory': subcategory, 'setting': setting},
                    detection_method='powershell_cmdlet',
                )

    def _parse_password_policy(self, net_text: str, hostname: str) -> None:
        """Parse 'net accounts' output for password-policy weaknesses."""
        # Example lines:
        #   Minimum password length                  0
        #   Lockout threshold                        Never
        #   Maximum password age (days)              42

        # Minimum password length
        m = re.search(r'Minimum password length\s+(\d+)', net_text)
        if m:
            min_len = int(m.group(1))
            if min_len < 14:
                self.add_finding(
                    severity='MEDIUM',
                    title=f'Minimum password length is {min_len} (recommended: 14+)',
                    description=(
                        f'The local password policy requires a minimum of '
                        f'{min_len} characters.  NIST SP 800-63B and CIS '
                        f'benchmarks recommend at least 14 characters.'
                    ),
                    affected_asset=hostname,
                    finding_type='password_policy',
                    cvss_score=5.0,
                    remediation='Set via secpol.msc or: net accounts /minpwlen:14',
                    raw_data={'minimum_password_length': min_len},
                    detection_method='powershell_cmdlet',
                )

        # Lockout threshold
        m = re.search(r'Lockout threshold\s+(\S+)', net_text)
        if m:
            threshold = m.group(1)
            if threshold.lower() in ('never', '0'):
                self.add_finding(
                    severity='MEDIUM',
                    title='Account lockout threshold is disabled',
                    description=(
                        'The account lockout threshold is set to "Never".  '
                        'An attacker can attempt unlimited password guesses '
                        'without triggering a lockout.'
                    ),
                    affected_asset=hostname,
                    finding_type='password_policy',
                    cvss_score=5.0,
                    remediation='Set lockout threshold: net accounts /lockoutthreshold:5',
                    raw_data={'lockout_threshold': threshold},
                    detection_method='powershell_cmdlet',
                )

        # Maximum password age
        m = re.search(r'Maximum password age \(days\)\s+(\S+)', net_text)
        if m:
            max_age = m.group(1)
            if max_age.lower() == 'unlimited':
                self.add_finding(
                    severity='LOW',
                    title='Password expiration is disabled',
                    description=(
                        'The maximum password age is set to "Unlimited".  '
                        'While NIST no longer mandates periodic rotation, '
                        'organisations with compliance requirements may need '
                        'a defined expiration policy.'
                    ),
                    affected_asset=hostname,
                    finding_type='password_policy',
                    cvss_score=2.0,
                    remediation='Review policy: net accounts /maxpwage:365',
                    raw_data={'max_password_age': max_age},
                    detection_method='powershell_cmdlet',
                )

    def _check_guest_account(self, hostname: str) -> None:
        """Check whether the built-in Guest account is active."""
        guest_raw = self._run_ps(
            "net user guest 2>&1",
            timeout=15,
        )
        if guest_raw is None:
            return

        # Look for "Account active               Yes"
        if re.search(r'Account active\s+Yes', guest_raw, re.IGNORECASE):
            self.add_finding(
                severity='HIGH',
                title='Built-in Guest account is enabled',
                description=(
                    'The local Guest account is active.  Guest accounts '
                    'provide unauthenticated access and should be disabled '
                    'on all systems.'
                ),
                affected_asset=hostname,
                finding_type='account_hygiene',
                cvss_score=7.0,
                remediation='Disable the Guest account: net user guest /active:no',
                detection_method='powershell_cmdlet',
            )

    # ===================================================================== #
    #  CHECK 4 - Firewall                                                   #
    # ===================================================================== #

    def _check_firewall(self, hostname: str, scan_type: str) -> None:
        """Assess Windows Firewall profile configuration."""

        profiles = self._run_ps_json(
            "Get-NetFirewallProfile | Select-Object Name, Enabled, "
            "DefaultInboundAction, DefaultOutboundAction, LogFileName, "
            "LogAllowed, LogBlocked"
        )

        if profiles is None:
            # Try the netsh fallback for non-admin / older systems
            self._check_firewall_netsh(hostname)
            return

        profiles_list = self._ensure_list(profiles)

        for profile in profiles_list:
            name = profile.get('Name', 'Unknown')
            enabled = profile.get('Enabled', True)
            inbound = str(profile.get('DefaultInboundAction', ''))
            outbound = str(profile.get('DefaultOutboundAction', ''))

            # Enabled can be True/False or 1/0 or the string representations
            is_enabled = enabled in (True, 1, 'True', '1')

            if not is_enabled:
                self.add_finding(
                    severity='CRITICAL',
                    title=f'Windows Firewall profile "{name}" is DISABLED',
                    description=(
                        f'The {name} firewall profile is disabled.  All '
                        f'inbound and outbound traffic on this profile is '
                        f'unfiltered, exposing the host to network attacks.'
                    ),
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    cvss_score=9.0,
                    remediation=f'Enable the profile: Set-NetFirewallProfile -Profile {name} -Enabled True',
                    raw_data=profile,
                    detection_method='powershell_cmdlet',
                )
                continue

            # Default inbound action
            # 2 = Block (enum value), 4 = Allow
            if inbound in ('Allow', '4', 'NotConfigured'):
                self.add_finding(
                    severity='HIGH',
                    title=f'Firewall "{name}": default inbound action is Allow',
                    description=(
                        f'The {name} firewall profile allows inbound '
                        f'connections by default.  Only explicitly permitted '
                        f'services should accept inbound traffic.'
                    ),
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    cvss_score=7.0,
                    remediation=f'Set-NetFirewallProfile -Profile {name} -DefaultInboundAction Block',
                    raw_data=profile,
                    detection_method='powershell_cmdlet',
                )

            # Log-blocked not enabled
            log_blocked = profile.get('LogBlocked', True)
            if log_blocked in (False, 0, 'False', '0'):
                self.add_finding(
                    severity='LOW',
                    title=f'Firewall "{name}": blocked-connection logging disabled',
                    description=(
                        f'The {name} profile does not log blocked connections.  '
                        f'Enabling logging aids incident investigation.'
                    ),
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    cvss_score=2.0,
                    remediation=f'Set-NetFirewallProfile -Profile {name} -LogBlocked True',
                    raw_data=profile,
                    detection_method='powershell_cmdlet',
                )

    def _check_firewall_netsh(self, hostname: str) -> None:
        """Fallback firewall check using netsh (works without admin)."""
        raw = self._run_ps("netsh advfirewall show allprofiles state", timeout=15)
        if raw is None:
            self.add_finding(
                severity='MEDIUM',
                title='Unable to determine firewall status',
                description=(
                    'Neither Get-NetFirewallProfile nor netsh could retrieve '
                    'the firewall state.  The firewall configuration is unknown.'
                ),
                affected_asset=hostname,
                finding_type='firewall_config',
                cvss_score=5.0,
                remediation='Run the scanner as administrator for full firewall assessment.',
                detection_method='powershell_cmdlet',
            )
            return

        # Parse netsh output - look for "State  OFF" lines
        for match in re.finditer(
            r'(\w+)\s+Profile Settings.*?State\s+(ON|OFF)',
            raw,
            re.DOTALL | re.IGNORECASE,
        ):
            profile_name = match.group(1)
            state = match.group(2).upper()
            if state == 'OFF':
                self.add_finding(
                    severity='CRITICAL',
                    title=f'Windows Firewall profile "{profile_name}" is DISABLED',
                    description=(
                        f'The {profile_name} firewall profile is off '
                        f'(detected via netsh fallback).'
                    ),
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    cvss_score=9.0,
                    remediation=f'netsh advfirewall set {profile_name.lower()}profile state on',
                    raw_data={'profile': profile_name, 'state': state},
                    detection_method='powershell_cmdlet',
                )

    # ===================================================================== #
    #  CHECK 5 - Network (listening ports)                                  #
    # ===================================================================== #

    def _check_network(self, hostname: str, scan_type: str) -> None:
        """Check for dangerous listening ports on all interfaces."""

        connections = self._run_ps_json(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
            "| Select-Object LocalAddress, LocalPort, OwningProcess"
        )

        if connections is None:
            # Fallback: netstat
            self._check_network_netstat(hostname)
            return

        connections_list = self._ensure_list(connections)

        # Track which dangerous ports we have already reported
        reported_ports: set = set()

        for conn in connections_list:
            local_addr = str(conn.get('LocalAddress', ''))
            local_port = conn.get('LocalPort', 0)
            pid = conn.get('OwningProcess', 0)

            try:
                local_port = int(local_port)
            except (ValueError, TypeError):
                continue

            # Only flag services bound to all interfaces (0.0.0.0 or ::)
            if local_addr not in ('0.0.0.0', '::', ''):
                continue

            if local_port not in self.DANGEROUS_PORTS:
                continue

            if local_port in reported_ports:
                continue
            reported_ports.add(local_port)

            service_name = self.DANGEROUS_PORTS[local_port]

            # Attempt to resolve the process name
            proc_name = self._resolve_process_name(pid)

            # RDP on all interfaces gets special treatment
            if local_port == 3389:
                self.add_finding(
                    severity='HIGH',
                    title=f'RDP (port 3389) listening on all interfaces',
                    description=(
                        f'Remote Desktop Protocol is bound to {local_addr}:{local_port} '
                        f'(PID {pid}{", " + proc_name if proc_name else ""}).  '
                        f'RDP exposed to untrusted networks is a common '
                        f'initial-access vector (ref: BlueKeep CVE-2019-0708).'
                    ),
                    affected_asset=hostname,
                    finding_type='open_port',
                    cvss_score=7.5,
                    cve_ids=['CVE-2019-0708'],
                    remediation=(
                        'Restrict RDP to specific IPs via firewall rules or '
                        'disable if not needed: '
                        'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
                        '-Name fDenyTSConnections -Value 1'
                    ),
                    raw_data=conn,
                    detection_method='powershell_cmdlet',
                )
                continue

            self.add_finding(
                severity='HIGH',
                title=f'{service_name} (port {local_port}) listening on all interfaces',
                description=(
                    f'{service_name} is bound to {local_addr}:{local_port} '
                    f'(PID {pid}{", " + proc_name if proc_name else ""}).  '
                    f'This service should not be exposed on all interfaces '
                    f'unless explicitly required.'
                ),
                affected_asset=hostname,
                finding_type='open_port',
                cvss_score=7.0,
                remediation=(
                    f'Bind {service_name} to localhost only, restrict via '
                    f'firewall, or disable the service if not needed.'
                ),
                raw_data=conn,
                detection_method='powershell_cmdlet',
            )

        # Report total listener count as informational
        total_listeners = len(connections_list)
        self.add_finding(
            severity='INFO',
            title=f'{total_listeners} TCP listeners detected',
            description=(
                f'The system has {total_listeners} TCP ports in LISTEN state.  '
                f'{len(reported_ports)} dangerous ports were found listening '
                f'on all interfaces.'
            ),
            affected_asset=hostname,
            finding_type='open_port',
            raw_data={'total_listeners': total_listeners, 'dangerous_count': len(reported_ports)},
            detection_method='powershell_cmdlet',
        )

    def _resolve_process_name(self, pid: int) -> Optional[str]:
        """Try to resolve a PID to a process name."""
        if not pid:
            return None
        result = self._run_ps(
            f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName",
            timeout=10,
        )
        return result if result else None

    def _check_network_netstat(self, hostname: str) -> None:
        """Fallback network check using netstat."""
        raw = self._run_ps("netstat -an | Select-String 'LISTENING'", timeout=20)
        if raw is None:
            return

        reported: set = set()
        for line in raw.splitlines():
            # Example: TCP    0.0.0.0:3389    0.0.0.0:0    LISTENING
            m = re.search(r'TCP\s+(0\.0\.0\.0|::):(\d+)\s+', line)
            if not m:
                continue
            port = int(m.group(2))
            if port in self.DANGEROUS_PORTS and port not in reported:
                reported.add(port)
                svc = self.DANGEROUS_PORTS[port]
                cvss = 7.5 if port == 3389 else 7.0
                cves = ['CVE-2019-0708'] if port == 3389 else None
                self.add_finding(
                    severity='HIGH',
                    title=f'{svc} (port {port}) listening on all interfaces',
                    description=f'{svc} detected via netstat on 0.0.0.0:{port}.',
                    affected_asset=hostname,
                    finding_type='open_port',
                    cvss_score=cvss,
                    cve_ids=cves,
                    remediation=f'Restrict or disable {svc} on port {port}.',
                    detection_method='powershell_cmdlet',
                )

    # ===================================================================== #
    #  CHECK 6 - System Hardening                                           #
    # ===================================================================== #

    def _check_hardening(self, hostname: str, scan_type: str) -> None:
        """Check SMBv1, local admin count, and password-less users."""

        # --- SMBv1 ---
        self._check_smbv1(hostname)

        # --- Local administrators count ---
        self._check_local_admins(hostname)

        # --- Users without password ---
        self._check_passwordless_users(hostname)

    def _check_smbv1(self, hostname: str) -> None:
        """Detect whether SMBv1 is enabled."""
        # Try the feature-level check first
        smb1_feature = self._run_ps_json(
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
            "-ErrorAction SilentlyContinue | Select-Object State"
        )

        smb1_enabled = None

        if smb1_feature is not None:
            state_data = smb1_feature if isinstance(smb1_feature, dict) else (
                smb1_feature[0] if smb1_feature else {}
            )
            state = str(state_data.get('State', '')).lower()
            # State: Enabled / Disabled / 2 (Disabled) / 1 (Enabled)
            if state in ('enabled', '1'):
                smb1_enabled = True
            elif state in ('disabled', '2'):
                smb1_enabled = False

        # Fallback: registry check
        if smb1_enabled is None:
            reg_raw = self._run_ps(
                "Get-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                "-Name SMB1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SMB1",
                timeout=15,
            )
            if reg_raw is not None:
                try:
                    smb1_enabled = int(reg_raw.strip()) != 0
                except (ValueError, TypeError):
                    pass

        if smb1_enabled is True:
            self.add_finding(
                severity='HIGH',
                title='SMBv1 protocol is enabled',
                description=(
                    'The legacy SMBv1 protocol is enabled on this system.  '
                    'SMBv1 is exploited by EternalBlue (WannaCry, NotPetya) '
                    'and should be disabled on all modern Windows systems.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=8.0,
                cve_ids=['CVE-2017-0144'],
                remediation=(
                    'Disable SMBv1: '
                    'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
                ),
                detection_method='powershell_cmdlet',
            )
        elif smb1_enabled is False:
            self.add_finding(
                severity='INFO',
                title='SMBv1 is disabled',
                description='The legacy SMBv1 protocol is correctly disabled.',
                affected_asset=hostname,
                finding_type='insecure_configuration',
                detection_method='powershell_cmdlet',
            )

    def _check_local_admins(self, hostname: str) -> None:
        """Count members of the local Administrators group."""
        admins = self._run_ps_json(
            "Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue "
            "| Select-Object Name, ObjectClass, PrincipalSource"
        )

        if admins is None:
            # May fail without admin or on domain controllers
            self.scan_logger.debug("Could not enumerate local Administrators group")
            return

        admins_list = self._ensure_list(admins)
        admin_count = len(admins_list)
        admin_names = [str(a.get('Name', '')) for a in admins_list]

        if admin_count > 3:
            self.add_finding(
                severity='MEDIUM',
                title=f'{admin_count} members in the local Administrators group',
                description=(
                    f'The local Administrators group has {admin_count} members: '
                    f'{", ".join(admin_names)}.  Excessive admin accounts '
                    f'increase the attack surface (lateral movement, '
                    f'credential theft).'
                ),
                affected_asset=hostname,
                finding_type='account_hygiene',
                cvss_score=5.0,
                remediation='Remove unnecessary accounts from the Administrators group.',
                raw_data={'count': admin_count, 'members': admin_names},
                detection_method='powershell_cmdlet',
            )
        else:
            self.add_finding(
                severity='INFO',
                title=f'{admin_count} local administrator(s)',
                description=f'Local Administrators: {", ".join(admin_names)}',
                affected_asset=hostname,
                finding_type='account_hygiene',
                raw_data={'count': admin_count, 'members': admin_names},
                detection_method='powershell_cmdlet',
            )

    def _check_passwordless_users(self, hostname: str) -> None:
        """Find enabled local users that do not require a password."""
        users = self._run_ps_json(
            "Get-LocalUser | Where-Object "
            "{$_.PasswordRequired -eq $false -and $_.Enabled -eq $true} "
            "| Select-Object Name, Enabled, PasswordRequired, LastLogon"
        )

        if users is None:
            return

        users_list = self._ensure_list(users)
        if not users_list:
            return

        user_names = [str(u.get('Name', '')) for u in users_list]

        self.add_finding(
            severity='HIGH',
            title=f'{len(users_list)} enabled user(s) without a required password',
            description=(
                f'The following enabled local accounts do not require a '
                f'password: {", ".join(user_names)}.  Any user or process '
                f'can authenticate as these accounts without credentials.'
            ),
            affected_asset=hostname,
            finding_type='authentication_weakness',
            cvss_score=8.0,
            remediation='Set passwords or disable unused accounts: Set-LocalUser -Name <user> -PasswordNeverExpires $false',
            raw_data={'users': user_names},
            detection_method='powershell_cmdlet',
        )

    # ===================================================================== #
    #  CHECK 7 - Patch Status                                               #
    # ===================================================================== #

    def _check_patches(self, hostname: str, scan_type: str) -> None:
        """Evaluate system patching currency."""

        hotfixes = self._run_ps_json(
            "Get-HotFix | Sort-Object InstalledOn -Descending "
            "| Select-Object -First 20 HotFixID, InstalledOn, Description"
        )

        if hotfixes is None:
            self.add_finding(
                severity='MEDIUM',
                title='Unable to retrieve hotfix information',
                description=(
                    'Get-HotFix returned no data.  Patch status could not be '
                    'assessed.'
                ),
                affected_asset=hostname,
                finding_type='missing_patch',
                cvss_score=5.0,
                remediation='Run the scanner as administrator or check Windows Update manually.',
                detection_method='powershell_cmdlet',
            )
            return

        hotfixes_list = self._ensure_list(hotfixes)

        if not hotfixes_list:
            self.add_finding(
                severity='HIGH',
                title='No hotfixes found on the system',
                description=(
                    'Get-HotFix returned an empty list.  Either the system '
                    'has never been patched or patch history is unavailable.'
                ),
                affected_asset=hostname,
                finding_type='missing_patch',
                cvss_score=7.5,
                remediation='Run Windows Update immediately: Install-WindowsUpdate',
                detection_method='powershell_cmdlet',
            )
            return

        # Determine the most recent patch date
        latest_date = None
        for hf in hotfixes_list:
            installed_raw = hf.get('InstalledOn')
            if installed_raw is None:
                continue
            # PowerShell serialises DateTime as "/Date(millis)/" or ISO string
            parsed = self._parse_ps_date(installed_raw)
            if parsed and (latest_date is None or parsed > latest_date):
                latest_date = parsed

        now = datetime.utcnow()
        hotfix_ids = [str(hf.get('HotFixID', '')) for hf in hotfixes_list[:10]]

        if latest_date is not None:
            days_since = (now - latest_date).days

            if days_since > 60:
                self.add_finding(
                    severity='HIGH',
                    title=f'No patches installed in {days_since} days',
                    description=(
                        f'The most recent hotfix was installed on '
                        f'{latest_date.strftime("%Y-%m-%d")} ({days_since} days '
                        f'ago).  Systems should be patched at least monthly.'
                    ),
                    affected_asset=hostname,
                    finding_type='missing_patch',
                    cvss_score=7.5,
                    remediation='Apply pending updates via Windows Update.',
                    raw_data={'last_patch_date': latest_date.isoformat(), 'days_since': days_since},
                    detection_method='powershell_cmdlet',
                )
            elif days_since > 30:
                self.add_finding(
                    severity='MEDIUM',
                    title=f'No patches installed in {days_since} days',
                    description=(
                        f'The most recent hotfix was installed on '
                        f'{latest_date.strftime("%Y-%m-%d")} ({days_since} days '
                        f'ago).  Monthly patching is recommended.'
                    ),
                    affected_asset=hostname,
                    finding_type='missing_patch',
                    cvss_score=5.0,
                    remediation='Review pending updates: Get-WindowsUpdate',
                    raw_data={'last_patch_date': latest_date.isoformat(), 'days_since': days_since},
                    detection_method='powershell_cmdlet',
                )
            else:
                self.add_finding(
                    severity='INFO',
                    title=f'System patched {days_since} days ago',
                    description=(
                        f'Last hotfix installed on '
                        f'{latest_date.strftime("%Y-%m-%d")}.  '
                        f'Recent patches: {", ".join(hotfix_ids[:5])}'
                    ),
                    affected_asset=hostname,
                    finding_type='missing_patch',
                    raw_data={'last_patch_date': latest_date.isoformat(), 'hotfixes': hotfix_ids},
                    detection_method='powershell_cmdlet',
                )
        else:
            self.add_finding(
                severity='MEDIUM',
                title='Patch dates unavailable',
                description=(
                    f'Hotfixes are installed ({len(hotfixes_list)} found) but '
                    f'installation dates could not be parsed.  '
                    f'Recent IDs: {", ".join(hotfix_ids[:5])}'
                ),
                affected_asset=hostname,
                finding_type='missing_patch',
                cvss_score=4.0,
                raw_data={'hotfixes': hotfix_ids},
                detection_method='powershell_cmdlet',
            )

        # Total count (informational)
        total_raw = self._run_ps(
            "(Get-HotFix | Measure-Object).Count",
            timeout=15,
        )
        total_count = None
        if total_raw is not None:
            try:
                total_count = int(total_raw.strip())
            except (ValueError, TypeError):
                pass

        if total_count is not None:
            self.scan_logger.info(f"Total hotfixes installed: {total_count}")

    @staticmethod
    def _parse_ps_date(value: Any) -> Optional[datetime]:
        """Parse a PowerShell-serialised DateTime value."""
        if isinstance(value, str):
            # "/Date(1700000000000)/" format
            m = re.match(r'/Date\((\d+)\)/', value)
            if m:
                ts = int(m.group(1)) / 1000
                return datetime.utcfromtimestamp(ts)
            # ISO-like format
            for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S',
                        '%m/%d/%Y %H:%M:%S', '%m/%d/%Y %I:%M:%S %p',
                        '%d/%m/%Y %H:%M:%S'):
                try:
                    return datetime.strptime(value.strip(), fmt)
                except ValueError:
                    continue
        elif isinstance(value, (int, float)):
            # Unix timestamp in milliseconds
            try:
                return datetime.utcfromtimestamp(value / 1000 if value > 1e12 else value)
            except (OSError, OverflowError):
                return None
        elif isinstance(value, dict):
            # {"value": "/Date(...)/"} wrapper
            inner = value.get('value') or value.get('DateTime')
            if inner:
                return WindowsScanner._parse_ps_date(inner)
        return None

    # ===================================================================== #
    #  CHECK 8 - Certificates                                               #
    # ===================================================================== #

    def _check_certificates(self, hostname: str, scan_type: str) -> None:
        """Check for expired or soon-to-expire certificates."""

        certs = self._run_ps_json(
            "Get-ChildItem Cert:\\LocalMachine\\My -ErrorAction SilentlyContinue "
            "| Select-Object Subject, NotAfter, NotBefore, Issuer, Thumbprint, "
            "HasPrivateKey"
        )

        if certs is None:
            self.scan_logger.debug("Could not enumerate LocalMachine\\My certificates")
            # Also try CurrentUser store as a fallback
            certs = self._run_ps_json(
                "Get-ChildItem Cert:\\CurrentUser\\My -ErrorAction SilentlyContinue "
                "| Select-Object Subject, NotAfter, NotBefore, Issuer, Thumbprint, "
                "HasPrivateKey"
            )
            if certs is None:
                self.add_finding(
                    severity='INFO',
                    title='Certificate store: no certificates found or access denied',
                    description=(
                        'Could not enumerate certificates from '
                        'LocalMachine\\My or CurrentUser\\My.'
                    ),
                    affected_asset=hostname,
                    finding_type='expired_certificate',
                    detection_method='powershell_cmdlet',
                )
                return

        certs_list = self._ensure_list(certs)
        if not certs_list:
            self.add_finding(
                severity='INFO',
                title='No certificates in the personal store',
                description='The LocalMachine\\My certificate store is empty.',
                affected_asset=hostname,
                finding_type='expired_certificate',
                detection_method='powershell_cmdlet',
            )
            return

        now = datetime.utcnow()
        soon = now + timedelta(days=30)

        expired_certs: List[str] = []
        expiring_certs: List[str] = []

        for cert in certs_list:
            subject = str(cert.get('Subject', 'Unknown'))
            thumbprint = str(cert.get('Thumbprint', ''))[:12]
            not_after_raw = cert.get('NotAfter')

            not_after = self._parse_ps_date(not_after_raw)
            if not_after is None:
                continue

            friendly_name = subject[:80]

            if not_after < now:
                expired_certs.append(f"{friendly_name} (expired {not_after.strftime('%Y-%m-%d')})")
                self.add_finding(
                    severity='MEDIUM',
                    title=f'Expired certificate: {friendly_name}',
                    description=(
                        f'Certificate "{friendly_name}" '
                        f'(thumb: {thumbprint}...) expired on '
                        f'{not_after.strftime("%Y-%m-%d")}.  Expired '
                        f'certificates may cause service disruptions or '
                        f'security warnings.'
                    ),
                    affected_asset=hostname,
                    finding_type='expired_certificate',
                    cvss_score=5.0,
                    remediation='Renew or remove the expired certificate.',
                    raw_data=cert,
                    detection_method='powershell_cmdlet',
                )
            elif not_after < soon:
                days_left = (not_after - now).days
                expiring_certs.append(f"{friendly_name} ({days_left}d left)")
                self.add_finding(
                    severity='HIGH',
                    title=f'Certificate expiring soon: {friendly_name}',
                    description=(
                        f'Certificate "{friendly_name}" '
                        f'(thumb: {thumbprint}...) expires on '
                        f'{not_after.strftime("%Y-%m-%d")} '
                        f'({days_left} day(s) remaining).  Renew before '
                        f'expiration to avoid outages.'
                    ),
                    affected_asset=hostname,
                    finding_type='expired_certificate',
                    cvss_score=6.5,
                    remediation='Renew the certificate before expiration.',
                    raw_data=cert,
                    detection_method='powershell_cmdlet',
                )

        # Summary
        total = len(certs_list)
        self.add_finding(
            severity='INFO',
            title=f'Certificate summary: {total} cert(s), {len(expired_certs)} expired, {len(expiring_certs)} expiring soon',
            description=(
                f'Reviewed {total} certificate(s) in the personal store.  '
                f'Expired: {len(expired_certs)}, expiring within 30 days: '
                f'{len(expiring_certs)}.'
            ),
            affected_asset=hostname,
            finding_type='expired_certificate',
            raw_data={
                'total': total,
                'expired': expired_certs,
                'expiring_soon': expiring_certs,
            },
            detection_method='powershell_cmdlet',
        )

    # ===================================================================== #
    #  CHECK 9 - Registry Security Settings                                 #
    # ===================================================================== #

    def _check_registry(self, hostname: str, scan_type: str) -> None:
        """Inspect security-critical registry values."""
        self._check_reg_auto_logon(hostname)
        self._check_reg_uac(hostname)
        self._check_reg_rdp(hostname)
        self._check_reg_smb_signing(hostname)

        if scan_type == 'deep':
            self._check_reg_lsa_protection(hostname)
            self._check_reg_wdigest(hostname)

    # --- Auto-logon ---

    def _check_reg_auto_logon(self, hostname: str) -> None:
        """Check for automatic logon (plaintext credentials in registry)."""
        result = self._run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
            "-Name AutoAdminLogon -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty AutoAdminLogon",
            timeout=15,
        )

        if result is not None and result.strip() == '1':
            # Also try to detect the default username (not password!)
            user = self._run_ps(
                "Get-ItemProperty "
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
                "-Name DefaultUserName -ErrorAction SilentlyContinue "
                "| Select-Object -ExpandProperty DefaultUserName",
                timeout=10,
            )
            username = user.strip() if user else 'Unknown'

            self.add_finding(
                severity='CRITICAL',
                title='Auto-logon is enabled (credentials stored in registry)',
                description=(
                    f'AutoAdminLogon is set to 1 in the Winlogon registry key '
                    f'for user "{username}".  The password is stored in '
                    f'cleartext (or LSA secret) and the system logs in '
                    f'automatically, bypassing authentication.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=9.5,
                remediation=(
                    'Disable auto-logon: '
                    'Set-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                    '-Name AutoAdminLogon -Value 0'
                ),
                raw_data={'AutoAdminLogon': '1', 'DefaultUserName': username},
                detection_method='registry_check',
            )

    # --- UAC ---

    def _check_reg_uac(self, hostname: str) -> None:
        """Assess User Account Control configuration."""
        uac_data = self._run_ps_json(
            "Get-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-ErrorAction SilentlyContinue "
            "| Select-Object EnableLUA, ConsentPromptBehaviorAdmin, "
            "ConsentPromptBehaviorUser, PromptOnSecureDesktop, "
            "FilterAdministratorToken"
        )

        if uac_data is None:
            self.scan_logger.debug("Could not read UAC registry keys")
            return

        uac = uac_data if isinstance(uac_data, dict) else (
            uac_data[0] if uac_data else {}
        )

        # EnableLUA (UAC master switch)
        enable_lua = uac.get('EnableLUA')
        if enable_lua is not None and int(enable_lua) == 0:
            self.add_finding(
                severity='HIGH',
                title='User Account Control (UAC) is DISABLED',
                description=(
                    'EnableLUA is set to 0.  All processes run with full '
                    'admin privileges without elevation prompts, removing a '
                    'critical defense-in-depth layer.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=8.0,
                remediation=(
                    'Enable UAC: '
                    'Set-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
                    '-Name EnableLUA -Value 1'
                ),
                raw_data=uac,
                detection_method='registry_check',
            )

        # ConsentPromptBehaviorAdmin == 0 (elevate without prompt)
        consent = uac.get('ConsentPromptBehaviorAdmin')
        if consent is not None and int(consent) == 0:
            self.add_finding(
                severity='MEDIUM',
                title='UAC admin consent prompt is disabled (auto-elevate)',
                description=(
                    'ConsentPromptBehaviorAdmin is 0 (elevate without prompting).  '
                    'Malware running in the admin context can silently elevate '
                    'to full privileges.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=5.5,
                remediation=(
                    'Set ConsentPromptBehaviorAdmin to 2 (prompt on secure desktop): '
                    'Set-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
                    '-Name ConsentPromptBehaviorAdmin -Value 2'
                ),
                raw_data=uac,
                detection_method='registry_check',
            )

        # PromptOnSecureDesktop == 0
        secure_desktop = uac.get('PromptOnSecureDesktop')
        if secure_desktop is not None and int(secure_desktop) == 0:
            self.add_finding(
                severity='LOW',
                title='UAC prompts do not use the secure desktop',
                description=(
                    'PromptOnSecureDesktop is 0.  UAC prompts can be '
                    'spoofed or interacted with by malicious software.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=3.0,
                remediation=(
                    'Enable secure desktop: '
                    'Set-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" '
                    '-Name PromptOnSecureDesktop -Value 1'
                ),
                raw_data=uac,
                detection_method='registry_check',
            )

    # --- RDP ---

    def _check_reg_rdp(self, hostname: str) -> None:
        """Check whether RDP is enabled via registry."""
        result = self._run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty fDenyTSConnections",
            timeout=15,
        )

        if result is None:
            return

        try:
            deny_ts = int(result.strip())
        except (ValueError, TypeError):
            return

        if deny_ts == 0:
            # RDP is enabled
            # Check NLA requirement
            nla_raw = self._run_ps(
                "Get-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                "-Name UserAuthentication -ErrorAction SilentlyContinue "
                "| Select-Object -ExpandProperty UserAuthentication",
                timeout=10,
            )
            nla_enabled = False
            if nla_raw is not None:
                try:
                    nla_enabled = int(nla_raw.strip()) == 1
                except (ValueError, TypeError):
                    pass

            sev = 'MEDIUM' if nla_enabled else 'HIGH'
            cvss = 5.0 if nla_enabled else 6.5

            self.add_finding(
                severity=sev,
                title='Remote Desktop Protocol is enabled',
                description=(
                    f'RDP is enabled (fDenyTSConnections=0).  '
                    f'Network Level Authentication (NLA): '
                    f'{"enabled" if nla_enabled else "DISABLED"}.  '
                    f'RDP without NLA is vulnerable to man-in-the-middle '
                    f'and brute-force attacks.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=cvss,
                remediation=(
                    'Disable RDP if not needed: '
                    'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
                    '-Name fDenyTSConnections -Value 1'
                    + ('' if nla_enabled else
                       ' ; Enable NLA: '
                       'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
                       '-Name UserAuthentication -Value 1')
                ),
                raw_data={'fDenyTSConnections': deny_ts, 'NLA': nla_enabled},
                detection_method='registry_check',
            )

    # --- SMB Signing ---

    def _check_reg_smb_signing(self, hostname: str) -> None:
        """Verify SMB signing enforcement."""
        result = self._run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
            "-Name RequireSecuritySignature -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty RequireSecuritySignature",
            timeout=15,
        )

        if result is None:
            self.scan_logger.debug("Could not read SMB signing registry key")
            return

        try:
            require_signing = int(result.strip())
        except (ValueError, TypeError):
            return

        if require_signing == 0:
            self.add_finding(
                severity='MEDIUM',
                title='SMB signing is not required',
                description=(
                    'RequireSecuritySignature is 0 on the SMB server.  '
                    'Without mandatory SMB signing, the system is susceptible '
                    'to SMB relay and man-in-the-middle attacks.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=5.5,
                remediation=(
                    'Require SMB signing: '
                    'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
                    '-Name RequireSecuritySignature -Value 1'
                ),
                raw_data={'RequireSecuritySignature': require_signing},
                detection_method='registry_check',
            )

        # Also check the client side
        client_raw = self._run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' "
            "-Name RequireSecuritySignature -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty RequireSecuritySignature",
            timeout=15,
        )
        if client_raw is not None:
            try:
                client_signing = int(client_raw.strip())
            except (ValueError, TypeError):
                client_signing = None

            if client_signing == 0:
                self.add_finding(
                    severity='MEDIUM',
                    title='SMB client signing is not required',
                    description=(
                        'RequireSecuritySignature is 0 on the SMB client '
                        '(LanmanWorkstation).  Outbound SMB connections are '
                        'vulnerable to relay attacks.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=5.5,
                    remediation=(
                        'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" '
                        '-Name RequireSecuritySignature -Value 1'
                    ),
                    raw_data={'RequireSecuritySignature_Client': client_signing},
                    detection_method='registry_check',
                )

    # --- Deep-mode extras ---

    def _check_reg_lsa_protection(self, hostname: str) -> None:
        """Check if LSA protection (RunAsPPL) is enabled."""
        result = self._run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name RunAsPPL -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty RunAsPPL",
            timeout=15,
        )

        if result is None:
            # Key may not exist
            self.add_finding(
                severity='MEDIUM',
                title='LSA protection (RunAsPPL) is not configured',
                description=(
                    'The RunAsPPL registry value is not set.  Enabling LSA '
                    'protection prevents credential-dumping tools like '
                    'Mimikatz from accessing LSASS memory.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=6.0,
                remediation=(
                    'Enable LSA protection: '
                    'New-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
                    '-Name RunAsPPL -Value 1 -PropertyType DWORD -Force'
                ),
                detection_method='registry_check',
            )
            return

        try:
            val = int(result.strip())
        except (ValueError, TypeError):
            return

        if val == 0:
            self.add_finding(
                severity='MEDIUM',
                title='LSA protection (RunAsPPL) is disabled',
                description=(
                    'RunAsPPL is explicitly set to 0.  LSASS is not running '
                    'as a Protected Process Light, leaving it exposed to '
                    'credential-dumping attacks.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=6.0,
                remediation=(
                    'Set RunAsPPL to 1: '
                    'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" '
                    '-Name RunAsPPL -Value 1'
                ),
                raw_data={'RunAsPPL': val},
                detection_method='registry_check',
            )

    def _check_reg_wdigest(self, hostname: str) -> None:
        """Check if WDigest plaintext credential caching is disabled."""
        result = self._run_ps(
            "Get-ItemProperty "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
            "-Name UseLogonCredential -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty UseLogonCredential",
            timeout=15,
        )

        if result is not None:
            try:
                val = int(result.strip())
            except (ValueError, TypeError):
                return

            if val == 1:
                self.add_finding(
                    severity='HIGH',
                    title='WDigest plaintext credential caching is ENABLED',
                    description=(
                        'UseLogonCredential is set to 1 in the WDigest '
                        'provider.  Plaintext passwords are cached in LSASS '
                        'memory and can be extracted by tools like Mimikatz.'
                    ),
                    affected_asset=hostname,
                    finding_type='authentication_weakness',
                    cvss_score=7.5,
                    remediation=(
                        'Disable WDigest caching: '
                        'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" '
                        '-Name UseLogonCredential -Value 0'
                    ),
                    raw_data={'UseLogonCredential': val},
                    detection_method='registry_check',
                )

    # ===================================================================== #
    #  CHECK 10 - Event Logs                                                #
    # ===================================================================== #

    def _check_event_logs(self, hostname: str, scan_type: str) -> None:
        """Analyse security event logs for suspicious activity."""
        self._check_failed_logons(hostname, scan_type)
        self._check_privilege_use(hostname)
        self._check_account_creation(hostname)

        if scan_type == 'deep':
            self._check_service_installs(hostname)
            self._check_log_cleared(hostname)

    def _check_failed_logons(self, hostname: str, scan_type: str) -> None:
        """Analyse Event ID 4625 (failed logons)."""
        # Query last 7 days
        max_events = 200 if scan_type == 'deep' else 100
        count_raw = self._run_ps(
            f"(Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4625;"
            f"StartTime=(Get-Date).AddDays(-7)}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue "
            f"| Measure-Object).Count",
            timeout=30,
        )

        if count_raw is None:
            self.scan_logger.debug("Could not query Event ID 4625 (may need admin)")
            return

        try:
            count = int(count_raw.strip())
        except (ValueError, TypeError):
            return

        if count > 50:
            self.add_finding(
                severity='HIGH',
                title=f'{count} failed logon attempts in the last 7 days',
                description=(
                    f'Detected {count} failed logon events (Event ID 4625) '
                    f'in the Security log over the past 7 days.  This may '
                    f'indicate a brute-force or password-spraying attack.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=7.0,
                remediation=(
                    'Investigate the source IPs and accounts involved.  '
                    'Consider enabling account lockout and reviewing '
                    'firewall rules.'
                ),
                raw_data={'event_id': 4625, 'count_7d': count},
                detection_method='event_log_analysis',
            )
        elif count > 20:
            self.add_finding(
                severity='MEDIUM',
                title=f'{count} failed logon attempts in the last 7 days',
                description=(
                    f'Detected {count} failed logon events (Event ID 4625) '
                    f'over the past 7 days.  While not extreme, this '
                    f'warrants investigation.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=5.5,
                remediation='Review failed logon events: Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625} -MaxEvents 50',
                raw_data={'event_id': 4625, 'count_7d': count},
                detection_method='event_log_analysis',
            )
        else:
            self.add_finding(
                severity='INFO',
                title=f'{count} failed logon attempts in the last 7 days',
                description=f'{count} failed logon events (4625) in the past week.',
                affected_asset=hostname,
                finding_type='authentication_weakness',
                raw_data={'event_id': 4625, 'count_7d': count},
                detection_method='event_log_analysis',
            )

    def _check_privilege_use(self, hostname: str) -> None:
        """Report Event ID 4672 (special privileges assigned) count."""
        count_raw = self._run_ps(
            "(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672;"
            "StartTime=(Get-Date).AddDays(-7)} "
            "-MaxEvents 500 -ErrorAction SilentlyContinue "
            "| Measure-Object).Count",
            timeout=30,
        )

        if count_raw is None:
            return

        try:
            count = int(count_raw.strip())
        except (ValueError, TypeError):
            return

        self.add_finding(
            severity='INFO',
            title=f'{count} special privilege logon events in the last 7 days',
            description=(
                f'Event ID 4672 (special privileges assigned at logon) '
                f'occurred {count} times in the past 7 days.  High counts '
                f'are normal on servers with frequent admin activity.'
            ),
            affected_asset=hostname,
            finding_type='audit_policy',
            raw_data={'event_id': 4672, 'count_7d': count},
            detection_method='event_log_analysis',
        )

    def _check_account_creation(self, hostname: str) -> None:
        """Detect recent local account creation (Event ID 4720)."""
        events = self._run_ps_json(
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720;"
            "StartTime=(Get-Date).AddDays(-30)} "
            "-MaxEvents 20 -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated, Message"
        )

        if events is None:
            return

        events_list = self._ensure_list(events)
        if not events_list:
            return

        count = len(events_list)

        # Try to extract created usernames from the message
        created_users: List[str] = []
        for evt in events_list:
            msg = str(evt.get('Message', ''))
            # Message contains "Account Name:  <username>"
            m = re.search(r'Account Name:\s+(\S+)', msg)
            if m:
                name = m.group(1)
                # Skip the subject account (first match is usually subject)
                if name not in created_users and name != '-':
                    created_users.append(name)

        self.add_finding(
            severity='MEDIUM',
            title=f'{count} user account(s) created in the last 30 days',
            description=(
                f'Detected {count} account-creation events (Event ID 4720) '
                f'in the last 30 days.  '
                + (f'Account names: {", ".join(created_users[:10])}.  ' if created_users else '')
                + 'Verify that all new accounts are authorised.'
            ),
            affected_asset=hostname,
            finding_type='account_hygiene',
            cvss_score=5.0,
            remediation='Review: Get-WinEvent -FilterHashtable @{LogName="Security";Id=4720} -MaxEvents 20',
            raw_data={'event_id': 4720, 'count_30d': count, 'users': created_users[:10]},
            detection_method='event_log_analysis',
        )

    def _check_service_installs(self, hostname: str) -> None:
        """Detect recent service installations (Event ID 7045 in System log)."""
        events = self._run_ps_json(
            "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;"
            "StartTime=(Get-Date).AddDays(-30)} "
            "-MaxEvents 20 -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated, Message"
        )

        if events is None:
            return

        events_list = self._ensure_list(events)
        if not events_list:
            return

        count = len(events_list)
        service_names: List[str] = []
        for evt in events_list:
            msg = str(evt.get('Message', ''))
            m = re.search(r'service was installed.*?Service Name:\s*(.+)', msg, re.DOTALL)
            if m:
                service_names.append(m.group(1).strip()[:60])

        self.add_finding(
            severity='INFO',
            title=f'{count} new service(s) installed in the last 30 days',
            description=(
                f'{count} service-installation events (Event ID 7045) '
                f'detected.  '
                + (f'Services: {", ".join(service_names[:10])}.  ' if service_names else '')
                + 'Malware often installs services for persistence.'
            ),
            affected_asset=hostname,
            finding_type='insecure_configuration',
            raw_data={'event_id': 7045, 'count_30d': count, 'services': service_names[:10]},
            detection_method='event_log_analysis',
        )

    def _check_log_cleared(self, hostname: str) -> None:
        """Detect security-log-cleared events (Event ID 1102)."""
        events = self._run_ps_json(
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;"
            "StartTime=(Get-Date).AddDays(-90)} "
            "-MaxEvents 10 -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated, Message"
        )

        if events is None:
            return

        events_list = self._ensure_list(events)
        if not events_list:
            return

        count = len(events_list)
        self.add_finding(
            severity='HIGH',
            title=f'Security log was cleared {count} time(s) in the last 90 days',
            description=(
                f'Event ID 1102 indicates the Security event log was '
                f'cleared {count} time(s).  Attackers clear logs to cover '
                f'their tracks.  Investigate who cleared the log and why.'
            ),
            affected_asset=hostname,
            finding_type='audit_policy',
            cvss_score=7.0,
            remediation='Enable log forwarding to a SIEM to prevent loss of evidence.',
            raw_data={'event_id': 1102, 'count_90d': count},
            detection_method='event_log_analysis',
        )

    # ===================================================================== #
    #  CHECK 11 - Unauthorized AI Detection                                 #
    # ===================================================================== #

    # Known AI applications, processes, services, and model file extensions
    AI_PROCESSES = {
        'ollama':           'Ollama (local LLM runtime)',
        'ollama app':       'Ollama Desktop',
        'lms':              'LM Studio',
        'lm studio':        'LM Studio',
        'lm-studio':        'LM Studio',
        'localai':          'LocalAI',
        'koboldcpp':        'KoboldCpp (local LLM)',
        'text-generation':  'Text Generation WebUI (oobabooga)',
        'gpt4all':          'GPT4All',
        'jan':              'Jan (local AI)',
        'msty':             'Msty (local AI)',
        'llamafile':        'Mozilla llamafile',
        'llama.cpp':        'llama.cpp server',
        'server':           None,  # generic - only flag if on AI ports
        'vllm':             'vLLM inference server',
        'tgi':              'HuggingFace Text Generation Inference',
        'tritonserver':     'NVIDIA Triton Inference Server',
        'anythingllm':      'AnythingLLM',
        'open-webui':       'Open WebUI (Ollama frontend)',
        'chatbox':          'Chatbox AI',
        'faraday':          'Faraday (local AI)',
        'privateGPT':       'PrivateGPT',
        'h2ogpt':           'h2oGPT',
        'openclaw':         'OpenClaw AI',
    }

    AI_PORTS = {
        11434: 'Ollama API',
        11435: 'Ollama API (alt)',
        1234:  'LM Studio API',
        8080:  'LocalAI / KoboldCpp / Open WebUI',
        5000:  'Text Generation WebUI',
        5001:  'Text Generation WebUI (API)',
        7860:  'Gradio (AI WebUI)',
        7861:  'Gradio (alt)',
        3000:  'Open WebUI / Chatbox',
        3001:  'AnythingLLM',
        4891:  'GPT4All API',
        8000:  'vLLM / FastChat',
        8001:  'Triton HTTP',
        8002:  'Triton gRPC',
        9090:  'Prometheus (AI monitoring)',
        6333:  'Qdrant vector DB',
        8765:  'TabbyML',
        39281: 'Jan AI',
    }

    AI_INSTALL_PATHS = [
        r'C:\Users\*\AppData\Local\Ollama',
        r'C:\Users\*\AppData\Local\Programs\Ollama',
        r'C:\Users\*\.ollama',
        r'C:\Users\*\AppData\Local\LM-Studio',
        r'C:\Users\*\AppData\Local\Programs\LM Studio',
        r'C:\Users\*\AppData\Local\AnythingLLM',
        r'C:\Users\*\AppData\Local\Jan',
        r'C:\Users\*\AppData\Local\Programs\Jan',
        r'C:\Users\*\AppData\Local\Chatbox',
        r'C:\Users\*\AppData\Local\Programs\GPT4All',
        r'C:\Users\*\gpt4all',
        r'C:\Program Files\Ollama',
        r'C:\Program Files\LM Studio',
        r'C:\Program Files\GPT4All',
        r'C:\ProgramData\Ollama',
    ]

    AI_MODEL_EXTENSIONS = {
        '.gguf':         'GGUF model (llama.cpp/Ollama)',
        '.ggml':         'GGML model (legacy llama.cpp)',
        '.safetensors':  'SafeTensors model (HuggingFace)',
        '.bin':          None,  # too generic alone, check with context
        '.onnx':         'ONNX model',
        '.pt':           'PyTorch model',
        '.pth':          'PyTorch model',
    }

    AI_MODEL_SEARCH_PATHS = [
        r'C:\Users\*\.ollama\models',
        r'C:\Users\*\.cache\huggingface',
        r'C:\Users\*\.cache\lm-studio',
        r'C:\Users\*\AppData\Local\nomic.ai',
        r'C:\Users\*\.local\share\nomic.ai',
        r'C:\Users\*\gpt4all\models',
    ]

    AI_SERVICES = [
        'ollama',
        'OllamaService',
        'LMStudioServer',
    ]

    AI_SCHEDULED_TASKS = [
        'ollama',
        'lm studio',
        'gpt4all',
        'localai',
    ]

    def _check_unauthorized_ai(self, hostname: str, scan_type: str) -> None:
        """Detect unauthorized AI installations, processes, models, and network activity."""

        self._check_ai_processes(hostname)
        self._check_ai_ports(hostname)
        self._check_ai_installations(hostname)
        self._check_ai_services(hostname)

        if scan_type == 'deep':
            self._check_ai_models(hostname)
            self._check_ai_scheduled_tasks(hostname)
            self._check_ai_browser_extensions(hostname)
            self._check_ai_python_packages(hostname)
            self._check_ai_network_rules(hostname)

    def _check_ai_processes(self, hostname: str) -> None:
        """Detect running AI-related processes."""
        procs = self._run_ps_json(
            "Get-Process | Select-Object ProcessName, Id, Path, "
            "Company, Description, StartTime | ConvertTo-Json -Depth 2"
        )
        if not procs:
            return
        if isinstance(procs, dict):
            procs = [procs]

        for proc in procs:
            pname = (proc.get('ProcessName') or '').lower()
            ppath = (proc.get('Path') or '').lower()
            pdesc = (proc.get('Description') or '').lower()
            pid = proc.get('Id', '?')

            # Check against known AI process names
            for ai_name, ai_label in self.AI_PROCESSES.items():
                if ai_label is None:
                    continue  # skip generic entries
                if ai_name.lower() in pname or ai_name.lower() in pdesc:
                    self.add_finding(
                        severity='HIGH',
                        title=f'Unauthorized AI Process: {ai_label}',
                        description=(
                            f'Detected running AI process: {proc.get("ProcessName")} '
                            f'(PID {pid}). Path: {proc.get("Path") or "unknown"}. '
                            f'Unauthorized local AI tools may pose data exfiltration, '
                            f'compliance, and shadow IT risks.'
                        ),
                        affected_asset=hostname,
                        finding_type='insecure_configuration',
                        detection_method='service_enumeration',
                        remediation=(
                            f'Investigate whether {ai_label} is authorized. '
                            f'If unauthorized, terminate the process (PID {pid}) '
                            f'and uninstall the application. Implement application '
                            f'whitelisting to prevent future installations.'
                        ),
                    )
                    break

            # Also flag if process path contains AI-related directories
            for ai_path_pattern in ['ollama', 'lm-studio', 'lm studio',
                                     'gpt4all', 'koboldcpp', 'localai',
                                     'anythingllm', 'openclaw']:
                if ai_path_pattern in ppath and not any(
                    ai_name.lower() in pname for ai_name in self.AI_PROCESSES
                    if self.AI_PROCESSES[ai_name] is not None
                ):
                    self.add_finding(
                        severity='HIGH',
                        title=f'AI-related process from suspicious path',
                        description=(
                            f'Process {proc.get("ProcessName")} (PID {pid}) '
                            f'running from AI-related path: {proc.get("Path")}.'
                        ),
                        affected_asset=hostname,
                        finding_type='insecure_configuration',
                        detection_method='service_enumeration',
                        remediation='Investigate the process and its origin.',
                    )
                    break

    def _check_ai_ports(self, hostname: str) -> None:
        """Check for AI services listening on known ports."""
        listeners = self._run_ps_json(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
            "| Select-Object LocalPort, OwningProcess, LocalAddress "
            "| ConvertTo-Json -Depth 2"
        )
        if not listeners:
            return
        if isinstance(listeners, dict):
            listeners = [listeners]

        for conn in listeners:
            port = conn.get('LocalPort', 0)
            pid = conn.get('OwningProcess', 0)

            if port in self.AI_PORTS:
                ai_svc = self.AI_PORTS[port]
                # Get process name for this PID
                proc_info = self._run_ps(
                    f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"
                )
                proc_name = (proc_info or 'unknown').strip()

                self.add_finding(
                    severity='HIGH',
                    title=f'AI Service Port Active: {port} ({ai_svc})',
                    description=(
                        f'Port {port} is listening (commonly used by {ai_svc}). '
                        f'Process: {proc_name} (PID {pid}), '
                        f'Address: {conn.get("LocalAddress", "?")}. '
                        f'This may indicate an unauthorized AI service.'
                    ),
                    affected_asset=hostname,
                    finding_type='open_port',
                    detection_method='powershell_cmdlet',
                    remediation=(
                        f'Verify if the service on port {port} is authorized. '
                        f'If not, stop the process and block the port via firewall.'
                    ),
                )

    def _check_ai_installations(self, hostname: str) -> None:
        """Scan for AI application installations on disk."""
        import glob as _glob

        found_paths = []
        for pattern in self.AI_INSTALL_PATHS:
            try:
                matches = _glob.glob(pattern)
                found_paths.extend(matches)
            except Exception:
                continue

        for path in found_paths:
            # Determine which AI tool this is
            path_lower = path.lower()
            ai_name = 'Unknown AI application'
            for keyword, label in [
                ('ollama', 'Ollama'), ('lm-studio', 'LM Studio'),
                ('lm studio', 'LM Studio'), ('anythingllm', 'AnythingLLM'),
                ('jan', 'Jan AI'), ('chatbox', 'Chatbox'),
                ('gpt4all', 'GPT4All'), ('openclaw', 'OpenClaw'),
            ]:
                if keyword in path_lower:
                    ai_name = label
                    break

            self.add_finding(
                severity='MEDIUM',
                title=f'AI Application Installed: {ai_name}',
                description=(
                    f'Found AI application directory: {path}. '
                    f'This may indicate an unauthorized AI tool installation.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                detection_method='powershell_cmdlet',
                remediation=(
                    f'Verify if {ai_name} at {path} is authorized. '
                    f'If unauthorized, remove the directory and uninstall.'
                ),
            )

        # Also check installed programs via registry
        installed = self._run_ps_json(
            "Get-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
            "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
            "-ErrorAction SilentlyContinue "
            "| Where-Object { $_.DisplayName -ne $null } "
            "| Select-Object DisplayName, Publisher, InstallLocation, DisplayVersion "
            "| ConvertTo-Json -Depth 2"
        )
        if installed:
            if isinstance(installed, dict):
                installed = [installed]
            ai_keywords = [
                'ollama', 'lm studio', 'gpt4all', 'koboldcpp', 'localai',
                'anythingllm', 'jan ai', 'jan-', 'chatbox', 'openclaw',
                'llamafile', 'msty', 'open webui', 'private gpt',
                'text generation', 'stable diffusion', 'comfyui',
                'automatic1111', 'invoke ai', 'fooocus',
            ]
            for app in installed:
                name = (app.get('DisplayName') or '').lower()
                for kw in ai_keywords:
                    if kw in name:
                        self.add_finding(
                            severity='HIGH',
                            title=f'AI Software Installed: {app.get("DisplayName")}',
                            description=(
                                f'Installed application: {app.get("DisplayName")} '
                                f'v{app.get("DisplayVersion", "?")} '
                                f'by {app.get("Publisher", "unknown")}. '
                                f'Location: {app.get("InstallLocation", "unknown")}.'
                            ),
                            affected_asset=hostname,
                            finding_type='insecure_configuration',
                            detection_method='registry_check',
                            remediation=(
                                f'Verify authorization for {app.get("DisplayName")}. '
                                f'Uninstall if not approved by security policy.'
                            ),
                        )
                        break

    def _check_ai_services(self, hostname: str) -> None:
        """Check for AI-related Windows services."""
        services = self._run_ps_json(
            "Get-Service -ErrorAction SilentlyContinue "
            "| Where-Object { $_.Status -eq 'Running' } "
            "| Select-Object Name, DisplayName, Status, StartType "
            "| ConvertTo-Json -Depth 2"
        )
        if not services:
            return
        if isinstance(services, dict):
            services = [services]

        ai_keywords = ['ollama', 'lm studio', 'localai', 'gpt4all',
                        'kobold', 'triton', 'vllm', 'openclaw']

        for svc in services:
            svc_name = (svc.get('Name') or '').lower()
            svc_display = (svc.get('DisplayName') or '').lower()
            for kw in ai_keywords:
                if kw in svc_name or kw in svc_display:
                    self.add_finding(
                        severity='HIGH',
                        title=f'AI Service Running: {svc.get("DisplayName")}',
                        description=(
                            f'Windows service "{svc.get("DisplayName")}" '
                            f'(name: {svc.get("Name")}) is running with '
                            f'start type: {svc.get("StartType", "?")}. '
                            f'This is a persistent AI service.'
                        ),
                        affected_asset=hostname,
                        finding_type='insecure_configuration',
                        detection_method='service_enumeration',
                        remediation=(
                            f'Stop and disable the service if unauthorized: '
                            f'Stop-Service "{svc.get("Name")}"; '
                            f'Set-Service "{svc.get("Name")}" -StartupType Disabled'
                        ),
                    )
                    break

    def _check_ai_models(self, hostname: str) -> None:
        """Scan for AI model files on disk (deep scan only)."""
        import glob as _glob

        model_files = []
        # Check known model directories
        for pattern in self.AI_MODEL_SEARCH_PATHS:
            try:
                base_dirs = _glob.glob(pattern)
                for base_dir in base_dirs:
                    for ext in ['.gguf', '.ggml', '.safetensors']:
                        matches = _glob.glob(
                            os.path.join(base_dir, '**', f'*{ext}'),
                            recursive=True
                        )
                        model_files.extend(matches[:50])  # cap per dir
            except Exception:
                continue

        if model_files:
            total_size = 0
            model_list = []
            for mf in model_files[:20]:  # report up to 20
                try:
                    sz = os.path.getsize(mf)
                    total_size += sz
                    model_list.append(f'{os.path.basename(mf)} ({sz / (1024**3):.1f} GB)')
                except OSError:
                    model_list.append(os.path.basename(mf))

            self.add_finding(
                severity='HIGH',
                title=f'AI Model Files Found ({len(model_files)} files, '
                      f'{total_size / (1024**3):.1f} GB)',
                description=(
                    f'Found {len(model_files)} AI model files on disk. '
                    f'Total size: {total_size / (1024**3):.1f} GB. '
                    f'Files include: {"; ".join(model_list[:10])}. '
                    f'Large language models stored locally may indicate '
                    f'unauthorized AI usage and consume significant storage.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                detection_method='powershell_cmdlet',
                remediation=(
                    'Review AI model files and remove unauthorized ones. '
                    'Implement DLP controls to detect model file downloads.'
                ),
            )

    def _check_ai_scheduled_tasks(self, hostname: str) -> None:
        """Check for AI-related scheduled tasks."""
        tasks = self._run_ps_json(
            "Get-ScheduledTask -ErrorAction SilentlyContinue "
            "| Where-Object { $_.State -ne 'Disabled' } "
            "| Select-Object TaskName, TaskPath, State, "
            "  @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute }) -join ';'}} "
            "| ConvertTo-Json -Depth 2"
        )
        if not tasks:
            return
        if isinstance(tasks, dict):
            tasks = [tasks]

        ai_keywords = ['ollama', 'lm studio', 'gpt4all', 'localai',
                        'kobold', 'openclaw', 'llamafile']
        for task in tasks:
            name = (task.get('TaskName') or '').lower()
            actions = (task.get('Actions') or '').lower()
            for kw in ai_keywords:
                if kw in name or kw in actions:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'AI Scheduled Task: {task.get("TaskName")}',
                        description=(
                            f'Scheduled task "{task.get("TaskName")}" '
                            f'(state: {task.get("State")}) references AI software. '
                            f'Actions: {task.get("Actions", "?")}.'
                        ),
                        affected_asset=hostname,
                        finding_type='scheduled_task_anomaly',
                        detection_method='powershell_cmdlet',
                        remediation='Disable or remove unauthorized AI scheduled tasks.',
                    )
                    break

    def _check_ai_browser_extensions(self, hostname: str) -> None:
        """Check for AI-related browser extensions (Chrome/Edge)."""
        import glob as _glob

        ai_extension_ids = {
            # Chrome extension IDs for popular AI tools
            'jbdheaknhcalmapenleimoadanoclfjb': 'ChatGPT Chrome Extension',
            'aapbdbdomjkkjkaonfhkkikfgjllcleb': 'Google Translate (AI)',
            'mhnlakgilnojmhinhkckjpncpbhabphi': 'Claude Chrome Extension',
        }

        ai_extension_names = [
            'chatgpt', 'openai', 'claude', 'copilot', 'bard', 'gemini',
            'ollama', 'perplexity', 'character.ai', 'poe', 'writesonic',
            'jasper', 'copy.ai', 'notion ai', 'grammarly ai',
        ]

        # Scan Chrome and Edge extension directories
        ext_patterns = [
            r'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions\*',
            r'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\*',
        ]

        found_ai_extensions = []
        for pattern in ext_patterns:
            try:
                for ext_dir in _glob.glob(pattern):
                    ext_id = os.path.basename(ext_dir)
                    if ext_id in ai_extension_ids:
                        found_ai_extensions.append(ai_extension_ids[ext_id])
                        continue
                    # Check manifest for AI-related names
                    manifest_files = _glob.glob(
                        os.path.join(ext_dir, '*', 'manifest.json')
                    )
                    for mf in manifest_files[:1]:
                        try:
                            with open(mf, 'r', encoding='utf-8') as f:
                                manifest = json.load(f)
                            name = (manifest.get('name') or '').lower()
                            desc = (manifest.get('description') or '').lower()
                            for kw in ai_extension_names:
                                if kw in name or kw in desc:
                                    found_ai_extensions.append(
                                        manifest.get('name', ext_id)
                                    )
                                    break
                        except Exception:
                            continue
            except Exception:
                continue

        for ext_name in found_ai_extensions[:10]:
            self.add_finding(
                severity='LOW',
                title=f'AI Browser Extension: {ext_name}',
                description=(
                    f'Browser extension "{ext_name}" detected. '
                    f'AI browser extensions may transmit sensitive data to '
                    f'third-party AI services.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                detection_method='powershell_cmdlet',
                remediation=(
                    'Review browser extension policies. Use Group Policy to '
                    'manage allowed extensions if AI tools are not authorized.'
                ),
            )

    def _check_ai_python_packages(self, hostname: str) -> None:
        """Check for AI-related Python packages installed."""
        pip_output = self._run_ps(
            "& { $pips = @(); "
            "foreach ($p in (Get-Command pip, pip3 -ErrorAction SilentlyContinue)) { "
            "  $pips += & $p.Source list 2>$null }; "
            "$pips | Select-Object -Unique }"
        )
        if not pip_output:
            return

        ai_packages = [
            'openai', 'anthropic', 'langchain', 'transformers', 'torch',
            'tensorflow', 'ollama', 'llama-cpp-python', 'vllm',
            'huggingface-hub', 'sentence-transformers', 'chromadb',
            'pinecone', 'weaviate', 'qdrant', 'faiss', 'auto-gptq',
            'ctransformers', 'guidance', 'llamaindex', 'llama-index',
            'autogen', 'crewai', 'langsmith', 'litellm',
        ]

        found = []
        for line in pip_output.splitlines():
            pkg_name = line.strip().split()[0].lower() if line.strip() else ''
            for ai_pkg in ai_packages:
                if ai_pkg == pkg_name:
                    found.append(pkg_name)
                    break

        if found:
            self.add_finding(
                severity='MEDIUM',
                title=f'AI Python Packages Installed ({len(found)})',
                description=(
                    f'Found {len(found)} AI-related Python packages: '
                    f'{", ".join(found[:15])}. '
                    f'These enable local AI development and API access.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                detection_method='service_enumeration',
                remediation=(
                    'Review AI Python packages against authorized software list. '
                    'Remove unauthorized packages with: pip uninstall <package>'
                ),
            )

    def _check_ai_network_rules(self, hostname: str) -> None:
        """Check firewall for rules allowing AI service traffic."""
        rules = self._run_ps_json(
            "Get-NetFirewallRule -Direction Inbound -Action Allow "
            "-Enabled True -ErrorAction SilentlyContinue "
            "| Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue "
            "| Select-Object Program "
            "| ConvertTo-Json -Depth 2"
        )
        if not rules:
            return
        if isinstance(rules, dict):
            rules = [rules]

        ai_keywords = ['ollama', 'lm-studio', 'gpt4all', 'koboldcpp',
                        'localai', 'openclaw', 'llamafile']

        for rule in rules:
            program = (rule.get('Program') or '').lower()
            for kw in ai_keywords:
                if kw in program:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'Firewall Rule Allows AI Service: {os.path.basename(program)}',
                        description=(
                            f'Inbound firewall rule allows traffic to AI application: '
                            f'{rule.get("Program")}.'
                        ),
                        affected_asset=hostname,
                        finding_type='firewall_config',
                        detection_method='powershell_cmdlet',
                        remediation='Remove or disable unauthorized AI firewall rules.',
                    )
                    break

    # ===================================================================== #
    #  Air-gap / offline readiness check                                    #
    # ===================================================================== #

    @staticmethod
    def verify_offline_data() -> Dict:
        """Check offline data and tools readiness for air-gapped operation.

        Returns a dict with ``ready`` (bool) and ``details`` describing the
        availability of the vulnerability database, KEV catalog, EPSS data,
        and bundled tools.
        """
        from paths import paths as _paths

        status: Dict[str, Any] = {'ready': True, 'details': {}}

        # --- Vulnerability database ---
        db_path = _paths.data / 'vuln_db' / 'vuln_intel.db'
        if db_path.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(db_path))
                count = conn.execute('SELECT COUNT(*) FROM nvd_cves').fetchone()[0]
                conn.close()
                size_mb = db_path.stat().st_size / (1024 * 1024)
                status['details']['vuln_db'] = {
                    'cve_count': count,
                    'size_mb': round(size_mb, 1),
                }
            except Exception as exc:
                status['details']['vuln_db'] = {'status': f'error: {exc}'}
                status['ready'] = False
        else:
            status['details']['vuln_db'] = {'status': 'missing'}
            status['ready'] = False

        # --- CISA KEV catalog ---
        kev_path = _paths.data / 'threat_intel' / 'cisa_kev.json'
        if kev_path.exists():
            try:
                data = json.loads(kev_path.read_text(encoding='utf-8'))
                entries = len(data.get('vulnerabilities', []))
                status['details']['kev'] = {'entries': entries}
            except Exception as exc:
                status['details']['kev'] = {'status': f'error: {exc}'}
        else:
            status['details']['kev'] = {'status': 'missing'}

        # --- EPSS cache ---
        epss_path = _paths.data / 'threat_intel' / 'epss_cache.json'
        if epss_path.exists():
            size_mb = epss_path.stat().st_size / (1024 * 1024)
            status['details']['epss'] = {
                'status': 'present',
                'size_mb': round(size_mb, 1),
            }
        else:
            status['details']['epss'] = {'status': 'missing'}

        # --- Bundled tools ---
        tools_dir = _paths.home / 'tools'
        tools_found: List[str] = []
        if tools_dir.exists():
            for item in tools_dir.iterdir():
                if item.is_file() and item.suffix == '.exe':
                    tools_found.append(item.stem)
                elif item.is_dir():
                    tools_found.append(item.name)
        status['details']['tools'] = tools_found

        return status


# =========================================================================== #
#  CLI entry point                                                            #
# =========================================================================== #

if __name__ == '__main__':
    import sys as _sys

    scan_type = _sys.argv[1] if len(_sys.argv) > 1 else 'standard'
    scanner = WindowsScanner()

    print(f"Windows Security Scanner - {scan_type} scan")
    print("=" * 50)

    # Show offline data status
    offline = WindowsScanner.verify_offline_data()
    print(f"Offline data: {'READY' if offline['ready'] else 'INCOMPLETE'}")
    for k, v in offline['details'].items():
        print(f"  {k}: {v}")
    print()

    results = scanner.scan(scan_type=scan_type)

    # Print summary
    summary = results.get('summary', {})
    print(f"\nScan Complete:")
    print(f"  Admin: {results.get('is_admin', False)}")
    print(f"  Checks completed: {results.get('checks_completed', 0)}")
    print(f"  Checks skipped: {results.get('checks_skipped', 0)}")
    print(f"  Findings: {summary.get('findings_count', 0)}")
    for sev, count in summary.get('findings_by_severity', {}).items():
        if count > 0:
            print(f"    {sev}: {count}")
