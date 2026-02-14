#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Active Directory Security Scanner

Assesses Active Directory security configuration on domain-joined Windows
machines using PowerShell AD cmdlets and LDAP queries.

Performs 10 security checks covering:
  1.  Domain information and functional level
  2.  Password policy assessment
  3.  Privileged account enumeration
  4.  Stale / dormant account detection
  5.  Kerberos attack surface (Kerberoast, AS-REP roast, delegation)
  6.  GPO security analysis
  7.  LDAP security configuration
  8.  Trust relationship assessment
  9.  SYSVOL / NETLOGON replication share permissions
  10. DNS zone security

Scan types:
  quick    - checks 1-4 only
  standard - all 10 checks
  deep     - all 10 checks with expanded depth (nested groups, all GPOs)

Requires: domain-joined Windows host with RSAT / AD PowerShell module.
"""

import json
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


class ADScanner(BaseScanner):
    """Active Directory security scanner using PowerShell AD cmdlets."""

    SCANNER_NAME = "activedirectory"
    SCANNER_DESCRIPTION = "Active Directory security assessment"

    # Privileged groups to audit
    PRIVILEGED_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
    ]

    # Stale threshold in days
    STALE_THRESHOLD_DAYS = 90

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.domain_info: Dict[str, Any] = {}
        self.domain_dn: str = ""

    # -----------------------------------------------------------------------
    # PowerShell helpers
    # -----------------------------------------------------------------------

    def _run_ps(self, script: str, timeout: int = 120) -> Optional[str]:
        """Execute a PowerShell command and return stdout, or None on error."""
        cmd = [
            'powershell.exe',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-Command', script,
        ]
        self.scan_logger.debug(
            f"PS> {script[:120]}{'...' if len(script) > 120 else ''}"
        )
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode != 0:
                stderr = (proc.stderr or '').strip()
                if stderr:
                    self.scan_logger.debug(f"PS stderr: {stderr[:200]}")
                return None
            return (proc.stdout or '').strip()
        except subprocess.TimeoutExpired:
            self.scan_logger.warning("PowerShell command timed out")
            return None
        except Exception as exc:
            self.scan_logger.debug(f"PowerShell error: {exc}")
            return None

    def _run_ps_json(self, script: str, timeout: int = 120) -> Any:
        """Run a PowerShell command and parse the JSON output."""
        full_script = f"{script} | ConvertTo-Json -Depth 5 -Compress"
        raw = self._run_ps(full_script, timeout=timeout)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            self.scan_logger.debug("Failed to parse PS JSON output")
            return None

    def _run_ad_query(self, ldap_filter: str,
                      properties: List[str]) -> List[Dict]:
        """Query AD objects via Get-ADObject with an LDAP filter.

        Returns a list of dicts with the requested properties.
        """
        props_str = ','.join(f"'{p}'" for p in properties)
        script = (
            f"Import-Module ActiveDirectory -ErrorAction Stop; "
            f"Get-ADObject -LDAPFilter '{ldap_filter}' "
            f"-Properties {','.join(properties)} "
            f"| Select-Object {','.join(properties)} "
            f"| ConvertTo-Json -Depth 3 -Compress"
        )
        raw = self._run_ps(script, timeout=180)
        if not raw:
            return []
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return [data]
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError:
            return []

    # -----------------------------------------------------------------------
    # AD module availability check
    # -----------------------------------------------------------------------

    def _check_ad_module(self) -> bool:
        """Return True if the ActiveDirectory PS module is available."""
        result = self._run_ps(
            "Import-Module ActiveDirectory -ErrorAction Stop; "
            "Write-Output 'OK'"
        )
        return result is not None and 'OK' in result

    # -----------------------------------------------------------------------
    # Main scan entry point
    # -----------------------------------------------------------------------

    def scan(self, targets: List[str] = None, scan_type: str = 'standard',
             **kwargs) -> Dict:
        """Execute Active Directory security scan.

        Args:
            targets: Ignored (scans the joined domain).
            scan_type: 'quick', 'standard', or 'deep'.

        Returns:
            Dict with scan results and summary.
        """
        self.start_time = datetime.utcnow()
        self.scan_logger.info(
            f"Starting {scan_type} Active Directory scan"
        )

        # Verify prerequisites
        if sys.platform != 'win32':
            self.scan_logger.error("AD scanner requires Windows")
            self.end_time = datetime.utcnow()
            return {'error': 'AD scanner requires Windows'}

        if not self._check_ad_module():
            self.scan_logger.error(
                "ActiveDirectory PowerShell module not available"
            )
            self.add_finding(
                severity='HIGH',
                title='AD PowerShell Module Not Available',
                description=(
                    'The ActiveDirectory PowerShell module is not installed '
                    'or the machine is not domain-joined. Install RSAT or '
                    'run on a domain controller.'
                ),
                affected_asset='localhost',
                finding_type='ad_prerequisite',
                remediation='Install RSAT: Add-WindowsCapability -Name '
                            'Rsat.ActiveDirectory.DS-LDS.Tools -Online',
                detection_method='module_check',
            )
            self.end_time = datetime.utcnow()
            self.save_results()
            return self.get_summary()

        # Phase 1: Domain information (always)
        self.scan_logger.info("Phase 1: Domain Information")
        self._check_domain_info()
        self.human_delay()

        # Phase 2: Password policy (always)
        self.scan_logger.info("Phase 2: Password Policy")
        self._check_password_policy(scan_type)
        self.human_delay()

        # Phase 3: Privileged accounts (always)
        self.scan_logger.info("Phase 3: Privileged Accounts")
        self._check_privileged_accounts(scan_type)
        self.human_delay()

        # Phase 4: Stale accounts (always)
        self.scan_logger.info("Phase 4: Stale Accounts")
        self._check_stale_accounts(scan_type)
        self.human_delay()

        # Standard and deep only
        if scan_type in ('standard', 'deep'):
            # Phase 5: Kerberos
            self.scan_logger.info("Phase 5: Kerberos Security")
            self._check_kerberos(scan_type)
            self.human_delay()

            # Phase 6: GPO Security
            self.scan_logger.info("Phase 6: GPO Security")
            self._check_gpo_security(scan_type)
            self.human_delay()

            # Phase 7: LDAP Security
            self.scan_logger.info("Phase 7: LDAP Security")
            self._check_ldap_security()
            self.human_delay()

            # Phase 8: Trust Relationships
            self.scan_logger.info("Phase 8: Trust Relationships")
            self._check_trusts()
            self.human_delay()

            # Phase 9: Replication shares
            self.scan_logger.info("Phase 9: Replication Shares")
            self._check_replication()
            self.human_delay()

            # Phase 10: DNS Security
            self.scan_logger.info("Phase 10: DNS Security")
            self._check_dns_security()
            self.human_delay()

        self.end_time = datetime.utcnow()
        self.save_results()

        summary = self.get_summary()
        self.scan_logger.info(
            f"AD scan complete: {summary['findings_count']} findings"
        )
        return summary

    # -----------------------------------------------------------------------
    # Check 1: Domain Information
    # -----------------------------------------------------------------------

    def _check_domain_info(self) -> None:
        """Gather domain metadata, functional level, and trusts."""
        data = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADDomain | Select-Object Name,DNSRoot,DomainMode,"
            "NetBIOSName,Forest,InfrastructureMaster,"
            "PDCEmulator,RIDMaster,DistinguishedName,"
            "DomainSID"
        )
        if not data:
            self.scan_logger.warning("Could not retrieve domain information")
            return

        self.domain_info = data if isinstance(data, dict) else {}
        self.domain_dn = self.domain_info.get('DistinguishedName', '')
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        self.add_result('domain_info', self.domain_info, domain_name)

        # Check functional level
        domain_mode = self.domain_info.get('DomainMode', '')
        old_levels = [
            'Windows2003Domain', 'Windows2008Domain',
            'Windows2008R2Domain', 'Windows2012Domain',
        ]
        if any(level in str(domain_mode) for level in old_levels):
            self.add_finding(
                severity='MEDIUM',
                title='Outdated Domain Functional Level',
                description=(
                    f"Domain '{domain_name}' is running at functional level "
                    f"'{domain_mode}'. Older levels lack modern security "
                    f"features such as Protected Users group, authentication "
                    f"policies, and AES Kerberos support."
                ),
                affected_asset=domain_name,
                finding_type='ad_functional_level',
                remediation=(
                    'Raise the domain functional level to Windows Server 2016 '
                    'or later after ensuring all DCs meet the minimum OS.'
                ),
                raw_data=self.domain_info,
                detection_method='ad_cmdlet',
            )
        else:
            self.add_finding(
                severity='INFO',
                title='Domain Functional Level',
                description=(
                    f"Domain '{domain_name}' is at functional level "
                    f"'{domain_mode}'."
                ),
                affected_asset=domain_name,
                finding_type='ad_functional_level',
                raw_data=self.domain_info,
                detection_method='ad_cmdlet',
            )

        # Forest functional level
        forest_data = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADForest | Select-Object Name,ForestMode,"
            "RootDomain,Domains,GlobalCatalogs,SchemaMaster,"
            "DomainNamingMaster"
        )
        if forest_data:
            self.add_result(
                'forest_info', forest_data,
                forest_data.get('Name', 'unknown')
            )

    # -----------------------------------------------------------------------
    # Check 2: Password Policy
    # -----------------------------------------------------------------------

    def _check_password_policy(self, scan_type: str) -> None:
        """Assess default and fine-grained password policies."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        # Default domain password policy
        policy = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADDefaultDomainPasswordPolicy | Select-Object "
            "ComplexityEnabled,LockoutDuration,LockoutObservationWindow,"
            "LockoutThreshold,MaxPasswordAge,MinPasswordAge,"
            "MinPasswordLength,PasswordHistoryCount,"
            "ReversibleEncryptionEnabled"
        )
        if policy:
            self.add_result('password_policy', policy, domain_name)
            self._evaluate_password_policy(policy, domain_name)

        # Fine-grained password policies (PSOs)
        fgpp = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADFineGrainedPasswordPolicy -Filter * | "
            "Select-Object Name,Precedence,MinPasswordLength,"
            "ComplexityEnabled,LockoutThreshold,MaxPasswordAge,"
            "PasswordHistoryCount,AppliesTo"
        )
        if fgpp:
            policies = fgpp if isinstance(fgpp, list) else [fgpp]
            self.add_result(
                'fine_grained_policies',
                {'count': len(policies), 'policies': policies},
                domain_name,
            )
            for fgp in policies:
                min_len = fgp.get('MinPasswordLength', 0)
                if isinstance(min_len, (int, float)) and min_len < 12:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f"Weak Fine-Grained Password Policy: "
                              f"{fgp.get('Name', 'unknown')}",
                        description=(
                            f"Fine-grained policy '{fgp.get('Name')}' "
                            f"requires only {min_len} characters."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_password_policy',
                        remediation='Increase minimum length to at least 14.',
                        raw_data=fgp,
                        detection_method='ad_cmdlet',
                    )

        # Accounts with PasswordNeverExpires
        never_expires = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADUser -Filter {PasswordNeverExpires -eq $true -and "
            "Enabled -eq $true} -Properties Name,SamAccountName,"
            "PasswordNeverExpires,PasswordLastSet,LastLogonDate "
            "| Select-Object Name,SamAccountName,PasswordLastSet,"
            "LastLogonDate "
            "| Measure-Object | Select-Object Count"
        )
        if never_expires:
            count = never_expires.get('Count', 0)
            if isinstance(count, (int, float)) and count > 0:
                sev = 'HIGH' if count > 50 else 'MEDIUM'
                self.add_finding(
                    severity=sev,
                    title=f'{count} Accounts With Non-Expiring Passwords',
                    description=(
                        f"{count} enabled user accounts have "
                        f"PasswordNeverExpires set. This violates most "
                        f"compliance frameworks and increases credential "
                        f"compromise risk."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_password_policy',
                    remediation=(
                        'Remove PasswordNeverExpires flag from user accounts. '
                        'Use fine-grained policies for service accounts.'
                    ),
                    raw_data=never_expires,
                    detection_method='ad_cmdlet',
                )

    def _evaluate_password_policy(self, policy: Dict,
                                  domain_name: str) -> None:
        """Evaluate password policy settings and raise findings."""
        # Minimum length
        min_len = policy.get('MinPasswordLength', 0)
        if isinstance(min_len, (int, float)):
            if min_len < 8:
                sev = 'CRITICAL'
            elif min_len < 12:
                sev = 'HIGH'
            elif min_len < 14:
                sev = 'MEDIUM'
            else:
                sev = None

            if sev:
                self.add_finding(
                    severity=sev,
                    title=f'Weak Minimum Password Length ({min_len})',
                    description=(
                        f"Domain password policy requires only {min_len} "
                        f"characters. NIST SP 800-63B recommends at least 8 "
                        f"characters and industry best practice is 14+."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_password_policy',
                    remediation='Increase MinPasswordLength to at least 14.',
                    raw_data=policy,
                    detection_method='ad_cmdlet',
                )

        # Complexity
        if not policy.get('ComplexityEnabled', True):
            self.add_finding(
                severity='HIGH',
                title='Password Complexity Disabled',
                description=(
                    'The default domain password policy does not require '
                    'complexity. Users may set trivially guessable passwords.'
                ),
                affected_asset=domain_name,
                finding_type='ad_password_policy',
                remediation='Enable password complexity requirements.',
                raw_data=policy,
                detection_method='ad_cmdlet',
            )

        # Reversible encryption
        if policy.get('ReversibleEncryptionEnabled', False):
            self.add_finding(
                severity='CRITICAL',
                title='Reversible Encryption Enabled',
                description=(
                    'Storing passwords with reversible encryption is '
                    'equivalent to storing them in plaintext.'
                ),
                affected_asset=domain_name,
                finding_type='ad_password_policy',
                remediation=(
                    'Disable reversible encryption and reset all affected '
                    'passwords.'
                ),
                raw_data=policy,
                detection_method='ad_cmdlet',
            )

        # Lockout threshold
        lockout = policy.get('LockoutThreshold', 0)
        if isinstance(lockout, (int, float)) and lockout == 0:
            self.add_finding(
                severity='HIGH',
                title='No Account Lockout Policy',
                description=(
                    'No account lockout threshold is configured. Brute-force '
                    'attacks can run indefinitely without triggering lockout.'
                ),
                affected_asset=domain_name,
                finding_type='ad_password_policy',
                remediation='Set LockoutThreshold to 5-10 attempts.',
                raw_data=policy,
                detection_method='ad_cmdlet',
            )

        # Password history
        history = policy.get('PasswordHistoryCount', 0)
        if isinstance(history, (int, float)) and history < 12:
            self.add_finding(
                severity='LOW',
                title=f'Low Password History Count ({history})',
                description=(
                    f"Password history remembers only {history} passwords. "
                    f"Users can quickly cycle back to old passwords."
                ),
                affected_asset=domain_name,
                finding_type='ad_password_policy',
                remediation='Set PasswordHistoryCount to at least 24.',
                raw_data=policy,
                detection_method='ad_cmdlet',
            )

    # -----------------------------------------------------------------------
    # Check 3: Privileged Accounts
    # -----------------------------------------------------------------------

    def _check_privileged_accounts(self, scan_type: str) -> None:
        """Enumerate privileged group membership."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')
        total_privileged = 0

        for group_name in self.PRIVILEGED_GROUPS:
            members = self._run_ps_json(
                f"Import-Module ActiveDirectory; "
                f"Get-ADGroupMember '{group_name}' -ErrorAction SilentlyContinue "
                f"| Select-Object Name,SamAccountName,objectClass,distinguishedName"
            )
            if members is None:
                continue

            if isinstance(members, dict):
                members = [members]

            count = len(members)
            total_privileged += count

            self.add_result(
                'privileged_group',
                {'group': group_name, 'count': count, 'members': members},
                domain_name,
            )

            # Too many members in critical groups
            if group_name in ('Domain Admins', 'Enterprise Admins',
                              'Schema Admins'):
                if count > 5:
                    self.add_finding(
                        severity='HIGH',
                        title=f'Excessive {group_name} Members ({count})',
                        description=(
                            f"The '{group_name}' group has {count} members. "
                            f"Excessive privileged accounts increase attack "
                            f"surface."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_privileged_accounts',
                        remediation=(
                            f"Review and reduce {group_name} membership to "
                            f"the minimum necessary."
                        ),
                        raw_data=members,
                        detection_method='ad_cmdlet',
                    )

            # Service accounts in admin groups
            for member in members:
                sam = str(member.get('SamAccountName', '')).lower()
                if any(tok in sam for tok in ('svc', 'service', 'sql', 'app',
                                              'backup', 'scan', 'task')):
                    self.add_finding(
                        severity='HIGH',
                        title=(
                            f"Service Account in {group_name}: "
                            f"{member.get('SamAccountName')}"
                        ),
                        description=(
                            f"Account '{member.get('SamAccountName')}' "
                            f"appears to be a service account and is a "
                            f"member of '{group_name}'. Service accounts "
                            f"should use least privilege."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_privileged_accounts',
                        remediation=(
                            'Remove service accounts from privileged groups '
                            'and use Managed Service Accounts (gMSA).'
                        ),
                        raw_data=member,
                        detection_method='ad_cmdlet',
                    )

        # Deep scan: nested group membership
        if scan_type == 'deep':
            self._check_nested_groups(domain_name)

        self.add_finding(
            severity='INFO',
            title=f'Privileged Account Summary: {total_privileged} Total',
            description=(
                f"Found {total_privileged} accounts across "
                f"{len(self.PRIVILEGED_GROUPS)} privileged groups."
            ),
            affected_asset=domain_name,
            finding_type='ad_privileged_accounts',
            detection_method='ad_cmdlet',
        )

    def _check_nested_groups(self, domain_name: str) -> None:
        """Check for nested group membership in privileged groups."""
        for group_name in ('Domain Admins', 'Enterprise Admins'):
            nested = self._run_ps_json(
                f"Import-Module ActiveDirectory; "
                f"Get-ADGroupMember '{group_name}' -Recursive "
                f"| Where-Object {{ $_.objectClass -eq 'user' }} "
                f"| Select-Object Name,SamAccountName "
            )
            direct = self._run_ps_json(
                f"Import-Module ActiveDirectory; "
                f"Get-ADGroupMember '{group_name}' "
                f"| Where-Object {{ $_.objectClass -eq 'user' }} "
                f"| Select-Object Name,SamAccountName "
            )
            if nested and direct:
                nested_list = nested if isinstance(nested, list) else [nested]
                direct_list = direct if isinstance(direct, list) else [direct]
                if len(nested_list) > len(direct_list):
                    diff = len(nested_list) - len(direct_list)
                    self.add_finding(
                        severity='MEDIUM',
                        title=(
                            f'{diff} Nested Members in {group_name}'
                        ),
                        description=(
                            f"'{group_name}' has {diff} users who are members "
                            f"only through nested group membership, making "
                            f"privilege auditing more difficult."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_privileged_accounts',
                        remediation=(
                            'Flatten nested group memberships or document '
                            'approved nesting paths.'
                        ),
                        raw_data={
                            'direct_count': len(direct_list),
                            'recursive_count': len(nested_list),
                        },
                        detection_method='ad_cmdlet',
                    )

    # -----------------------------------------------------------------------
    # Check 4: Stale Accounts
    # -----------------------------------------------------------------------

    def _check_stale_accounts(self, scan_type: str) -> None:
        """Find stale, dormant, and misconfigured accounts."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')
        threshold = datetime.utcnow() - timedelta(days=self.STALE_THRESHOLD_DAYS)
        threshold_str = threshold.strftime('%m/%d/%Y')

        # Accounts not logged in for 90+ days
        stale_count_data = self._run_ps_json(
            f"Import-Module ActiveDirectory; "
            f"$cutoff = (Get-Date).AddDays(-{self.STALE_THRESHOLD_DAYS}); "
            f"Get-ADUser -Filter {{LastLogonDate -lt $cutoff -and "
            f"Enabled -eq $true}} -Properties LastLogonDate "
            f"| Measure-Object | Select-Object Count"
        )
        if stale_count_data:
            count = stale_count_data.get('Count', 0)
            if isinstance(count, (int, float)) and count > 0:
                sev = 'HIGH' if count > 100 else 'MEDIUM'
                self.add_finding(
                    severity=sev,
                    title=f'{count} Stale Accounts (No Login in {self.STALE_THRESHOLD_DAYS}+ Days)',
                    description=(
                        f"{count} enabled accounts have not logged in for "
                        f"over {self.STALE_THRESHOLD_DAYS} days. Dormant "
                        f"accounts are prime targets for attackers."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_stale_accounts',
                    remediation=(
                        'Disable or remove stale accounts. Implement an '
                        'automated account lifecycle process.'
                    ),
                    raw_data=stale_count_data,
                    detection_method='ad_cmdlet',
                )

        # Disabled accounts still in privileged groups
        for group_name in ('Domain Admins', 'Enterprise Admins',
                           'Schema Admins'):
            disabled_in_group = self._run_ps_json(
                f"Import-Module ActiveDirectory; "
                f"Get-ADGroupMember '{group_name}' "
                f"| Where-Object {{ $_.objectClass -eq 'user' }} "
                f"| Get-ADUser -Properties Enabled "
                f"| Where-Object {{ $_.Enabled -eq $false }} "
                f"| Select-Object Name,SamAccountName"
            )
            if disabled_in_group:
                items = (disabled_in_group if isinstance(disabled_in_group, list)
                         else [disabled_in_group])
                if items:
                    self.add_finding(
                        severity='MEDIUM',
                        title=(
                            f'{len(items)} Disabled Accounts in {group_name}'
                        ),
                        description=(
                            f"{len(items)} disabled accounts remain in "
                            f"'{group_name}'. They should be removed to "
                            f"maintain clean group membership."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_stale_accounts',
                        remediation=(
                            f'Remove disabled accounts from {group_name}.'
                        ),
                        raw_data=items,
                        detection_method='ad_cmdlet',
                    )

        # Accounts with password never expires (already checked in phase 2
        # but here we look for intersection with stale accounts)
        if scan_type == 'deep':
            stale_never_expire = self._run_ps_json(
                f"Import-Module ActiveDirectory; "
                f"$cutoff = (Get-Date).AddDays(-{self.STALE_THRESHOLD_DAYS}); "
                f"Get-ADUser -Filter {{PasswordNeverExpires -eq $true -and "
                f"Enabled -eq $true -and LastLogonDate -lt $cutoff}} "
                f"-Properties LastLogonDate,PasswordLastSet "
                f"| Measure-Object | Select-Object Count"
            )
            if stale_never_expire:
                count = stale_never_expire.get('Count', 0)
                if isinstance(count, (int, float)) and count > 0:
                    self.add_finding(
                        severity='HIGH',
                        title=(
                            f'{count} Stale Accounts With Non-Expiring '
                            f'Passwords'
                        ),
                        description=(
                            f"{count} accounts are stale, have non-expiring "
                            f"passwords, and are still enabled. This is a "
                            f"high-risk combination."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_stale_accounts',
                        remediation='Disable these accounts immediately.',
                        raw_data=stale_never_expire,
                        detection_method='ad_cmdlet',
                    )

        # Never-logged-in accounts
        never_logged = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADUser -Filter {LastLogonDate -notlike '*' -and "
            "Enabled -eq $true} -Properties LastLogonDate,WhenCreated "
            "| Measure-Object | Select-Object Count"
        )
        if never_logged:
            count = never_logged.get('Count', 0)
            if isinstance(count, (int, float)) and count > 10:
                self.add_finding(
                    severity='LOW',
                    title=f'{count} Enabled Accounts Never Logged In',
                    description=(
                        f"{count} enabled accounts have never logged in. "
                        f"These may be provisioned but unused accounts."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_stale_accounts',
                    remediation='Review and disable unused accounts.',
                    raw_data=never_logged,
                    detection_method='ad_cmdlet',
                )

    # -----------------------------------------------------------------------
    # Check 5: Kerberos Security
    # -----------------------------------------------------------------------

    def _check_kerberos(self, scan_type: str) -> None:
        """Check for Kerberos-related attack vectors."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        # Kerberoastable accounts (user accounts with SPNs)
        kerberoastable = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADUser -Filter {ServicePrincipalName -like '*' -and "
            "Enabled -eq $true} "
            "-Properties ServicePrincipalName,SamAccountName,"
            "PasswordLastSet,LastLogonDate,AdminCount "
            "| Select-Object SamAccountName,ServicePrincipalName,"
            "PasswordLastSet,LastLogonDate,AdminCount"
        )
        if kerberoastable:
            items = (kerberoastable if isinstance(kerberoastable, list)
                     else [kerberoastable])
            if items:
                admin_spns = [i for i in items
                              if i.get('AdminCount') == 1]
                self.add_finding(
                    severity='HIGH' if admin_spns else 'MEDIUM',
                    title=f'{len(items)} Kerberoastable Accounts',
                    description=(
                        f"{len(items)} enabled user accounts have SPNs set, "
                        f"making them targets for Kerberoasting. "
                        f"{len(admin_spns)} are admin accounts."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_kerberos',
                    remediation=(
                        'Use Managed Service Accounts (gMSA), ensure strong '
                        'passwords (25+ chars) on SPN accounts, and use '
                        'AES-only encryption.'
                    ),
                    raw_data={'count': len(items), 'admin_count': len(admin_spns)},
                    detection_method='ad_cmdlet',
                )

                # Individual high-risk SPN accounts
                for item in admin_spns:
                    self.add_finding(
                        severity='HIGH',
                        title=(
                            f"Admin Kerberoastable: "
                            f"{item.get('SamAccountName')}"
                        ),
                        description=(
                            f"Admin account '{item.get('SamAccountName')}' "
                            f"has SPNs set: {item.get('ServicePrincipalName')}."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_kerberos',
                        remediation=(
                            'Remove SPNs from admin accounts or migrate to '
                            'gMSA.'
                        ),
                        raw_data=item,
                        detection_method='ad_cmdlet',
                    )

        # AS-REP Roastable (no pre-auth required)
        asrep = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and "
            "Enabled -eq $true} "
            "-Properties DoesNotRequirePreAuth,SamAccountName "
            "| Select-Object SamAccountName"
        )
        if asrep:
            items = asrep if isinstance(asrep, list) else [asrep]
            if items:
                self.add_finding(
                    severity='HIGH',
                    title=f'{len(items)} AS-REP Roastable Accounts',
                    description=(
                        f"{len(items)} accounts do not require Kerberos "
                        f"pre-authentication, making them vulnerable to "
                        f"offline password cracking."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_kerberos',
                    remediation=(
                        'Enable Kerberos pre-authentication for all accounts.'
                    ),
                    raw_data=items,
                    detection_method='ad_cmdlet',
                )

        # Unconstrained delegation
        unconstrained = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADComputer -Filter {TrustedForDelegation -eq $true} "
            "-Properties TrustedForDelegation,DNSHostName "
            "| Select-Object Name,DNSHostName"
        )
        if unconstrained:
            items = unconstrained if isinstance(unconstrained, list) else [unconstrained]
            # Filter out domain controllers (they have unconstrained by default)
            non_dc = [i for i in items
                      if not str(i.get('Name', '')).upper().startswith('DC')]
            if non_dc:
                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'{len(non_dc)} Non-DC Hosts With Unconstrained '
                        f'Delegation'
                    ),
                    description=(
                        f"{len(non_dc)} non-DC computers have unconstrained "
                        f"delegation enabled. An attacker compromising these "
                        f"hosts can impersonate any user authenticating to them."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_kerberos',
                    remediation=(
                        'Switch to constrained delegation or resource-based '
                        'constrained delegation. Add sensitive accounts to '
                        'Protected Users group.'
                    ),
                    raw_data=non_dc,
                    detection_method='ad_cmdlet',
                )

        # Constrained delegation (deep scan)
        if scan_type == 'deep':
            constrained = self._run_ps_json(
                "Import-Module ActiveDirectory; "
                "Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} "
                "-Properties msDS-AllowedToDelegateTo,SamAccountName "
                "| Select-Object SamAccountName,msDS-AllowedToDelegateTo"
            )
            if constrained:
                items = constrained if isinstance(constrained, list) else [constrained]
                self.add_finding(
                    severity='INFO',
                    title=f'{len(items)} Objects With Constrained Delegation',
                    description=(
                        f"{len(items)} objects have constrained delegation "
                        f"configured. Review targets for appropriateness."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_kerberos',
                    raw_data=items,
                    detection_method='ad_cmdlet',
                )

    # -----------------------------------------------------------------------
    # Check 6: GPO Security
    # -----------------------------------------------------------------------

    def _check_gpo_security(self, scan_type: str) -> None:
        """Check GPO permissions and link enforcement."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        # Get all GPOs
        gpos = self._run_ps_json(
            "Import-Module GroupPolicy; "
            "Get-GPO -All | Select-Object DisplayName,Id,GpoStatus,"
            "CreationTime,ModificationTime,Owner"
        )
        if not gpos:
            self.scan_logger.warning("Could not retrieve GPOs")
            return

        gpo_list = gpos if isinstance(gpos, list) else [gpos]
        self.add_result(
            'gpo_list', {'count': len(gpo_list)}, domain_name
        )

        # Check for disabled GPOs still linked
        disabled_gpos = [g for g in gpo_list
                         if g.get('GpoStatus') == 'AllSettingsDisabled']
        if disabled_gpos:
            self.add_finding(
                severity='LOW',
                title=f'{len(disabled_gpos)} Fully Disabled GPOs',
                description=(
                    f"{len(disabled_gpos)} GPOs have all settings disabled "
                    f"but may still be linked. Consider removing them."
                ),
                affected_asset=domain_name,
                finding_type='ad_gpo_security',
                remediation='Remove or unlink disabled GPOs.',
                raw_data=disabled_gpos,
                detection_method='ad_cmdlet',
            )

        # GPO permissions check (deep scan checks all, standard checks top-level)
        limit = len(gpo_list) if scan_type == 'deep' else min(20, len(gpo_list))
        weak_perm_gpos = []

        for gpo in gpo_list[:limit]:
            gpo_name = gpo.get('DisplayName', 'unknown')
            perms = self._run_ps_json(
                f"Import-Module GroupPolicy; "
                f"Get-GPPermission -Name '{gpo_name}' -All "
                f"-ErrorAction SilentlyContinue "
                f"| Select-Object Trustee,Permission,Inherited"
            )
            if perms:
                perm_list = perms if isinstance(perms, list) else [perms]
                for perm in perm_list:
                    trustee = str(perm.get('Trustee', {})
                                 if isinstance(perm.get('Trustee'), dict)
                                 else perm.get('Trustee', ''))
                    permission = str(perm.get('Permission', ''))
                    # Flag if Authenticated Users or Domain Users have edit
                    if ('Authenticated Users' in trustee or
                            'Domain Users' in trustee):
                        if 'Edit' in permission or 'FullControl' in permission:
                            weak_perm_gpos.append({
                                'gpo': gpo_name,
                                'trustee': trustee,
                                'permission': permission,
                            })

        if weak_perm_gpos:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(weak_perm_gpos)} GPOs With Weak Permissions'
                ),
                description=(
                    f"{len(weak_perm_gpos)} GPOs grant edit or full-control "
                    f"permissions to broad groups. An attacker could modify "
                    f"GPOs to push malicious settings domain-wide."
                ),
                affected_asset=domain_name,
                finding_type='ad_gpo_security',
                remediation=(
                    'Restrict GPO edit permissions to specific admin groups.'
                ),
                raw_data=weak_perm_gpos,
                detection_method='ad_cmdlet',
            )

        # Check for unenforced GPO links on domain root
        ou_links = self._run_ps(
            f"Import-Module ActiveDirectory; "
            f"(Get-ADOrganizationalUnit -Filter * "
            f"-Properties gPLink | Where-Object {{ $_.gPLink }}).Count"
        )
        if ou_links:
            self.add_result(
                'gpo_links', {'ous_with_links': ou_links}, domain_name
            )

    # -----------------------------------------------------------------------
    # Check 7: LDAP Security
    # -----------------------------------------------------------------------

    def _check_ldap_security(self) -> None:
        """Check LDAP signing, channel binding, and anonymous bind."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        # LDAP signing requirement (registry)
        ldap_signing = self._run_ps(
            "Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
            "-Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty LDAPServerIntegrity"
        )
        if ldap_signing is not None:
            try:
                level = int(ldap_signing.strip())
            except ValueError:
                level = -1

            if level < 2:
                self.add_finding(
                    severity='HIGH',
                    title='LDAP Signing Not Required',
                    description=(
                        f"LDAP server integrity level is {level}. "
                        f"Level 2 (Require signing) is recommended to "
                        f"prevent LDAP relay attacks."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_ldap_security',
                    remediation=(
                        'Set LDAPServerIntegrity to 2 via GPO: '
                        'Computer Configuration > Policies > Windows Settings '
                        '> Security Settings > Local Policies > Security '
                        'Options > Domain controller: LDAP server signing '
                        'requirements = Require signing.'
                    ),
                    raw_data={'LDAPServerIntegrity': level},
                    detection_method='registry_check',
                )
            else:
                self.add_finding(
                    severity='INFO',
                    title='LDAP Signing Required',
                    description='LDAP signing is enforced (level 2).',
                    affected_asset=domain_name,
                    finding_type='ad_ldap_security',
                    detection_method='registry_check',
                )

        # LDAP channel binding
        channel_binding = self._run_ps(
            "Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
            "-Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty LdapEnforceChannelBinding"
        )
        if channel_binding is not None:
            try:
                cb_level = int(channel_binding.strip())
            except ValueError:
                cb_level = -1

            if cb_level < 2:
                self.add_finding(
                    severity='MEDIUM',
                    title='LDAP Channel Binding Not Enforced',
                    description=(
                        f"LDAP channel binding level is {cb_level}. "
                        f"Level 2 prevents LDAP relay via TLS."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_ldap_security',
                    remediation=(
                        'Set LdapEnforceChannelBinding to 2 in registry.'
                    ),
                    raw_data={'LdapEnforceChannelBinding': cb_level},
                    detection_method='registry_check',
                )
        else:
            self.add_finding(
                severity='MEDIUM',
                title='LDAP Channel Binding Not Configured',
                description=(
                    'The LdapEnforceChannelBinding registry value is not set. '
                    'Channel binding should be enabled to prevent relay attacks.'
                ),
                affected_asset=domain_name,
                finding_type='ad_ldap_security',
                remediation='Set LdapEnforceChannelBinding to 2.',
                detection_method='registry_check',
            )

        # Anonymous LDAP bind
        anon_bind = self._run_ps(
            "Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
            "-Name 'dsHeuristics' -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty dsHeuristics"
        )
        if anon_bind:
            # 7th character controls anonymous access
            heuristics = anon_bind.strip()
            if len(heuristics) >= 7 and heuristics[6] == '2':
                self.add_finding(
                    severity='HIGH',
                    title='Anonymous LDAP Bind Enabled',
                    description=(
                        'dsHeuristics 7th character is set to 2, enabling '
                        'anonymous LDAP access. Attackers can enumerate '
                        'directory information without credentials.'
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_ldap_security',
                    remediation='Disable anonymous LDAP bind in dsHeuristics.',
                    raw_data={'dsHeuristics': heuristics},
                    detection_method='registry_check',
                )

    # -----------------------------------------------------------------------
    # Check 8: Trust Relationships
    # -----------------------------------------------------------------------

    def _check_trusts(self) -> None:
        """Assess trust relationships and SID filtering."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        trusts = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADTrust -Filter * | Select-Object Name,Direction,"
            "TrustType,ForestTransitive,IntraForest,"
            "IsTreeParent,IsTreeRoot,SelectiveAuthentication,"
            "SIDFilteringForestAware,SIDFilteringQuarantined,"
            "TGTDelegation,TrustedPolicy,TrustingPolicy"
        )
        if not trusts:
            self.add_finding(
                severity='INFO',
                title='No Trust Relationships Found',
                description='No AD trust relationships detected.',
                affected_asset=domain_name,
                finding_type='ad_trusts',
                detection_method='ad_cmdlet',
            )
            return

        trust_list = trusts if isinstance(trusts, list) else [trusts]
        self.add_result(
            'trusts', {'count': len(trust_list), 'trusts': trust_list},
            domain_name,
        )

        for trust in trust_list:
            trust_name = trust.get('Name', 'unknown')
            direction = trust.get('Direction', 'unknown')

            # SID filtering disabled
            if not trust.get('SIDFilteringQuarantined', True):
                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'SID Filtering Disabled for Trust: {trust_name}'
                    ),
                    description=(
                        f"SID filtering is not quarantined on the trust "
                        f"with '{trust_name}' ({direction}). An attacker "
                        f"in the trusted domain could inject arbitrary SIDs "
                        f"to escalate privileges."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_trusts',
                    remediation=(
                        'Enable SID filtering: '
                        f'netdom trust {domain_name} /domain:{trust_name} '
                        '/quarantine:yes'
                    ),
                    raw_data=trust,
                    detection_method='ad_cmdlet',
                )

            # Selective authentication not enabled on external trusts
            if (not trust.get('IntraForest', True) and
                    not trust.get('SelectiveAuthentication', False)):
                self.add_finding(
                    severity='MEDIUM',
                    title=(
                        f'No Selective Auth on External Trust: {trust_name}'
                    ),
                    description=(
                        f"External trust with '{trust_name}' does not use "
                        f"selective authentication. All users in the trusted "
                        f"domain can authenticate to all resources."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_trusts',
                    remediation=(
                        'Enable selective authentication on external trusts.'
                    ),
                    raw_data=trust,
                    detection_method='ad_cmdlet',
                )

            # TGT delegation
            if trust.get('TGTDelegation', False):
                self.add_finding(
                    severity='MEDIUM',
                    title=f'TGT Delegation Enabled: {trust_name}',
                    description=(
                        f"TGT delegation is enabled on the trust with "
                        f"'{trust_name}'. This allows credential forwarding "
                        f"across trust boundaries."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_trusts',
                    remediation='Disable TGT delegation unless required.',
                    raw_data=trust,
                    detection_method='ad_cmdlet',
                )

    # -----------------------------------------------------------------------
    # Check 9: Replication (SYSVOL / NETLOGON)
    # -----------------------------------------------------------------------

    def _check_replication(self) -> None:
        """Check SYSVOL and NETLOGON share permissions."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        for share_name in ('SYSVOL', 'NETLOGON'):
            # Get share permissions
            perms = self._run_ps_json(
                f"Get-SmbShareAccess -Name '{share_name}' "
                f"-ErrorAction SilentlyContinue "
                f"| Select-Object AccountName,AccessControlType,AccessRight"
            )
            if perms:
                perm_list = perms if isinstance(perms, list) else [perms]
                self.add_result(
                    f'{share_name.lower()}_permissions',
                    {'share': share_name, 'permissions': perm_list},
                    domain_name,
                )

                for perm in perm_list:
                    acct = str(perm.get('AccountName', ''))
                    right = str(perm.get('AccessRight', ''))
                    acl_type = str(perm.get('AccessControlType', ''))

                    if (acl_type == 'Allow' and
                            ('Everyone' in acct or 'Anonymous' in acct)):
                        if 'Change' in right or 'Full' in right:
                            self.add_finding(
                                severity='CRITICAL',
                                title=(
                                    f'{share_name} Share Writable by '
                                    f'{acct}'
                                ),
                                description=(
                                    f"The {share_name} share grants "
                                    f"'{right}' to '{acct}'. This could "
                                    f"allow GPO tampering or malware "
                                    f"deployment."
                                ),
                                affected_asset=domain_name,
                                finding_type='ad_replication',
                                remediation=(
                                    f'Restrict {share_name} share permissions '
                                    f'to Authenticated Users with Read access.'
                                ),
                                raw_data=perm,
                                detection_method='share_check',
                            )

        # DFSR health (if running DFSR for SYSVOL)
        dfsr_state = self._run_ps(
            "Get-WmiObject -Class 'msftSR_ReplicationGroup' "
            "-Namespace 'root\\microsoftdfs' -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty ReplicationGroupName"
        )
        if dfsr_state:
            self.add_result(
                'dfsr_status',
                {'replication_groups': dfsr_state},
                domain_name,
            )
        else:
            # May be using FRS (legacy)
            frs_check = self._run_ps(
                "Get-Service 'NTFRS' -ErrorAction SilentlyContinue "
                "| Select-Object -ExpandProperty Status"
            )
            if frs_check and 'Running' in frs_check:
                self.add_finding(
                    severity='MEDIUM',
                    title='SYSVOL Using Legacy FRS Replication',
                    description=(
                        'SYSVOL is replicated via FRS instead of DFSR. '
                        'FRS is deprecated and should be migrated.'
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_replication',
                    remediation=(
                        'Migrate SYSVOL replication from FRS to DFSR using '
                        'dfsrmig.exe.'
                    ),
                    detection_method='service_check',
                )

    # -----------------------------------------------------------------------
    # Check 10: DNS Security
    # -----------------------------------------------------------------------

    def _check_dns_security(self) -> None:
        """Check DNS zone configuration and dynamic updates."""
        domain_name = self.domain_info.get('DNSRoot', 'unknown')

        # Get DNS zones
        zones = self._run_ps_json(
            "Get-DnsServerZone -ErrorAction SilentlyContinue "
            "| Where-Object { $_.IsAutoCreated -eq $false } "
            "| Select-Object ZoneName,ZoneType,DynamicUpdate,"
            "IsReverseLookupZone,IsSigned,SecureSecondaries"
        )
        if not zones:
            self.scan_logger.info("DNS Server zones not accessible")
            return

        zone_list = zones if isinstance(zones, list) else [zones]
        self.add_result(
            'dns_zones', {'count': len(zone_list), 'zones': zone_list},
            domain_name,
        )

        for zone in zone_list:
            zone_name = zone.get('ZoneName', 'unknown')
            dyn_update = str(zone.get('DynamicUpdate', ''))

            # Insecure dynamic updates
            if dyn_update == 'NonsecureAndSecure':
                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'Insecure Dynamic DNS Updates: {zone_name}'
                    ),
                    description=(
                        f"Zone '{zone_name}' allows non-secure dynamic "
                        f"updates. Any host can register DNS records, "
                        f"enabling DNS spoofing attacks."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_dns_security',
                    remediation=(
                        'Set dynamic updates to "Secure Only" for '
                        'AD-integrated zones.'
                    ),
                    raw_data=zone,
                    detection_method='dns_check',
                )
            elif dyn_update == 'None':
                self.add_finding(
                    severity='INFO',
                    title=f'Dynamic DNS Updates Disabled: {zone_name}',
                    description=(
                        f"Zone '{zone_name}' has dynamic updates disabled."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_dns_security',
                    raw_data=zone,
                    detection_method='dns_check',
                )

            # DNSSEC signing
            if not zone.get('IsSigned', False):
                is_reverse = zone.get('IsReverseLookupZone', False)
                if not is_reverse:
                    self.add_finding(
                        severity='LOW',
                        title=f'DNSSEC Not Enabled: {zone_name}',
                        description=(
                            f"Zone '{zone_name}' is not signed with DNSSEC. "
                            f"DNSSEC protects against DNS spoofing."
                        ),
                        affected_asset=domain_name,
                        finding_type='ad_dns_security',
                        remediation='Enable DNSSEC zone signing.',
                        raw_data=zone,
                        detection_method='dns_check',
                    )

            # Zone transfer restrictions
            sec_secondaries = zone.get('SecureSecondaries', '')
            if str(sec_secondaries) == 'TransferAnyServer':
                self.add_finding(
                    severity='MEDIUM',
                    title=f'Unrestricted Zone Transfers: {zone_name}',
                    description=(
                        f"Zone '{zone_name}' allows transfers to any server. "
                        f"Attackers can download the full zone contents."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_dns_security',
                    remediation=(
                        'Restrict zone transfers to specific name servers.'
                    ),
                    raw_data=zone,
                    detection_method='dns_check',
                )

        # Check for DNS admin group membership
        dns_admins = self._run_ps_json(
            "Import-Module ActiveDirectory; "
            "Get-ADGroupMember 'DnsAdmins' -ErrorAction SilentlyContinue "
            "| Select-Object Name,SamAccountName,objectClass"
        )
        if dns_admins:
            items = dns_admins if isinstance(dns_admins, list) else [dns_admins]
            if len(items) > 3:
                self.add_finding(
                    severity='MEDIUM',
                    title=f'{len(items)} Members in DnsAdmins Group',
                    description=(
                        f"The DnsAdmins group has {len(items)} members. "
                        f"DnsAdmins can load arbitrary DLLs on DCs via "
                        f"the DNS service, enabling privilege escalation."
                    ),
                    affected_asset=domain_name,
                    finding_type='ad_dns_security',
                    remediation=(
                        'Restrict DnsAdmins membership to dedicated DNS '
                        'admin accounts only.'
                    ),
                    raw_data=items,
                    detection_method='ad_cmdlet',
                )


if __name__ == '__main__':
    scanner = ADScanner()
    print(f"AD Scanner initialized: {scanner.SCANNER_NAME}")
    print(f"AD module available: {scanner._check_ad_module()}")
