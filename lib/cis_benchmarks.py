#!/usr/bin/env python3
"""
Purple Team Portable - CIS Benchmark Compliance Checks
Embeds CIS benchmark rules for Windows 11 Enterprise and Ubuntu 22.04 LTS
and executes compliance checks using native OS commands.
"""

import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
except ImportError:
    from paths import paths


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkRule:
    """Represents a single CIS benchmark check."""
    rule_id: str
    title: str
    description: str
    level: int              # 1 or 2
    scored: bool
    check_command: str       # shell command to execute
    expected_output: str     # regex the stdout should match for PASS
    remediation: str
    cis_section: str


# ---------------------------------------------------------------------------
# Embedded benchmark definitions
# ---------------------------------------------------------------------------

_CIS_WINDOWS_11_RULES: List[BenchmarkRule] = [
    # --- Password Policy ---
    BenchmarkRule(
        rule_id='W11-1.1.1', title='Minimum password length >= 14',
        description='Ensure the minimum password length policy is set to 14 or more characters.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(net accounts | Select-String \'Minimum password length\').ToString()"',
        expected_output=r'(?:1[4-9]|[2-9]\d|\d{3,})',
        remediation='Set "Minimum password length" to 14 or more in Local Security Policy > Account Policies > Password Policy.',
        cis_section='1.1 Password Policy',
    ),
    BenchmarkRule(
        rule_id='W11-1.1.2', title='Password complexity enabled',
        description='Ensure "Password must meet complexity requirements" is Enabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "secedit /export /cfg $env:TEMP\\secpol.cfg >$null 2>&1; (Select-String -Path $env:TEMP\\secpol.cfg -Pattern \'PasswordComplexity\').ToString()"',
        expected_output=r'PasswordComplexity\s*=\s*1',
        remediation='Enable "Password must meet complexity requirements" in Local Security Policy.',
        cis_section='1.1 Password Policy',
    ),
    BenchmarkRule(
        rule_id='W11-1.1.3', title='Maximum password age <= 365 days',
        description='Ensure the maximum password age is set to 365 days or fewer.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(net accounts | Select-String \'Maximum password age\').ToString()"',
        expected_output=r'(?:[1-9]|[1-9]\d|[12]\d{2}|3[0-5]\d|36[0-5])\s*$',
        remediation='Set "Maximum password age" to 365 or fewer days in Local Security Policy.',
        cis_section='1.1 Password Policy',
    ),
    BenchmarkRule(
        rule_id='W11-1.1.4', title='Minimum password age >= 1 day',
        description='Ensure the minimum password age is set to 1 or more days.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(net accounts | Select-String \'Minimum password age\').ToString()"',
        expected_output=r'[1-9]\d*',
        remediation='Set "Minimum password age" to 1 or more days in Local Security Policy.',
        cis_section='1.1 Password Policy',
    ),
    BenchmarkRule(
        rule_id='W11-1.1.5', title='Account lockout threshold <= 5',
        description='Ensure the account lockout threshold is set to 5 or fewer invalid attempts.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(net accounts | Select-String \'Lockout threshold\').ToString()"',
        expected_output=r'[1-5]\s*$',
        remediation='Set "Account lockout threshold" to 5 or fewer in Local Security Policy.',
        cis_section='1.1 Password Policy',
    ),
    BenchmarkRule(
        rule_id='W11-1.1.6', title='Account lockout duration >= 15 minutes',
        description='Ensure the account lockout duration is 15 or more minutes.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(net accounts | Select-String \'Lockout duration\').ToString()"',
        expected_output=r'(?:1[5-9]|[2-9]\d|\d{3,})',
        remediation='Set "Account lockout duration" to 15 or more minutes.',
        cis_section='1.1 Password Policy',
    ),
    # --- Account Policies ---
    BenchmarkRule(
        rule_id='W11-1.2.1', title='Guest account is disabled',
        description='Ensure the Guest account is disabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-LocalUser -Name Guest).Enabled"',
        expected_output=r'(?i)false',
        remediation='Disable the Guest account: net user Guest /active:no',
        cis_section='1.2 Account Policies',
    ),
    BenchmarkRule(
        rule_id='W11-1.2.2', title='Administrator account renamed',
        description='Ensure the built-in Administrator account has been renamed.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-LocalUser | Where-Object {$_.SID -like \'*-500\'}).Name"',
        expected_output=r'^(?!Administrator$).+',
        remediation='Rename the built-in Administrator account in Local Security Policy > Local Policies > Security Options.',
        cis_section='1.2 Account Policies',
    ),
    # --- Audit Policy ---
    BenchmarkRule(
        rule_id='W11-2.1.1', title='Audit logon events',
        description='Ensure "Audit Logon Events" is set to Success and Failure.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "auditpol /get /subcategory:Logon 2>$null"',
        expected_output=r'(?i)success\s+and\s+failure',
        remediation='Run: auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
        cis_section='2.1 Audit Policy',
    ),
    BenchmarkRule(
        rule_id='W11-2.1.2', title='Audit privilege use',
        description='Ensure "Audit Sensitive Privilege Use" is set to Success and Failure.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "auditpol /get /subcategory:\"Sensitive Privilege Use\" 2>$null"',
        expected_output=r'(?i)success\s+and\s+failure',
        remediation='Run: auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable',
        cis_section='2.1 Audit Policy',
    ),
    BenchmarkRule(
        rule_id='W11-2.1.3', title='Audit system events',
        description='Ensure "Audit System Integrity" is set to Success and Failure.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "auditpol /get /subcategory:\"System Integrity\" 2>$null"',
        expected_output=r'(?i)success\s+and\s+failure',
        remediation='Run: auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable',
        cis_section='2.1 Audit Policy',
    ),
    BenchmarkRule(
        rule_id='W11-2.1.4', title='Audit account logon events',
        description='Ensure "Audit Credential Validation" is set to Success and Failure.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "auditpol /get /subcategory:\"Credential Validation\" 2>$null"',
        expected_output=r'(?i)success\s+and\s+failure',
        remediation='Run: auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable',
        cis_section='2.1 Audit Policy',
    ),
    BenchmarkRule(
        rule_id='W11-2.1.5', title='Audit account management',
        description='Ensure "Audit User Account Management" is set to Success and Failure.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "auditpol /get /subcategory:\"User Account Management\" 2>$null"',
        expected_output=r'(?i)success\s+and\s+failure',
        remediation='Run: auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable',
        cis_section='2.1 Audit Policy',
    ),
    # --- Security Options ---
    BenchmarkRule(
        rule_id='W11-3.1.1', title='UAC: Admin Approval Mode enabled',
        description='Ensure UAC Admin Approval Mode is enabled for the built-in Administrator.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\' -Name EnableLUA).EnableLUA"',
        expected_output=r'^1$',
        remediation='Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1.',
        cis_section='3.1 Security Options',
    ),
    BenchmarkRule(
        rule_id='W11-3.1.2', title='UAC: Elevation prompt for admins',
        description='Ensure UAC behaviour for admins is "Prompt for consent on the secure desktop".',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\' -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin"',
        expected_output=r'^[12]$',
        remediation='Set ConsentPromptBehaviorAdmin to 2 (Prompt for consent on secure desktop).',
        cis_section='3.1 Security Options',
    ),
    BenchmarkRule(
        rule_id='W11-3.1.3', title='LAN Manager hash storage disabled',
        description='Ensure "Do not store LAN Manager hash value" is Enabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\' -Name NoLMHash -ErrorAction SilentlyContinue).NoLMHash"',
        expected_output=r'^1$',
        remediation='Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash to 1.',
        cis_section='3.1 Security Options',
    ),
    BenchmarkRule(
        rule_id='W11-3.1.4', title='SMB signing required (server)',
        description='Ensure "Microsoft network server: Digitally sign communications (always)" is Enabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\' -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature"',
        expected_output=r'^1$',
        remediation='Set RequireSecuritySignature to 1 under LanManServer\\Parameters.',
        cis_section='3.1 Security Options',
    ),
    BenchmarkRule(
        rule_id='W11-3.1.5', title='SMB signing required (client)',
        description='Ensure "Microsoft network client: Digitally sign communications (always)" is Enabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\' -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature"',
        expected_output=r'^1$',
        remediation='Set RequireSecuritySignature to 1 under LanmanWorkstation\\Parameters.',
        cis_section='3.1 Security Options',
    ),
    BenchmarkRule(
        rule_id='W11-3.1.6', title='NTLMv2 authentication required',
        description='Ensure LAN Manager authentication level is set to "Send NTLMv2 response only. Refuse LM & NTLM".',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel"',
        expected_output=r'^5$',
        remediation='Set LmCompatibilityLevel to 5 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.',
        cis_section='3.1 Security Options',
    ),
    # --- Windows Firewall ---
    BenchmarkRule(
        rule_id='W11-4.1.1', title='Windows Firewall: Domain profile enabled',
        description='Ensure Windows Firewall is enabled for the Domain profile.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-NetFirewallProfile -Name Domain).Enabled"',
        expected_output=r'(?i)true',
        remediation='Enable the Domain firewall profile: Set-NetFirewallProfile -Name Domain -Enabled True',
        cis_section='4.1 Windows Firewall',
    ),
    BenchmarkRule(
        rule_id='W11-4.1.2', title='Windows Firewall: Private profile enabled',
        description='Ensure Windows Firewall is enabled for the Private profile.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-NetFirewallProfile -Name Private).Enabled"',
        expected_output=r'(?i)true',
        remediation='Enable the Private firewall profile: Set-NetFirewallProfile -Name Private -Enabled True',
        cis_section='4.1 Windows Firewall',
    ),
    BenchmarkRule(
        rule_id='W11-4.1.3', title='Windows Firewall: Public profile enabled',
        description='Ensure Windows Firewall is enabled for the Public profile.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-NetFirewallProfile -Name Public).Enabled"',
        expected_output=r'(?i)true',
        remediation='Enable the Public firewall profile: Set-NetFirewallProfile -Name Public -Enabled True',
        cis_section='4.1 Windows Firewall',
    ),
    # --- Windows Defender ---
    BenchmarkRule(
        rule_id='W11-5.1.1', title='Windows Defender: Real-time protection enabled',
        description='Ensure Windows Defender real-time protection is enabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-MpPreference).DisableRealtimeMonitoring"',
        expected_output=r'(?i)false',
        remediation='Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring $false',
        cis_section='5.1 Windows Defender',
    ),
    BenchmarkRule(
        rule_id='W11-5.1.2', title='Windows Defender: Cloud-delivered protection enabled',
        description='Ensure cloud-delivered protection is enabled in Defender.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-MpPreference).MAPSReporting"',
        expected_output=r'^[12]$',
        remediation='Set-MpPreference -MAPSReporting Advanced',
        cis_section='5.1 Windows Defender',
    ),
    BenchmarkRule(
        rule_id='W11-5.1.3', title='Windows Defender: PUA protection enabled',
        description='Ensure Potentially Unwanted Application protection is enabled.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-MpPreference).PUAProtection"',
        expected_output=r'^[12]$',
        remediation='Set-MpPreference -PUAProtection Enabled',
        cis_section='5.1 Windows Defender',
    ),
    # --- Additional hardening ---
    BenchmarkRule(
        rule_id='W11-6.1.1', title='Remote Desktop NLA required',
        description='Ensure Network Level Authentication is required for Remote Desktop.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication"',
        expected_output=r'^1$',
        remediation='Enable NLA for RDP: Set UserAuthentication to 1 in RDP-Tcp registry key.',
        cis_section='6.1 Remote Desktop',
    ),
    BenchmarkRule(
        rule_id='W11-6.1.2', title='AutoPlay disabled',
        description='Ensure AutoPlay is turned off for all drives.',
        level=1, scored=True,
        check_command='powershell -NoProfile -Command "(Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"',
        expected_output=r'255',
        remediation='Set NoDriveTypeAutoRun to 255 to disable AutoPlay on all drives.',
        cis_section='6.1 Remote Desktop',
    ),
]


_CIS_UBUNTU_2204_RULES: List[BenchmarkRule] = [
    # --- Filesystem ---
    BenchmarkRule(
        rule_id='U22-1.1.1', title='Ensure /tmp is a separate partition with noexec',
        description='The /tmp directory should be mounted with noexec option.',
        level=1, scored=True,
        check_command='mount | grep -E "\\s/tmp\\s"',
        expected_output=r'noexec',
        remediation='Add noexec option to /tmp in /etc/fstab and remount.',
        cis_section='1.1 Filesystem Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-1.1.2', title='Ensure cramfs kernel module is disabled',
        description='The cramfs filesystem type should be disabled.',
        level=1, scored=True,
        check_command='modprobe -n -v cramfs 2>&1; lsmod | grep cramfs',
        expected_output=r'install\s+/bin/(true|false)|No such file',
        remediation='echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf',
        cis_section='1.1 Filesystem Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-1.1.3', title='Ensure freevxfs kernel module is disabled',
        description='The freevxfs filesystem type should be disabled.',
        level=1, scored=True,
        check_command='modprobe -n -v freevxfs 2>&1; lsmod | grep freevxfs',
        expected_output=r'install\s+/bin/(true|false)|No such file',
        remediation='echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf',
        cis_section='1.1 Filesystem Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-1.1.4', title='Ensure squashfs kernel module is disabled',
        description='The squashfs filesystem type should be disabled if not needed.',
        level=2, scored=True,
        check_command='modprobe -n -v squashfs 2>&1; lsmod | grep squashfs',
        expected_output=r'install\s+/bin/(true|false)|No such file',
        remediation='echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf',
        cis_section='1.1 Filesystem Configuration',
    ),
    # --- Services ---
    BenchmarkRule(
        rule_id='U22-2.1.1', title='Ensure inetd/xinetd is not installed',
        description='Legacy inetd services should not be installed.',
        level=1, scored=True,
        check_command='dpkg -s inetutils-inetd xinetd 2>&1',
        expected_output=r'not installed|no packages found|is not installed',
        remediation='apt purge inetutils-inetd xinetd',
        cis_section='2.1 Services',
    ),
    BenchmarkRule(
        rule_id='U22-2.1.2', title='Ensure rsh server is not installed',
        description='The rsh server package should not be installed.',
        level=1, scored=True,
        check_command='dpkg -s rsh-server 2>&1',
        expected_output=r'not installed|is not installed',
        remediation='apt purge rsh-server',
        cis_section='2.1 Services',
    ),
    BenchmarkRule(
        rule_id='U22-2.1.3', title='Ensure telnet server is not installed',
        description='The telnet server should not be installed.',
        level=1, scored=True,
        check_command='dpkg -s telnetd 2>&1',
        expected_output=r'not installed|is not installed',
        remediation='apt purge telnetd',
        cis_section='2.1 Services',
    ),
    BenchmarkRule(
        rule_id='U22-2.1.4', title='Ensure avahi-daemon is not running',
        description='Avahi mDNS service should be disabled if not required.',
        level=1, scored=True,
        check_command='systemctl is-enabled avahi-daemon 2>&1',
        expected_output=r'disabled|not-found|masked',
        remediation='systemctl stop avahi-daemon && systemctl disable avahi-daemon',
        cis_section='2.1 Services',
    ),
    BenchmarkRule(
        rule_id='U22-2.1.5', title='Ensure CUPS is not running (unless needed)',
        description='CUPS print service should be disabled if not required.',
        level=1, scored=True,
        check_command='systemctl is-enabled cups 2>&1',
        expected_output=r'disabled|not-found|masked',
        remediation='systemctl stop cups && systemctl disable cups',
        cis_section='2.1 Services',
    ),
    BenchmarkRule(
        rule_id='U22-2.1.6', title='Ensure NFS server is not running',
        description='NFS server should be disabled if not required.',
        level=1, scored=True,
        check_command='systemctl is-enabled nfs-kernel-server 2>&1',
        expected_output=r'disabled|not-found|masked',
        remediation='systemctl stop nfs-kernel-server && systemctl disable nfs-kernel-server',
        cis_section='2.1 Services',
    ),
    # --- Network ---
    BenchmarkRule(
        rule_id='U22-3.1.1', title='Ensure IP forwarding is disabled',
        description='IP forwarding should be disabled unless the system is a router.',
        level=1, scored=True,
        check_command='sysctl net.ipv4.ip_forward',
        expected_output=r'net\.ipv4\.ip_forward\s*=\s*0',
        remediation='sysctl -w net.ipv4.ip_forward=0 and add to /etc/sysctl.conf',
        cis_section='3.1 Network Parameters',
    ),
    BenchmarkRule(
        rule_id='U22-3.1.2', title='Ensure source routed packets are not accepted',
        description='Source routed packets should be rejected.',
        level=1, scored=True,
        check_command='sysctl net.ipv4.conf.all.accept_source_route',
        expected_output=r'accept_source_route\s*=\s*0',
        remediation='sysctl -w net.ipv4.conf.all.accept_source_route=0',
        cis_section='3.1 Network Parameters',
    ),
    BenchmarkRule(
        rule_id='U22-3.1.3', title='Ensure ICMP redirects are not accepted',
        description='ICMP redirect messages should be rejected.',
        level=1, scored=True,
        check_command='sysctl net.ipv4.conf.all.accept_redirects',
        expected_output=r'accept_redirects\s*=\s*0',
        remediation='sysctl -w net.ipv4.conf.all.accept_redirects=0',
        cis_section='3.1 Network Parameters',
    ),
    BenchmarkRule(
        rule_id='U22-3.1.4', title='Ensure secure ICMP redirects are not accepted',
        description='Secure ICMP redirect messages should be rejected.',
        level=1, scored=True,
        check_command='sysctl net.ipv4.conf.all.secure_redirects',
        expected_output=r'secure_redirects\s*=\s*0',
        remediation='sysctl -w net.ipv4.conf.all.secure_redirects=0',
        cis_section='3.1 Network Parameters',
    ),
    BenchmarkRule(
        rule_id='U22-3.1.5', title='Ensure broadcast ICMP requests are ignored',
        description='The system should ignore ICMP broadcast echo requests.',
        level=1, scored=True,
        check_command='sysctl net.ipv4.icmp_echo_ignore_broadcasts',
        expected_output=r'icmp_echo_ignore_broadcasts\s*=\s*1',
        remediation='sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1',
        cis_section='3.1 Network Parameters',
    ),
    # --- Logging ---
    BenchmarkRule(
        rule_id='U22-4.1.1', title='Ensure rsyslog is installed',
        description='rsyslog should be installed for centralised logging.',
        level=1, scored=True,
        check_command='dpkg -s rsyslog 2>&1',
        expected_output=r'Status:\s*install\s+ok\s+installed',
        remediation='apt install rsyslog',
        cis_section='4.1 Logging',
    ),
    BenchmarkRule(
        rule_id='U22-4.1.2', title='Ensure rsyslog service is enabled',
        description='rsyslog service should be enabled and running.',
        level=1, scored=True,
        check_command='systemctl is-enabled rsyslog 2>&1',
        expected_output=r'enabled',
        remediation='systemctl enable rsyslog && systemctl start rsyslog',
        cis_section='4.1 Logging',
    ),
    BenchmarkRule(
        rule_id='U22-4.1.3', title='Ensure journald is configured to compress large logs',
        description='journald should compress logs to save disk space.',
        level=1, scored=True,
        check_command='grep -E "^Compress=" /etc/systemd/journald.conf 2>/dev/null || echo "not set"',
        expected_output=r'Compress\s*=\s*yes',
        remediation='Set Compress=yes in /etc/systemd/journald.conf',
        cis_section='4.1 Logging',
    ),
    BenchmarkRule(
        rule_id='U22-4.1.4', title='Ensure log file permissions are configured',
        description='/var/log should have restrictive permissions.',
        level=1, scored=True,
        check_command='stat -c "%a" /var/log/syslog 2>/dev/null || stat -c "%a" /var/log/messages 2>/dev/null || echo "640"',
        expected_output=r'^[0-6][0-4]0$',
        remediation='chmod 640 /var/log/syslog',
        cis_section='4.1 Logging',
    ),
    # --- Access / SSH ---
    BenchmarkRule(
        rule_id='U22-5.1.1', title='Ensure SSH MaxAuthTries is set to 4 or less',
        description='Limit SSH authentication attempts per connection.',
        level=1, scored=True,
        check_command='sshd -T 2>/dev/null | grep -i maxauthtries || grep -i "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null',
        expected_output=r'maxauthtries\s+[1-4]',
        remediation='Set MaxAuthTries 4 in /etc/ssh/sshd_config and restart sshd.',
        cis_section='5.1 SSH Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-5.1.2', title='Ensure SSH PermitRootLogin is disabled',
        description='Root login via SSH should be disabled.',
        level=1, scored=True,
        check_command='sshd -T 2>/dev/null | grep -i permitrootlogin || grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null',
        expected_output=r'permitrootlogin\s+no',
        remediation='Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd.',
        cis_section='5.1 SSH Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-5.1.3', title='Ensure SSH PermitEmptyPasswords is disabled',
        description='SSH should not allow empty passwords.',
        level=1, scored=True,
        check_command='sshd -T 2>/dev/null | grep -i permitemptypasswords || grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null',
        expected_output=r'permitemptypasswords\s+no',
        remediation='Set PermitEmptyPasswords no in /etc/ssh/sshd_config and restart sshd.',
        cis_section='5.1 SSH Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-5.1.4', title='Ensure SSH Protocol is 2',
        description='Only SSH protocol version 2 should be used.',
        level=1, scored=True,
        check_command='sshd -T 2>/dev/null | grep -i "^protocol" || echo "protocol 2"',
        expected_output=r'protocol\s+2',
        remediation='Set Protocol 2 in /etc/ssh/sshd_config (default in modern OpenSSH).',
        cis_section='5.1 SSH Configuration',
    ),
    # --- File Permissions ---
    BenchmarkRule(
        rule_id='U22-6.1.1', title='Ensure /etc/passwd permissions are 644 or more restrictive',
        description='The /etc/passwd file should be readable but not writable by others.',
        level=1, scored=True,
        check_command='stat -c "%a" /etc/passwd',
        expected_output=r'^[0-6]44$',
        remediation='chmod 644 /etc/passwd',
        cis_section='6.1 File Permissions',
    ),
    BenchmarkRule(
        rule_id='U22-6.1.2', title='Ensure /etc/shadow permissions are 640 or more restrictive',
        description='The /etc/shadow file must not be world-readable.',
        level=1, scored=True,
        check_command='stat -c "%a" /etc/shadow',
        expected_output=r'^[0-6][0-4]0$',
        remediation='chmod 640 /etc/shadow',
        cis_section='6.1 File Permissions',
    ),
    BenchmarkRule(
        rule_id='U22-6.1.3', title='Ensure /etc/group permissions are 644 or more restrictive',
        description='The /etc/group file should be readable but not writable by others.',
        level=1, scored=True,
        check_command='stat -c "%a" /etc/group',
        expected_output=r'^[0-6]44$',
        remediation='chmod 644 /etc/group',
        cis_section='6.1 File Permissions',
    ),
    # --- PAM ---
    BenchmarkRule(
        rule_id='U22-7.1.1', title='Ensure password retry is limited to 3 or less',
        description='PAM should limit password retries to 3 attempts.',
        level=1, scored=True,
        check_command='grep -E "pam_pwquality|retry=" /etc/pam.d/common-password 2>/dev/null || echo "retry=3"',
        expected_output=r'retry\s*=\s*[1-3]',
        remediation='Set retry=3 in pam_pwquality line of /etc/pam.d/common-password.',
        cis_section='7.1 PAM Configuration',
    ),
    BenchmarkRule(
        rule_id='U22-7.1.2', title='Ensure password minimum length is 14 or more',
        description='PAM should enforce a minimum password length of 14 characters.',
        level=1, scored=True,
        check_command='grep -E "minlen" /etc/security/pwquality.conf 2>/dev/null || echo "minlen = 8"',
        expected_output=r'minlen\s*=\s*(1[4-9]|[2-9]\d|\d{3,})',
        remediation='Set minlen = 14 in /etc/security/pwquality.conf.',
        cis_section='7.1 PAM Configuration',
    ),
]


# ---------------------------------------------------------------------------
# Benchmark registry
# ---------------------------------------------------------------------------

_BENCHMARK_MAP: Dict[str, List[BenchmarkRule]] = {
    'cis_windows_11': _CIS_WINDOWS_11_RULES,
    'cis_ubuntu_2204': _CIS_UBUNTU_2204_RULES,
}


# ---------------------------------------------------------------------------
# CISBenchmarks
# ---------------------------------------------------------------------------

class CISBenchmarks:
    """Executes CIS benchmark compliance checks and reports results."""

    def __init__(self):
        self._os = self._detect_os()

    # ------------------------------------------------------------------
    # OS detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_os() -> str:
        """Return 'windows' or 'linux' (or 'other')."""
        if sys.platform == 'win32':
            return 'windows'
        elif sys.platform.startswith('linux'):
            return 'linux'
        return 'other'

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_benchmarks(self) -> List[str]:
        """Return list of available benchmark names."""
        return list(_BENCHMARK_MAP.keys())

    def get_rules(self, benchmark: str,
                  level: int = 1) -> List[BenchmarkRule]:
        """Return rules for *benchmark* up to and including *level*."""
        rules = _BENCHMARK_MAP.get(benchmark, [])
        return [r for r in rules if r.level <= level]

    def run_benchmark(self, benchmark: str,
                      level: int = 1,
                      timeout: int = 30) -> Dict[str, Any]:
        """Execute all checks for *benchmark* at the specified *level*.

        Returns a dict with:
            benchmark, level, os_detected, timestamp,
            results (list of per-rule dicts with status/output/expected),
            summary (pass/fail/error counts).
        """
        rules = self.get_rules(benchmark, level)

        # Warn (but don't fail) if the benchmark doesn't match the OS
        os_match = True
        if 'windows' in benchmark and self._os != 'windows':
            os_match = False
        if 'ubuntu' in benchmark and self._os != 'linux':
            os_match = False

        results: List[Dict[str, Any]] = []
        pass_count = 0
        fail_count = 0
        error_count = 0
        skip_count = 0

        for rule in rules:
            entry: Dict[str, Any] = {
                'rule_id': rule.rule_id,
                'title': rule.title,
                'cis_section': rule.cis_section,
                'level': rule.level,
                'scored': rule.scored,
                'remediation': rule.remediation,
            }

            if not os_match:
                entry['status'] = 'SKIP'
                entry['output'] = 'Benchmark does not match detected OS.'
                entry['expected'] = rule.expected_output
                skip_count += 1
                results.append(entry)
                continue

            try:
                output = self._run_command(rule.check_command, timeout=timeout)
                entry['output'] = output.strip()
                entry['expected'] = rule.expected_output

                if re.search(rule.expected_output, output, re.IGNORECASE | re.MULTILINE):
                    entry['status'] = 'PASS'
                    pass_count += 1
                else:
                    entry['status'] = 'FAIL'
                    fail_count += 1

            except Exception as exc:
                entry['status'] = 'ERROR'
                entry['output'] = str(exc)
                entry['expected'] = rule.expected_output
                error_count += 1

            results.append(entry)

        total = len(results)
        scored_total = sum(1 for r in results if r.get('scored', True) and r['status'] != 'SKIP')
        scored_pass = sum(1 for r in results if r.get('scored', True) and r['status'] == 'PASS')

        return {
            'benchmark': benchmark,
            'level': level,
            'os_detected': self._os,
            'os_match': os_match,
            'timestamp': datetime.utcnow().isoformat(),
            'results': results,
            'summary': {
                'total': total,
                'pass': pass_count,
                'fail': fail_count,
                'error': error_count,
                'skip': skip_count,
                'scored_total': scored_total,
                'scored_pass': scored_pass,
                'compliance_pct': round(
                    (scored_pass / scored_total * 100) if scored_total else 0.0, 1
                ),
            },
        }

    # ------------------------------------------------------------------

    def get_compliance_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate compliance percentages per CIS section and overall.

        *results* is the dict returned by ``run_benchmark()``.
        """
        section_stats: Dict[str, Dict[str, int]] = {}

        for r in results.get('results', []):
            sec = r.get('cis_section', 'Unknown')
            if sec not in section_stats:
                section_stats[sec] = {'pass': 0, 'fail': 0, 'error': 0, 'skip': 0, 'total': 0}
            status = r.get('status', 'ERROR')
            section_stats[sec]['total'] += 1
            if status == 'PASS':
                section_stats[sec]['pass'] += 1
            elif status == 'FAIL':
                section_stats[sec]['fail'] += 1
            elif status == 'ERROR':
                section_stats[sec]['error'] += 1
            else:
                section_stats[sec]['skip'] += 1

        sections: Dict[str, float] = {}
        for sec, st in section_stats.items():
            scorable = st['total'] - st['skip']
            sections[sec] = round(
                (st['pass'] / scorable * 100) if scorable else 0.0, 1
            )

        overall = results.get('summary', {}).get('compliance_pct', 0.0)

        return {
            'benchmark': results.get('benchmark', ''),
            'level': results.get('level', 1),
            'overall_pct': overall,
            'by_section': sections,
            'section_details': section_stats,
        }

    # ------------------------------------------------------------------

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a formatted text compliance report from *results*."""
        summary = results.get('summary', {})
        score = self.get_compliance_score(results)

        lines: List[str] = []
        w = 78

        lines.append('=' * w)
        lines.append('  CIS BENCHMARK COMPLIANCE REPORT')
        lines.append('=' * w)
        lines.append(f'  Benchmark : {results.get("benchmark", "N/A")}')
        lines.append(f'  Level     : {results.get("level", "N/A")}')
        lines.append(f'  OS        : {results.get("os_detected", "N/A")}')
        lines.append(f'  Timestamp : {results.get("timestamp", "N/A")}')
        lines.append('-' * w)

        # Overall
        lines.append('')
        lines.append('  OVERALL COMPLIANCE')
        lines.append('  ' + '-' * 40)
        lines.append(f'  Score : {score["overall_pct"]:.1f}%')
        lines.append(f'  Pass  : {summary.get("pass", 0)}')
        lines.append(f'  Fail  : {summary.get("fail", 0)}')
        lines.append(f'  Error : {summary.get("error", 0)}')
        lines.append(f'  Skip  : {summary.get("skip", 0)}')
        lines.append(f'  Total : {summary.get("total", 0)}')
        lines.append('')

        # By section
        lines.append('  COMPLIANCE BY SECTION')
        lines.append('  ' + '-' * 40)
        for sec, pct in score.get('by_section', {}).items():
            detail = score['section_details'][sec]
            lines.append(f'  {sec:40s}  {pct:5.1f}%  ({detail["pass"]}/{detail["total"]})')
        lines.append('')

        # Detailed results
        lines.append('-' * w)
        lines.append('  DETAILED RESULTS')
        lines.append('-' * w)

        current_section = ''
        for r in results.get('results', []):
            sec = r.get('cis_section', '')
            if sec != current_section:
                current_section = sec
                lines.append('')
                lines.append(f'  --- {sec} ---')

            status = r.get('status', 'ERROR')
            marker = {'PASS': '[PASS]', 'FAIL': '[FAIL]', 'ERROR': '[ERR ]', 'SKIP': '[SKIP]'}
            lines.append(f'  {marker.get(status, "[????]")} {r["rule_id"]}  {r["title"]}')

            if status == 'FAIL':
                output = r.get('output', '')
                if output:
                    lines.append(f'           Got     : {output[:60]}')
                lines.append(f'           Expected: /{r.get("expected", "")}/')
                lines.append(f'           Fix     : {r.get("remediation", "")}')
            elif status == 'ERROR':
                lines.append(f'           Error   : {r.get("output", "unknown")}')

        lines.append('')
        lines.append('=' * w)
        lines.append('  END OF REPORT')
        lines.append('=' * w)

        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def _run_command(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command and return combined stdout+stderr."""
        if self._os == 'windows':
            # Use cmd /c to run the command (which may invoke powershell)
            proc = subprocess.run(
                command,
                capture_output=True, text=True, timeout=timeout,
                shell=True,
            )
        else:
            proc = subprocess.run(
                command,
                capture_output=True, text=True, timeout=timeout,
                shell=True, executable='/bin/bash',
            )

        # Combine stdout and stderr for matching
        return (proc.stdout or '') + '\n' + (proc.stderr or '')


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_cis_benchmarks: Optional[CISBenchmarks] = None


def get_cis_benchmarks() -> CISBenchmarks:
    """Get the CIS benchmarks singleton."""
    global _cis_benchmarks
    if _cis_benchmarks is None:
        _cis_benchmarks = CISBenchmarks()
    return _cis_benchmarks


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    cb = get_cis_benchmarks()
    print(f"Detected OS: {cb._os}")
    print(f"Available benchmarks: {cb.get_benchmarks()}")

    # Pick the appropriate benchmark for this OS
    if cb._os == 'windows':
        benchmark = 'cis_windows_11'
    elif cb._os == 'linux':
        benchmark = 'cis_ubuntu_2204'
    else:
        benchmark = cb.get_benchmarks()[0]

    rules = cb.get_rules(benchmark, level=1)
    print(f"\nRules for {benchmark} (Level 1): {len(rules)}")
    for r in rules[:5]:
        print(f"  {r.rule_id}: {r.title}")

    print(f"\nRunning benchmark {benchmark} (Level 1) ...")
    results = cb.run_benchmark(benchmark, level=1, timeout=15)
    report = cb.generate_report(results)
    print(report)
