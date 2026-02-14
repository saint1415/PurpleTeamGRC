#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Linux Security Scanner
Local Linux security assessment using only built-in tools.
Works without root, internet, or external tool installs.

Performs 11 security checks covering:
  1. Antivirus / rootkit detection (ClamAV, rkhunter, chkrootkit)
  2. Disk encryption (LUKS / dm-crypt)
  3. Audit policy and password policy (auditd, PAM, login.defs)
  4. Firewall (iptables, nftables, ufw, firewalld)
  5. Network listening ports and dangerous services
  6. System hardening (SSH, SUID/SGID, sysctl, services)
  7. Patch / update status (apt, yum, dnf)
  8. Certificate expiration (/etc/ssl/certs)
  9. System configuration (passwd, shadow, sudoers, cron)
 10. Log analysis (auth.log, journalctl)
 11. Unauthorized AI detection (processes, ports, models, packages)

Scan types:
  quick    - checks 1-6 only
  standard - all 11 checks
  deep     - all 11 checks with expanded depth
"""

import os
import sys
import json
import re
import subprocess
import glob as _glob
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
# LinuxScanner
# ===========================================================================

class LinuxScanner(BaseScanner):
    """Linux security assessment using built-in tools."""

    SCANNER_NAME = "linux"
    SCANNER_DESCRIPTION = "Linux security assessment using built-in tools"

    # Ports considered dangerous when listening on all interfaces
    DANGEROUS_PORTS: Dict[int, str] = {
        21: 'FTP',
        23: 'Telnet',
        25: 'SMTP',
        111: 'RPCbind',
        445: 'SMB',
        512: 'rexec',
        513: 'rlogin',
        514: 'rsh',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP (xrdp)',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        27017: 'MongoDB',
    }

    # -----------------------------------------------------------------------
    # AI detection constants (mirrors Windows scanner)
    # -----------------------------------------------------------------------

    AI_PROCESSES = {
        'ollama':           'Ollama (local LLM runtime)',
        'lms':              'LM Studio',
        'lm-studio':        'LM Studio',
        'localai':          'LocalAI',
        'koboldcpp':        'KoboldCpp (local LLM)',
        'text-generation':  'Text Generation WebUI (oobabooga)',
        'gpt4all':          'GPT4All',
        'jan':              'Jan (local AI)',
        'msty':             'Msty (local AI)',
        'llamafile':        'Mozilla llamafile',
        'llama-server':     'llama.cpp server',
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
        '/usr/local/bin/ollama',
        '/usr/bin/ollama',
        '/opt/ollama',
        '/opt/lm-studio',
        '/opt/localai',
        '/opt/gpt4all',
        '/opt/koboldcpp',
        '/opt/text-generation-webui',
        '/opt/open-webui',
    ]

    AI_HOME_PATHS = [
        '.ollama',
        '.cache/huggingface',
        '.cache/lm-studio',
        '.local/share/nomic.ai',
        'gpt4all',
        '.local/share/anythingllm',
        '.jan',
        '.chatbox',
    ]

    AI_MODEL_EXTENSIONS = {
        '.gguf':         'GGUF model (llama.cpp/Ollama)',
        '.ggml':         'GGML model (legacy llama.cpp)',
        '.safetensors':  'SafeTensors model (HuggingFace)',
        '.onnx':         'ONNX model',
        '.pt':           'PyTorch model',
        '.pth':          'PyTorch model',
    }

    AI_MODEL_SEARCH_DIRS = [
        '.ollama/models',
        '.cache/huggingface',
        '.cache/lm-studio/models',
        '.local/share/nomic.ai',
        'gpt4all/models',
    ]

    AI_SERVICES = [
        'ollama',
        'ollama.service',
        'localai',
        'open-webui',
        'text-generation',
    ]

    AI_DOCKER_IMAGES = [
        'ollama',
        'localai',
        'open-webui',
        'ghcr.io/open-webui',
        'text-generation-inference',
        'vllm',
        'tritonserver',
        'anythingllm',
        'chromadb',
        'qdrant',
    ]

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.is_root: bool = False

    # -----------------------------------------------------------------------
    # Core helpers
    # -----------------------------------------------------------------------

    def _run_cmd(self, cmd: str, timeout: int = 60) -> Optional[str]:
        """Execute a shell command and return stdout.

        Returns *None* on any error (non-zero exit, timeout, exception) so
        callers can simply test ``if result is None``.
        """
        self.scan_logger.debug(
            f"CMD> {cmd[:120]}{'...' if len(cmd) > 120 else ''}"
        )
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                stderr = (proc.stderr or '').strip()
                if 'permission denied' in stderr.lower():
                    self.scan_logger.debug(
                        f"CMD permission denied: {stderr[:200]}"
                    )
                else:
                    self.scan_logger.debug(
                        f"CMD non-zero exit ({proc.returncode}): "
                        f"{stderr[:200]}"
                    )
                return None
            return (proc.stdout or '').strip() or None
        except subprocess.TimeoutExpired:
            self.scan_logger.warning(
                f"CMD timed out ({timeout}s): {cmd[:80]}"
            )
            return None
        except FileNotFoundError:
            self.scan_logger.debug(f"CMD not found: {cmd[:40]}")
            return None
        except Exception as exc:
            self.scan_logger.warning(f"CMD execution error: {exc}")
            return None

    def _run_cmd_lines(self, cmd: str, timeout: int = 60) -> List[str]:
        """Run a command and return non-empty output lines."""
        raw = self._run_cmd(cmd, timeout=timeout)
        if raw is None:
            return []
        return [line for line in raw.splitlines() if line.strip()]

    def _check_root(self) -> bool:
        """Return *True* if the current process is running as root."""
        return os.geteuid() == 0

    @staticmethod
    def _ensure_list(data: Any) -> list:
        """Wrap a single item in a list; pass through lists unchanged."""
        if data is None:
            return []
        if isinstance(data, list):
            return data
        return [data]

    # -----------------------------------------------------------------------
    # scan()
    # -----------------------------------------------------------------------

    def scan(self, targets=None, scan_type: str = 'standard', **kwargs) -> Dict:
        """Run the Linux security assessment.

        Parameters
        ----------
        targets : ignored
            Present for API compatibility; this scanner always assesses the
            local machine.
        scan_type : str
            ``'quick'`` runs checks 1-6, ``'standard'`` runs all 11,
            ``'deep'`` runs all 11 with additional depth.
        """
        self.start_time = datetime.utcnow()
        self.is_root = self._check_root()

        hostname = (
            self._run_cmd('hostname', timeout=10) or 'localhost'
        ).strip()

        self.scan_logger.info(
            f"Starting Linux {scan_type} scan on {hostname} "
            f"(root={self.is_root})"
        )

        results: Dict[str, Any] = {
            'scanner': self.SCANNER_NAME,
            'hostname': hostname,
            'is_root': self.is_root,
            'scan_type': scan_type,
            'checks_completed': 0,
            'checks_skipped': 0,
        }

        # Ordered list of checks -----------------------------------------------
        checks = [
            ('Antivirus/Rootkit',   self._check_antivirus),
            ('Disk Encryption',     self._check_disk_encryption),
            ('Audit Policy',        self._check_audit_policy),
            ('Firewall',            self._check_firewall),
            ('Network',             self._check_network),
            ('System Hardening',    self._check_hardening),
        ]

        if scan_type in ('standard', 'deep'):
            checks.extend([
                ('Patch Status',        self._check_patches),
                ('Certificates',        self._check_certificates),
                ('System Config',       self._check_system_config),
                ('Log Analysis',        self._check_logs),
                ('Unauthorized AI',     self._check_unauthorized_ai),
            ])

        # Execute each check ---------------------------------------------------
        for name, check_fn in checks:
            try:
                self.scan_logger.info(f"Checking: {name}")
                check_fn(hostname, scan_type)
                results['checks_completed'] += 1
            except PermissionError:
                results['checks_skipped'] += 1
                self.scan_logger.info(
                    f"Skipped {name}: requires root privileges"
                )
                self.add_finding(
                    severity='INFO',
                    title=f'{name}: Skipped (root required)',
                    description=(
                        f'The {name} check requires root privileges. '
                        f'Re-run the scanner with sudo for full coverage.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    detection_method='system_command',
                )
            except Exception as exc:
                results['checks_skipped'] += 1
                self.scan_logger.warning(f"{name} check failed: {exc}")

        # Wrap up ---------------------------------------------------------------
        self.end_time = datetime.utcnow()
        results['summary'] = self.get_summary()
        self.save_results()
        return results

    # ===================================================================== #
    #  CHECK 1 - Antivirus / Rootkit Detection                              #
    # ===================================================================== #

    def _check_antivirus(self, hostname: str, scan_type: str) -> None:
        """Assess antivirus and rootkit detection posture."""

        av_found = False

        # --- ClamAV ---
        clamscan = self._run_cmd('which clamscan 2>/dev/null')
        if clamscan:
            av_found = True
            # Check if clamd is running
            clamd_running = self._run_cmd(
                'systemctl is-active clamav-daemon 2>/dev/null || '
                'systemctl is-active clamd 2>/dev/null || '
                'pgrep -x clamd >/dev/null 2>&1 && echo active'
            )
            if clamd_running and 'active' in clamd_running:
                self.add_finding(
                    severity='INFO',
                    title='ClamAV daemon is running',
                    description='ClamAV antivirus is installed and the clamd daemon is active.',
                    affected_asset=hostname,
                    finding_type='endpoint_protection',
                    detection_method='system_command',
                )
            else:
                self.add_finding(
                    severity='MEDIUM',
                    title='ClamAV installed but daemon not running',
                    description=(
                        'ClamAV is installed but the clamd daemon is not running. '
                        'Without the daemon, on-access scanning is not available.'
                    ),
                    affected_asset=hostname,
                    finding_type='endpoint_protection',
                    cvss_score=5.0,
                    remediation='Start ClamAV: sudo systemctl start clamav-daemon',
                    detection_method='system_command',
                )

            # Check signature freshness
            freshclam_log = self._run_cmd(
                'stat -c %Y /var/lib/clamav/daily.cvd 2>/dev/null || '
                'stat -c %Y /var/lib/clamav/daily.cld 2>/dev/null'
            )
            if freshclam_log:
                try:
                    sig_mtime = int(freshclam_log.strip())
                    sig_age_days = (
                        datetime.utcnow() -
                        datetime.utcfromtimestamp(sig_mtime)
                    ).days
                    if sig_age_days > 7:
                        self.add_finding(
                            severity='HIGH',
                            title=f'ClamAV signatures are {sig_age_days} days old',
                            description=(
                                f'ClamAV definitions have not been updated in '
                                f'{sig_age_days} days. New threats may not be detected.'
                            ),
                            affected_asset=hostname,
                            finding_type='endpoint_protection',
                            cvss_score=7.0,
                            remediation='Update signatures: sudo freshclam',
                            detection_method='system_command',
                        )
                except (ValueError, OSError):
                    pass

        # --- rkhunter ---
        rkhunter = self._run_cmd('which rkhunter 2>/dev/null')
        if rkhunter:
            av_found = True
            self.add_finding(
                severity='INFO',
                title='rkhunter (rootkit hunter) is installed',
                description=f'rkhunter is available at {rkhunter.strip()}.',
                affected_asset=hostname,
                finding_type='endpoint_protection',
                detection_method='system_command',
            )

        # --- chkrootkit ---
        chkrootkit = self._run_cmd('which chkrootkit 2>/dev/null')
        if chkrootkit:
            av_found = True
            self.add_finding(
                severity='INFO',
                title='chkrootkit is installed',
                description=f'chkrootkit is available at {chkrootkit.strip()}.',
                affected_asset=hostname,
                finding_type='endpoint_protection',
                detection_method='system_command',
            )

        if not av_found:
            self.add_finding(
                severity='HIGH',
                title='No antivirus or rootkit detection tools installed',
                description=(
                    'Neither ClamAV, rkhunter, nor chkrootkit were detected. '
                    'The system has no local malware or rootkit detection capability.'
                ),
                affected_asset=hostname,
                finding_type='endpoint_protection',
                cvss_score=7.5,
                remediation=(
                    'Install ClamAV: sudo apt install clamav clamav-daemon '
                    'or sudo yum install clamav clamd. '
                    'Install rkhunter: sudo apt install rkhunter'
                ),
                detection_method='system_command',
            )

    # ===================================================================== #
    #  CHECK 2 - Disk Encryption (LUKS / dm-crypt)                          #
    # ===================================================================== #

    def _check_disk_encryption(self, hostname: str, scan_type: str) -> None:
        """Assess disk encryption via LUKS / dm-crypt."""

        # Check for LUKS encrypted partitions
        lsblk_output = self._run_cmd(
            'lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT -n 2>/dev/null'
        )

        has_encrypted = False
        unencrypted_root = True

        if lsblk_output:
            for line in lsblk_output.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    fstype = parts[2] if len(parts) > 2 else ''
                    mountpoint = parts[3] if len(parts) > 3 else ''
                    if fstype == 'crypto_LUKS' or 'crypt' in line.lower():
                        has_encrypted = True
                    if mountpoint == '/' and 'crypt' in line.lower():
                        unencrypted_root = False

        # Also check /etc/crypttab
        crypttab = self._run_cmd('cat /etc/crypttab 2>/dev/null')
        if crypttab:
            active_entries = [
                l for l in crypttab.splitlines()
                if l.strip() and not l.strip().startswith('#')
            ]
            if active_entries:
                has_encrypted = True

        # Check dmsetup for active dm-crypt targets
        dmsetup = self._run_cmd('dmsetup status 2>/dev/null')
        if dmsetup and 'crypt' in dmsetup.lower():
            has_encrypted = True
            unencrypted_root = False

        if has_encrypted:
            self.add_finding(
                severity='INFO',
                title='Disk encryption (LUKS/dm-crypt) detected',
                description='One or more encrypted volumes are configured on this system.',
                affected_asset=hostname,
                finding_type='disk_encryption',
                detection_method='system_command',
            )
        else:
            self.add_finding(
                severity='HIGH',
                title='No disk encryption detected',
                description=(
                    'No LUKS or dm-crypt encrypted volumes were found. '
                    'If the device is lost or stolen, all data is accessible.'
                ),
                affected_asset=hostname,
                finding_type='disk_encryption',
                cvss_score=7.5,
                remediation=(
                    'Encrypt disks using LUKS: cryptsetup luksFormat /dev/sdX. '
                    'For full-disk encryption, reinstall with encrypted LVM.'
                ),
                detection_method='system_command',
            )

        if has_encrypted and unencrypted_root:
            self.add_finding(
                severity='MEDIUM',
                title='Root filesystem may not be encrypted',
                description=(
                    'Encrypted volumes were found but the root (/) filesystem '
                    'does not appear to be on an encrypted volume.'
                ),
                affected_asset=hostname,
                finding_type='disk_encryption',
                cvss_score=6.0,
                remediation='Reinstall with full-disk encryption (encrypted LVM).',
                detection_method='system_command',
            )

    # ===================================================================== #
    #  CHECK 3 - Audit Policy & Password Policy                             #
    # ===================================================================== #

    def _check_audit_policy(self, hostname: str, scan_type: str) -> None:
        """Check audit daemon, PAM configuration, and password policy."""

        # --- auditd status ---
        auditd_status = self._run_cmd(
            'systemctl is-active auditd 2>/dev/null'
        )
        if auditd_status and 'active' in auditd_status:
            self.add_finding(
                severity='INFO',
                title='auditd is running',
                description='The Linux audit daemon (auditd) is active.',
                affected_asset=hostname,
                finding_type='audit_policy',
                detection_method='service_enumeration',
            )

            # Check number of audit rules
            rules = self._run_cmd('auditctl -l 2>/dev/null')
            if rules:
                rule_count = len([
                    l for l in rules.splitlines()
                    if l.strip() and 'No rules' not in l
                ])
                if rule_count == 0:
                    self.add_finding(
                        severity='MEDIUM',
                        title='auditd has no audit rules configured',
                        description=(
                            'The audit daemon is running but no audit rules '
                            'are configured. Security events are not being '
                            'captured.'
                        ),
                        affected_asset=hostname,
                        finding_type='audit_policy',
                        cvss_score=5.5,
                        remediation=(
                            'Add audit rules from CIS benchmark: '
                            'sudo cp /usr/share/doc/audit/rules/cis.rules '
                            '/etc/audit/rules.d/'
                        ),
                        detection_method='system_command',
                    )
                else:
                    self.add_finding(
                        severity='INFO',
                        title=f'{rule_count} audit rules configured',
                        description=f'auditd has {rule_count} active rules.',
                        affected_asset=hostname,
                        finding_type='audit_policy',
                        raw_data={'rule_count': rule_count},
                        detection_method='system_command',
                    )
            else:
                self.scan_logger.info(
                    "Could not list audit rules (may need root)"
                )
        else:
            self.add_finding(
                severity='HIGH',
                title='auditd is not running',
                description=(
                    'The Linux audit daemon (auditd) is not active. '
                    'Without auditd, security-relevant events such as file '
                    'access, privilege escalation, and authentication '
                    'are not being recorded.'
                ),
                affected_asset=hostname,
                finding_type='audit_policy',
                cvss_score=7.0,
                remediation=(
                    'Install and enable auditd: '
                    'sudo apt install auditd && sudo systemctl enable --now auditd'
                ),
                detection_method='service_enumeration',
            )

        # --- Password policy: /etc/login.defs ---
        login_defs = self._run_cmd('cat /etc/login.defs 2>/dev/null')
        if login_defs:
            # PASS_MIN_LEN
            m = re.search(r'^PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
            if m:
                min_len = int(m.group(1))
                if min_len < 14:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'Minimum password length is {min_len} (recommended: 14+)',
                        description=(
                            f'/etc/login.defs sets PASS_MIN_LEN to {min_len}. '
                            f'CIS benchmarks recommend at least 14 characters.'
                        ),
                        affected_asset=hostname,
                        finding_type='password_policy',
                        cvss_score=5.0,
                        remediation='Edit /etc/login.defs: PASS_MIN_LEN 14',
                        raw_data={'PASS_MIN_LEN': min_len},
                        detection_method='config_file_check',
                    )

            # PASS_MAX_DAYS
            m = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
            if m:
                max_days = int(m.group(1))
                if max_days > 365 or max_days == 99999:
                    self.add_finding(
                        severity='LOW',
                        title=f'Password expiration set to {max_days} days',
                        description=(
                            f'/etc/login.defs PASS_MAX_DAYS is {max_days}. '
                            f'While NIST no longer mandates rotation, '
                            f'organizations with compliance requirements '
                            f'may need a defined policy.'
                        ),
                        affected_asset=hostname,
                        finding_type='password_policy',
                        cvss_score=2.0,
                        remediation='Edit /etc/login.defs: PASS_MAX_DAYS 365',
                        raw_data={'PASS_MAX_DAYS': max_days},
                        detection_method='config_file_check',
                    )

            # PASS_MIN_DAYS
            m = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
            if m:
                min_days = int(m.group(1))
                if min_days == 0:
                    self.add_finding(
                        severity='LOW',
                        title='Password minimum age is 0 days',
                        description=(
                            'PASS_MIN_DAYS is 0, meaning users can change '
                            'passwords immediately. This may allow password '
                            'history bypass.'
                        ),
                        affected_asset=hostname,
                        finding_type='password_policy',
                        cvss_score=2.0,
                        remediation='Edit /etc/login.defs: PASS_MIN_DAYS 1',
                        detection_method='config_file_check',
                    )

        # --- PAM pwquality ---
        pwquality = self._run_cmd(
            'cat /etc/security/pwquality.conf 2>/dev/null'
        )
        if pwquality:
            m = re.search(r'^minlen\s*=\s*(\d+)', pwquality, re.MULTILINE)
            if m:
                pam_min = int(m.group(1))
                if pam_min < 14:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'PAM pwquality minlen is {pam_min} (recommended: 14+)',
                        description=(
                            f'pwquality.conf minlen={pam_min}. CIS benchmarks '
                            f'recommend at least 14.'
                        ),
                        affected_asset=hostname,
                        finding_type='password_policy',
                        cvss_score=5.0,
                        remediation='Edit /etc/security/pwquality.conf: minlen = 14',
                        detection_method='config_file_check',
                    )
        else:
            # Check if pam_pwquality is loaded
            pam_has_pwquality = self._run_cmd(
                'grep -r pam_pwquality /etc/pam.d/ 2>/dev/null'
            )
            if not pam_has_pwquality:
                self.add_finding(
                    severity='MEDIUM',
                    title='PAM password quality module not configured',
                    description=(
                        'pam_pwquality is not loaded in PAM configuration. '
                        'Password complexity is not enforced.'
                    ),
                    affected_asset=hostname,
                    finding_type='password_policy',
                    cvss_score=5.0,
                    remediation=(
                        'Install and configure: '
                        'sudo apt install libpam-pwquality && '
                        'edit /etc/security/pwquality.conf'
                    ),
                    detection_method='config_file_check',
                )

        # --- Account lockout (pam_faillock / pam_tally2) ---
        faillock = self._run_cmd(
            'grep -r pam_faillock /etc/pam.d/ 2>/dev/null || '
            'grep -r pam_tally2 /etc/pam.d/ 2>/dev/null'
        )
        if not faillock:
            self.add_finding(
                severity='MEDIUM',
                title='Account lockout is not configured',
                description=(
                    'Neither pam_faillock nor pam_tally2 is configured. '
                    'An attacker can attempt unlimited password guesses.'
                ),
                affected_asset=hostname,
                finding_type='password_policy',
                cvss_score=5.0,
                remediation=(
                    'Configure pam_faillock in /etc/pam.d/common-auth '
                    'with deny=5 unlock_time=900'
                ),
                detection_method='config_file_check',
            )

    # ===================================================================== #
    #  CHECK 4 - Firewall                                                   #
    # ===================================================================== #

    def _check_firewall(self, hostname: str, scan_type: str) -> None:
        """Assess firewall configuration (iptables/nftables/ufw/firewalld)."""

        fw_found = False

        # --- ufw ---
        ufw_status = self._run_cmd('ufw status 2>/dev/null')
        if ufw_status:
            if 'Status: active' in ufw_status:
                fw_found = True
                self.add_finding(
                    severity='INFO',
                    title='ufw firewall is active',
                    description=f'ufw status: active.',
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    raw_data={'ufw_status': ufw_status[:500]},
                    detection_method='system_command',
                )

                # Check default policies
                if 'Default: allow (incoming)' in ufw_status:
                    self.add_finding(
                        severity='HIGH',
                        title='ufw default incoming policy is ALLOW',
                        description=(
                            'The ufw firewall allows all incoming connections '
                            'by default. Only explicitly permitted services '
                            'should accept inbound traffic.'
                        ),
                        affected_asset=hostname,
                        finding_type='firewall_config',
                        cvss_score=7.0,
                        remediation='sudo ufw default deny incoming',
                        detection_method='system_command',
                    )
            elif 'Status: inactive' in ufw_status:
                self.add_finding(
                    severity='HIGH',
                    title='ufw firewall is installed but INACTIVE',
                    description=(
                        'ufw is installed but not enabled. '
                        'The system has no active host-based firewall.'
                    ),
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    cvss_score=7.5,
                    remediation='Enable ufw: sudo ufw enable',
                    detection_method='system_command',
                )

        # --- firewalld ---
        firewalld = self._run_cmd(
            'systemctl is-active firewalld 2>/dev/null'
        )
        if firewalld and 'active' in firewalld:
            fw_found = True
            self.add_finding(
                severity='INFO',
                title='firewalld is active',
                description='firewalld service is running.',
                affected_asset=hostname,
                finding_type='firewall_config',
                detection_method='service_enumeration',
            )

            # Default zone
            default_zone = self._run_cmd(
                'firewall-cmd --get-default-zone 2>/dev/null'
            )
            if default_zone and default_zone.strip() == 'trusted':
                self.add_finding(
                    severity='HIGH',
                    title='firewalld default zone is "trusted" (allow all)',
                    description=(
                        'The default firewalld zone is set to "trusted" which '
                        'allows all incoming traffic.'
                    ),
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    cvss_score=7.0,
                    remediation=(
                        'Set a restrictive default zone: '
                        'sudo firewall-cmd --set-default-zone=public'
                    ),
                    detection_method='system_command',
                )

        # --- iptables ---
        iptables_rules = self._run_cmd(
            'iptables -L -n 2>/dev/null | head -50'
        )
        if iptables_rules and 'Chain' in iptables_rules:
            # Check for default ACCEPT on INPUT
            if re.search(
                r'Chain INPUT \(policy ACCEPT\)', iptables_rules
            ):
                if not fw_found:
                    self.add_finding(
                        severity='HIGH',
                        title='iptables INPUT chain default policy is ACCEPT',
                        description=(
                            'The iptables INPUT chain has a default policy of '
                            'ACCEPT. Without restrictive rules, all inbound '
                            'traffic is permitted.'
                        ),
                        affected_asset=hostname,
                        finding_type='firewall_config',
                        cvss_score=7.0,
                        remediation=(
                            'Set default drop policy: '
                            'sudo iptables -P INPUT DROP'
                        ),
                        raw_data={'iptables_output': iptables_rules[:500]},
                        detection_method='system_command',
                    )
            else:
                fw_found = True
                self.add_finding(
                    severity='INFO',
                    title='iptables rules are configured',
                    description='iptables has active rules with non-ACCEPT default policy.',
                    affected_asset=hostname,
                    finding_type='firewall_config',
                    detection_method='system_command',
                )

        # --- nftables ---
        nft_rules = self._run_cmd('nft list ruleset 2>/dev/null | head -50')
        if nft_rules and 'table' in nft_rules:
            fw_found = True
            self.add_finding(
                severity='INFO',
                title='nftables rules are configured',
                description='nftables has active rulesets.',
                affected_asset=hostname,
                finding_type='firewall_config',
                detection_method='system_command',
            )

        # No firewall at all
        if not fw_found:
            self.add_finding(
                severity='CRITICAL',
                title='No active firewall detected',
                description=(
                    'No host-based firewall (ufw, firewalld, iptables, '
                    'nftables) is actively configured. The system is '
                    'unprotected against network attacks.'
                ),
                affected_asset=hostname,
                finding_type='firewall_config',
                cvss_score=9.0,
                remediation=(
                    'Enable a firewall: sudo apt install ufw && '
                    'sudo ufw default deny incoming && sudo ufw enable'
                ),
                detection_method='system_command',
            )

    # ===================================================================== #
    #  CHECK 5 - Network (listening ports)                                  #
    # ===================================================================== #

    def _check_network(self, hostname: str, scan_type: str) -> None:
        """Check for dangerous listening ports and network settings."""

        # Use ss for listening ports
        ss_output = self._run_cmd('ss -tlnp 2>/dev/null')

        reported_ports: set = set()
        total_listeners = 0

        if ss_output:
            for line in ss_output.splitlines()[1:]:  # skip header
                total_listeners += 1
                # Parse ss output: State Recv-Q Send-Q Local Address:Port ...
                m = re.search(
                    r'LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s', line
                )
                if not m:
                    continue

                local_addr = m.group(1)
                local_port = int(m.group(2))

                # Only flag services bound to all interfaces
                if local_addr not in ('0.0.0.0', '::', '*'):
                    continue

                if local_port not in self.DANGEROUS_PORTS:
                    continue

                if local_port in reported_ports:
                    continue
                reported_ports.add(local_port)

                service_name = self.DANGEROUS_PORTS[local_port]

                # Try to extract process name from ss output
                proc_match = re.search(
                    r'users:\(\("([^"]+)"', line
                )
                proc_name = proc_match.group(1) if proc_match else None

                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'{service_name} (port {local_port}) '
                        f'listening on all interfaces'
                    ),
                    description=(
                        f'{service_name} is bound to {local_addr}:{local_port}'
                        f'{" (process: " + proc_name + ")" if proc_name else ""}. '
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
                    raw_data={'port': local_port, 'address': local_addr},
                    detection_method='system_command',
                )

        # Report total listener count
        self.add_finding(
            severity='INFO',
            title=f'{total_listeners} TCP listeners detected',
            description=(
                f'The system has {total_listeners} TCP ports in LISTEN state. '
                f'{len(reported_ports)} dangerous ports were found listening '
                f'on all interfaces.'
            ),
            affected_asset=hostname,
            finding_type='open_port',
            raw_data={
                'total_listeners': total_listeners,
                'dangerous_count': len(reported_ports),
            },
            detection_method='system_command',
        )

        # --- IP forwarding ---
        ipv4_forward = self._run_cmd(
            'cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'
        )
        if ipv4_forward and ipv4_forward.strip() == '1':
            self.add_finding(
                severity='MEDIUM',
                title='IPv4 forwarding is enabled',
                description=(
                    'net.ipv4.ip_forward is set to 1. Unless this system is '
                    'a router or VPN gateway, IP forwarding should be disabled.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=5.0,
                remediation='sudo sysctl -w net.ipv4.ip_forward=0',
                detection_method='config_file_check',
            )

        # --- /etc/hosts unusual entries ---
        if scan_type == 'deep':
            hosts_content = self._run_cmd('cat /etc/hosts 2>/dev/null')
            if hosts_content:
                suspicious = [
                    l for l in hosts_content.splitlines()
                    if l.strip() and not l.strip().startswith('#')
                    and 'localhost' not in l.lower()
                    and '::1' not in l
                    and '127.0.0.1' not in l[:15]
                ]
                if len(suspicious) > 5:
                    self.add_finding(
                        severity='LOW',
                        title=f'{len(suspicious)} custom entries in /etc/hosts',
                        description=(
                            f'/etc/hosts contains {len(suspicious)} non-default '
                            f'entries. Review for potential DNS hijacking.'
                        ),
                        affected_asset=hostname,
                        finding_type='insecure_configuration',
                        cvss_score=2.0,
                        remediation='Review /etc/hosts for unauthorized entries.',
                        detection_method='config_file_check',
                    )

    # ===================================================================== #
    #  CHECK 6 - System Hardening                                           #
    # ===================================================================== #

    def _check_hardening(self, hostname: str, scan_type: str) -> None:
        """Check SSH config, SUID/SGID, sysctl hardening, services."""

        self._check_ssh_config(hostname)
        self._check_sysctl_hardening(hostname)
        self._check_unnecessary_services(hostname)

        if scan_type in ('standard', 'deep'):
            self._check_suid_sgid(hostname, scan_type)

        if scan_type == 'deep':
            self._check_world_writable(hostname)

    def _check_ssh_config(self, hostname: str) -> None:
        """Inspect SSH server configuration for security weaknesses."""
        sshd_config = self._run_cmd('cat /etc/ssh/sshd_config 2>/dev/null')
        if sshd_config is None:
            self.scan_logger.debug("Could not read /etc/ssh/sshd_config")
            return

        # Also read config drop-in files
        dropin_config = self._run_cmd(
            'cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null'
        )
        full_config = sshd_config + '\n' + (dropin_config or '')

        # PermitRootLogin
        m = re.search(
            r'^\s*PermitRootLogin\s+(\S+)',
            full_config,
            re.MULTILINE | re.IGNORECASE,
        )
        if m:
            value = m.group(1).lower()
            if value == 'yes':
                self.add_finding(
                    severity='HIGH',
                    title='SSH PermitRootLogin is set to "yes"',
                    description=(
                        'Direct root login via SSH is permitted. This '
                        'increases the attack surface by allowing brute-force '
                        'attacks against the root account.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=7.5,
                    remediation=(
                        'Set PermitRootLogin to "prohibit-password" or "no" '
                        'in /etc/ssh/sshd_config, then restart sshd.'
                    ),
                    detection_method='config_file_check',
                )
            elif value in ('no', 'prohibit-password', 'without-password'):
                self.add_finding(
                    severity='INFO',
                    title=f'SSH PermitRootLogin is "{value}"',
                    description=f'Root login via SSH is appropriately restricted.',
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    detection_method='config_file_check',
                )

        # PasswordAuthentication
        m = re.search(
            r'^\s*PasswordAuthentication\s+(\S+)',
            full_config,
            re.MULTILINE | re.IGNORECASE,
        )
        if m:
            value = m.group(1).lower()
            if value == 'yes':
                self.add_finding(
                    severity='MEDIUM',
                    title='SSH password authentication is enabled',
                    description=(
                        'SSH allows password-based authentication. '
                        'Key-based authentication is more secure and '
                        'resistant to brute-force attacks.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=5.5,
                    remediation=(
                        'Set PasswordAuthentication no in /etc/ssh/sshd_config '
                        'after ensuring key-based access is configured.'
                    ),
                    detection_method='config_file_check',
                )

        # Protocol 1
        m = re.search(
            r'^\s*Protocol\s+1\b',
            full_config,
            re.MULTILINE | re.IGNORECASE,
        )
        if m:
            self.add_finding(
                severity='CRITICAL',
                title='SSH Protocol 1 is enabled',
                description=(
                    'SSH Protocol version 1 is explicitly enabled. '
                    'SSHv1 has known vulnerabilities and must not be used.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=9.0,
                remediation='Remove "Protocol 1" from /etc/ssh/sshd_config.',
                detection_method='config_file_check',
            )

        # PermitEmptyPasswords
        m = re.search(
            r'^\s*PermitEmptyPasswords\s+yes',
            full_config,
            re.MULTILINE | re.IGNORECASE,
        )
        if m:
            self.add_finding(
                severity='CRITICAL',
                title='SSH allows empty passwords',
                description=(
                    'PermitEmptyPasswords is set to yes. Users with empty '
                    'passwords can log in via SSH.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=9.5,
                remediation=(
                    'Set PermitEmptyPasswords no in /etc/ssh/sshd_config.'
                ),
                detection_method='config_file_check',
            )

        # X11Forwarding
        m = re.search(
            r'^\s*X11Forwarding\s+yes',
            full_config,
            re.MULTILINE | re.IGNORECASE,
        )
        if m:
            self.add_finding(
                severity='LOW',
                title='SSH X11 forwarding is enabled',
                description=(
                    'X11Forwarding is enabled. Unless required, disable it '
                    'to reduce attack surface.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=3.0,
                remediation='Set X11Forwarding no in /etc/ssh/sshd_config.',
                detection_method='config_file_check',
            )

        # MaxAuthTries
        m = re.search(
            r'^\s*MaxAuthTries\s+(\d+)',
            full_config,
            re.MULTILINE | re.IGNORECASE,
        )
        if m:
            max_tries = int(m.group(1))
            if max_tries > 6:
                self.add_finding(
                    severity='LOW',
                    title=f'SSH MaxAuthTries is {max_tries} (recommended: 4)',
                    description=(
                        f'MaxAuthTries is set to {max_tries}. A lower value '
                        f'reduces the window for brute-force attacks.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=3.0,
                    remediation='Set MaxAuthTries 4 in /etc/ssh/sshd_config.',
                    detection_method='config_file_check',
                )

    def _check_sysctl_hardening(self, hostname: str) -> None:
        """Check kernel hardening parameters via sysctl."""
        hardening_checks = [
            (
                'net.ipv4.conf.all.accept_redirects', '0',
                'ICMP redirect acceptance enabled',
                'ICMP redirects can be used for MitM attacks.',
                'MEDIUM', 5.0,
            ),
            (
                'net.ipv4.conf.all.send_redirects', '0',
                'ICMP redirect sending enabled',
                'System is sending ICMP redirects.',
                'LOW', 3.0,
            ),
            (
                'net.ipv4.conf.all.accept_source_route', '0',
                'Source routing accepted',
                'Source routing allows attackers to specify routes.',
                'MEDIUM', 5.0,
            ),
            (
                'net.ipv4.conf.all.log_martians', '1',
                'Martian packet logging disabled',
                'Impossible-source-address packets are not being logged.',
                'LOW', 2.0,
            ),
            (
                'kernel.randomize_va_space', '2',
                'ASLR not fully enabled',
                'Address Space Layout Randomization is not set to full (2).',
                'HIGH', 7.0,
            ),
            (
                'kernel.exec-shield', '1',
                'ExecShield not enabled',
                'Exec-Shield protection is not enabled (if available).',
                'MEDIUM', 5.0,
            ),
            (
                'net.ipv4.tcp_syncookies', '1',
                'TCP SYN cookies disabled',
                'Without SYN cookies, the system is vulnerable to SYN floods.',
                'MEDIUM', 5.0,
            ),
        ]

        for param, expected, title, desc, severity, cvss in hardening_checks:
            value = self._run_cmd(f'sysctl -n {param} 2>/dev/null')
            if value is None:
                continue
            value = value.strip()
            if value != expected:
                self.add_finding(
                    severity=severity,
                    title=f'Kernel: {title}',
                    description=(
                        f'{desc} Current value of {param}={value} '
                        f'(expected: {expected}).'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=cvss,
                    remediation=f'sudo sysctl -w {param}={expected}',
                    raw_data={'param': param, 'value': value, 'expected': expected},
                    detection_method='system_command',
                )

    def _check_unnecessary_services(self, hostname: str) -> None:
        """Flag legacy or insecure services that should be disabled."""
        insecure_services = [
            ('telnet.socket', 'Telnet', 'CRITICAL', 9.0),
            ('rsh.socket', 'RSH (remote shell)', 'CRITICAL', 9.0),
            ('rlogin.socket', 'rlogin', 'CRITICAL', 9.0),
            ('rexec.socket', 'rexec', 'CRITICAL', 9.0),
            ('xinetd', 'xinetd', 'MEDIUM', 5.0),
            ('vsftpd', 'FTP server', 'MEDIUM', 5.0),
            ('avahi-daemon', 'Avahi (mDNS)', 'LOW', 3.0),
        ]

        for svc, label, severity, cvss in insecure_services:
            status = self._run_cmd(
                f'systemctl is-active {svc} 2>/dev/null'
            )
            if status and 'active' in status:
                self.add_finding(
                    severity=severity,
                    title=f'Insecure service running: {label}',
                    description=(
                        f'The {label} service ({svc}) is active. '
                        f'Legacy/insecure services increase the attack surface.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=cvss,
                    remediation=(
                        f'Disable: sudo systemctl stop {svc} && '
                        f'sudo systemctl disable {svc}'
                    ),
                    detection_method='service_enumeration',
                )

    def _check_suid_sgid(self, hostname: str, scan_type: str) -> None:
        """Scan for SUID/SGID binaries (potential privilege escalation)."""
        # Limit search depth and time
        max_depth = '-maxdepth 4' if scan_type != 'deep' else '-maxdepth 6'
        timeout = 30 if scan_type != 'deep' else 60

        suid_files = self._run_cmd_lines(
            f'find / -perm -4000 -type f {max_depth} '
            f'-not -path "/proc/*" -not -path "/sys/*" '
            f'-not -path "/snap/*" 2>/dev/null | head -100',
            timeout=timeout,
        )

        # Known safe SUID binaries (common, expected)
        safe_suid = {
            '/usr/bin/passwd', '/usr/bin/su', '/usr/bin/sudo',
            '/usr/bin/newgrp', '/usr/bin/chsh', '/usr/bin/chfn',
            '/usr/bin/gpasswd', '/usr/bin/mount', '/usr/bin/umount',
            '/usr/lib/openssh/ssh-keysign',
            '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
            '/usr/bin/pkexec', '/usr/bin/crontab',
            '/usr/bin/at', '/usr/sbin/unix_chkpwd',
            '/usr/bin/fusermount', '/usr/bin/fusermount3',
            '/bin/mount', '/bin/umount', '/bin/su',
            '/bin/ping', '/usr/bin/ping',
        }

        suspicious_suid = [
            f for f in suid_files if f.strip() not in safe_suid
        ]

        if len(suspicious_suid) > 0:
            severity = 'MEDIUM' if len(suspicious_suid) < 10 else 'HIGH'
            self.add_finding(
                severity=severity,
                title=f'{len(suspicious_suid)} unusual SUID binaries found',
                description=(
                    f'Found {len(suspicious_suid)} SUID binaries outside the '
                    f'expected set: {", ".join(suspicious_suid[:10])}. '
                    f'SUID binaries can be exploited for privilege escalation.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=6.0 if len(suspicious_suid) < 10 else 7.0,
                remediation=(
                    'Review SUID binaries: find / -perm -4000 -type f. '
                    'Remove SUID bit from unnecessary files: chmod u-s <file>'
                ),
                raw_data={'suid_files': suspicious_suid[:20]},
                detection_method='system_command',
            )

        self.add_finding(
            severity='INFO',
            title=f'{len(suid_files)} total SUID binaries found',
            description=(
                f'Total: {len(suid_files)}, '
                f'Unusual: {len(suspicious_suid)}'
            ),
            affected_asset=hostname,
            finding_type='insecure_configuration',
            raw_data={'total': len(suid_files), 'unusual': len(suspicious_suid)},
            detection_method='system_command',
        )

    def _check_world_writable(self, hostname: str) -> None:
        """Find world-writable files and directories (deep scan only)."""
        ww_dirs = self._run_cmd_lines(
            'find / -xdev -type d -perm -0002 '
            '-not -path "/proc/*" -not -path "/sys/*" '
            '-not -path "/tmp" -not -path "/var/tmp" '
            '-not -path "/dev/shm" '
            '2>/dev/null | head -50',
            timeout=30,
        )

        # Filter out expected world-writable dirs
        expected_ww = {'/tmp', '/var/tmp', '/dev/shm', '/var/lock'}
        suspicious_ww = [
            d for d in ww_dirs
            if d.strip() not in expected_ww
        ]

        if suspicious_ww:
            self.add_finding(
                severity='MEDIUM',
                title=f'{len(suspicious_ww)} unexpected world-writable directories',
                description=(
                    f'Found world-writable directories outside /tmp: '
                    f'{", ".join(suspicious_ww[:10])}. '
                    f'World-writable directories can be exploited for '
                    f'symlink attacks and data tampering.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=5.0,
                remediation=(
                    'Remove world-writable permission: chmod o-w <directory> '
                    'or set sticky bit: chmod +t <directory>'
                ),
                raw_data={'world_writable_dirs': suspicious_ww[:20]},
                detection_method='system_command',
            )

    # ===================================================================== #
    #  CHECK 7 - Patch / Update Status                                      #
    # ===================================================================== #

    def _check_patches(self, hostname: str, scan_type: str) -> None:
        """Evaluate system patching currency."""

        pending_updates = None
        pkg_manager = None

        # --- apt (Debian/Ubuntu) ---
        apt_check = self._run_cmd(
            'apt list --upgradable 2>/dev/null | grep -c upgradable'
        )
        if apt_check is not None:
            pkg_manager = 'apt'
            try:
                pending_updates = int(apt_check.strip())
            except ValueError:
                pending_updates = 0

            # Check for security updates specifically
            sec_updates = self._run_cmd(
                'apt list --upgradable 2>/dev/null | grep -ci security'
            )
            sec_count = 0
            if sec_updates:
                try:
                    sec_count = int(sec_updates.strip())
                except ValueError:
                    pass

            if sec_count > 0:
                self.add_finding(
                    severity='HIGH',
                    title=f'{sec_count} security updates pending',
                    description=(
                        f'{sec_count} security patches are available and '
                        f'not installed. Security updates should be applied '
                        f'promptly.'
                    ),
                    affected_asset=hostname,
                    finding_type='missing_patch',
                    cvss_score=7.5,
                    remediation='sudo apt update && sudo apt upgrade -y',
                    raw_data={'security_updates': sec_count},
                    detection_method='system_command',
                )

        # --- yum/dnf (RHEL/CentOS/Fedora) ---
        if pkg_manager is None:
            yum_check = self._run_cmd(
                'yum check-update --quiet 2>/dev/null | '
                'grep -v "^$" | grep -v "Loaded plugins" | wc -l'
            )
            if yum_check is None:
                yum_check = self._run_cmd(
                    'dnf check-update --quiet 2>/dev/null | '
                    'grep -v "^$" | wc -l'
                )
                if yum_check is not None:
                    pkg_manager = 'dnf'
            else:
                pkg_manager = 'yum'

            if yum_check is not None:
                try:
                    pending_updates = int(yum_check.strip())
                except ValueError:
                    pending_updates = 0

                # Security updates
                sec_cmd = (
                    f'{pkg_manager} updateinfo list security 2>/dev/null | '
                    f'grep -c "."'
                )
                sec_updates = self._run_cmd(sec_cmd)
                if sec_updates:
                    try:
                        sec_count = int(sec_updates.strip())
                        if sec_count > 0:
                            self.add_finding(
                                severity='HIGH',
                                title=f'{sec_count} security updates pending',
                                description=(
                                    f'{sec_count} security advisories with '
                                    f'pending patches.'
                                ),
                                affected_asset=hostname,
                                finding_type='missing_patch',
                                cvss_score=7.5,
                                remediation=(
                                    f'sudo {pkg_manager} update --security -y'
                                ),
                                detection_method='system_command',
                            )
                    except ValueError:
                        pass

        # Report total pending updates
        if pending_updates is not None:
            if pending_updates > 50:
                sev = 'HIGH'
                cvss = 7.0
            elif pending_updates > 10:
                sev = 'MEDIUM'
                cvss = 5.0
            elif pending_updates > 0:
                sev = 'LOW'
                cvss = 3.0
            else:
                sev = 'INFO'
                cvss = 0.0

            self.add_finding(
                severity=sev,
                title=f'{pending_updates} pending package updates ({pkg_manager})',
                description=(
                    f'{pending_updates} packages have updates available via '
                    f'{pkg_manager}.'
                ),
                affected_asset=hostname,
                finding_type='missing_patch',
                cvss_score=cvss,
                remediation=(
                    f'Apply updates: sudo {pkg_manager} upgrade -y'
                    if pkg_manager == 'apt' else
                    f'sudo {pkg_manager} update -y'
                ),
                raw_data={'pending': pending_updates, 'manager': pkg_manager},
                detection_method='system_command',
            )
        else:
            self.add_finding(
                severity='INFO',
                title='Could not determine package update status',
                description='Neither apt, yum, nor dnf was available to check updates.',
                affected_asset=hostname,
                finding_type='missing_patch',
                detection_method='system_command',
            )

        # --- Kernel version ---
        kernel = self._run_cmd('uname -r 2>/dev/null')
        if kernel:
            self.add_finding(
                severity='INFO',
                title=f'Kernel version: {kernel.strip()}',
                description=f'Running kernel: {kernel.strip()}',
                affected_asset=hostname,
                finding_type='missing_patch',
                raw_data={'kernel': kernel.strip()},
                detection_method='system_command',
            )

        # --- Last update timestamp ---
        # Debian/Ubuntu
        last_update = self._run_cmd(
            'stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null'
        )
        if last_update is None:
            # RHEL/CentOS
            last_update = self._run_cmd(
                'stat -c %Y /var/cache/yum 2>/dev/null || '
                'stat -c %Y /var/cache/dnf 2>/dev/null'
            )

        if last_update:
            try:
                update_ts = int(last_update.strip())
                update_dt = datetime.utcfromtimestamp(update_ts)
                days_since = (datetime.utcnow() - update_dt).days
                if days_since > 30:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'Package cache not refreshed in {days_since} days',
                        description=(
                            f'The package manager cache was last updated '
                            f'{days_since} days ago on '
                            f'{update_dt.strftime("%Y-%m-%d")}.'
                        ),
                        affected_asset=hostname,
                        finding_type='missing_patch',
                        cvss_score=4.0,
                        remediation='sudo apt update or sudo yum makecache',
                        detection_method='system_command',
                    )
            except (ValueError, OSError):
                pass

    # ===================================================================== #
    #  CHECK 8 - Certificates                                               #
    # ===================================================================== #

    def _check_certificates(self, hostname: str, scan_type: str) -> None:
        """Check for expired or soon-to-expire TLS certificates."""

        cert_dir = '/etc/ssl/certs'
        cert_files: List[str] = []

        # Find certificate files
        if os.path.isdir(cert_dir):
            for ext in ('*.pem', '*.crt', '*.cer'):
                cert_files.extend(
                    _glob.glob(os.path.join(cert_dir, ext))
                )

        # Also check common locations
        for extra_dir in [
            '/etc/pki/tls/certs',
            '/etc/letsencrypt/live',
            '/etc/nginx/ssl',
            '/etc/apache2/ssl',
        ]:
            if os.path.isdir(extra_dir):
                for ext in ('*.pem', '*.crt', '*.cer'):
                    cert_files.extend(
                        _glob.glob(
                            os.path.join(extra_dir, '**', ext),
                            recursive=True,
                        )
                    )

        # Limit to avoid very long scans
        cert_files = cert_files[:100]

        now = datetime.utcnow()
        soon = now + timedelta(days=30)
        expired_certs: List[str] = []
        expiring_certs: List[str] = []
        checked = 0

        for cert_file in cert_files:
            # Use openssl to check expiry
            expiry_raw = self._run_cmd(
                f'openssl x509 -in "{cert_file}" -noout -enddate 2>/dev/null',
                timeout=5,
            )
            if expiry_raw is None:
                continue

            # Parse: notAfter=Mar 15 12:00:00 2025 GMT
            m = re.search(r'notAfter=(.+)', expiry_raw)
            if not m:
                continue

            checked += 1
            date_str = m.group(1).strip()
            try:
                not_after = datetime.strptime(
                    date_str, '%b %d %H:%M:%S %Y %Z'
                )
            except ValueError:
                try:
                    not_after = datetime.strptime(
                        date_str, '%b  %d %H:%M:%S %Y %Z'
                    )
                except ValueError:
                    continue

            cert_name = os.path.basename(cert_file)

            if not_after < now:
                expired_certs.append(
                    f'{cert_name} (expired {not_after.strftime("%Y-%m-%d")})'
                )
                self.add_finding(
                    severity='MEDIUM',
                    title=f'Expired certificate: {cert_name}',
                    description=(
                        f'Certificate "{cert_file}" expired on '
                        f'{not_after.strftime("%Y-%m-%d")}.'
                    ),
                    affected_asset=hostname,
                    finding_type='expired_certificate',
                    cvss_score=5.0,
                    remediation='Renew or remove the expired certificate.',
                    raw_data={'file': cert_file, 'expiry': date_str},
                    detection_method='system_command',
                )
            elif not_after < soon:
                days_left = (not_after - now).days
                expiring_certs.append(
                    f'{cert_name} ({days_left}d left)'
                )
                self.add_finding(
                    severity='HIGH',
                    title=f'Certificate expiring soon: {cert_name}',
                    description=(
                        f'Certificate "{cert_file}" expires on '
                        f'{not_after.strftime("%Y-%m-%d")} '
                        f'({days_left} day(s) remaining).'
                    ),
                    affected_asset=hostname,
                    finding_type='expired_certificate',
                    cvss_score=6.5,
                    remediation='Renew the certificate before expiration.',
                    raw_data={'file': cert_file, 'expiry': date_str},
                    detection_method='system_command',
                )

        self.add_finding(
            severity='INFO',
            title=(
                f'Certificate summary: {checked} checked, '
                f'{len(expired_certs)} expired, '
                f'{len(expiring_certs)} expiring soon'
            ),
            description=(
                f'Checked {checked} certificate files. '
                f'Expired: {len(expired_certs)}, '
                f'expiring within 30 days: {len(expiring_certs)}.'
            ),
            affected_asset=hostname,
            finding_type='expired_certificate',
            raw_data={
                'checked': checked,
                'expired': expired_certs,
                'expiring_soon': expiring_certs,
            },
            detection_method='system_command',
        )

    # ===================================================================== #
    #  CHECK 9 - System Configuration                                       #
    # ===================================================================== #

    def _check_system_config(self, hostname: str, scan_type: str) -> None:
        """Inspect /etc/passwd, /etc/shadow, /etc/sudoers, cron."""

        self._check_passwd(hostname)
        self._check_shadow_permissions(hostname)
        self._check_sudoers(hostname)
        self._check_cron(hostname, scan_type)

    def _check_passwd(self, hostname: str) -> None:
        """Check /etc/passwd for security issues."""
        passwd_content = self._run_cmd('cat /etc/passwd 2>/dev/null')
        if passwd_content is None:
            return

        # UID 0 accounts (should only be root)
        uid0_accounts = []
        empty_password_users = []

        for line in passwd_content.splitlines():
            parts = line.split(':')
            if len(parts) < 7:
                continue
            username = parts[0]
            password_field = parts[1]
            uid = parts[2]

            if uid == '0' and username != 'root':
                uid0_accounts.append(username)

            # Empty password field (not 'x' which means use shadow)
            if password_field == '' or password_field == '::':
                empty_password_users.append(username)

        if uid0_accounts:
            self.add_finding(
                severity='CRITICAL',
                title=f'Non-root accounts with UID 0: {", ".join(uid0_accounts)}',
                description=(
                    f'The following accounts have UID 0 (root-equivalent): '
                    f'{", ".join(uid0_accounts)}. Multiple UID 0 accounts '
                    f'make privilege abuse harder to track.'
                ),
                affected_asset=hostname,
                finding_type='account_hygiene',
                cvss_score=9.5,
                remediation=(
                    'Remove or change UID for non-root UID 0 accounts: '
                    'usermod -u <new_uid> <username>'
                ),
                raw_data={'uid0_accounts': uid0_accounts},
                detection_method='config_file_check',
            )

        if empty_password_users:
            self.add_finding(
                severity='CRITICAL',
                title=f'Accounts with empty password field: {", ".join(empty_password_users)}',
                description=(
                    f'The following accounts have empty password fields in '
                    f'/etc/passwd: {", ".join(empty_password_users)}. '
                    f'These accounts may allow passwordless login.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=9.5,
                remediation='Lock accounts or set passwords: passwd <username>',
                raw_data={'empty_password_users': empty_password_users},
                detection_method='config_file_check',
            )

    def _check_shadow_permissions(self, hostname: str) -> None:
        """Check /etc/shadow file permissions."""
        shadow_perms = self._run_cmd(
            'stat -c "%a %U %G" /etc/shadow 2>/dev/null'
        )
        if shadow_perms is None:
            self.scan_logger.info(
                "Cannot check /etc/shadow permissions (may need root)"
            )
            return

        parts = shadow_perms.strip().split()
        if len(parts) >= 3:
            perms = parts[0]
            owner = parts[1]
            group = parts[2]

            # Should be 640 or 600, owned by root
            if owner != 'root':
                self.add_finding(
                    severity='CRITICAL',
                    title=f'/etc/shadow not owned by root (owner: {owner})',
                    description=(
                        f'/etc/shadow is owned by {owner} instead of root. '
                        f'The shadow file contains password hashes.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=9.0,
                    remediation='sudo chown root:shadow /etc/shadow',
                    detection_method='config_file_check',
                )

            perm_int = int(perms, 8) if len(perms) <= 4 else 0
            if perm_int > 0o640:
                self.add_finding(
                    severity='HIGH',
                    title=f'/etc/shadow has excessive permissions ({perms})',
                    description=(
                        f'/etc/shadow permissions are {perms}. '
                        f'Should be 640 or 600 to prevent password hash exposure.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    cvss_score=7.5,
                    remediation='sudo chmod 640 /etc/shadow',
                    raw_data={'perms': perms, 'owner': owner, 'group': group},
                    detection_method='config_file_check',
                )

    def _check_sudoers(self, hostname: str) -> None:
        """Check sudoers for NOPASSWD entries."""
        sudoers = self._run_cmd(
            'cat /etc/sudoers 2>/dev/null; '
            'cat /etc/sudoers.d/* 2>/dev/null'
        )
        if sudoers is None:
            self.scan_logger.info(
                "Cannot read sudoers (may need root)"
            )
            return

        nopasswd_entries = []
        for line in sudoers.splitlines():
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            if 'NOPASSWD' in line:
                nopasswd_entries.append(line[:100])

        if nopasswd_entries:
            # Check if NOPASSWD ALL is used
            has_nopasswd_all = any(
                'NOPASSWD' in l and 'ALL' in l
                for l in nopasswd_entries
            )
            severity = 'HIGH' if has_nopasswd_all else 'MEDIUM'
            cvss = 7.5 if has_nopasswd_all else 5.0

            self.add_finding(
                severity=severity,
                title=f'{len(nopasswd_entries)} NOPASSWD sudo entries found',
                description=(
                    f'Found {len(nopasswd_entries)} sudoers rules with '
                    f'NOPASSWD. Users can execute privileged commands '
                    f'without re-authenticating.\n'
                    f'Entries: {"; ".join(nopasswd_entries[:5])}'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=cvss,
                remediation='Review and remove NOPASSWD from sudoers entries.',
                raw_data={'nopasswd_entries': nopasswd_entries[:10]},
                detection_method='config_file_check',
            )

    def _check_cron(self, hostname: str, scan_type: str) -> None:
        """Review cron jobs for security issues."""
        # System cron
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
        ]

        cron_files = []
        for cron_dir in cron_dirs:
            if os.path.isdir(cron_dir):
                for f in os.listdir(cron_dir):
                    fpath = os.path.join(cron_dir, f)
                    if os.path.isfile(fpath):
                        cron_files.append(fpath)

        # Check /etc/crontab
        crontab = self._run_cmd('cat /etc/crontab 2>/dev/null')

        # Check world-writable cron files
        ww_cron = []
        for cf in cron_files:
            perms = self._run_cmd(f'stat -c "%a" "{cf}" 2>/dev/null')
            if perms:
                perm_int = int(perms.strip(), 8) if perms.strip() else 0
                if perm_int & 0o002:
                    ww_cron.append(cf)

        if ww_cron:
            self.add_finding(
                severity='HIGH',
                title=f'{len(ww_cron)} world-writable cron files found',
                description=(
                    f'World-writable cron files: {", ".join(ww_cron[:5])}. '
                    f'Any user can modify these files to execute commands '
                    f'with elevated privileges.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                cvss_score=7.5,
                remediation='Remove world-writable permissions: chmod o-w <file>',
                raw_data={'world_writable_cron': ww_cron},
                detection_method='config_file_check',
            )

        self.add_finding(
            severity='INFO',
            title=f'{len(cron_files)} system cron files found',
            description=f'Reviewed {len(cron_files)} cron files across system cron directories.',
            affected_asset=hostname,
            finding_type='insecure_configuration',
            raw_data={'cron_file_count': len(cron_files)},
            detection_method='config_file_check',
        )

    # ===================================================================== #
    #  CHECK 10 - Log Analysis                                              #
    # ===================================================================== #

    def _check_logs(self, hostname: str, scan_type: str) -> None:
        """Analyse authentication logs for suspicious activity."""

        self._check_failed_ssh(hostname, scan_type)
        self._check_suspicious_logs(hostname, scan_type)

    def _check_failed_ssh(self, hostname: str, scan_type: str) -> None:
        """Count failed SSH login attempts."""
        max_events = 200 if scan_type == 'deep' else 100

        # Try journalctl first
        count_raw = self._run_cmd(
            f'journalctl -u sshd -u ssh --since "7 days ago" '
            f'--no-pager 2>/dev/null | '
            f'grep -ci "failed password" | head -1',
            timeout=30,
        )

        if count_raw is None or not count_raw.strip().isdigit():
            # Fall back to auth.log
            count_raw = self._run_cmd(
                'grep -ci "failed password" /var/log/auth.log 2>/dev/null || '
                'grep -ci "failed password" /var/log/secure 2>/dev/null',
                timeout=30,
            )

        if count_raw is None:
            self.scan_logger.debug(
                "Could not query failed SSH logins (may need root)"
            )
            return

        try:
            count = int(count_raw.strip())
        except ValueError:
            return

        if count > 100:
            self.add_finding(
                severity='HIGH',
                title=f'{count} failed SSH login attempts detected',
                description=(
                    f'Detected {count} failed SSH password attempts in '
                    f'recent logs. This may indicate a brute-force or '
                    f'password-spraying attack.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=7.0,
                remediation=(
                    'Investigate source IPs. Install fail2ban: '
                    'sudo apt install fail2ban. '
                    'Consider disabling password authentication.'
                ),
                raw_data={'failed_ssh_count': count},
                detection_method='log_analysis',
            )
        elif count > 20:
            self.add_finding(
                severity='MEDIUM',
                title=f'{count} failed SSH login attempts detected',
                description=(
                    f'Detected {count} failed SSH password attempts. '
                    f'While not extreme, this warrants investigation.'
                ),
                affected_asset=hostname,
                finding_type='authentication_weakness',
                cvss_score=5.5,
                remediation=(
                    'Review auth logs: '
                    'grep "Failed password" /var/log/auth.log | tail -20'
                ),
                raw_data={'failed_ssh_count': count},
                detection_method='log_analysis',
            )
        else:
            self.add_finding(
                severity='INFO',
                title=f'{count} failed SSH login attempts in recent logs',
                description=f'{count} failed SSH authentication events detected.',
                affected_asset=hostname,
                finding_type='authentication_weakness',
                raw_data={'failed_ssh_count': count},
                detection_method='log_analysis',
            )

    def _check_suspicious_logs(self, hostname: str, scan_type: str) -> None:
        """Check for suspicious log entries."""

        # Sudo failures
        sudo_fail = self._run_cmd(
            'grep -ci "NOT in sudoers\\|incorrect password attempt" '
            '/var/log/auth.log 2>/dev/null || '
            'journalctl --since "7 days ago" --no-pager 2>/dev/null | '
            'grep -ci "NOT in sudoers\\|incorrect password attempt"',
            timeout=20,
        )
        if sudo_fail and sudo_fail.strip().isdigit():
            fail_count = int(sudo_fail.strip())
            if fail_count > 10:
                self.add_finding(
                    severity='MEDIUM',
                    title=f'{fail_count} sudo authorization failures detected',
                    description=(
                        f'{fail_count} sudo failures found in logs. '
                        f'This may indicate privilege escalation attempts.'
                    ),
                    affected_asset=hostname,
                    finding_type='authentication_weakness',
                    cvss_score=5.0,
                    remediation='Review sudo failures: grep "NOT in sudoers" /var/log/auth.log',
                    raw_data={'sudo_failures': fail_count},
                    detection_method='log_analysis',
                )

        # Check if log files exist and are being written
        if scan_type == 'deep':
            log_files = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/kern.log',
                '/var/log/secure',
                '/var/log/messages',
            ]

            missing_logs = []
            for log_file in log_files:
                if not os.path.exists(log_file):
                    # Only flag if neither pair exists (syslog vs messages)
                    if log_file in ('/var/log/auth.log', '/var/log/syslog'):
                        alt = log_file.replace('auth.log', 'secure').replace(
                            'syslog', 'messages'
                        )
                        if not os.path.exists(alt):
                            missing_logs.append(log_file)
                    elif log_file in ('/var/log/secure', '/var/log/messages'):
                        alt = log_file.replace('secure', 'auth.log').replace(
                            'messages', 'syslog'
                        )
                        if not os.path.exists(alt):
                            missing_logs.append(log_file)

            if missing_logs:
                self.add_finding(
                    severity='MEDIUM',
                    title=f'{len(missing_logs)} critical log files missing',
                    description=(
                        f'Missing log files: {", ".join(missing_logs)}. '
                        f'Without proper logging, security events cannot '
                        f'be investigated.'
                    ),
                    affected_asset=hostname,
                    finding_type='audit_policy',
                    cvss_score=5.0,
                    remediation='Verify rsyslog/syslog-ng configuration.',
                    detection_method='config_file_check',
                )

    # ===================================================================== #
    #  CHECK 11 - Unauthorized AI Detection                                 #
    # ===================================================================== #

    def _check_unauthorized_ai(self, hostname: str, scan_type: str) -> None:
        """Detect unauthorized AI installations, processes, models, and network activity."""

        self._check_ai_processes(hostname)
        self._check_ai_ports(hostname)
        self._check_ai_installations(hostname)
        self._check_ai_services(hostname)
        self._check_ai_docker(hostname)

        if scan_type == 'deep':
            self._check_ai_models(hostname)
            self._check_ai_python_packages(hostname)

    def _check_ai_processes(self, hostname: str) -> None:
        """Detect running AI-related processes."""
        ps_output = self._run_cmd(
            'ps aux --no-headers 2>/dev/null'
        )
        if not ps_output:
            return

        reported_procs: set = set()

        for line in ps_output.splitlines():
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            pid = parts[1]
            cmd_full = parts[10].lower()
            cmd_name = os.path.basename(
                parts[10].split()[0] if parts[10] else ''
            ).lower()

            for ai_name, ai_label in self.AI_PROCESSES.items():
                if ai_label is None:
                    continue
                ai_lower = ai_name.lower()
                if ai_lower in cmd_name or ai_lower in cmd_full:
                    if ai_lower not in reported_procs:
                        reported_procs.add(ai_lower)
                        self.add_finding(
                            severity='HIGH',
                            title=f'Unauthorized AI Process: {ai_label}',
                            description=(
                                f'Detected running AI process matching '
                                f'"{ai_name}" (PID {pid}). '
                                f'Command: {parts[10][:120]}. '
                                f'Unauthorized local AI tools may pose data '
                                f'exfiltration, compliance, and shadow IT risks.'
                            ),
                            affected_asset=hostname,
                            finding_type='insecure_configuration',
                            detection_method='service_enumeration',
                            remediation=(
                                f'Investigate whether {ai_label} is authorized. '
                                f'If not, terminate PID {pid} and uninstall.'
                            ),
                        )
                    break

    def _check_ai_ports(self, hostname: str) -> None:
        """Check for AI services listening on known ports."""
        ss_output = self._run_cmd('ss -tlnp 2>/dev/null')
        if not ss_output:
            return

        for line in ss_output.splitlines():
            m = re.search(r'LISTEN\s+\d+\s+\d+\s+\S+:(\d+)\s', line)
            if not m:
                continue
            port = int(m.group(1))
            if port in self.AI_PORTS:
                ai_svc = self.AI_PORTS[port]

                # Extract process info
                proc_match = re.search(r'users:\(\("([^"]+)"', line)
                proc_name = proc_match.group(1) if proc_match else 'unknown'

                self.add_finding(
                    severity='HIGH',
                    title=f'AI Service Port Active: {port} ({ai_svc})',
                    description=(
                        f'Port {port} is listening (commonly used by {ai_svc}). '
                        f'Process: {proc_name}. '
                        f'This may indicate an unauthorized AI service.'
                    ),
                    affected_asset=hostname,
                    finding_type='open_port',
                    detection_method='system_command',
                    remediation=(
                        f'Verify if the service on port {port} is authorized. '
                        f'If not, stop the process and block the port.'
                    ),
                )

    def _check_ai_installations(self, hostname: str) -> None:
        """Scan for AI application installations on disk."""

        # Check system-level paths
        for path in self.AI_INSTALL_PATHS:
            if os.path.exists(path):
                ai_name = 'Unknown AI application'
                path_lower = path.lower()
                for keyword, label in [
                    ('ollama', 'Ollama'), ('lm-studio', 'LM Studio'),
                    ('localai', 'LocalAI'), ('gpt4all', 'GPT4All'),
                    ('koboldcpp', 'KoboldCpp'),
                    ('text-generation', 'Text Generation WebUI'),
                    ('open-webui', 'Open WebUI'),
                ]:
                    if keyword in path_lower:
                        ai_name = label
                        break

                self.add_finding(
                    severity='MEDIUM',
                    title=f'AI Application Installed: {ai_name}',
                    description=(
                        f'Found AI application at: {path}. '
                        f'This may indicate an unauthorized AI tool.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    detection_method='system_command',
                    remediation=(
                        f'Verify if {ai_name} at {path} is authorized. '
                        f'If unauthorized, remove it.'
                    ),
                )

        # Check user home directories
        home_dirs = self._run_cmd_lines(
            'ls -d /home/*/ /root/ 2>/dev/null'
        )
        for home_dir in home_dirs:
            home_dir = home_dir.strip().rstrip('/')
            for ai_subdir in self.AI_HOME_PATHS:
                full_path = os.path.join(home_dir, ai_subdir)
                if os.path.exists(full_path):
                    ai_name = 'Unknown AI data'
                    for keyword, label in [
                        ('.ollama', 'Ollama'),
                        ('huggingface', 'HuggingFace'),
                        ('lm-studio', 'LM Studio'),
                        ('nomic.ai', 'GPT4All/Nomic'),
                        ('gpt4all', 'GPT4All'),
                        ('anythingllm', 'AnythingLLM'),
                        ('.jan', 'Jan AI'),
                        ('.chatbox', 'Chatbox'),
                    ]:
                        if keyword in ai_subdir:
                            ai_name = label
                            break

                    self.add_finding(
                        severity='MEDIUM',
                        title=f'AI Data Directory Found: {ai_name}',
                        description=(
                            f'Found AI-related directory: {full_path}. '
                            f'This indicates {ai_name} has been used '
                            f'on this system.'
                        ),
                        affected_asset=hostname,
                        finding_type='insecure_configuration',
                        detection_method='system_command',
                        remediation=(
                            f'Verify if {ai_name} usage is authorized. '
                            f'Remove {full_path} if not approved.'
                        ),
                    )

        # Check snap/flatpak for AI packages
        snap_list = self._run_cmd('snap list 2>/dev/null')
        if snap_list:
            ai_keywords = [
                'ollama', 'lm-studio', 'gpt4all', 'localai', 'jan',
            ]
            for line in snap_list.splitlines():
                name = line.split()[0].lower() if line.split() else ''
                for kw in ai_keywords:
                    if kw in name:
                        self.add_finding(
                            severity='HIGH',
                            title=f'AI Snap Package Installed: {name}',
                            description=(
                                f'Snap package "{name}" is installed. '
                                f'This is an AI-related application.'
                            ),
                            affected_asset=hostname,
                            finding_type='insecure_configuration',
                            detection_method='system_command',
                            remediation=f'Remove if unauthorized: sudo snap remove {name}',
                        )
                        break

        flatpak_list = self._run_cmd('flatpak list 2>/dev/null')
        if flatpak_list:
            ai_keywords = [
                'ollama', 'lm-studio', 'gpt4all', 'localai', 'jan',
            ]
            for line in flatpak_list.splitlines():
                name = line.split('\t')[0].lower() if line else ''
                for kw in ai_keywords:
                    if kw in name:
                        self.add_finding(
                            severity='HIGH',
                            title=f'AI Flatpak Package Installed: {name}',
                            description=(
                                f'Flatpak "{name}" is installed. '
                                f'This is an AI-related application.'
                            ),
                            affected_asset=hostname,
                            finding_type='insecure_configuration',
                            detection_method='system_command',
                            remediation=f'Remove if unauthorized: flatpak uninstall {name}',
                        )
                        break

    def _check_ai_services(self, hostname: str) -> None:
        """Check for AI-related systemd services."""
        for svc in self.AI_SERVICES:
            status = self._run_cmd(
                f'systemctl is-active {svc} 2>/dev/null'
            )
            if status and 'active' in status:
                self.add_finding(
                    severity='HIGH',
                    title=f'AI Service Running: {svc}',
                    description=(
                        f'Systemd service "{svc}" is active. '
                        f'This is a persistent AI service that starts '
                        f'automatically.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    detection_method='service_enumeration',
                    remediation=(
                        f'Stop and disable if unauthorized: '
                        f'sudo systemctl stop {svc} && '
                        f'sudo systemctl disable {svc}'
                    ),
                )

            # Also check enabled (but perhaps not currently active)
            enabled = self._run_cmd(
                f'systemctl is-enabled {svc} 2>/dev/null'
            )
            if enabled and 'enabled' in enabled and (
                not status or 'active' not in status
            ):
                self.add_finding(
                    severity='MEDIUM',
                    title=f'AI Service Enabled: {svc}',
                    description=(
                        f'Systemd service "{svc}" is enabled (auto-start) '
                        f'but not currently running.'
                    ),
                    affected_asset=hostname,
                    finding_type='insecure_configuration',
                    detection_method='service_enumeration',
                    remediation=f'Disable: sudo systemctl disable {svc}',
                )

    def _check_ai_docker(self, hostname: str) -> None:
        """Check for Docker containers running AI-related images."""
        docker_ps = self._run_cmd(
            'docker ps --format "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}" '
            '2>/dev/null'
        )
        if not docker_ps:
            return

        for line in docker_ps.splitlines():
            parts = line.split('\t')
            if len(parts) < 4:
                continue
            container_id = parts[0]
            image = parts[1].lower()
            name = parts[2]
            status = parts[3]

            for ai_image in self.AI_DOCKER_IMAGES:
                if ai_image in image:
                    self.add_finding(
                        severity='HIGH',
                        title=f'AI Docker Container Running: {name}',
                        description=(
                            f'Docker container "{name}" (ID: {container_id}) '
                            f'is running image "{parts[1]}" ({status}). '
                            f'This is an AI-related container.'
                        ),
                        affected_asset=hostname,
                        finding_type='insecure_configuration',
                        detection_method='service_enumeration',
                        remediation=(
                            f'If unauthorized: docker stop {name} && '
                            f'docker rm {name}'
                        ),
                    )
                    break

    def _check_ai_models(self, hostname: str) -> None:
        """Scan for AI model files on disk (deep scan only)."""
        model_files: List[str] = []

        home_dirs = self._run_cmd_lines(
            'ls -d /home/*/ /root/ 2>/dev/null'
        )

        for home_dir in home_dirs:
            home_dir = home_dir.strip().rstrip('/')
            for model_subdir in self.AI_MODEL_SEARCH_DIRS:
                base_dir = os.path.join(home_dir, model_subdir)
                if not os.path.isdir(base_dir):
                    continue
                for ext in ('.gguf', '.ggml', '.safetensors'):
                    try:
                        matches = _glob.glob(
                            os.path.join(base_dir, '**', f'*{ext}'),
                            recursive=True,
                        )
                        model_files.extend(matches[:50])
                    except Exception:
                        continue

        # Also check /opt
        for ext in ('.gguf', '.ggml', '.safetensors'):
            try:
                matches = _glob.glob(
                    os.path.join('/opt', '**', f'*{ext}'),
                    recursive=True,
                )
                model_files.extend(matches[:50])
            except Exception:
                continue

        if model_files:
            total_size = 0
            model_list = []
            for mf in model_files[:20]:
                try:
                    sz = os.path.getsize(mf)
                    total_size += sz
                    model_list.append(
                        f'{os.path.basename(mf)} ({sz / (1024**3):.1f} GB)'
                    )
                except OSError:
                    model_list.append(os.path.basename(mf))

            self.add_finding(
                severity='HIGH',
                title=(
                    f'AI Model Files Found ({len(model_files)} files, '
                    f'{total_size / (1024**3):.1f} GB)'
                ),
                description=(
                    f'Found {len(model_files)} AI model files on disk. '
                    f'Total size: {total_size / (1024**3):.1f} GB. '
                    f'Files: {"; ".join(model_list[:10])}. '
                    f'Large language models stored locally may indicate '
                    f'unauthorized AI usage.'
                ),
                affected_asset=hostname,
                finding_type='insecure_configuration',
                detection_method='system_command',
                remediation=(
                    'Review AI model files and remove unauthorized ones. '
                    'Implement DLP controls to detect model downloads.'
                ),
            )

    def _check_ai_python_packages(self, hostname: str) -> None:
        """Check for AI-related Python packages installed."""
        pip_output = self._run_cmd(
            'pip3 list 2>/dev/null || pip list 2>/dev/null',
            timeout=30,
        )
        if not pip_output:
            return

        ai_packages = [
            'openai', 'anthropic', 'langchain', 'transformers', 'torch',
            'tensorflow', 'ollama', 'llama-cpp-python', 'vllm',
            'huggingface-hub', 'sentence-transformers', 'chromadb',
            'pinecone', 'weaviate', 'qdrant-client', 'faiss-cpu',
            'faiss-gpu', 'auto-gptq', 'ctransformers', 'guidance',
            'llama-index', 'llamaindex', 'autogen', 'crewai',
            'langsmith', 'litellm',
        ]

        found = []
        for line in pip_output.splitlines():
            pkg_parts = line.strip().split()
            if not pkg_parts:
                continue
            pkg_name = pkg_parts[0].lower()
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
                    'Review AI Python packages against authorized software '
                    'list. Remove: pip3 uninstall <package>'
                ),
            )

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
                count = conn.execute(
                    'SELECT COUNT(*) FROM nvd_cves'
                ).fetchone()[0]
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

        # --- System tools ---
        tools_status: List[str] = []
        for tool in ['ss', 'ip', 'systemctl', 'journalctl', 'openssl',
                      'find', 'grep', 'awk']:
            check = subprocess.run(
                f'which {tool}', shell=True,
                capture_output=True, text=True, timeout=5,
            )
            if check.returncode == 0:
                tools_status.append(tool)
        status['details']['tools'] = tools_status

        return status


# =========================================================================== #
#  CLI entry point                                                            #
# =========================================================================== #

if __name__ == '__main__':
    import sys as _sys

    scan_type = _sys.argv[1] if len(_sys.argv) > 1 else 'standard'
    scanner = LinuxScanner()

    print(f"Linux Security Scanner - {scan_type} scan")
    print("=" * 50)

    # Show offline data status
    offline = LinuxScanner.verify_offline_data()
    print(f"Offline data: {'READY' if offline['ready'] else 'INCOMPLETE'}")
    for k, v in offline['details'].items():
        print(f"  {k}: {v}")
    print()

    results = scanner.scan(scan_type=scan_type)

    # Print summary
    summary = results.get('summary', {})
    print(f"\nScan Complete:")
    print(f"  Root: {results.get('is_root', False)}")
    print(f"  Checks completed: {results.get('checks_completed', 0)}")
    print(f"  Checks skipped: {results.get('checks_skipped', 0)}")
    print(f"  Findings: {summary.get('findings_count', 0)}")
    for sev, count in summary.get('findings_by_severity', {}).items():
        if count > 0:
            print(f"    {sev}: {count}")
