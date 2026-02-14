#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Cloud Configuration Scanner

Assesses security configuration across AWS, Azure, and GCP using their
respective CLI tools (aws, az, gcloud).

Auto-detects which cloud providers are configured and skips unavailable ones
gracefully.

AWS checks:
  1.  S3 - public buckets, encryption, versioning, logging
  2.  IAM - root MFA, access key age, unused creds, overly permissive policies
  3.  Security Groups - 0.0.0.0/0 inbound, unrestricted SSH/RDP
  4.  Logging - CloudTrail, S3 access logging, VPC flow logs
  5.  Encryption - EBS defaults, RDS encryption, unencrypted snapshots

Azure checks:
  6.  Storage - public blob access, encryption, HTTPS-only
  7.  Identity - MFA enforcement, conditional access, PIM
  8.  NSG - network security group rules, any-any rules
  9.  Logging - diagnostic settings, activity log alerts

GCP checks:
  10. Storage - public buckets, uniform access
  11. IAM - service account keys, primitive roles
  12. Firewall - overly permissive rules
  13. Logging - audit logs, VPC flow logs

Scan types:
  quick    - high-severity checks only (IAM, public exposure)
  standard - all checks
  deep     - all checks with per-resource detail
"""

import base64
import json
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


class CloudScanner(BaseScanner):
    """Multi-cloud security configuration scanner."""

    SCANNER_NAME = "cloud"
    SCANNER_DESCRIPTION = "Cloud security configuration assessment (AWS/Azure/GCP)"

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.available_providers: List[str] = []

    # -----------------------------------------------------------------------
    # CLI helpers
    # -----------------------------------------------------------------------

    def _run_cli(self, command: List[str],
                 timeout: int = 120) -> Optional[str]:
        """Run a CLI command and return stdout, or None on error."""
        self.scan_logger.debug(f"CLI> {' '.join(command[:5])}")
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout
            )
            if proc.returncode != 0:
                stderr = (proc.stderr or '').strip()
                if stderr:
                    self.scan_logger.debug(f"CLI stderr: {stderr[:200]}")
                return None
            return (proc.stdout or '').strip()
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            self.scan_logger.warning(
                f"CLI timed out: {' '.join(command[:3])}"
            )
            return None
        except Exception as exc:
            self.scan_logger.debug(f"CLI error: {exc}")
            return None

    def _run_cli_json(self, command: List[str],
                      timeout: int = 120) -> Any:
        """Run a CLI command and parse JSON output."""
        raw = self._run_cli(command, timeout)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    # -----------------------------------------------------------------------
    # Provider detection
    # -----------------------------------------------------------------------

    def _detect_providers(self) -> List[str]:
        """Detect which cloud CLIs are installed and configured."""
        providers = []

        # AWS CLI
        result = self._run_cli(['aws', 'sts', 'get-caller-identity'])
        if result:
            providers.append('aws')
            self.scan_logger.info("AWS CLI detected and configured")

        # Azure CLI
        result = self._run_cli(['az', 'account', 'show', '-o', 'json'])
        if result:
            providers.append('azure')
            self.scan_logger.info("Azure CLI detected and configured")

        # GCP CLI
        result = self._run_cli(
            ['gcloud', 'config', 'get-value', 'project']
        )
        if result and result != '(unset)':
            providers.append('gcp')
            self.scan_logger.info("GCP CLI detected and configured")

        return providers

    # -----------------------------------------------------------------------
    # Main scan entry point
    # -----------------------------------------------------------------------

    def scan(self, targets: List[str] = None,
             scan_type: str = 'standard', **kwargs) -> Dict:
        """Execute cloud security scan.

        Args:
            targets: Optional list of provider names (['aws','azure','gcp']).
            scan_type: 'quick', 'standard', or 'deep'.

        Returns:
            Dict with scan results and summary.
        """
        self.start_time = datetime.utcnow()
        self.scan_logger.info(f"Starting {scan_type} cloud scan")

        # Detect available providers
        self.available_providers = self._detect_providers()
        if targets:
            self.available_providers = [
                p for p in self.available_providers
                if p in [t.lower() for t in targets]
            ]

        if not self.available_providers:
            self.scan_logger.warning("No cloud providers available")
            self.add_finding(
                severity='INFO',
                title='No Cloud Providers Detected',
                description=(
                    'No configured cloud CLI tools found. Install and '
                    'configure aws, az, or gcloud to enable cloud scanning.'
                ),
                affected_asset='localhost',
                finding_type='cloud_prerequisite',
                detection_method='cli_check',
            )
            self.end_time = datetime.utcnow()
            self.save_results()
            return self.get_summary()

        # --- AWS ---
        if 'aws' in self.available_providers:
            self.scan_logger.info("=== AWS Security Checks ===")
            self._check_aws_iam(scan_type)
            self.human_delay()
            self._check_aws_s3(scan_type)
            self.human_delay()

            if scan_type in ('standard', 'deep'):
                self._check_aws_security_groups(scan_type)
                self.human_delay()
                self._check_aws_logging(scan_type)
                self.human_delay()
                self._check_aws_encryption(scan_type)
                self.human_delay()

        # --- Azure ---
        if 'azure' in self.available_providers:
            self.scan_logger.info("=== Azure Security Checks ===")
            self._check_azure_identity(scan_type)
            self.human_delay()
            self._check_azure_storage(scan_type)
            self.human_delay()

            if scan_type in ('standard', 'deep'):
                self._check_azure_nsg(scan_type)
                self.human_delay()
                self._check_azure_logging(scan_type)
                self.human_delay()

        # --- GCP ---
        if 'gcp' in self.available_providers:
            self.scan_logger.info("=== GCP Security Checks ===")
            self._check_gcp_iam(scan_type)
            self.human_delay()
            self._check_gcp_storage(scan_type)
            self.human_delay()

            if scan_type in ('standard', 'deep'):
                self._check_gcp_firewall(scan_type)
                self.human_delay()
                self._check_gcp_logging(scan_type)
                self.human_delay()

        self.end_time = datetime.utcnow()
        self.save_results()

        summary = self.get_summary()
        self.scan_logger.info(
            f"Cloud scan complete: {summary['findings_count']} findings "
            f"across {self.available_providers}"
        )
        return summary

    # =======================================================================
    # AWS Checks
    # =======================================================================

    # -- IAM ----------------------------------------------------------------

    def _check_aws_iam(self, scan_type: str) -> None:
        """Check AWS IAM security configuration."""
        # Root account MFA
        summary = self._run_cli_json([
            'aws', 'iam', 'get-account-summary', '--output', 'json'
        ])
        if summary:
            smap = summary.get('SummaryMap', {})
            self.add_result('aws_iam_summary', smap, 'aws')

            if not smap.get('AccountMFAEnabled', 0):
                self.add_finding(
                    severity='CRITICAL',
                    title='AWS Root Account MFA Not Enabled',
                    description=(
                        'The AWS root account does not have MFA enabled. '
                        'Root has unrestricted access and should always '
                        'be protected with MFA.'
                    ),
                    affected_asset='aws:root',
                    finding_type='cloud_iam',
                    remediation=(
                        'Enable MFA on the root account immediately.'
                    ),
                    raw_data=smap,
                    detection_method='aws_cli',
                )

        # Credential report
        self._run_cli([
            'aws', 'iam', 'generate-credential-report',
            '--output', 'json'
        ])
        report = self._run_cli_json([
            'aws', 'iam', 'get-credential-report', '--output', 'json'
        ])
        if report and report.get('Content'):
            try:
                content = base64.b64decode(
                    report['Content']
                ).decode('utf-8')
                self._analyze_credential_report(content, scan_type)
            except Exception as exc:
                self.scan_logger.debug(
                    f"Credential report error: {exc}"
                )

        # Overly permissive policies
        if scan_type in ('standard', 'deep'):
            policies = self._run_cli_json([
                'aws', 'iam', 'list-policies', '--scope', 'Local',
                '--only-attached', '--output', 'json',
            ])
            if policies:
                self._check_aws_permissive_policies(
                    policies.get('Policies', []), scan_type
                )

    def _analyze_credential_report(self, csv_content: str,
                                   scan_type: str) -> None:
        """Analyze the IAM credential report CSV."""
        lines = csv_content.strip().split('\n')
        if len(lines) < 2:
            return
        headers = lines[0].split(',')
        old_keys: List[Dict] = []
        unused_accounts: List[Dict] = []

        for line in lines[1:]:
            fields = line.split(',')
            if len(fields) < len(headers):
                continue
            row = dict(zip(headers, fields))
            user = row.get('user', '')

            for key_num in ('1', '2'):
                active = row.get(
                    f'access_key_{key_num}_active', 'false'
                )
                last_rotated = row.get(
                    f'access_key_{key_num}_last_rotated', 'N/A'
                )
                if active == 'true' and last_rotated != 'N/A':
                    try:
                        rotated = datetime.strptime(
                            last_rotated[:10], '%Y-%m-%d'
                        )
                        age_days = (datetime.utcnow() - rotated).days
                        if age_days > 90:
                            old_keys.append({
                                'user': user, 'key': key_num,
                                'age_days': age_days,
                            })
                    except ValueError:
                        pass

            pw_enabled = row.get('password_enabled', 'false')
            pw_last_used = row.get('password_last_used', 'N/A')
            if pw_enabled == 'true' and pw_last_used in (
                    'N/A', 'no_information', 'not_supported'):
                unused_accounts.append({'user': user})

        if old_keys:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(old_keys)} AWS Access Keys Older Than 90 Days'
                ),
                description=(
                    f"{len(old_keys)} IAM access keys have not been "
                    f"rotated in over 90 days."
                ),
                affected_asset='aws:iam',
                finding_type='cloud_iam',
                remediation='Rotate access keys at least every 90 days.',
                raw_data=old_keys,
                detection_method='aws_cli',
            )
        if unused_accounts:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(unused_accounts)} AWS IAM Users With '
                    f'Unused Credentials'
                ),
                description=(
                    f"{len(unused_accounts)} IAM users have password "
                    f"credentials enabled but have never logged in."
                ),
                affected_asset='aws:iam',
                finding_type='cloud_iam',
                remediation='Disable or remove unused IAM credentials.',
                raw_data=unused_accounts,
                detection_method='aws_cli',
            )

    def _check_aws_permissive_policies(self, policies: List[Dict],
                                       scan_type: str) -> None:
        """Check for overly permissive IAM policies."""
        limit = (len(policies) if scan_type == 'deep'
                 else min(20, len(policies)))
        overly_permissive: List[Dict] = []

        for policy in policies[:limit]:
            arn = policy.get('Arn', '')
            version = policy.get('DefaultVersionId', 'v1')
            doc = self._run_cli_json([
                'aws', 'iam', 'get-policy-version',
                '--policy-arn', arn, '--version-id', version,
                '--output', 'json',
            ])
            if not doc:
                continue
            stmts = (doc.get('PolicyVersion', {})
                     .get('Document', {})
                     .get('Statement', []))
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if (stmt.get('Effect') == 'Allow' and
                        stmt.get('Action') == '*' and
                        stmt.get('Resource') == '*'):
                    overly_permissive.append({
                        'policy': policy.get('PolicyName', ''),
                        'arn': arn,
                    })
                    break

        if overly_permissive:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(overly_permissive)} Overly Permissive '
                    f'IAM Policies'
                ),
                description=(
                    f"{len(overly_permissive)} custom IAM policies grant "
                    f"'*' action on '*' resource (full admin)."
                ),
                affected_asset='aws:iam',
                finding_type='cloud_iam',
                remediation=(
                    'Apply least-privilege: scope actions and resources.'
                ),
                raw_data=overly_permissive,
                detection_method='aws_cli',
            )

    # -- S3 -----------------------------------------------------------------

    def _check_aws_s3(self, scan_type: str) -> None:
        """Check S3 bucket security."""
        buckets = self._run_cli_json([
            'aws', 's3api', 'list-buckets', '--output', 'json'
        ])
        if not buckets:
            return
        bucket_list = buckets.get('Buckets', [])
        self.add_result('aws_s3_buckets', {'count': len(bucket_list)}, 'aws')

        public_buckets: List[str] = []
        unencrypted: List[str] = []
        no_versioning: List[str] = []
        no_logging: List[str] = []
        limit = (len(bucket_list) if scan_type == 'deep'
                 else min(25, len(bucket_list)))

        for bucket in bucket_list[:limit]:
            name = bucket.get('Name', '')

            # Public access block
            pab = self._run_cli_json([
                'aws', 's3api', 'get-public-access-block',
                '--bucket', name, '--output', 'json'
            ])
            if pab:
                cfg = pab.get('PublicAccessBlockConfiguration', {})
                if not all([
                    cfg.get('BlockPublicAcls', False),
                    cfg.get('IgnorePublicAcls', False),
                    cfg.get('BlockPublicPolicy', False),
                    cfg.get('RestrictPublicBuckets', False),
                ]):
                    public_buckets.append(name)
            else:
                public_buckets.append(name)

            # Encryption
            enc = self._run_cli_json([
                'aws', 's3api', 'get-bucket-encryption',
                '--bucket', name, '--output', 'json'
            ])
            if not enc:
                unencrypted.append(name)

            # Versioning
            ver = self._run_cli_json([
                'aws', 's3api', 'get-bucket-versioning',
                '--bucket', name, '--output', 'json'
            ])
            if not ver or ver.get('Status') != 'Enabled':
                no_versioning.append(name)

            # Logging (standard+)
            if scan_type in ('standard', 'deep'):
                log = self._run_cli_json([
                    'aws', 's3api', 'get-bucket-logging',
                    '--bucket', name, '--output', 'json'
                ])
                if not log or not log.get('LoggingEnabled'):
                    no_logging.append(name)

        if public_buckets:
            self.add_finding(
                severity='CRITICAL',
                title=(
                    f'{len(public_buckets)} S3 Buckets Without Full '
                    f'Public Access Block'
                ),
                description=(
                    f"{len(public_buckets)} S3 buckets do not have all "
                    f"four public access block settings enabled."
                ),
                affected_asset='aws:s3',
                finding_type='cloud_storage',
                remediation='Enable S3 Block Public Access on all buckets.',
                raw_data=public_buckets,
                detection_method='aws_cli',
            )
        if unencrypted:
            self.add_finding(
                severity='HIGH',
                title=f'{len(unencrypted)} S3 Buckets Without Encryption',
                description=(
                    f"{len(unencrypted)} S3 buckets do not have default "
                    f"encryption configured."
                ),
                affected_asset='aws:s3',
                finding_type='cloud_encryption',
                remediation='Enable default SSE-S3 or SSE-KMS encryption.',
                raw_data=unencrypted,
                detection_method='aws_cli',
            )
        if no_versioning:
            self.add_finding(
                severity='MEDIUM',
                title=f'{len(no_versioning)} S3 Buckets Without Versioning',
                description=(
                    f"{len(no_versioning)} S3 buckets do not have versioning "
                    f"enabled, risking data loss."
                ),
                affected_asset='aws:s3',
                finding_type='cloud_storage',
                remediation='Enable versioning on critical buckets.',
                raw_data=no_versioning,
                detection_method='aws_cli',
            )
        if no_logging:
            self.add_finding(
                severity='MEDIUM',
                title=f'{len(no_logging)} S3 Buckets Without Access Logging',
                description=(
                    f"{len(no_logging)} S3 buckets do not have access "
                    f"logging enabled."
                ),
                affected_asset='aws:s3',
                finding_type='cloud_logging',
                remediation=(
                    'Enable S3 server access logging or CloudTrail '
                    'S3 data events.'
                ),
                raw_data=no_logging,
                detection_method='aws_cli',
            )

    # -- Security Groups ----------------------------------------------------

    def _check_aws_security_groups(self, scan_type: str) -> None:
        """Check EC2 security groups for overly permissive rules."""
        sgs = self._run_cli_json([
            'aws', 'ec2', 'describe-security-groups', '--output', 'json'
        ])
        if not sgs:
            return
        sg_list = sgs.get('SecurityGroups', [])
        self.add_result('aws_security_groups', {'count': len(sg_list)}, 'aws')

        open_to_world: List[Dict] = []
        open_ssh: List[Dict] = []
        open_rdp: List[Dict] = []

        for sg in sg_list:
            sg_id = sg.get('GroupId', '')
            sg_name = sg.get('GroupName', '')
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                proto = rule.get('IpProtocol', '-1')

                all_cidrs = (
                    [r.get('CidrIp', '') for r in rule.get('IpRanges', [])]
                    + [r.get('CidrIpv6', '') for r in rule.get('Ipv6Ranges', [])]
                )
                for cidr in all_cidrs:
                    if cidr not in ('0.0.0.0/0', '::/0'):
                        continue
                    entry = {
                        'sg_id': sg_id, 'sg_name': sg_name,
                        'from_port': from_port, 'to_port': to_port,
                        'protocol': proto, 'cidr': cidr,
                    }
                    if proto == '-1':
                        open_to_world.append(entry)
                    elif from_port <= 22 <= to_port:
                        open_ssh.append(entry)
                    elif from_port <= 3389 <= to_port:
                        open_rdp.append(entry)
                    else:
                        open_to_world.append(entry)

        if open_to_world:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(open_to_world)} Security Group Rules Open '
                    f'to 0.0.0.0/0'
                ),
                description=(
                    f"{len(open_to_world)} security group rules allow "
                    f"unrestricted inbound access from any IP."
                ),
                affected_asset='aws:ec2',
                finding_type='cloud_network',
                remediation='Restrict inbound rules to specific CIDR ranges.',
                raw_data=open_to_world,
                detection_method='aws_cli',
            )
        if open_ssh:
            self.add_finding(
                severity='CRITICAL',
                title=(
                    f'{len(open_ssh)} Security Groups With SSH Open to World'
                ),
                description=(
                    f"{len(open_ssh)} security groups allow SSH (port 22) "
                    f"from 0.0.0.0/0."
                ),
                affected_asset='aws:ec2',
                finding_type='cloud_network',
                remediation='Restrict SSH to known IP ranges or use SSM.',
                raw_data=open_ssh,
                detection_method='aws_cli',
            )
        if open_rdp:
            self.add_finding(
                severity='CRITICAL',
                title=(
                    f'{len(open_rdp)} Security Groups With RDP Open to World'
                ),
                description=(
                    f"{len(open_rdp)} security groups allow RDP (port 3389) "
                    f"from 0.0.0.0/0."
                ),
                affected_asset='aws:ec2',
                finding_type='cloud_network',
                remediation='Restrict RDP to known IP ranges or use a bastion.',
                raw_data=open_rdp,
                detection_method='aws_cli',
            )

    # -- Logging ------------------------------------------------------------

    def _check_aws_logging(self, scan_type: str) -> None:
        """Check AWS logging configuration."""
        trails = self._run_cli_json([
            'aws', 'cloudtrail', 'describe-trails', '--output', 'json'
        ])
        if trails:
            trail_list = trails.get('trailList', [])
            if not trail_list:
                self.add_finding(
                    severity='CRITICAL',
                    title='No CloudTrail Trails Configured',
                    description='No CloudTrail trails found in this region.',
                    affected_asset='aws:cloudtrail',
                    finding_type='cloud_logging',
                    remediation='Enable CloudTrail with multi-region logging.',
                    detection_method='aws_cli',
                )
            else:
                for trail in trail_list:
                    name = trail.get('Name', '')
                    status = self._run_cli_json([
                        'aws', 'cloudtrail', 'get-trail-status',
                        '--name', name, '--output', 'json'
                    ])
                    if status and not status.get('IsLogging', False):
                        self.add_finding(
                            severity='HIGH',
                            title=f'CloudTrail Not Logging: {name}',
                            description=(
                                f"Trail '{name}' exists but is not logging."
                            ),
                            affected_asset='aws:cloudtrail',
                            finding_type='cloud_logging',
                            remediation=(
                                f'Start logging: aws cloudtrail '
                                f'start-logging --name {name}'
                            ),
                            raw_data=status,
                            detection_method='aws_cli',
                        )
                    if not trail.get('IsMultiRegionTrail', False):
                        self.add_finding(
                            severity='MEDIUM',
                            title=f'CloudTrail Not Multi-Region: {name}',
                            description=(
                                f"Trail '{name}' is not configured for "
                                f"multi-region."
                            ),
                            affected_asset='aws:cloudtrail',
                            finding_type='cloud_logging',
                            remediation='Enable multi-region on the trail.',
                            raw_data=trail,
                            detection_method='aws_cli',
                        )

        # VPC Flow Logs (deep)
        if scan_type == 'deep':
            vpcs = self._run_cli_json([
                'aws', 'ec2', 'describe-vpcs', '--output', 'json'
            ])
            if vpcs:
                for vpc in vpcs.get('Vpcs', []):
                    vpc_id = vpc.get('VpcId', '')
                    fl = self._run_cli_json([
                        'aws', 'ec2', 'describe-flow-logs',
                        '--filter',
                        f'Name=resource-id,Values={vpc_id}',
                        '--output', 'json',
                    ])
                    if not fl or not fl.get('FlowLogs'):
                        self.add_finding(
                            severity='MEDIUM',
                            title=f'No VPC Flow Logs: {vpc_id}',
                            description=(
                                f"VPC '{vpc_id}' has no flow logs."
                            ),
                            affected_asset=f'aws:vpc:{vpc_id}',
                            finding_type='cloud_logging',
                            remediation='Enable VPC flow logs.',
                            detection_method='aws_cli',
                        )

    # -- Encryption ---------------------------------------------------------

    def _check_aws_encryption(self, scan_type: str) -> None:
        """Check AWS encryption settings."""
        ebs_enc = self._run_cli_json([
            'aws', 'ec2', 'get-ebs-encryption-by-default',
            '--output', 'json'
        ])
        if ebs_enc and not ebs_enc.get('EbsEncryptionByDefault', False):
            self.add_finding(
                severity='MEDIUM',
                title='EBS Default Encryption Not Enabled',
                description=(
                    'EBS volumes are not encrypted by default.'
                ),
                affected_asset='aws:ec2',
                finding_type='cloud_encryption',
                remediation='Enable EBS encryption by default.',
                raw_data=ebs_enc,
                detection_method='aws_cli',
            )

        if scan_type in ('standard', 'deep'):
            rds = self._run_cli_json([
                'aws', 'rds', 'describe-db-instances', '--output', 'json'
            ])
            if rds:
                for inst in rds.get('DBInstances', []):
                    db_id = inst.get('DBInstanceIdentifier', '')
                    if not inst.get('StorageEncrypted', False):
                        self.add_finding(
                            severity='HIGH',
                            title=f'Unencrypted RDS Instance: {db_id}',
                            description=(
                                f"RDS instance '{db_id}' is not encrypted."
                            ),
                            affected_asset=f'aws:rds:{db_id}',
                            finding_type='cloud_encryption',
                            remediation=(
                                'Create an encrypted snapshot and restore.'
                            ),
                            raw_data={'db_id': db_id},
                            detection_method='aws_cli',
                        )

        if scan_type == 'deep':
            snaps = self._run_cli_json([
                'aws', 'ec2', 'describe-snapshots',
                '--owner-ids', 'self', '--output', 'json'
            ])
            if snaps:
                unenc = [s for s in snaps.get('Snapshots', [])
                         if not s.get('Encrypted', False)]
                if unenc:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'{len(unenc)} Unencrypted EBS Snapshots',
                        description=(
                            f"{len(unenc)} EBS snapshots are not encrypted."
                        ),
                        affected_asset='aws:ec2',
                        finding_type='cloud_encryption',
                        remediation='Copy snapshots with encryption enabled.',
                        raw_data={'count': len(unenc)},
                        detection_method='aws_cli',
                    )

    # =======================================================================
    # Azure Checks
    # =======================================================================

    def _check_azure_storage(self, scan_type: str) -> None:
        """Check Azure Storage account security."""
        accounts = self._run_cli_json([
            'az', 'storage', 'account', 'list', '-o', 'json'
        ])
        if not accounts:
            return
        self.add_result('azure_storage', {'count': len(accounts)}, 'azure')

        for acct in accounts:
            name = acct.get('name', '')
            if acct.get('allowBlobPublicAccess', False):
                self.add_finding(
                    severity='HIGH',
                    title=f'Azure Storage Public Blob Access: {name}',
                    description=(
                        f"Storage account '{name}' allows public blob access."
                    ),
                    affected_asset=f'azure:storage:{name}',
                    finding_type='cloud_storage',
                    remediation='Disable public blob access.',
                    raw_data={'name': name},
                    detection_method='azure_cli',
                )
            if not acct.get('enableHttpsTrafficOnly', True):
                self.add_finding(
                    severity='HIGH',
                    title=f'Azure Storage HTTP Allowed: {name}',
                    description=(
                        f"Storage account '{name}' allows non-HTTPS traffic."
                    ),
                    affected_asset=f'azure:storage:{name}',
                    finding_type='cloud_encryption',
                    remediation='Enable HTTPS-only on the storage account.',
                    raw_data={'name': name},
                    detection_method='azure_cli',
                )
            tls = acct.get('minimumTlsVersion', '')
            if tls and tls < 'TLS1_2':
                self.add_finding(
                    severity='MEDIUM',
                    title=f'Azure Storage Weak TLS: {name}',
                    description=(
                        f"Storage account '{name}' allows TLS below 1.2."
                    ),
                    affected_asset=f'azure:storage:{name}',
                    finding_type='cloud_encryption',
                    remediation='Set minimum TLS version to TLS1_2.',
                    raw_data={'name': name, 'tls': tls},
                    detection_method='azure_cli',
                )

    def _check_azure_identity(self, scan_type: str) -> None:
        """Check Azure AD / Entra ID security."""
        users = self._run_cli_json([
            'az', 'ad', 'user', 'list', '--query',
            '[].{upn:userPrincipalName,accountEnabled:accountEnabled}',
            '-o', 'json',
        ])
        if users:
            enabled = sum(1 for u in users if u.get('accountEnabled'))
            self.add_result(
                'azure_ad_users',
                {'total': len(users), 'enabled': enabled}, 'azure',
            )

        if scan_type in ('standard', 'deep'):
            ca = self._run_cli_json([
                'az', 'rest', '--method', 'GET', '--uri',
                'https://graph.microsoft.com/v1.0/identity/'
                'conditionalAccess/policies',
                '-o', 'json',
            ])
            if ca:
                policies = ca.get('value', [])
                enabled_ca = [p for p in policies
                              if p.get('state') == 'enabled']
                self.add_result(
                    'azure_conditional_access',
                    {'total': len(policies), 'enabled': len(enabled_ca)},
                    'azure',
                )
                if not enabled_ca:
                    self.add_finding(
                        severity='HIGH',
                        title='No Enabled Conditional Access Policies',
                        description=(
                            'No conditional access policies are enabled. '
                            'MFA and access controls are not enforced.'
                        ),
                        affected_asset='azure:entra',
                        finding_type='cloud_iam',
                        remediation=(
                            'Create and enable conditional access policies.'
                        ),
                        detection_method='azure_cli',
                    )
            else:
                self.add_finding(
                    severity='INFO',
                    title='Cannot Query Conditional Access Policies',
                    description=(
                        'Insufficient permissions to read conditional access.'
                    ),
                    affected_asset='azure:entra',
                    finding_type='cloud_iam',
                    detection_method='azure_cli',
                )

    def _check_azure_nsg(self, scan_type: str) -> None:
        """Check Azure Network Security Groups."""
        nsgs = self._run_cli_json([
            'az', 'network', 'nsg', 'list', '-o', 'json'
        ])
        if not nsgs:
            return
        self.add_result('azure_nsgs', {'count': len(nsgs)}, 'azure')

        any_any: List[Dict] = []
        open_mgmt: List[Dict] = []

        for nsg in nsgs:
            nsg_name = nsg.get('name', '')
            for rule in nsg.get('securityRules', []):
                if rule.get('access') != 'Allow':
                    continue
                if rule.get('direction') != 'Inbound':
                    continue
                src = rule.get('sourceAddressPrefix', '')
                port = rule.get('destinationPortRange', '')
                proto = rule.get('protocol', '')

                if src not in ('*', 'Internet', '0.0.0.0/0'):
                    continue

                entry = {
                    'nsg': nsg_name, 'rule': rule.get('name', ''),
                    'port': port, 'protocol': proto,
                }
                if port == '*' or proto == '*':
                    any_any.append(entry)
                elif port in ('22', '3389'):
                    open_mgmt.append(entry)

        if any_any:
            self.add_finding(
                severity='CRITICAL',
                title=f'{len(any_any)} NSG Any-Any Inbound Rules',
                description=(
                    f"{len(any_any)} NSG rules allow all traffic from "
                    f"any source."
                ),
                affected_asset='azure:network',
                finding_type='cloud_network',
                remediation='Restrict NSG rules to specific ports and sources.',
                raw_data=any_any,
                detection_method='azure_cli',
            )
        if open_mgmt:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(open_mgmt)} NSG Rules With SSH/RDP Open '
                    f'to Internet'
                ),
                description=(
                    f"{len(open_mgmt)} NSG rules allow SSH or RDP from "
                    f"the internet."
                ),
                affected_asset='azure:network',
                finding_type='cloud_network',
                remediation='Use Azure Bastion or restrict to known IPs.',
                raw_data=open_mgmt,
                detection_method='azure_cli',
            )

    def _check_azure_logging(self, scan_type: str) -> None:
        """Check Azure diagnostic and activity logging."""
        alerts = self._run_cli_json([
            'az', 'monitor', 'activity-log', 'alert', 'list', '-o', 'json'
        ])
        if alerts is not None:
            enabled = [a for a in alerts if a.get('enabled', False)]
            self.add_result(
                'azure_activity_alerts',
                {'total': len(alerts), 'enabled': len(enabled)}, 'azure',
            )
            if not enabled:
                self.add_finding(
                    severity='MEDIUM',
                    title='No Activity Log Alerts Configured',
                    description=(
                        'No Azure activity log alerts are enabled.'
                    ),
                    affected_asset='azure:monitor',
                    finding_type='cloud_logging',
                    remediation=(
                        'Configure activity log alerts for critical ops.'
                    ),
                    detection_method='azure_cli',
                )

        if scan_type == 'deep':
            sub = self._run_cli_json([
                'az', 'account', 'show', '-o', 'json'
            ])
            if sub:
                sub_id = sub.get('id', '')
                diag = self._run_cli_json([
                    'az', 'monitor', 'diagnostic-settings',
                    'subscription', 'list',
                    '--subscription', sub_id, '-o', 'json',
                ])
                if diag is not None:
                    items = (diag.get('value', diag)
                             if isinstance(diag, dict) else diag)
                    if not items:
                        self.add_finding(
                            severity='MEDIUM',
                            title='No Subscription Diagnostic Settings',
                            description=(
                                'No diagnostic settings on the subscription.'
                            ),
                            affected_asset=f'azure:subscription:{sub_id}',
                            finding_type='cloud_logging',
                            remediation=(
                                'Configure diagnostic settings to a '
                                'Log Analytics workspace.'
                            ),
                            detection_method='azure_cli',
                        )

    # =======================================================================
    # GCP Checks
    # =======================================================================

    def _check_gcp_storage(self, scan_type: str) -> None:
        """Check GCP Cloud Storage bucket security."""
        buckets = self._run_cli_json([
            'gcloud', 'storage', 'buckets', 'list', '--format=json'
        ])
        if not buckets:
            return
        self.add_result('gcp_buckets', {'count': len(buckets)}, 'gcp')

        public_buckets: List[Dict] = []
        no_uniform: List[str] = []

        for bucket in buckets:
            name = bucket.get('name', '')
            iam = self._run_cli_json([
                'gcloud', 'storage', 'buckets', 'get-iam-policy',
                f'gs://{name}', '--format=json',
            ])
            if iam:
                for binding in iam.get('bindings', []):
                    members = binding.get('members', [])
                    if ('allUsers' in members or
                            'allAuthenticatedUsers' in members):
                        public_buckets.append({
                            'bucket': name,
                            'role': binding.get('role', ''),
                        })
                        break

            ubl = bucket.get('iamConfiguration', {}).get(
                'uniformBucketLevelAccess', {}
            )
            if not ubl.get('enabled', False):
                no_uniform.append(name)

        if public_buckets:
            self.add_finding(
                severity='CRITICAL',
                title=(
                    f'{len(public_buckets)} GCP Buckets Publicly Accessible'
                ),
                description=(
                    f"{len(public_buckets)} buckets grant access to "
                    f"allUsers or allAuthenticatedUsers."
                ),
                affected_asset='gcp:storage',
                finding_type='cloud_storage',
                remediation=(
                    'Remove allUsers / allAuthenticatedUsers from IAM.'
                ),
                raw_data=public_buckets,
                detection_method='gcloud_cli',
            )
        if no_uniform:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(no_uniform)} GCP Buckets Without Uniform Access'
                ),
                description=(
                    f"{len(no_uniform)} buckets do not enforce uniform "
                    f"bucket-level access."
                ),
                affected_asset='gcp:storage',
                finding_type='cloud_storage',
                remediation='Enable uniform bucket-level access.',
                raw_data=no_uniform,
                detection_method='gcloud_cli',
            )

    def _check_gcp_iam(self, scan_type: str) -> None:
        """Check GCP IAM configuration."""
        project = self._run_cli([
            'gcloud', 'config', 'get-value', 'project'
        ])
        if not project:
            return

        # Service account user-managed keys
        sa_list = self._run_cli_json([
            'gcloud', 'iam', 'service-accounts', 'list', '--format=json'
        ])
        if sa_list:
            with_keys: List[Dict] = []
            for sa in sa_list:
                email = sa.get('email', '')
                keys = self._run_cli_json([
                    'gcloud', 'iam', 'service-accounts', 'keys', 'list',
                    '--iam-account', email,
                    '--managed-by=user', '--format=json',
                ])
                if keys:
                    with_keys.append({
                        'service_account': email,
                        'key_count': len(keys),
                    })
            if with_keys:
                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'{len(with_keys)} Service Accounts With '
                        f'User-Managed Keys'
                    ),
                    description=(
                        f"{len(with_keys)} service accounts have "
                        f"user-managed keys that do not auto-rotate."
                    ),
                    affected_asset=f'gcp:iam:{project}',
                    finding_type='cloud_iam',
                    remediation=(
                        'Use workload identity federation instead of SA keys.'
                    ),
                    raw_data=with_keys,
                    detection_method='gcloud_cli',
                )

        # Primitive roles
        iam_policy = self._run_cli_json([
            'gcloud', 'projects', 'get-iam-policy', project, '--format=json'
        ])
        if iam_policy:
            prim: List[Dict] = []
            for binding in iam_policy.get('bindings', []):
                role = binding.get('role', '')
                if role in ('roles/owner', 'roles/editor'):
                    user_m = [m for m in binding.get('members', [])
                              if m.startswith(('user:', 'group:'))]
                    if user_m:
                        prim.append({'role': role, 'members': user_m})
            if prim:
                self.add_finding(
                    severity='HIGH',
                    title='GCP Primitive Roles In Use',
                    description=(
                        'Primitive roles (Owner/Editor) are assigned to '
                        'users or groups.'
                    ),
                    affected_asset=f'gcp:iam:{project}',
                    finding_type='cloud_iam',
                    remediation=(
                        'Replace primitive roles with predefined or '
                        'custom roles.'
                    ),
                    raw_data=prim,
                    detection_method='gcloud_cli',
                )

    def _check_gcp_firewall(self, scan_type: str) -> None:
        """Check GCP firewall rules."""
        rules = self._run_cli_json([
            'gcloud', 'compute', 'firewall-rules', 'list', '--format=json'
        ])
        if not rules:
            return
        self.add_result('gcp_firewall', {'count': len(rules)}, 'gcp')

        permissive: List[Dict] = []
        open_mgmt: List[Dict] = []

        for rule in rules:
            if rule.get('direction') != 'INGRESS' or rule.get('disabled'):
                continue
            if '0.0.0.0/0' not in rule.get('sourceRanges', []):
                continue
            name = rule.get('name', '')
            for ar in rule.get('allowed', []):
                proto = ar.get('IPProtocol', '')
                ports = ar.get('ports', [])
                if not ports:
                    permissive.append({
                        'rule': name, 'protocol': proto, 'ports': 'all',
                    })
                else:
                    for p in ports:
                        if p in ('22', '3389'):
                            open_mgmt.append({'rule': name, 'port': p})
                        elif '-' in str(p):
                            permissive.append({
                                'rule': name, 'protocol': proto, 'ports': p,
                            })

        if permissive:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(permissive)} GCP Firewall Rules Open to 0.0.0.0/0'
                ),
                description=(
                    f"{len(permissive)} rules allow broad inbound internet "
                    f"access."
                ),
                affected_asset='gcp:compute',
                finding_type='cloud_network',
                remediation='Restrict source ranges to specific CIDRs.',
                raw_data=permissive,
                detection_method='gcloud_cli',
            )
        if open_mgmt:
            self.add_finding(
                severity='CRITICAL',
                title=(
                    f'{len(open_mgmt)} GCP Firewall Rules With SSH/RDP '
                    f'Open to World'
                ),
                description=(
                    f"{len(open_mgmt)} rules allow SSH or RDP from 0.0.0.0/0."
                ),
                affected_asset='gcp:compute',
                finding_type='cloud_network',
                remediation='Use IAP tunneling instead of open SSH/RDP.',
                raw_data=open_mgmt,
                detection_method='gcloud_cli',
            )

    def _check_gcp_logging(self, scan_type: str) -> None:
        """Check GCP logging configuration."""
        project = self._run_cli([
            'gcloud', 'config', 'get-value', 'project'
        ])
        if not project:
            return

        iam_policy = self._run_cli_json([
            'gcloud', 'projects', 'get-iam-policy', project, '--format=json'
        ])
        if iam_policy:
            ac = iam_policy.get('auditConfigs', [])
            if not ac:
                self.add_finding(
                    severity='MEDIUM',
                    title='GCP Audit Logging Not Configured',
                    description='No audit log config found on the project.',
                    affected_asset=f'gcp:project:{project}',
                    finding_type='cloud_logging',
                    remediation='Configure Data Access audit logs.',
                    detection_method='gcloud_cli',
                )
            else:
                self.add_result(
                    'gcp_audit_config', {'configs': len(ac)}, 'gcp',
                )

        if scan_type == 'deep':
            subnets = self._run_cli_json([
                'gcloud', 'compute', 'networks', 'subnets', 'list',
                '--format=json',
            ])
            if subnets:
                no_fl = [
                    s.get('name', '') for s in subnets
                    if not s.get('logConfig', {}).get('enable', False)
                ]
                if no_fl:
                    self.add_finding(
                        severity='MEDIUM',
                        title=(
                            f'{len(no_fl)} GCP Subnets Without VPC Flow Logs'
                        ),
                        description=(
                            f"{len(no_fl)} subnets lack VPC flow logs."
                        ),
                        affected_asset=f'gcp:network:{project}',
                        finding_type='cloud_logging',
                        remediation='Enable VPC flow logs on all subnets.',
                        raw_data=no_fl,
                        detection_method='gcloud_cli',
                    )


if __name__ == '__main__':
    scanner = CloudScanner()
    print(f"Cloud Scanner initialized: {scanner.SCANNER_NAME}")
    providers = scanner._detect_providers()
    print(f"Available providers: {providers}")
