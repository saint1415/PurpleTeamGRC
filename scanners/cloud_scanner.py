#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Cloud Security Scanner
AWS, Azure, GCP security configuration assessment.
DISABLED in portable deployment mode (no cloud creds on USB).
All API calls are read-only (no modifications to cloud resources).
Warns: "Cloud credentials should use read-only IAM roles"
"""

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from platform_detect import get_platform_info
except ImportError:
    get_platform_info = None

# Optional cloud SDKs -- graceful degradation to CLI fallback
_boto3 = None
_azure_identity = None
_azure_mgmt_resource = None
_azure_mgmt_network = None
_azure_mgmt_storage = None
_azure_mgmt_sql = None
_google_cloud_resource_manager = None
_google_cloud_compute = None
_google_cloud_storage = None
_google_cloud_sql = None

try:
    import boto3 as _boto3
except ImportError:
    pass

try:
    import azure.identity as _azure_identity
    import azure.mgmt.resource as _azure_mgmt_resource
except ImportError:
    pass

try:
    import azure.mgmt.network as _azure_mgmt_network
except ImportError:
    pass

try:
    import azure.mgmt.storage as _azure_mgmt_storage
except ImportError:
    pass

try:
    import azure.mgmt.sql as _azure_mgmt_sql
except ImportError:
    pass

try:
    import google.cloud.resourcemanager as _google_cloud_resource_manager
except ImportError:
    pass

try:
    import google.cloud.compute as _google_cloud_compute
except ImportError:
    pass

try:
    import google.cloud.storage as _google_cloud_storage
except ImportError:
    pass

try:
    import google.cloud.sql as _google_cloud_sql
except ImportError:
    pass


class CloudScanner(BaseScanner):
    """Cloud security assessment scanner for AWS, Azure, and GCP."""

    SCANNER_NAME = "cloud"
    SCANNER_DESCRIPTION = "Cloud security assessment (AWS/Azure/GCP)"

    # CVSS score mapping for cloud findings
    CVSS_MAP = {
        'CRITICAL': 9.5,
        'HIGH': 7.5,
        'MEDIUM': 5.5,
        'LOW': 3.0,
        'INFO': 0.0,
    }

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.aws_available = False
        self.azure_available = False
        self.gcp_available = False
        self._detect_providers()

    # ------------------------------------------------------------------
    # Provider detection
    # ------------------------------------------------------------------

    def _detect_providers(self):
        """Detect which cloud providers are accessible (SDK or CLI)."""
        # AWS: boto3 or aws CLI
        if _boto3 is not None:
            self.aws_available = True
        elif shutil.which('aws'):
            self.aws_available = True

        # Azure: azure-identity SDK or az CLI
        if _azure_identity is not None:
            self.azure_available = True
        elif shutil.which('az'):
            self.azure_available = True

        # GCP: google-cloud SDK or gcloud CLI
        if _google_cloud_resource_manager is not None:
            self.gcp_available = True
        elif shutil.which('gcloud'):
            self.gcp_available = True

    # ------------------------------------------------------------------
    # CLI helpers
    # ------------------------------------------------------------------

    def _run_aws_cli(self, args: List[str]) -> Optional[dict]:
        """Run AWS CLI command, return parsed JSON or None."""
        cmd = ['aws'] + args + ['--output', 'json']
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _run_az_cli(self, args: List[str]) -> Optional[dict]:
        """Run Azure CLI command, return parsed JSON or None."""
        cmd = ['az'] + args + ['--output', 'json']
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _run_gcloud_cli(self, args: List[str]) -> Optional[dict]:
        """Run gcloud CLI command, return parsed JSON or None."""
        cmd = ['gcloud'] + args + ['--format=json']
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _run_gsutil(self, args: List[str]) -> Optional[str]:
        """Run gsutil command, return stdout or None."""
        cmd = ['gsutil'] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    def scan(self, targets: Optional[List[str]] = None, **kwargs) -> Dict:
        """
        Execute cloud security assessment.

        Args:
            targets: Optional list of provider names to scan ('aws', 'azure', 'gcp').
                     If None, all detected providers are scanned.
        """
        self.start_time = datetime.utcnow()

        results: Dict = {
            'targets': targets,
            'providers_scanned': [],
            'providers_skipped': [],
            'checks': [],
            'summary': {},
        }

        # ---- Check deployment mode (portable = refuse) ----
        if get_platform_info is not None:
            try:
                pi = get_platform_info()
                if pi.is_portable:
                    self.scan_logger.error(
                        "Cloud scanning DISABLED in portable deployment mode"
                    )
                    return {
                        'error': 'Cloud scanning is disabled in portable mode. '
                                 'Cloud credentials should not be stored on USB media.',
                        'deployment_mode': 'portable',
                    }
            except Exception:
                pass

        # ---- IAM role warning ----
        self.scan_logger.warning(
            "Cloud credentials should use read-only IAM roles. "
            "This scanner performs read-only operations only."
        )

        # ---- Determine which providers to scan ----
        if targets:
            requested = [t.lower().strip() for t in targets]
        else:
            requested = []
            if self.aws_available:
                requested.append('aws')
            if self.azure_available:
                requested.append('azure')
            if self.gcp_available:
                requested.append('gcp')

        if not requested:
            self.scan_logger.error("No cloud providers detected")
            return {
                'error': 'No cloud providers available. '
                         'Install boto3 / azure-identity / google-cloud SDK, '
                         'or ensure aws / az / gcloud CLI is on PATH.',
            }

        # ---- Run checks per provider ----
        for provider in requested:
            if provider == 'aws' and self.aws_available:
                self.scan_logger.info("Starting AWS security checks")
                results['providers_scanned'].append('aws')
                results['checks'].extend(self._scan_aws())
                self.human_delay()

            elif provider == 'azure' and self.azure_available:
                self.scan_logger.info("Starting Azure security checks")
                results['providers_scanned'].append('azure')
                results['checks'].extend(self._scan_azure())
                self.human_delay()

            elif provider == 'gcp' and self.gcp_available:
                self.scan_logger.info("Starting GCP security checks")
                results['providers_scanned'].append('gcp')
                results['checks'].extend(self._scan_gcp())
                self.human_delay()

            else:
                results['providers_skipped'].append({
                    'provider': provider,
                    'reason': 'Not available (SDK/CLI not detected)',
                })

        # ---- Summary ----
        results['summary'] = self._generate_summary(results)

        self.end_time = datetime.utcnow()
        self.save_results()
        return results

    # ==================================================================
    # AWS Checks
    # ==================================================================

    def _scan_aws(self) -> List[Dict]:
        """Run all AWS security checks."""
        checks: List[Dict] = []
        checks.extend(self._aws_check_s3_public_buckets())
        checks.extend(self._aws_check_iam_mfa())
        checks.extend(self._aws_check_security_groups())
        checks.extend(self._aws_check_cloudtrail())
        checks.extend(self._aws_check_old_access_keys())
        checks.extend(self._aws_check_unencrypted_ebs())
        return checks

    def _aws_check_s3_public_buckets(self) -> List[Dict]:
        """CRITICAL: Detect S3 buckets with public access."""
        checks: List[Dict] = []
        self.scan_logger.info("AWS: Checking S3 bucket public access")

        bucket_data = self._run_aws_cli(['s3api', 'list-buckets'])
        if not bucket_data or 'Buckets' not in bucket_data:
            return checks

        for bucket in bucket_data.get('Buckets', []):
            name = bucket.get('Name', '')

            # Check public access block
            pab = self._run_aws_cli([
                's3api', 'get-public-access-block', '--bucket', name
            ])
            block_cfg = (pab or {}).get('PublicAccessBlockConfiguration', {})
            all_blocked = (
                block_cfg.get('BlockPublicAcls', False)
                and block_cfg.get('IgnorePublicAcls', False)
                and block_cfg.get('BlockPublicPolicy', False)
                and block_cfg.get('RestrictPublicBuckets', False)
            )

            if not all_blocked:
                # Double-check with ACL
                acl = self._run_aws_cli(['s3api', 'get-bucket-acl', '--bucket', name])
                public_grants = []
                for grant in (acl or {}).get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        public_grants.append(grant.get('Permission', 'unknown'))

                if public_grants:
                    self.add_finding(
                        severity='CRITICAL',
                        title=f"[Cloud/AWS] S3 bucket publicly accessible: {name}",
                        description=(
                            f"S3 bucket '{name}' has public grants: "
                            f"{', '.join(public_grants)}. "
                            "Public access block is not fully enabled."
                        ),
                        affected_asset=f"aws:s3:{name}",
                        finding_type='cloud_misconfiguration',
                        cvss_score=self.CVSS_MAP['CRITICAL'],
                        remediation=(
                            "Enable S3 Block Public Access at both the account and "
                            "bucket level. Review and remove public ACL grants."
                        ),
                        detection_method='cloud_api_check',
                    )
                    checks.append({
                        'provider': 'aws', 'check': 's3_public_bucket',
                        'resource': name, 'status': 'CRITICAL',
                        'detail': f"Public grants: {public_grants}",
                    })
                elif not all_blocked:
                    # Block Public Access not fully enabled but no public ACL grants
                    self.add_finding(
                        severity='MEDIUM',
                        title=f"[Cloud/AWS] S3 Block Public Access not fully enabled: {name}",
                        description=(
                            f"S3 bucket '{name}' does not have all four Block Public "
                            "Access settings enabled."
                        ),
                        affected_asset=f"aws:s3:{name}",
                        finding_type='cloud_misconfiguration',
                        cvss_score=self.CVSS_MAP['MEDIUM'],
                        remediation="Enable all four S3 Block Public Access settings.",
                        detection_method='cloud_api_check',
                    )
                    checks.append({
                        'provider': 'aws', 'check': 's3_block_public_access',
                        'resource': name, 'status': 'MEDIUM',
                    })

        return checks

    def _aws_check_iam_mfa(self) -> List[Dict]:
        """HIGH: Detect IAM users without MFA enabled."""
        checks: List[Dict] = []
        self.scan_logger.info("AWS: Checking IAM users for MFA")

        users_data = self._run_aws_cli(['iam', 'list-users'])
        if not users_data or 'Users' not in users_data:
            return checks

        for user in users_data.get('Users', []):
            username = user.get('UserName', '')
            mfa_data = self._run_aws_cli([
                'iam', 'list-mfa-devices', '--user-name', username
            ])
            mfa_devices = (mfa_data or {}).get('MFADevices', [])

            if not mfa_devices:
                self.add_finding(
                    severity='HIGH',
                    title=f"[Cloud/AWS] IAM user without MFA: {username}",
                    description=(
                        f"IAM user '{username}' has no MFA device configured. "
                        "Accounts without MFA are vulnerable to credential compromise."
                    ),
                    affected_asset=f"aws:iam:user/{username}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP['HIGH'],
                    remediation="Enable MFA for all IAM users, especially those with console access.",
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'aws', 'check': 'iam_no_mfa',
                    'resource': username, 'status': 'HIGH',
                })

        return checks

    def _aws_check_security_groups(self) -> List[Dict]:
        """HIGH: Detect security groups allowing 0.0.0.0/0 ingress."""
        checks: List[Dict] = []
        self.scan_logger.info("AWS: Checking security groups for wide-open ingress")

        sg_data = self._run_aws_cli(['ec2', 'describe-security-groups'])
        if not sg_data or 'SecurityGroups' not in sg_data:
            return checks

        for sg in sg_data.get('SecurityGroups', []):
            sg_id = sg.get('GroupId', '')
            sg_name = sg.get('GroupName', '')

            for perm in sg.get('IpPermissions', []):
                from_port = perm.get('FromPort', 0)
                to_port = perm.get('ToPort', 65535)
                protocol = perm.get('IpProtocol', '-1')

                for ip_range in perm.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr == '0.0.0.0/0':
                        port_desc = (
                            'all ports' if protocol == '-1'
                            else f"port {from_port}" if from_port == to_port
                            else f"ports {from_port}-{to_port}"
                        )
                        self.add_finding(
                            severity='HIGH',
                            title=f"[Cloud/AWS] Security group open to 0.0.0.0/0: {sg_id}",
                            description=(
                                f"Security group '{sg_name}' ({sg_id}) allows ingress "
                                f"from 0.0.0.0/0 on {port_desc} ({protocol})."
                            ),
                            affected_asset=f"aws:ec2:sg/{sg_id}",
                            finding_type='cloud_misconfiguration',
                            cvss_score=self.CVSS_MAP['HIGH'],
                            remediation=(
                                "Restrict security group ingress rules to specific "
                                "source IP ranges. Remove 0.0.0.0/0 rules."
                            ),
                            detection_method='cloud_api_check',
                        )
                        checks.append({
                            'provider': 'aws', 'check': 'sg_wide_open',
                            'resource': sg_id, 'status': 'HIGH',
                            'detail': f"0.0.0.0/0 on {port_desc}",
                        })

                for ip_range in perm.get('Ipv6Ranges', []):
                    cidr6 = ip_range.get('CidrIpv6', '')
                    if cidr6 == '::/0':
                        self.add_finding(
                            severity='HIGH',
                            title=f"[Cloud/AWS] Security group open to ::/0: {sg_id}",
                            description=(
                                f"Security group '{sg_name}' ({sg_id}) allows IPv6 "
                                f"ingress from ::/0."
                            ),
                            affected_asset=f"aws:ec2:sg/{sg_id}",
                            finding_type='cloud_misconfiguration',
                            cvss_score=self.CVSS_MAP['HIGH'],
                            remediation="Restrict IPv6 ingress to specific source ranges.",
                            detection_method='cloud_api_check',
                        )
                        checks.append({
                            'provider': 'aws', 'check': 'sg_wide_open_ipv6',
                            'resource': sg_id, 'status': 'HIGH',
                        })

        return checks

    def _aws_check_cloudtrail(self) -> List[Dict]:
        """HIGH: Detect disabled or non-logging CloudTrail trails."""
        checks: List[Dict] = []
        self.scan_logger.info("AWS: Checking CloudTrail status")

        trails_data = self._run_aws_cli(['cloudtrail', 'describe-trails'])
        if not trails_data or 'trailList' not in trails_data:
            # No trails at all is a finding
            self.add_finding(
                severity='HIGH',
                title="[Cloud/AWS] No CloudTrail trails configured",
                description="No CloudTrail trails were found. AWS API activity is not being logged.",
                affected_asset="aws:cloudtrail",
                finding_type='cloud_misconfiguration',
                cvss_score=self.CVSS_MAP['HIGH'],
                remediation="Create a CloudTrail trail that logs to an S3 bucket with encryption.",
                detection_method='cloud_api_check',
            )
            checks.append({
                'provider': 'aws', 'check': 'cloudtrail_missing',
                'resource': 'account', 'status': 'HIGH',
            })
            return checks

        for trail in trails_data.get('trailList', []):
            trail_name = trail.get('Name', '')
            trail_arn = trail.get('TrailARN', '')

            status = self._run_aws_cli([
                'cloudtrail', 'get-trail-status', '--name', trail_name
            ])
            if status and not status.get('IsLogging', False):
                self.add_finding(
                    severity='HIGH',
                    title=f"[Cloud/AWS] CloudTrail logging disabled: {trail_name}",
                    description=(
                        f"CloudTrail trail '{trail_name}' exists but logging is disabled. "
                        "API activity is not being recorded."
                    ),
                    affected_asset=f"aws:cloudtrail:{trail_arn}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP['HIGH'],
                    remediation="Enable logging on the CloudTrail trail.",
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'aws', 'check': 'cloudtrail_disabled',
                    'resource': trail_name, 'status': 'HIGH',
                })

        return checks

    def _aws_check_old_access_keys(self) -> List[Dict]:
        """MEDIUM: Detect IAM access keys older than 90 days."""
        checks: List[Dict] = []
        self.scan_logger.info("AWS: Checking for old IAM access keys")

        users_data = self._run_aws_cli(['iam', 'list-users'])
        if not users_data or 'Users' not in users_data:
            return checks

        now = datetime.now(timezone.utc)

        for user in users_data.get('Users', []):
            username = user.get('UserName', '')
            keys_data = self._run_aws_cli([
                'iam', 'list-access-keys', '--user-name', username
            ])
            if not keys_data:
                continue

            for key_meta in keys_data.get('AccessKeyMetadata', []):
                key_id = key_meta.get('AccessKeyId', '')
                create_date_str = key_meta.get('CreateDate', '')
                key_status = key_meta.get('Status', 'Inactive')

                if key_status != 'Active':
                    continue

                try:
                    # AWS returns ISO 8601 with Z
                    create_date = datetime.fromisoformat(
                        create_date_str.replace('Z', '+00:00')
                    )
                    age_days = (now - create_date).days
                except (ValueError, TypeError):
                    continue

                if age_days > 90:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f"[Cloud/AWS] Old access key ({age_days}d): {username}/{key_id}",
                        description=(
                            f"IAM user '{username}' has active access key '{key_id}' "
                            f"that is {age_days} days old (threshold: 90 days)."
                        ),
                        affected_asset=f"aws:iam:user/{username}",
                        finding_type='cloud_misconfiguration',
                        cvss_score=self.CVSS_MAP['MEDIUM'],
                        remediation="Rotate access keys that are older than 90 days.",
                        detection_method='cloud_api_check',
                    )
                    checks.append({
                        'provider': 'aws', 'check': 'old_access_key',
                        'resource': f"{username}/{key_id}",
                        'status': 'MEDIUM',
                        'detail': f"{age_days} days old",
                    })

        return checks

    def _aws_check_unencrypted_ebs(self) -> List[Dict]:
        """MEDIUM: Detect unencrypted EBS volumes."""
        checks: List[Dict] = []
        self.scan_logger.info("AWS: Checking for unencrypted EBS volumes")

        vol_data = self._run_aws_cli(['ec2', 'describe-volumes'])
        if not vol_data or 'Volumes' not in vol_data:
            return checks

        for vol in vol_data.get('Volumes', []):
            vol_id = vol.get('VolumeId', '')
            encrypted = vol.get('Encrypted', False)
            state = vol.get('State', '')

            if not encrypted:
                attachments = vol.get('Attachments', [])
                instance_id = (
                    attachments[0].get('InstanceId', 'unattached')
                    if attachments else 'unattached'
                )
                self.add_finding(
                    severity='MEDIUM',
                    title=f"[Cloud/AWS] Unencrypted EBS volume: {vol_id}",
                    description=(
                        f"EBS volume '{vol_id}' (state: {state}, attached to: "
                        f"{instance_id}) is not encrypted at rest."
                    ),
                    affected_asset=f"aws:ec2:volume/{vol_id}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP['MEDIUM'],
                    remediation=(
                        "Enable EBS encryption by default for the region. "
                        "Migrate existing volumes to encrypted copies."
                    ),
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'aws', 'check': 'ebs_unencrypted',
                    'resource': vol_id, 'status': 'MEDIUM',
                })

        return checks

    # ==================================================================
    # Azure Checks
    # ==================================================================

    def _scan_azure(self) -> List[Dict]:
        """Run all Azure security checks."""
        checks: List[Dict] = []
        checks.extend(self._azure_check_nsg_any_source())
        checks.extend(self._azure_check_storage_public())
        checks.extend(self._azure_check_sql_public())
        return checks

    def _azure_check_nsg_any_source(self) -> List[Dict]:
        """HIGH: Detect NSG rules allowing traffic from any source."""
        checks: List[Dict] = []
        self.scan_logger.info("Azure: Checking NSG rules for any-source access")

        nsg_data = self._run_az_cli(['network', 'nsg', 'list'])
        if not isinstance(nsg_data, list):
            return checks

        for nsg in nsg_data:
            nsg_name = nsg.get('name', '')
            rg = nsg.get('resourceGroup', '')

            rules_data = self._run_az_cli([
                'network', 'nsg', 'rule', 'list',
                '--nsg-name', nsg_name,
                '--resource-group', rg,
            ])
            if not isinstance(rules_data, list):
                continue

            for rule in rules_data:
                rule_name = rule.get('name', '')
                access = rule.get('access', '').lower()
                direction = rule.get('direction', '').lower()
                src_addr = rule.get('sourceAddressPrefix', '')

                if access == 'allow' and direction == 'inbound':
                    if src_addr in ('*', '0.0.0.0/0', 'Internet', 'Any'):
                        dest_port = rule.get('destinationPortRange', '*')
                        self.add_finding(
                            severity='HIGH',
                            title=f"[Cloud/Azure] NSG rule allows any source: {nsg_name}/{rule_name}",
                            description=(
                                f"NSG '{nsg_name}' in resource group '{rg}' has "
                                f"inbound allow rule '{rule_name}' with source "
                                f"'{src_addr}' on port(s) {dest_port}."
                            ),
                            affected_asset=f"azure:nsg:{nsg_name}",
                            finding_type='cloud_misconfiguration',
                            cvss_score=self.CVSS_MAP['HIGH'],
                            remediation=(
                                "Restrict NSG inbound rules to specific source IP "
                                "ranges. Remove rules that allow traffic from any source."
                            ),
                            detection_method='cloud_api_check',
                        )
                        checks.append({
                            'provider': 'azure', 'check': 'nsg_any_source',
                            'resource': f"{nsg_name}/{rule_name}",
                            'status': 'HIGH',
                        })

        return checks

    def _azure_check_storage_public(self) -> List[Dict]:
        """CRITICAL: Detect storage accounts with public blob access enabled."""
        checks: List[Dict] = []
        self.scan_logger.info("Azure: Checking storage account public access")

        sa_data = self._run_az_cli(['storage', 'account', 'list'])
        if not isinstance(sa_data, list):
            return checks

        for account in sa_data:
            name = account.get('name', '')
            rg = account.get('resourceGroup', '')
            public_access = account.get('allowBlobPublicAccess', False)

            if public_access:
                self.add_finding(
                    severity='CRITICAL',
                    title=f"[Cloud/Azure] Storage account allows public blob access: {name}",
                    description=(
                        f"Storage account '{name}' in resource group '{rg}' has "
                        "allowBlobPublicAccess set to true. Blob containers could "
                        "be publicly accessible."
                    ),
                    affected_asset=f"azure:storage:{name}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP['CRITICAL'],
                    remediation=(
                        "Disable public blob access on the storage account: "
                        "az storage account update --name <name> "
                        "--allow-blob-public-access false"
                    ),
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'azure', 'check': 'storage_public_access',
                    'resource': name, 'status': 'CRITICAL',
                })

        return checks

    def _azure_check_sql_public(self) -> List[Dict]:
        """HIGH: Detect Azure SQL servers with public network access."""
        checks: List[Dict] = []
        self.scan_logger.info("Azure: Checking SQL server public access")

        sql_data = self._run_az_cli(['sql', 'server', 'list'])
        if not isinstance(sql_data, list):
            return checks

        for server in sql_data:
            name = server.get('name', '')
            rg = server.get('resourceGroup', '')
            public_access = server.get('publicNetworkAccess', 'Enabled')

            if public_access == 'Enabled':
                self.add_finding(
                    severity='HIGH',
                    title=f"[Cloud/Azure] SQL server public network access: {name}",
                    description=(
                        f"Azure SQL server '{name}' in resource group '{rg}' has "
                        "public network access enabled."
                    ),
                    affected_asset=f"azure:sql:{name}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP['HIGH'],
                    remediation=(
                        "Disable public network access and use private endpoints: "
                        "az sql server update --name <name> --resource-group <rg> "
                        "--enable-public-network false"
                    ),
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'azure', 'check': 'sql_public_access',
                    'resource': name, 'status': 'HIGH',
                })

        return checks

    # ==================================================================
    # GCP Checks
    # ==================================================================

    def _scan_gcp(self) -> List[Dict]:
        """Run all GCP security checks."""
        checks: List[Dict] = []
        checks.extend(self._gcp_check_firewall_rules())
        checks.extend(self._gcp_check_gcs_public())
        checks.extend(self._gcp_check_cloudsql_public())
        return checks

    def _gcp_check_firewall_rules(self) -> List[Dict]:
        """HIGH: Detect firewall rules allowing 0.0.0.0/0 ingress."""
        checks: List[Dict] = []
        self.scan_logger.info("GCP: Checking firewall rules for 0.0.0.0/0")

        fw_data = self._run_gcloud_cli(['compute', 'firewall-rules', 'list'])
        if not isinstance(fw_data, list):
            return checks

        for rule in fw_data:
            rule_name = rule.get('name', '')
            direction = rule.get('direction', '').upper()
            disabled = rule.get('disabled', False)
            source_ranges = rule.get('sourceRanges', [])

            if disabled or direction != 'INGRESS':
                continue

            if '0.0.0.0/0' in source_ranges:
                allowed = rule.get('allowed', [])
                allowed_desc = []
                for a in allowed:
                    proto = a.get('IPProtocol', 'all')
                    ports = a.get('ports', ['all'])
                    allowed_desc.append(f"{proto}:{','.join(ports)}")

                self.add_finding(
                    severity='HIGH',
                    title=f"[Cloud/GCP] Firewall rule allows 0.0.0.0/0: {rule_name}",
                    description=(
                        f"Firewall rule '{rule_name}' allows ingress from 0.0.0.0/0 "
                        f"on {'; '.join(allowed_desc)}."
                    ),
                    affected_asset=f"gcp:compute:firewall/{rule_name}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP['HIGH'],
                    remediation=(
                        "Restrict firewall rule source ranges to specific IP "
                        "addresses or CIDR blocks."
                    ),
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'gcp', 'check': 'firewall_wide_open',
                    'resource': rule_name, 'status': 'HIGH',
                })

        return checks

    def _gcp_check_gcs_public(self) -> List[Dict]:
        """CRITICAL: Detect publicly accessible GCS buckets."""
        checks: List[Dict] = []
        self.scan_logger.info("GCP: Checking GCS bucket public access")

        # List buckets via gcloud (gsutil ls can also work)
        buckets_data = self._run_gcloud_cli([
            'storage', 'buckets', 'list',
        ])

        # Fallback: try gsutil ls
        bucket_names: List[str] = []
        if isinstance(buckets_data, list):
            for b in buckets_data:
                name = b.get('name', b.get('id', ''))
                if name:
                    bucket_names.append(name)
        else:
            ls_output = self._run_gsutil(['ls'])
            if ls_output:
                for line in ls_output.strip().split('\n'):
                    line = line.strip().rstrip('/')
                    if line.startswith('gs://'):
                        bucket_names.append(line[5:])

        for bucket_name in bucket_names:
            iam_output = self._run_gsutil(['iam', 'get', f'gs://{bucket_name}'])
            if not iam_output:
                continue

            try:
                iam_policy = json.loads(iam_output)
            except (json.JSONDecodeError, TypeError):
                continue

            public_members = {'allUsers', 'allAuthenticatedUsers'}
            for binding in iam_policy.get('bindings', []):
                members = set(binding.get('members', []))
                public_matched = members & public_members
                if public_matched:
                    role = binding.get('role', 'unknown')
                    self.add_finding(
                        severity='CRITICAL',
                        title=f"[Cloud/GCP] GCS bucket publicly accessible: {bucket_name}",
                        description=(
                            f"GCS bucket '{bucket_name}' grants role '{role}' to "
                            f"{', '.join(public_matched)}."
                        ),
                        affected_asset=f"gcp:storage:{bucket_name}",
                        finding_type='cloud_misconfiguration',
                        cvss_score=self.CVSS_MAP['CRITICAL'],
                        remediation=(
                            "Remove allUsers and allAuthenticatedUsers bindings "
                            "from the bucket IAM policy."
                        ),
                        detection_method='cloud_api_check',
                    )
                    checks.append({
                        'provider': 'gcp', 'check': 'gcs_public',
                        'resource': bucket_name, 'status': 'CRITICAL',
                    })

        return checks

    def _gcp_check_cloudsql_public(self) -> List[Dict]:
        """HIGH: Detect Cloud SQL instances with public IP."""
        checks: List[Dict] = []
        self.scan_logger.info("GCP: Checking Cloud SQL instances for public IPs")

        sql_data = self._run_gcloud_cli(['sql', 'instances', 'list'])
        if not isinstance(sql_data, list):
            return checks

        for instance in sql_data:
            name = instance.get('name', '')
            settings = instance.get('settings', {})
            ip_config = settings.get('ipConfiguration', {})
            ip_addresses = instance.get('ipAddresses', [])

            has_public_ip = False
            public_ip_addr = None
            for ip_entry in ip_addresses:
                if ip_entry.get('type') == 'PRIMARY':
                    has_public_ip = True
                    public_ip_addr = ip_entry.get('ipAddress', '')
                    break

            authorized_networks = ip_config.get('authorizedNetworks', [])
            has_wide_open_net = False
            for net in authorized_networks:
                value = net.get('value', '')
                if value in ('0.0.0.0/0', '::/0'):
                    has_wide_open_net = True
                    break

            if has_public_ip:
                severity = 'HIGH' if has_wide_open_net else 'MEDIUM'
                detail = (
                    f"Public IP: {public_ip_addr}."
                    + (" Authorized networks include 0.0.0.0/0!" if has_wide_open_net else "")
                )
                self.add_finding(
                    severity=severity,
                    title=f"[Cloud/GCP] Cloud SQL public IP: {name}",
                    description=(
                        f"Cloud SQL instance '{name}' has a public IP address "
                        f"({public_ip_addr}). {detail}"
                    ),
                    affected_asset=f"gcp:sql:{name}",
                    finding_type='cloud_misconfiguration',
                    cvss_score=self.CVSS_MAP[severity],
                    remediation=(
                        "Use private IP connectivity for Cloud SQL. If public IP is "
                        "required, restrict authorized networks to specific IPs."
                    ),
                    detection_method='cloud_api_check',
                )
                checks.append({
                    'provider': 'gcp', 'check': 'cloudsql_public_ip',
                    'resource': name, 'status': severity,
                })

        return checks

    # ==================================================================
    # Summary
    # ==================================================================

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate scan summary from check results."""
        checks = results.get('checks', [])
        summary: Dict = {
            'total_checks': len(checks),
            'providers_scanned': results.get('providers_scanned', []),
            'providers_skipped': len(results.get('providers_skipped', [])),
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
            'by_provider': {},
        }

        for check in checks:
            sev = check.get('status', 'INFO')
            if sev in summary['by_severity']:
                summary['by_severity'][sev] += 1

            provider = check.get('provider', 'unknown')
            summary['by_provider'][provider] = summary['by_provider'].get(provider, 0) + 1

        return summary


if __name__ == '__main__':
    scanner = CloudScanner()
    print("Cloud Scanner initialized")

    # Check deployment mode
    if get_platform_info:
        pi = get_platform_info()
        print(f"  Deployment mode: {pi.deployment_mode}")
        if pi.is_portable:
            print("  Cloud scanning DISABLED in portable mode")

    print(f"  AWS available: {scanner.aws_available}")
    print(f"  Azure available: {scanner.azure_available}")
    print(f"  GCP available: {scanner.gcp_available}")

    if not any([scanner.aws_available, scanner.azure_available, scanner.gcp_available]):
        print("\n  No cloud providers detected")
        print("  Install: pip install boto3 (AWS)")
        print("  Install: pip install azure-identity azure-mgmt-resource (Azure)")
        print("  Install: pip install google-cloud-resource-manager (GCP)")
        print("  Or install CLI: aws, az, gcloud")

    print("\nCloud Scanner ready")
