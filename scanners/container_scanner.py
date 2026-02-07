#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Container Security Scanner
Docker/Podman container and image security assessment.
Requires explicit user confirmation before Docker socket access.
Read-only inspection only - no exec/attach/pull operations.
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Add lib to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

from paths import paths
from logger import get_logger

try:
    from platform_detect import get_platform_info
except ImportError:
    get_platform_info = None


class ContainerScanner(BaseScanner):
    """Container security assessment for Docker and Podman environments."""

    SCANNER_NAME = "container"
    SCANNER_DESCRIPTION = "Container security assessment (Docker/Podman)"

    # Sensitive host paths that should not be mounted into containers
    SENSITIVE_MOUNT_PATHS = [
        '/etc/shadow', '/etc/passwd', '/var/run/docker.sock',
        '/root', '/home'
    ]

    # Environment variable names that may contain secrets
    SENSITIVE_ENV_NAMES = [
        'password', 'secret', 'key', 'token', 'api_key', 'private'
    ]

    # Maximum acceptable image age in days
    MAX_IMAGE_AGE_DAYS = 180

    # Layer count threshold for informational finding
    MAX_IMAGE_LAYERS = 40

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.runtime = None
        self.runtime_path = None
        self.trivy_path = None

    def _detect_runtime(self) -> Optional[str]:
        """Detect available container runtime (Docker or Podman)."""
        for runtime in ('docker', 'podman'):
            path = shutil.which(runtime)
            if path:
                self.runtime = runtime
                self.runtime_path = path
                self.scan_logger.info(f"Detected container runtime: {runtime} at {path}")
                return runtime
        return None

    def _check_runtime_access(self) -> bool:
        """Verify the container runtime daemon is accessible."""
        try:
            result = subprocess.run(
                [self.runtime_path, 'info', '--format', '{{.ServerVersion}}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                self.scan_logger.info(f"{self.runtime} daemon version: {version}")
                return True
            else:
                self.scan_logger.warning(
                    f"{self.runtime} daemon not accessible: {result.stderr.strip()}"
                )
                return False
        except subprocess.TimeoutExpired:
            self.scan_logger.warning(f"{self.runtime} info command timed out")
            return False
        except Exception as e:
            self.scan_logger.warning(f"Could not query {self.runtime}: {e}")
            return False

    def scan(self, targets: List[str] = None, scan_type: str = 'standard',
             user_confirmed: bool = False, **kwargs) -> Dict:
        """
        Execute container security scan.

        Args:
            targets: Optional list of container IDs or image names to scan.
                     If not provided, scans all running containers and local images.
            scan_type: 'quick', 'standard', or 'deep'
            user_confirmed: Must be True to acknowledge Docker socket access.
                            Required for security -- scanner will not proceed without it.
        """
        self.start_time = datetime.utcnow()

        results = {
            'scan_type': scan_type,
            'runtime': None,
            'containers': [],
            'images': [],
            'trivy_results': [],
            'summary': {}
        }

        # Phase 0: Detect container runtime
        runtime = self._detect_runtime()
        if not runtime:
            self.scan_logger.info("No container runtime (Docker/Podman) detected")
            self.add_finding(
                severity='INFO',
                title='No Container Runtime Detected',
                description='Neither Docker nor Podman is installed on this system. '
                            'Container security checks were skipped.',
                affected_asset='localhost',
                finding_type='container_runtime',
                remediation='Install Docker or Podman if container workloads are expected.',
                detection_method='runtime_detection'
            )
            self.end_time = datetime.utcnow()
            results['summary'] = self._build_summary(results)
            return results

        results['runtime'] = runtime

        # Phase 1: Require explicit user confirmation for Docker socket access
        if not user_confirmed:
            self.scan_logger.warning(
                "User confirmation required before accessing Docker socket. "
                "Pass user_confirmed=True to acknowledge."
            )
            self.add_finding(
                severity='INFO',
                title='Container Scan Requires Confirmation',
                description=f'Access to the {runtime} socket is required for container inspection. '
                            f'Re-run with user_confirmed=True to proceed.',
                affected_asset='localhost',
                finding_type='container_runtime',
                detection_method='runtime_detection'
            )
            self.end_time = datetime.utcnow()
            results['summary'] = self._build_summary(results)
            return results

        # Phase 2: Check daemon accessibility
        if not self._check_runtime_access():
            self.add_finding(
                severity='MEDIUM',
                title=f'{runtime.capitalize()} Daemon Not Accessible',
                description=f'The {runtime} daemon is installed but not accessible. '
                            f'It may not be running or the current user lacks permissions.',
                affected_asset='localhost',
                finding_type='container_runtime',
                remediation=f'Ensure the {runtime} daemon is running and the user has access '
                            f'(e.g., membership in the docker group).',
                detection_method='runtime_detection'
            )
            self.end_time = datetime.utcnow()
            results['summary'] = self._build_summary(results)
            return results

        # Phase 3: Enumerate and inspect running containers
        self.scan_logger.info("Phase 3: Enumerating running containers")
        containers = self._list_containers()
        for container in containers:
            container_id = container.get('ID', container.get('Id', ''))
            container_name = container.get('Names', container.get('Name', container_id))

            inspection = self._inspect_container(container_id)
            if inspection:
                container_report = {
                    'id': container_id,
                    'name': container_name,
                    'image': container.get('Image', ''),
                    'findings': []
                }
                self._check_container_security(inspection, container_id, container_name)
                results['containers'].append(container_report)

            self.human_delay()

        # Phase 4: Enumerate and inspect images
        self.scan_logger.info("Phase 4: Enumerating local images")
        images = self._list_images()
        for image in images:
            image_id = image.get('ID', image.get('Id', ''))
            image_repo = image.get('Repository', image.get('RepoTags', image_id))
            image_tag = image.get('Tag', 'latest')
            image_ref = f"{image_repo}:{image_tag}" if image_repo != '<none>' else image_id

            self._check_image_security(image, image_id, image_ref)
            results['images'].append({
                'id': image_id,
                'reference': image_ref,
                'size': image.get('Size', 'unknown'),
                'created': image.get('CreatedAt', image.get('Created', ''))
            })
            self.human_delay()

        # Phase 5: Trivy vulnerability scanning (if available)
        self.trivy_path = shutil.which('trivy')
        if self.trivy_path and scan_type in ('standard', 'deep'):
            self.scan_logger.info("Phase 5: Trivy image vulnerability scanning")
            scanned_images = set()
            for container in containers:
                image_name = container.get('Image', '')
                if image_name and image_name not in scanned_images:
                    trivy_findings = self._run_trivy(image_name)
                    results['trivy_results'].extend(trivy_findings)
                    scanned_images.add(image_name)
                    self.human_delay()

            # Also scan images not attached to running containers (deep only)
            if scan_type == 'deep':
                for image in images:
                    image_repo = image.get('Repository', '')
                    image_tag = image.get('Tag', 'latest')
                    if image_repo and image_repo != '<none>':
                        image_ref = f"{image_repo}:{image_tag}"
                        if image_ref not in scanned_images:
                            trivy_findings = self._run_trivy(image_ref)
                            results['trivy_results'].extend(trivy_findings)
                            scanned_images.add(image_ref)
                            self.human_delay()
        else:
            if not self.trivy_path:
                self.scan_logger.info("Trivy not found -- skipping image vulnerability scanning")

        # Generate summary
        results['summary'] = self._build_summary(results)

        self.end_time = datetime.utcnow()
        self.save_results()
        self._add_container_evidence(results)

        return results

    def _list_containers(self) -> List[Dict]:
        """List running containers. Read-only operation."""
        try:
            result = self.run_tool(
                [self.runtime_path, 'ps', '--format', 'json', '--no-trunc'],
                timeout=30,
                description='List running containers'
            )
            if result.returncode != 0:
                self.scan_logger.warning(f"Failed to list containers: {result.stderr.strip()}")
                return []

            containers = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return containers

        except Exception as e:
            self.scan_logger.warning(f"Error listing containers: {e}")
            return []

    def _list_images(self) -> List[Dict]:
        """List local images. Read-only operation."""
        try:
            result = self.run_tool(
                [self.runtime_path, 'images', '--format', 'json', '--no-trunc'],
                timeout=30,
                description='List local images'
            )
            if result.returncode != 0:
                self.scan_logger.warning(f"Failed to list images: {result.stderr.strip()}")
                return []

            images = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    try:
                        images.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return images

        except Exception as e:
            self.scan_logger.warning(f"Error listing images: {e}")
            return []

    def _inspect_container(self, container_id: str) -> Optional[Dict]:
        """Inspect a container configuration. Read-only operation."""
        try:
            result = self.run_tool(
                [self.runtime_path, 'inspect', container_id],
                timeout=30,
                description=f'Inspect container {container_id[:12]}'
            )
            if result.returncode != 0:
                self.scan_logger.warning(
                    f"Failed to inspect container {container_id[:12]}: {result.stderr.strip()}"
                )
                return None

            data = json.loads(result.stdout)
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            return data

        except (json.JSONDecodeError, Exception) as e:
            self.scan_logger.warning(f"Error inspecting container {container_id[:12]}: {e}")
            return None

    def _check_container_security(self, config: Dict, container_id: str,
                                  container_name: str):
        """Run security checks against an inspected container configuration."""
        asset = f"{container_name} ({container_id[:12]})"

        # Check: Privileged mode
        if config.get('HostConfig', {}).get('Privileged'):
            self.add_finding(
                severity='CRITICAL',
                title='Container Running in Privileged Mode',
                description=f'Container {asset} is running with --privileged flag. '
                            f'This grants full host access and effectively disables '
                            f'all container isolation.',
                affected_asset=asset,
                finding_type='container_misconfiguration',
                remediation='Remove the --privileged flag. Use specific --cap-add flags '
                            'for only the capabilities required.',
                raw_data={'container_id': container_id, 'privileged': True},
                detection_method='container_inspect'
            )

        # Check: Host network mode
        network_mode = config.get('HostConfig', {}).get('NetworkMode', '')
        if network_mode == 'host':
            self.add_finding(
                severity='HIGH',
                title='Container Using Host Network',
                description=f'Container {asset} is using host network mode (--network=host). '
                            f'This exposes all host network interfaces to the container.',
                affected_asset=asset,
                finding_type='container_misconfiguration',
                remediation='Use bridge networking or a custom Docker network instead of '
                            'host network mode.',
                raw_data={'container_id': container_id, 'network_mode': network_mode},
                detection_method='container_inspect'
            )

        # Check: Sensitive mount paths
        for mount in config.get('Mounts', []):
            source = mount.get('Source', '')
            for sensitive in self.SENSITIVE_MOUNT_PATHS:
                if source.startswith(sensitive):
                    self.add_finding(
                        severity='HIGH',
                        title=f'Container Mounting Sensitive Path: {sensitive}',
                        description=f'Container {asset} has a bind mount from '
                                    f'host path {source} to {mount.get("Destination", "unknown")}. '
                                    f'Mounting {sensitive} can expose sensitive host data.',
                        affected_asset=asset,
                        finding_type='container_misconfiguration',
                        remediation=f'Remove the volume mount for {source} or use a '
                                    f'read-only mount if absolutely necessary.',
                        raw_data={
                            'container_id': container_id,
                            'mount_source': source,
                            'mount_dest': mount.get('Destination', ''),
                            'read_only': mount.get('RW', True) is False
                        },
                        detection_method='container_inspect'
                    )

        # Check: Running as root
        user = config.get('Config', {}).get('User', '')
        if not user or user == 'root' or user == '0':
            self.add_finding(
                severity='MEDIUM',
                title='Container Running as Root',
                description=f'Container {asset} is running as the root user. '
                            f'If an attacker escapes the container, they may have '
                            f'root-level access on the host.',
                affected_asset=asset,
                finding_type='container_misconfiguration',
                remediation='Add a USER directive in the Dockerfile or use --user flag '
                            'to run as a non-root user.',
                raw_data={'container_id': container_id, 'user': user or 'root (default)'},
                detection_method='container_inspect'
            )

        # Check: Exposed ports
        ports = config.get('HostConfig', {}).get('PortBindings', {})
        if ports:
            port_list = []
            for container_port, bindings in ports.items():
                if bindings:
                    for binding in bindings:
                        host_ip = binding.get('HostIp', '0.0.0.0')
                        host_port = binding.get('HostPort', '')
                        port_list.append(f"{host_ip}:{host_port}->{container_port}")

            if port_list:
                self.add_finding(
                    severity='INFO',
                    title='Container Exposing Ports to Host',
                    description=f'Container {asset} has ports published to the host: '
                                f'{", ".join(port_list)}',
                    affected_asset=asset,
                    finding_type='container_configuration',
                    remediation='Verify all exposed ports are intentional and restrict '
                                'host binding to 127.0.0.1 where external access is not needed.',
                    raw_data={'container_id': container_id, 'ports': port_list},
                    detection_method='container_inspect'
                )

        # Check: Missing health check
        healthcheck = config.get('Config', {}).get('Healthcheck')
        if not healthcheck or not healthcheck.get('Test'):
            self.add_finding(
                severity='LOW',
                title='Container Missing Health Check',
                description=f'Container {asset} does not define a HEALTHCHECK. '
                            f'Without a health check, orchestrators cannot detect '
                            f'if the application inside the container is functional.',
                affected_asset=asset,
                finding_type='container_misconfiguration',
                remediation='Add a HEALTHCHECK instruction to the Dockerfile or use '
                            '--health-cmd when running the container.',
                raw_data={'container_id': container_id},
                detection_method='container_inspect'
            )

        # Check: Sensitive environment variables
        for env in config.get('Config', {}).get('Env', []):
            env_name = env.split('=')[0].lower()
            if any(s in env_name for s in self.SENSITIVE_ENV_NAMES):
                # Do NOT log the actual value -- only the variable name
                self.add_finding(
                    severity='MEDIUM',
                    title='Potential Secret in Environment Variable',
                    description=f'Container {asset} has an environment variable '
                                f'"{env.split("=")[0]}" that may contain a secret. '
                                f'Environment variables are visible via docker inspect '
                                f'and /proc inside the container.',
                    affected_asset=asset,
                    finding_type='container_secret_exposure',
                    remediation='Use Docker secrets, a secrets manager, or mounted '
                                'config files instead of environment variables for sensitive data.',
                    raw_data={
                        'container_id': container_id,
                        'env_name': env.split('=')[0],
                        'value_redacted': True
                    },
                    detection_method='container_inspect'
                )

    def _check_image_security(self, image: Dict, image_id: str, image_ref: str):
        """Run security checks against a local image."""
        asset = image_ref

        # Check: Image age
        created_str = image.get('CreatedAt', image.get('Created', ''))
        if created_str:
            try:
                # Handle various date formats from docker/podman
                created_str_clean = created_str.split('.')[0].replace('T', ' ')
                # Remove timezone info if present
                for tz_suffix in (' +0000 UTC', ' UTC', 'Z'):
                    created_str_clean = created_str_clean.replace(tz_suffix, '')
                created_str_clean = created_str_clean.strip()

                created = datetime.strptime(created_str_clean, '%Y-%m-%d %H:%M:%S')
                age_days = (datetime.utcnow() - created).days

                if age_days > self.MAX_IMAGE_AGE_DAYS:
                    self.add_finding(
                        severity='MEDIUM',
                        title=f'Container Image Over {self.MAX_IMAGE_AGE_DAYS} Days Old',
                        description=f'Image {asset} was created {age_days} days ago. '
                                    f'Stale images may contain unpatched vulnerabilities.',
                        affected_asset=asset,
                        finding_type='container_image_age',
                        remediation='Rebuild the image from an updated base image and '
                                    'redeploy the container.',
                        raw_data={'image_id': image_id, 'age_days': age_days},
                        detection_method='image_inspect'
                    )
            except (ValueError, TypeError):
                pass

        # Check: Excessive layers
        try:
            result = self.run_tool(
                [self.runtime_path, 'history', '--format', 'json', '--no-trunc', image_id],
                timeout=30,
                description=f'Get image history for {image_ref}'
            )
            if result.returncode == 0:
                layer_count = 0
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            json.loads(line)
                            layer_count += 1
                        except json.JSONDecodeError:
                            continue

                if layer_count > self.MAX_IMAGE_LAYERS:
                    self.add_finding(
                        severity='INFO',
                        title='Container Image Has Many Layers',
                        description=f'Image {asset} has {layer_count} layers. '
                                    f'Excessive layers increase image size and may '
                                    f'indicate suboptimal Dockerfile practices.',
                        affected_asset=asset,
                        finding_type='container_image_quality',
                        remediation='Consolidate RUN instructions in the Dockerfile '
                                    'and use multi-stage builds to reduce layer count.',
                        raw_data={'image_id': image_id, 'layer_count': layer_count},
                        detection_method='image_inspect'
                    )
        except Exception as e:
            self.scan_logger.debug(f"Could not check layers for {image_ref}: {e}")

    def _run_trivy(self, image_ref: str) -> List[Dict]:
        """Run Trivy vulnerability scanner on an image. Read-only operation."""
        findings = []

        self.scan_logger.info(f"Running Trivy scan on {image_ref}")

        try:
            result = self.run_tool(
                [self.trivy_path, 'image', '--format', 'json',
                 '--skip-update', '--no-progress', image_ref],
                timeout=300,
                description=f'Trivy scan on {image_ref}'
            )

            if result.returncode != 0:
                self.scan_logger.warning(
                    f"Trivy scan failed for {image_ref}: {result.stderr.strip()}"
                )
                return findings

            trivy_output = json.loads(result.stdout)
            trivy_results = trivy_output.get('Results', [])

            for target_result in trivy_results:
                target_name = target_result.get('Target', image_ref)
                vulnerabilities = target_result.get('Vulnerabilities', [])

                for vuln in vulnerabilities:
                    severity_map = {
                        'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH',
                        'MEDIUM': 'MEDIUM', 'LOW': 'LOW', 'UNKNOWN': 'INFO'
                    }
                    severity = severity_map.get(
                        vuln.get('Severity', 'UNKNOWN').upper(), 'INFO'
                    )

                    cvss_score = 0.0
                    cvss_data = vuln.get('CVSS', {})
                    for source_data in cvss_data.values():
                        score = source_data.get('V3Score', 0.0)
                        if score > cvss_score:
                            cvss_score = score

                    cve_id = vuln.get('VulnerabilityID', '')
                    cve_ids = [cve_id] if cve_id.startswith('CVE-') else []

                    self.add_finding(
                        severity=severity,
                        title=f"[Trivy] {cve_id}: {vuln.get('Title', vuln.get('PkgName', 'Unknown'))}",
                        description=vuln.get('Description', f"Vulnerability {cve_id} in {target_name}"),
                        affected_asset=f"{image_ref} ({target_name})",
                        finding_type='container_vulnerability',
                        cvss_score=cvss_score,
                        cve_ids=cve_ids,
                        remediation=f"Update {vuln.get('PkgName', 'package')} from "
                                    f"{vuln.get('InstalledVersion', '?')} to "
                                    f"{vuln.get('FixedVersion', 'latest available')}.",
                        raw_data=vuln,
                        detection_method='trivy_scan'
                    )

                    findings.append({
                        'cve': cve_id,
                        'severity': severity,
                        'package': vuln.get('PkgName', ''),
                        'installed': vuln.get('InstalledVersion', ''),
                        'fixed': vuln.get('FixedVersion', ''),
                        'image': image_ref,
                        'target': target_name
                    })

        except json.JSONDecodeError:
            self.scan_logger.warning(f"Failed to parse Trivy JSON output for {image_ref}")
        except Exception as e:
            self.scan_logger.warning(f"Trivy scan error for {image_ref}: {e}")

        return findings

    def _build_summary(self, results: Dict) -> Dict:
        """Build scan summary from results."""
        return {
            'runtime': results.get('runtime'),
            'containers_scanned': len(results.get('containers', [])),
            'images_scanned': len(results.get('images', [])),
            'trivy_findings': len(results.get('trivy_results', [])),
            'total_findings': len(self.findings),
            'findings_by_severity': self._count_by_severity()
        }

    def _add_container_evidence(self, results: Dict):
        """Add container scan results as evidence."""
        if not self.session_id:
            return

        summary = results.get('summary', {})
        evidence_id = self.evidence.add_evidence(
            session_id=self.session_id,
            evidence_type='container_scan',
            title=f"Container Scan ({results.get('runtime', 'unknown')})",
            description=f"Scanned {summary.get('containers_scanned', 0)} containers "
                        f"and {summary.get('images_scanned', 0)} images. "
                        f"Found {summary.get('total_findings', 0)} findings.",
            source_tool=f"{results.get('runtime', 'container')}/trivy",
            raw_data=summary
        )

        # Map to compliance controls
        frameworks = self.config.get_frameworks()
        self.compliance.map_finding_to_controls(
            'container_security', evidence_id, self.evidence, frameworks
        )


if __name__ == '__main__':
    scanner = ContainerScanner()
    print("Container Scanner initialized")
    print(f"  Docker: {shutil.which('docker') is not None}")
    print(f"  Podman: {shutil.which('podman') is not None}")
    print(f"  Trivy:  {shutil.which('trivy') is not None}")

    # Check runtime
    runtime = None
    if shutil.which('docker'):
        runtime = 'docker'
    elif shutil.which('podman'):
        runtime = 'podman'

    if runtime:
        print(f"\n  Runtime: {runtime}")
        try:
            result = subprocess.run(
                [runtime, 'info', '--format', '{{.ServerVersion}}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print(f"  Version: {result.stdout.strip()}")
            else:
                print(f"  Note: {runtime} daemon not accessible (normal if not running)")
        except Exception as e:
            print(f"  Note: Could not query {runtime}: {e}")
    else:
        print("\n  No container runtime detected (Docker/Podman)")

    print("\nContainer Scanner ready")
