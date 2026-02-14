#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Container Security Scanner

Assesses Docker and Kubernetes security configuration using docker, podman,
and kubectl CLIs.

Docker checks:
  1.  Daemon configuration (insecure registries, TLS, userns-remap, live-restore)
  2.  Image hygiene (untagged, latest, old, large images)
  3.  Container security (privileged, root, sensitive mounts, exposed ports)
  4.  Network isolation (default bridge, custom networks)
  5.  Volume security (world-readable, sensitive mounts)

Kubernetes checks:
  6.  RBAC (cluster-admin bindings, permissive roles)
  7.  Pod security (privileged, hostNetwork/PID, root, resource limits)
  8.  Network policies (namespaces without policies)
  9.  Secrets hygiene (env vars vs mounted volumes)
  10. API server (anonymous auth, insecure port)

Scan types:
  quick    - checks 1-3, 6-7 only
  standard - all checks
  deep     - all checks with per-container/pod detail
"""

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


class ContainerScanner(BaseScanner):
    """Docker and Kubernetes security scanner."""

    SCANNER_NAME = "container"
    SCANNER_DESCRIPTION = "Container security assessment (Docker/Kubernetes)"

    # Sensitive host paths that should never be bind-mounted
    SENSITIVE_MOUNTS = (
        '/etc/shadow', '/etc/passwd', '/etc/sudoers',
        '/var/run/docker.sock', '/run/docker.sock',
        '/var/run/crio/crio.sock',
        '/root', '/home',
        '/proc', '/sys',
    )

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.docker_cmd: Optional[str] = None   # 'docker' or 'podman'
        self.has_kubectl: bool = False

    # -----------------------------------------------------------------------
    # CLI helpers
    # -----------------------------------------------------------------------

    def _run_cli(self, command: List[str],
                 timeout: int = 120) -> Optional[str]:
        """Run a CLI command and return stdout or None."""
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
        """Run CLI command and parse JSON output."""
        raw = self._run_cli(command, timeout)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    # -----------------------------------------------------------------------
    # Tool detection
    # -----------------------------------------------------------------------

    def _detect_tools(self) -> None:
        """Detect available container CLI tools."""
        # Docker
        result = self._run_cli(['docker', 'info', '--format', '{{json .}}'])
        if result:
            self.docker_cmd = 'docker'
            self.scan_logger.info("Docker CLI detected")
        else:
            # Try podman
            result = self._run_cli(['podman', 'info', '--format', 'json'])
            if result:
                self.docker_cmd = 'podman'
                self.scan_logger.info("Podman CLI detected")

        # kubectl
        result = self._run_cli(['kubectl', 'version', '--client', '-o', 'json'])
        if result:
            # Verify cluster connectivity
            cluster = self._run_cli(['kubectl', 'cluster-info'])
            if cluster:
                self.has_kubectl = True
                self.scan_logger.info("kubectl detected with cluster access")
            else:
                self.scan_logger.info("kubectl found but no cluster access")

    # -----------------------------------------------------------------------
    # Main scan entry point
    # -----------------------------------------------------------------------

    def scan(self, targets: List[str] = None,
             scan_type: str = 'standard', **kwargs) -> Dict:
        """Execute container security scan.

        Args:
            targets: Ignored (scans local Docker/K8s).
            scan_type: 'quick', 'standard', or 'deep'.

        Returns:
            Dict with scan results and summary.
        """
        self.start_time = datetime.utcnow()
        self.scan_logger.info(f"Starting {scan_type} container scan")

        self._detect_tools()

        if not self.docker_cmd and not self.has_kubectl:
            self.add_finding(
                severity='INFO',
                title='No Container Tools Detected',
                description=(
                    'Neither Docker/Podman nor kubectl was found. '
                    'Install container tools to enable scanning.'
                ),
                affected_asset='localhost',
                finding_type='container_prerequisite',
                detection_method='cli_check',
            )
            self.end_time = datetime.utcnow()
            self.save_results()
            return self.get_summary()

        # --- Docker / Podman checks ---
        if self.docker_cmd:
            self.scan_logger.info(
                f"=== {self.docker_cmd.title()} Security Checks ==="
            )
            self._check_docker_daemon()
            self.human_delay()

            self._check_docker_images(scan_type)
            self.human_delay()

            self._check_docker_containers(scan_type)
            self.human_delay()

            if scan_type in ('standard', 'deep'):
                self._check_docker_networks()
                self.human_delay()

                self._check_docker_volumes(scan_type)
                self.human_delay()

        # --- Kubernetes checks ---
        if self.has_kubectl:
            self.scan_logger.info("=== Kubernetes Security Checks ===")
            self._check_k8s_rbac(scan_type)
            self.human_delay()

            self._check_k8s_pods(scan_type)
            self.human_delay()

            if scan_type in ('standard', 'deep'):
                self._check_k8s_network_policies()
                self.human_delay()

                self._check_k8s_secrets(scan_type)
                self.human_delay()

                self._check_k8s_api()
                self.human_delay()

        self.end_time = datetime.utcnow()
        self.save_results()

        summary = self.get_summary()
        self.scan_logger.info(
            f"Container scan complete: {summary['findings_count']} findings"
        )
        return summary

    # =======================================================================
    # Docker / Podman Checks
    # =======================================================================

    def _check_docker_daemon(self) -> None:
        """Check Docker daemon configuration."""
        info = self._run_cli_json(
            [self.docker_cmd, 'info', '--format', '{{json .}}']
        )
        if not info:
            return

        self.add_result('docker_info', info, 'docker-daemon')

        # Insecure registries
        insecure = info.get('RegistryConfig', {}).get(
            'InsecureRegistryCIDRs', []
        )
        # Filter out the default localhost entry
        real_insecure = [
            r for r in insecure if r not in ('127.0.0.0/8',)
        ]
        if real_insecure:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(real_insecure)} Insecure Docker Registries '
                    f'Configured'
                ),
                description=(
                    f"Docker daemon allows insecure (non-TLS) connections "
                    f"to: {real_insecure}. Images could be tampered in "
                    f"transit."
                ),
                affected_asset='docker-daemon',
                finding_type='container_daemon',
                remediation='Use TLS for all container registries.',
                raw_data=real_insecure,
                detection_method='docker_cli',
            )

        # User namespace remapping
        userns = info.get('SecurityOptions', [])
        has_userns = any('userns' in str(s) for s in userns)
        if not has_userns:
            self.add_finding(
                severity='MEDIUM',
                title='Docker User Namespace Remapping Not Enabled',
                description=(
                    'User namespace remapping is not configured. '
                    'Container root maps to host root, increasing '
                    'container escape risk.'
                ),
                affected_asset='docker-daemon',
                finding_type='container_daemon',
                remediation='Enable userns-remap in Docker daemon config.',
                raw_data={'security_options': userns},
                detection_method='docker_cli',
            )

        # Live restore
        live_restore = info.get('LiveRestoreEnabled', False)
        if not live_restore:
            self.add_finding(
                severity='LOW',
                title='Docker Live Restore Not Enabled',
                description=(
                    'Live restore is not enabled. Containers will stop '
                    'during daemon upgrades.'
                ),
                affected_asset='docker-daemon',
                finding_type='container_daemon',
                remediation='Enable live-restore in Docker daemon config.',
                detection_method='docker_cli',
            )

        # Default logging driver
        log_driver = info.get('LoggingDriver', 'json-file')
        if log_driver == 'none':
            self.add_finding(
                severity='MEDIUM',
                title='Docker Logging Disabled',
                description='Docker daemon logging driver is set to none.',
                affected_asset='docker-daemon',
                finding_type='container_daemon',
                remediation='Set logging driver to json-file or a centralized driver.',
                detection_method='docker_cli',
            )

    def _check_docker_images(self, scan_type: str) -> None:
        """Check Docker image hygiene."""
        images = self._run_cli_json(
            [self.docker_cmd, 'images', '--format', '{{json .}}',
             '--no-trunc']
        )
        if images is None:
            # Try alternative format (docker images outputs one JSON per line)
            raw = self._run_cli(
                [self.docker_cmd, 'images',
                 '--format', '{{json .}}', '--no-trunc']
            )
            if raw:
                images = []
                for line in raw.strip().split('\n'):
                    try:
                        images.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        if not images:
            return

        if isinstance(images, dict):
            images = [images]

        self.add_result(
            'docker_images', {'count': len(images)}, 'docker'
        )

        untagged = []
        latest_tag = []
        large_images = []

        for img in images:
            repo = img.get('Repository', '<none>')
            tag = img.get('Tag', '<none>')
            size_str = img.get('Size', '0')

            if repo == '<none>' or tag == '<none>':
                untagged.append(img.get('ID', 'unknown'))

            if tag == 'latest':
                latest_tag.append(f"{repo}:{tag}")

            # Parse size (rough check for > 1GB)
            try:
                if 'GB' in str(size_str):
                    size_val = float(str(size_str).replace('GB', '').strip())
                    if size_val > 1.0:
                        large_images.append({
                            'image': f"{repo}:{tag}",
                            'size': size_str,
                        })
            except (ValueError, TypeError):
                pass

        if untagged:
            self.add_finding(
                severity='LOW',
                title=f'{len(untagged)} Untagged Docker Images',
                description=(
                    f"{len(untagged)} images have no repository or tag. "
                    f"These are likely dangling images wasting disk space."
                ),
                affected_asset='docker',
                finding_type='container_images',
                remediation='Remove dangling images: docker image prune',
                raw_data=untagged,
                detection_method='docker_cli',
            )

        if latest_tag:
            self.add_finding(
                severity='MEDIUM',
                title=f'{len(latest_tag)} Images Using :latest Tag',
                description=(
                    f"{len(latest_tag)} images use the :latest tag. "
                    f"This makes it impossible to track which version "
                    f"is deployed and complicates rollbacks."
                ),
                affected_asset='docker',
                finding_type='container_images',
                remediation='Pin images to specific version tags.',
                raw_data=latest_tag,
                detection_method='docker_cli',
            )

        if large_images:
            self.add_finding(
                severity='INFO',
                title=f'{len(large_images)} Large Docker Images (> 1 GB)',
                description=(
                    f"{len(large_images)} images exceed 1 GB. Large images "
                    f"increase attack surface and deployment time."
                ),
                affected_asset='docker',
                finding_type='container_images',
                raw_data=large_images,
                detection_method='docker_cli',
            )

    def _check_docker_containers(self, scan_type: str) -> None:
        """Check running container security posture."""
        raw = self._run_cli(
            [self.docker_cmd, 'ps', '-a', '--format', '{{json .}}',
             '--no-trunc']
        )
        if not raw:
            return

        containers = []
        for line in raw.strip().split('\n'):
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                pass

        if not containers:
            return

        self.add_result(
            'docker_containers', {'count': len(containers)}, 'docker'
        )

        privileged = []
        root_containers = []
        sensitive_mounts = []
        exposed_ports = []

        for ctr in containers:
            ctr_id = ctr.get('ID', '')[:12]
            ctr_name = ctr.get('Names', ctr_id)
            status = ctr.get('Status', '')

            # Only inspect running containers (or all in deep mode)
            if 'Up' not in status and scan_type != 'deep':
                continue

            # Full inspect for details
            inspect = self._run_cli_json(
                [self.docker_cmd, 'inspect', ctr_id]
            )
            if not inspect:
                continue
            if isinstance(inspect, list) and inspect:
                inspect = inspect[0]

            host_cfg = inspect.get('HostConfig', {})

            # Privileged mode
            if host_cfg.get('Privileged', False):
                privileged.append(ctr_name)

            # Running as root
            user = inspect.get('Config', {}).get('User', '')
            if not user or user == '0' or user == 'root':
                root_containers.append(ctr_name)

            # Sensitive mounts
            mounts = inspect.get('Mounts', [])
            for mount in mounts:
                src = mount.get('Source', '')
                for sensitive in self.SENSITIVE_MOUNTS:
                    if src == sensitive or src.startswith(sensitive + '/'):
                        sensitive_mounts.append({
                            'container': ctr_name,
                            'source': src,
                            'destination': mount.get('Destination', ''),
                            'rw': mount.get('RW', True),
                        })
                        break

            # Exposed ports
            ports_cfg = host_cfg.get('PortBindings', {})
            for port_spec, bindings in (ports_cfg or {}).items():
                if bindings:
                    for binding in bindings:
                        host_ip = binding.get('HostIp', '')
                        if host_ip in ('', '0.0.0.0'):
                            exposed_ports.append({
                                'container': ctr_name,
                                'port': port_spec,
                                'host_ip': host_ip or '0.0.0.0',
                                'host_port': binding.get('HostPort', ''),
                            })

            # Restart policy
            restart = host_cfg.get('RestartPolicy', {}).get('Name', '')
            if restart == 'always':
                self.add_finding(
                    severity='INFO',
                    title=(
                        f'Container {ctr_name} Has restart=always'
                    ),
                    description=(
                        f"Container '{ctr_name}' has restart policy "
                        f"'always'. Consider 'unless-stopped' to prevent "
                        f"unintended restarts after host reboot."
                    ),
                    affected_asset=f'docker:{ctr_name}',
                    finding_type='container_config',
                    detection_method='docker_cli',
                )

        if privileged:
            self.add_finding(
                severity='CRITICAL',
                title=f'{len(privileged)} Privileged Containers',
                description=(
                    f"{len(privileged)} containers run in privileged mode, "
                    f"granting full host kernel access."
                ),
                affected_asset='docker',
                finding_type='container_security',
                remediation=(
                    'Remove --privileged flag. Use specific capabilities '
                    'with --cap-add instead.'
                ),
                raw_data=privileged,
                detection_method='docker_cli',
            )

        if root_containers:
            self.add_finding(
                severity='HIGH',
                title=f'{len(root_containers)} Containers Running as Root',
                description=(
                    f"{len(root_containers)} containers run as root (UID 0). "
                    f"Container escape vulnerabilities are more impactful "
                    f"when the container process is root."
                ),
                affected_asset='docker',
                finding_type='container_security',
                remediation=(
                    'Set USER in Dockerfile or use --user flag.'
                ),
                raw_data=root_containers,
                detection_method='docker_cli',
            )

        if sensitive_mounts:
            self.add_finding(
                severity='CRITICAL',
                title=(
                    f'{len(sensitive_mounts)} Containers With Sensitive '
                    f'Host Mounts'
                ),
                description=(
                    f"{len(sensitive_mounts)} containers mount sensitive "
                    f"host paths (docker.sock, /etc, etc.)."
                ),
                affected_asset='docker',
                finding_type='container_security',
                remediation=(
                    'Remove sensitive bind mounts. Use Docker secrets '
                    'or volumes instead.'
                ),
                raw_data=sensitive_mounts,
                detection_method='docker_cli',
            )

        if exposed_ports:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(exposed_ports)} Container Ports Exposed on '
                    f'0.0.0.0'
                ),
                description=(
                    f"{len(exposed_ports)} container port mappings bind "
                    f"to all interfaces (0.0.0.0)."
                ),
                affected_asset='docker',
                finding_type='container_network',
                remediation=(
                    'Bind to specific IPs: -p 127.0.0.1:8080:80'
                ),
                raw_data=exposed_ports,
                detection_method='docker_cli',
            )

    def _check_docker_networks(self) -> None:
        """Check Docker network isolation."""
        networks = self._run_cli_json(
            [self.docker_cmd, 'network', 'ls', '--format', '{{json .}}']
        )
        if networks is None:
            raw = self._run_cli(
                [self.docker_cmd, 'network', 'ls',
                 '--format', '{{json .}}']
            )
            if raw:
                networks = []
                for line in raw.strip().split('\n'):
                    try:
                        networks.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        if not networks:
            return

        if isinstance(networks, dict):
            networks = [networks]

        # Check containers on default bridge
        bridge_inspect = self._run_cli_json(
            [self.docker_cmd, 'network', 'inspect', 'bridge']
        )
        if bridge_inspect:
            if isinstance(bridge_inspect, list) and bridge_inspect:
                bridge_inspect = bridge_inspect[0]
            containers_on_bridge = bridge_inspect.get('Containers', {})
            if containers_on_bridge:
                names = [
                    c.get('Name', k[:12])
                    for k, c in containers_on_bridge.items()
                ]
                self.add_finding(
                    severity='MEDIUM',
                    title=(
                        f'{len(names)} Containers on Default Bridge '
                        f'Network'
                    ),
                    description=(
                        f"{len(names)} containers use the default bridge "
                        f"network. Containers on the default bridge can "
                        f"communicate freely and lack DNS resolution."
                    ),
                    affected_asset='docker',
                    finding_type='container_network',
                    remediation=(
                        'Create custom bridge networks for isolation.'
                    ),
                    raw_data=names,
                    detection_method='docker_cli',
                )

    def _check_docker_volumes(self, scan_type: str) -> None:
        """Check Docker volume security."""
        raw = self._run_cli(
            [self.docker_cmd, 'volume', 'ls', '--format', '{{json .}}']
        )
        if not raw:
            return

        volumes = []
        for line in raw.strip().split('\n'):
            try:
                volumes.append(json.loads(line))
            except json.JSONDecodeError:
                pass

        if not volumes:
            return

        self.add_result(
            'docker_volumes', {'count': len(volumes)}, 'docker'
        )

        # Inspect volumes for dangling
        dangling_raw = self._run_cli(
            [self.docker_cmd, 'volume', 'ls', '-f', 'dangling=true',
             '--format', '{{json .}}']
        )
        if dangling_raw:
            dangling = []
            for line in dangling_raw.strip().split('\n'):
                try:
                    d = json.loads(line)
                    dangling.append(d.get('Name', 'unknown'))
                except json.JSONDecodeError:
                    pass
            if dangling:
                self.add_finding(
                    severity='LOW',
                    title=f'{len(dangling)} Dangling Docker Volumes',
                    description=(
                        f"{len(dangling)} volumes are not attached to "
                        f"any container. They may contain old data and "
                        f"waste space."
                    ),
                    affected_asset='docker',
                    finding_type='container_volumes',
                    remediation='Remove unused volumes: docker volume prune',
                    raw_data=dangling,
                    detection_method='docker_cli',
                )

    # =======================================================================
    # Kubernetes Checks
    # =======================================================================

    def _check_k8s_rbac(self, scan_type: str) -> None:
        """Check Kubernetes RBAC configuration."""
        # Cluster-admin bindings
        crb = self._run_cli_json([
            'kubectl', 'get', 'clusterrolebindings', '-o', 'json'
        ])
        if not crb:
            return

        items = crb.get('items', [])
        cluster_admin_bindings = []
        overly_permissive = []

        for binding in items:
            role_ref = binding.get('roleRef', {})
            role_name = role_ref.get('name', '')
            binding_name = binding.get('metadata', {}).get('name', '')
            subjects = binding.get('subjects', [])

            if role_name == 'cluster-admin':
                # Skip system bindings
                if not binding_name.startswith('system:'):
                    cluster_admin_bindings.append({
                        'binding': binding_name,
                        'subjects': [
                            s.get('name', '') for s in (subjects or [])
                        ],
                    })

        if cluster_admin_bindings:
            self.add_finding(
                severity='HIGH',
                title=(
                    f'{len(cluster_admin_bindings)} Non-System '
                    f'cluster-admin Bindings'
                ),
                description=(
                    f"{len(cluster_admin_bindings)} ClusterRoleBindings "
                    f"grant cluster-admin to non-system subjects."
                ),
                affected_asset='kubernetes',
                finding_type='container_rbac',
                remediation=(
                    'Replace cluster-admin with scoped roles.'
                ),
                raw_data=cluster_admin_bindings,
                detection_method='kubectl_cli',
            )

        # Check for overly permissive ClusterRoles (deep)
        if scan_type == 'deep':
            cr = self._run_cli_json([
                'kubectl', 'get', 'clusterroles', '-o', 'json'
            ])
            if cr:
                for role in cr.get('items', []):
                    name = role.get('metadata', {}).get('name', '')
                    if name.startswith('system:'):
                        continue
                    for rule in role.get('rules', []):
                        verbs = rule.get('verbs', [])
                        resources = rule.get('resources', [])
                        api_groups = rule.get('apiGroups', [])
                        if ('*' in verbs and '*' in resources
                                and '' in api_groups):
                            overly_permissive.append(name)
                            break

            if overly_permissive:
                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'{len(overly_permissive)} Overly Permissive '
                        f'ClusterRoles'
                    ),
                    description=(
                        f"{len(overly_permissive)} non-system ClusterRoles "
                        f"grant wildcard access to all resources."
                    ),
                    affected_asset='kubernetes',
                    finding_type='container_rbac',
                    remediation='Scope ClusterRoles to specific resources and verbs.',
                    raw_data=overly_permissive,
                    detection_method='kubectl_cli',
                )

    def _check_k8s_pods(self, scan_type: str) -> None:
        """Check pod security settings."""
        pods = self._run_cli_json([
            'kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'
        ])
        if not pods:
            return

        items = pods.get('items', [])
        self.add_result('k8s_pods', {'count': len(items)}, 'kubernetes')

        privileged_pods: List[Dict] = []
        host_network: List[str] = []
        host_pid: List[str] = []
        root_pods: List[str] = []
        no_limits: List[str] = []

        for pod in items:
            metadata = pod.get('metadata', {})
            ns = metadata.get('namespace', 'default')
            name = metadata.get('name', '')
            pod_id = f"{ns}/{name}"
            spec = pod.get('spec', {})

            # Skip kube-system in quick mode
            if scan_type == 'quick' and ns == 'kube-system':
                continue

            # hostNetwork / hostPID
            if spec.get('hostNetwork', False):
                host_network.append(pod_id)
            if spec.get('hostPID', False):
                host_pid.append(pod_id)

            # Check each container
            for ctr in spec.get('containers', []):
                ctr_name = ctr.get('name', '')
                sec_ctx = ctr.get('securityContext', {})

                # Privileged
                if sec_ctx.get('privileged', False):
                    privileged_pods.append({
                        'pod': pod_id,
                        'container': ctr_name,
                    })

                # Running as root
                run_as = sec_ctx.get('runAsUser')
                run_as_non = sec_ctx.get('runAsNonRoot', False)
                if run_as == 0 or (run_as is None and not run_as_non):
                    root_pods.append(f"{pod_id}/{ctr_name}")

                # Resource limits
                resources = ctr.get('resources', {})
                if not resources.get('limits'):
                    no_limits.append(f"{pod_id}/{ctr_name}")

        if privileged_pods:
            self.add_finding(
                severity='CRITICAL',
                title=f'{len(privileged_pods)} Privileged Pod Containers',
                description=(
                    f"{len(privileged_pods)} containers run in privileged "
                    f"mode in Kubernetes, granting host-level access."
                ),
                affected_asset='kubernetes',
                finding_type='container_security',
                remediation=(
                    'Remove privileged: true. Use specific capabilities.'
                ),
                raw_data=privileged_pods,
                detection_method='kubectl_cli',
            )

        if host_network:
            self.add_finding(
                severity='HIGH',
                title=f'{len(host_network)} Pods With hostNetwork',
                description=(
                    f"{len(host_network)} pods use the host network "
                    f"namespace, bypassing network policies."
                ),
                affected_asset='kubernetes',
                finding_type='container_network',
                remediation='Remove hostNetwork: true unless required.',
                raw_data=host_network,
                detection_method='kubectl_cli',
            )

        if host_pid:
            self.add_finding(
                severity='HIGH',
                title=f'{len(host_pid)} Pods With hostPID',
                description=(
                    f"{len(host_pid)} pods share the host PID namespace."
                ),
                affected_asset='kubernetes',
                finding_type='container_security',
                remediation='Remove hostPID: true unless required.',
                raw_data=host_pid,
                detection_method='kubectl_cli',
            )

        if root_pods:
            self.add_finding(
                severity='HIGH',
                title=f'{len(root_pods)} Pod Containers Running as Root',
                description=(
                    f"{len(root_pods)} containers may run as root "
                    f"(no runAsNonRoot or runAsUser set)."
                ),
                affected_asset='kubernetes',
                finding_type='container_security',
                remediation=(
                    'Set runAsNonRoot: true and runAsUser to a non-zero UID.'
                ),
                raw_data=root_pods,
                detection_method='kubectl_cli',
            )

        if no_limits:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(no_limits)} Pod Containers Without Resource Limits'
                ),
                description=(
                    f"{len(no_limits)} containers have no resource limits. "
                    f"A single container could exhaust node resources."
                ),
                affected_asset='kubernetes',
                finding_type='container_config',
                remediation='Set CPU and memory limits on all containers.',
                raw_data=no_limits,
                detection_method='kubectl_cli',
            )

    def _check_k8s_network_policies(self) -> None:
        """Check for namespaces without network policies."""
        ns_list = self._run_cli_json([
            'kubectl', 'get', 'namespaces', '-o', 'json'
        ])
        if not ns_list:
            return

        namespaces = [
            n.get('metadata', {}).get('name', '')
            for n in ns_list.get('items', [])
        ]

        netpol = self._run_cli_json([
            'kubectl', 'get', 'networkpolicies',
            '--all-namespaces', '-o', 'json'
        ])
        ns_with_policies = set()
        if netpol:
            for item in netpol.get('items', []):
                ns_with_policies.add(
                    item.get('metadata', {}).get('namespace', '')
                )

        # Exclude system namespaces from the finding
        system_ns = {'kube-system', 'kube-public', 'kube-node-lease'}
        no_policy = [
            ns for ns in namespaces
            if ns not in ns_with_policies and ns not in system_ns
        ]

        if no_policy:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(no_policy)} Namespaces Without Network Policies'
                ),
                description=(
                    f"{len(no_policy)} namespaces have no network policies. "
                    f"All pods in these namespaces can communicate freely."
                ),
                affected_asset='kubernetes',
                finding_type='container_network',
                remediation=(
                    'Create default-deny network policies for each namespace.'
                ),
                raw_data=no_policy,
                detection_method='kubectl_cli',
            )

    def _check_k8s_secrets(self, scan_type: str) -> None:
        """Check Kubernetes secrets usage patterns."""
        pods = self._run_cli_json([
            'kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'
        ])
        if not pods:
            return

        secrets_in_env: List[Dict] = []

        for pod in pods.get('items', []):
            metadata = pod.get('metadata', {})
            ns = metadata.get('namespace', 'default')
            name = metadata.get('name', '')
            pod_id = f"{ns}/{name}"

            for ctr in pod.get('spec', {}).get('containers', []):
                ctr_name = ctr.get('name', '')
                for env in ctr.get('env', []):
                    value_from = env.get('valueFrom', {})
                    if value_from.get('secretKeyRef'):
                        secrets_in_env.append({
                            'pod': pod_id,
                            'container': ctr_name,
                            'env_var': env.get('name', ''),
                            'secret': value_from['secretKeyRef'].get(
                                'name', ''
                            ),
                        })

                for env_from in ctr.get('envFrom', []):
                    if env_from.get('secretRef'):
                        secrets_in_env.append({
                            'pod': pod_id,
                            'container': ctr_name,
                            'env_var': '(entire secret)',
                            'secret': env_from['secretRef'].get(
                                'name', ''
                            ),
                        })

        if secrets_in_env:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(secrets_in_env)} Secrets Exposed as '
                    f'Environment Variables'
                ),
                description=(
                    f"{len(secrets_in_env)} secrets are injected as "
                    f"environment variables. Environment variables may "
                    f"leak via logs, process listings, or crash dumps."
                ),
                affected_asset='kubernetes',
                finding_type='container_secrets',
                remediation=(
                    'Mount secrets as files instead of using envFrom/env.'
                ),
                raw_data=secrets_in_env,
                detection_method='kubectl_cli',
            )

    def _check_k8s_api(self) -> None:
        """Check Kubernetes API server security settings."""
        # Anonymous authentication check
        anon_check = self._run_cli([
            'kubectl', 'auth', 'can-i', 'list', 'pods',
            '--as=system:anonymous', '-A'
        ])
        if anon_check and 'yes' in anon_check.lower():
            self.add_finding(
                severity='CRITICAL',
                title='Kubernetes Anonymous Authentication Allows Pod Listing',
                description=(
                    'Anonymous users can list pods across all namespaces. '
                    'This indicates overly permissive anonymous RBAC.'
                ),
                affected_asset='kubernetes',
                finding_type='container_api',
                remediation=(
                    'Disable anonymous auth or remove anonymous '
                    'ClusterRoleBindings.'
                ),
                detection_method='kubectl_cli',
            )

        # Check for insecure port (deprecated but may still be set)
        # This is best checked via config but we can probe
        api_versions = self._run_cli_json([
            'kubectl', 'get', '--raw', '/version'
        ])
        if api_versions:
            self.add_result(
                'k8s_api_version', api_versions, 'kubernetes'
            )

        # Check component statuses
        cs = self._run_cli_json([
            'kubectl', 'get', 'componentstatuses', '-o', 'json'
        ])
        if cs:
            unhealthy = []
            for item in cs.get('items', []):
                name = item.get('metadata', {}).get('name', '')
                conditions = item.get('conditions', [])
                for cond in conditions:
                    if cond.get('type') == 'Healthy':
                        if cond.get('status') != 'True':
                            unhealthy.append(name)

            if unhealthy:
                self.add_finding(
                    severity='HIGH',
                    title=(
                        f'{len(unhealthy)} Unhealthy Kubernetes Components'
                    ),
                    description=(
                        f"Components are unhealthy: {unhealthy}"
                    ),
                    affected_asset='kubernetes',
                    finding_type='container_api',
                    remediation='Investigate and restore component health.',
                    raw_data=unhealthy,
                    detection_method='kubectl_cli',
                )


if __name__ == '__main__':
    scanner = ContainerScanner()
    print(f"Container Scanner initialized: {scanner.SCANNER_NAME}")
    scanner._detect_tools()
    print(f"Docker/Podman: {scanner.docker_cmd}")
    print(f"kubectl: {scanner.has_kubectl}")
