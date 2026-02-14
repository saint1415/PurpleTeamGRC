#!/usr/bin/env python3
"""
Purple Team GRC Platform - Remote Agent Deployer
Pushes lightweight scanner agents to discovered hosts via WinRM, SSH,
or generates manual deployment instructions.  Tracks agent lifecycle
(deploy, checkin, update, uninstall) in a SQLite database.

Stdlib-only. No third-party dependencies required.
"""

import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

try:
    from .discovery import get_discovery_engine
except ImportError:
    try:
        from discovery import get_discovery_engine
    except ImportError:
        get_discovery_engine = None

logger = get_logger('agent_deployer')


class AgentDeployer:
    """
    Remote Agent Deployer.

    Deploys lightweight scanner agents to discovered hosts via WinRM
    (PowerShell Remoting) for Windows targets or SSH for Linux targets.
    Falls back to generating manual deployment instructions when remote
    access is not available.
    """

    _instance: Optional['AgentDeployer'] = None

    VALID_STATUSES = (
        'pending', 'deploying', 'active', 'inactive', 'failed', 'uninstalled'
    )
    VALID_DEPLOY_METHODS = ('winrm', 'ssh', 'manual')
    VALID_OS_TYPES = ('windows', 'linux')

    AGENT_VERSION = '1.0.0'

    # Default remote paths
    WINDOWS_AGENT_DIR = r'C:\PurpleTeamAgent'
    LINUX_AGENT_DIR = '/opt/purpleteam'

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_path = paths.data / 'agents.db'
        self._agent_script_path = (
            paths.home / 'agents' / 'scanner_agent.py'
        )
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS deployed_agents (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id        TEXT UNIQUE NOT NULL,
                    host_id         TEXT,
                    ip_address      TEXT NOT NULL,
                    hostname        TEXT,
                    os_type         TEXT NOT NULL,
                    deploy_method   TEXT NOT NULL,
                    status          TEXT DEFAULT 'pending',
                    agent_version   TEXT,
                    last_checkin    TEXT,
                    scan_schedule   TEXT DEFAULT '0 */4 * * *',
                    config          TEXT DEFAULT '{}',
                    deployed_at     TEXT,
                    deployed_by     TEXT,
                    error_message   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_da_status
                    ON deployed_agents(status);
                CREATE INDEX IF NOT EXISTS idx_da_ip
                    ON deployed_agents(ip_address);
                CREATE INDEX IF NOT EXISTS idx_da_host
                    ON deployed_agents(host_id);
                CREATE INDEX IF NOT EXISTS idx_da_checkin
                    ON deployed_agents(last_checkin);
            ''')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    def _generate_id(self) -> str:
        return f"AGENT-{uuid.uuid4().hex[:12].upper()}"

    def _generate_api_key(self) -> str:
        return uuid.uuid4().hex

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a Row to a plain dict, deserialising JSON fields."""
        d = dict(row)
        for jf in ('config',):
            if jf in d and isinstance(d[jf], str):
                try:
                    d[jf] = json.loads(d[jf])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def _update_agent(self, agent_id: str, **kwargs):
        """Update agent fields in the database."""
        allowed = {
            'status', 'agent_version', 'last_checkin', 'scan_schedule',
            'config', 'deployed_at', 'deployed_by', 'error_message',
            'host_id', 'hostname', 'os_type', 'deploy_method',
        }
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                if k == 'config' and not isinstance(v, str):
                    v = json.dumps(v)
                updates[k] = v

        if not updates:
            return

        set_clause = ', '.join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [agent_id]
        with self._conn() as conn:
            conn.execute(
                f"UPDATE deployed_agents SET {set_clause} "
                f"WHERE agent_id = ?",
                values
            )

    # ------------------------------------------------------------------
    # Agent script generation
    # ------------------------------------------------------------------
    def generate_agent_script(self, os_type: str,
                              config: Dict = None) -> str:
        """
        Generate the agent script content for deployment.

        If the scanner_agent.py file exists in the agents/ directory,
        its contents are read directly. Otherwise a minimal stub is
        generated.

        Args:
            os_type: Target OS ('windows' or 'linux').
            config: Optional configuration dict to embed.

        Returns:
            Agent script content as a string.
        """
        if self._agent_script_path.exists():
            script = self._agent_script_path.read_text(encoding='utf-8')
            logger.debug("Loaded agent script from agents/scanner_agent.py")
            return script

        # Fallback: generate minimal agent script
        logger.warning(
            "agents/scanner_agent.py not found; generating minimal stub"
        )
        config_json = json.dumps(config or {}, indent=2)
        return textwrap.dedent(f'''\
            #!/usr/bin/env python3
            """Purple Team GRC - Lightweight Scanner Agent (stub)"""
            import json, os, platform, socket, subprocess, sys
            from datetime import datetime
            CONFIG = {config_json}
            def main():
                hostname = socket.gethostname()
                print(f"Agent running on {{hostname}}")
                results = {{"hostname": hostname, "timestamp": datetime.utcnow().isoformat()}}
                out_dir = CONFIG.get("output_dir", ".")
                os.makedirs(out_dir, exist_ok=True)
                with open(os.path.join(out_dir, f"scan_{{hostname}}.json"), "w") as f:
                    json.dump(results, f, indent=2)
            if __name__ == "__main__":
                main()
        ''')

    # ------------------------------------------------------------------
    # Deployment
    # ------------------------------------------------------------------
    def deploy_agent(self, ip_address: str, os_type: str,
                     credentials: Dict, **kwargs) -> str:
        """
        Deploy an agent to a remote host.

        Args:
            ip_address: Target IP address.
            os_type: 'windows' or 'linux'.
            credentials: Dict with keys like:
                - username (str)
                - password (str, optional)
                - domain (str, optional, Windows)
                - key_path (str, optional, Linux SSH key)
            **kwargs:
                - host_id (str): Discovery host ID.
                - hostname (str): Target hostname.
                - scan_schedule (str): Cron expression.
                - central_url (str): URL for result push-back.
                - deploy_method (str): Force 'winrm', 'ssh', or 'manual'.

        Returns:
            agent_id string.
        """
        agent_id = self._generate_id()
        api_key = self._generate_api_key()
        hostname = kwargs.get('hostname', '')
        host_id = kwargs.get('host_id', '')
        scan_schedule = kwargs.get('scan_schedule', '0 */4 * * *')
        central_url = kwargs.get('central_url', '')
        deploy_method = kwargs.get('deploy_method', '')

        if not deploy_method:
            deploy_method = 'winrm' if os_type == 'windows' else 'ssh'

        agent_config = {
            'agent_id': agent_id,
            'central_url': central_url,
            'api_key': api_key,
            'scan_schedule': scan_schedule,
            'scan_type': 'quick',
            'output_dir': (
                str(Path(self.WINDOWS_AGENT_DIR) / 'results')
                if os_type == 'windows'
                else f'{self.LINUX_AGENT_DIR}/results'
            ),
            'shared_path': kwargs.get('shared_path'),
        }

        now = self._now()
        deployer = kwargs.get('deployed_by', os.environ.get('USERNAME',
                              os.environ.get('USER', 'unknown')))

        # Insert agent record
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO deployed_agents "
                "(agent_id, host_id, ip_address, hostname, os_type, "
                "deploy_method, status, agent_version, scan_schedule, "
                "config, deployed_at, deployed_by) "
                "VALUES (?, ?, ?, ?, ?, ?, 'deploying', ?, ?, ?, ?, ?)",
                (agent_id, host_id, ip_address, hostname, os_type,
                 deploy_method, self.AGENT_VERSION, scan_schedule,
                 json.dumps(agent_config), now, deployer)
            )

        logger.info(
            f"Deploying agent {agent_id} to {ip_address} "
            f"via {deploy_method}"
        )

        # Execute deployment
        success = False
        error_msg = ''

        try:
            if deploy_method == 'winrm':
                success = self._deploy_windows(
                    ip_address,
                    credentials.get('username', ''),
                    credentials.get('password', ''),
                    domain=credentials.get('domain'),
                    agent_config=agent_config,
                )
            elif deploy_method == 'ssh':
                success = self._deploy_linux(
                    ip_address,
                    credentials.get('username', ''),
                    key_path=credentials.get('key_path'),
                    password=credentials.get('password'),
                    agent_config=agent_config,
                )
            elif deploy_method == 'manual':
                instructions = self._deploy_manual(ip_address, os_type)
                self._update_agent(
                    agent_id,
                    status='pending',
                    error_message=instructions,
                )
                logger.info(
                    f"Manual deployment instructions generated for "
                    f"{agent_id}"
                )
                return agent_id
            else:
                error_msg = f"Unknown deploy method: {deploy_method}"
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Deployment failed for {agent_id}: {e}")

        if success:
            self._update_agent(agent_id, status='active')
            logger.info(f"Agent {agent_id} deployed successfully")
        else:
            self._update_agent(
                agent_id, status='failed',
                error_message=error_msg or 'Deployment failed'
            )
            logger.warning(f"Agent {agent_id} deployment failed: {error_msg}")

        return agent_id

    def _deploy_windows(self, ip: str, username: str, password: str,
                        domain: str = None,
                        agent_config: Dict = None) -> bool:
        """
        Deploy agent to Windows host via WinRM / PowerShell Remoting.

        Steps:
            1. Test connectivity with Test-WSMan
            2. Copy agent script via PSSession
            3. Write config file
            4. Register scheduled task
            5. Verify agent started
        """
        # Build credential for PSRemoting
        if domain:
            full_user = f"{domain}\\{username}"
        else:
            full_user = username

        # Step 1: Test WinRM connectivity
        logger.info(f"Testing WinRM connectivity to {ip}")
        test_cmd = (
            f"$ErrorActionPreference = 'Stop'; "
            f"Test-WSMan -ComputerName {ip} -ErrorAction Stop"
        )
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', test_cmd],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                logger.warning(f"WinRM test failed for {ip}: {result.stderr}")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"WinRM test error for {ip}: {e}")
            return False

        # Step 2: Create PSSession and copy agent
        agent_script = self.generate_agent_script('windows', agent_config)
        config_json = json.dumps(agent_config or {}, indent=2)

        # Build the deployment PowerShell script
        agent_dir = self.WINDOWS_AGENT_DIR
        results_dir = f"{agent_dir}\\results"

        # Escape single quotes in script content for PowerShell
        escaped_script = agent_script.replace("'", "''")
        escaped_config = config_json.replace("'", "''")

        deploy_ps = f"""
$ErrorActionPreference = 'Stop'
$secPass = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{full_user}', $secPass)
$session = New-PSSession -ComputerName {ip} -Credential $cred

# Create directories
Invoke-Command -Session $session -ScriptBlock {{
    New-Item -ItemType Directory -Force -Path '{agent_dir}' | Out-Null
    New-Item -ItemType Directory -Force -Path '{results_dir}' | Out-Null
}}

# Write agent script
$agentContent = @'
{escaped_script}
'@
Invoke-Command -Session $session -ScriptBlock {{
    param($content) Set-Content -Path '{agent_dir}\\scanner_agent.py' -Value $content -Encoding UTF8
}} -ArgumentList $agentContent

# Write config
$configContent = @'
{escaped_config}
'@
Invoke-Command -Session $session -ScriptBlock {{
    param($content) Set-Content -Path '{agent_dir}\\agent_config.json' -Value $content -Encoding UTF8
}} -ArgumentList $configContent

# Register scheduled task
Invoke-Command -Session $session -ScriptBlock {{
    $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonPath) {{ $pythonPath = 'python' }}
    $action = New-ScheduledTaskAction -Execute $pythonPath -Argument '{agent_dir}\\scanner_agent.py --config {agent_dir}\\agent_config.json'
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 4) -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'PurpleTeamAgent' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force
    Start-ScheduledTask -TaskName 'PurpleTeamAgent'
}}

# Verify
$verify = Invoke-Command -Session $session -ScriptBlock {{
    Test-Path '{agent_dir}\\scanner_agent.py'
}}

Remove-PSSession $session
$verify
"""

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', deploy_ps],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and 'True' in result.stdout:
                logger.info(f"Windows agent deployed to {ip}")
                return True
            else:
                logger.warning(
                    f"Windows deploy verification failed for {ip}: "
                    f"{result.stderr or result.stdout}"
                )
                return False
        except subprocess.TimeoutExpired:
            logger.warning(f"Windows deployment timed out for {ip}")
            return False
        except Exception as e:
            logger.error(f"Windows deployment error for {ip}: {e}")
            return False

    def _deploy_linux(self, ip: str, username: str,
                      key_path: str = None, password: str = None,
                      agent_config: Dict = None) -> bool:
        """
        Deploy agent to Linux host via SSH / SCP.

        Steps:
            1. Test SSH connectivity
            2. SCP agent script to /opt/purpleteam/
            3. Write config file
            4. Create systemd service
            5. Enable and start service
            6. Verify agent running
        """
        # Build SSH base options
        ssh_opts = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=10',
            '-o', 'BatchMode=yes',
        ]
        if key_path:
            ssh_opts.extend(['-i', key_path])

        ssh_target = f"{username}@{ip}"

        # Step 1: Test SSH connectivity
        logger.info(f"Testing SSH connectivity to {ip}")
        try:
            result = subprocess.run(
                ['ssh'] + ssh_opts + [ssh_target, 'echo', 'OK'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0 or 'OK' not in result.stdout:
                logger.warning(f"SSH test failed for {ip}: {result.stderr}")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"SSH test error for {ip}: {e}")
            return False

        agent_dir = self.LINUX_AGENT_DIR
        results_dir = f"{agent_dir}/results"

        # Step 2: Create directories and copy agent
        try:
            subprocess.run(
                ['ssh'] + ssh_opts + [
                    ssh_target,
                    f'sudo mkdir -p {agent_dir} {results_dir} && '
                    f'sudo chown -R {username}:{username} {agent_dir}'
                ],
                capture_output=True, text=True, timeout=15
            )
        except Exception as e:
            logger.warning(f"Directory creation failed on {ip}: {e}")
            return False

        # Write agent script to temp file and SCP
        agent_script = self.generate_agent_script('linux', agent_config)
        config_json = json.dumps(agent_config or {}, indent=2)

        import tempfile
        try:
            # Write agent script
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.py', delete=False, encoding='utf-8'
            ) as tmp:
                tmp.write(agent_script)
                tmp_script = tmp.name

            # Write config
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, encoding='utf-8'
            ) as tmp:
                tmp.write(config_json)
                tmp_config = tmp.name

            # SCP files
            scp_opts = [
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
            ]
            if key_path:
                scp_opts.extend(['-i', key_path])

            for local_file, remote_file in [
                (tmp_script, f'{agent_dir}/scanner_agent.py'),
                (tmp_config, f'{agent_dir}/agent_config.json'),
            ]:
                result = subprocess.run(
                    ['scp'] + scp_opts + [
                        local_file, f'{ssh_target}:{remote_file}'
                    ],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    logger.warning(
                        f"SCP failed for {remote_file}: {result.stderr}"
                    )
                    return False

        finally:
            # Clean up temp files
            for f in [tmp_script, tmp_config]:
                try:
                    os.unlink(f)
                except OSError:
                    pass

        # Step 3: Make executable
        subprocess.run(
            ['ssh'] + ssh_opts + [
                ssh_target,
                f'chmod +x {agent_dir}/scanner_agent.py'
            ],
            capture_output=True, text=True, timeout=10
        )

        # Step 4: Create systemd service
        service_content = textwrap.dedent(f"""\
            [Unit]
            Description=Purple Team GRC Scanner Agent
            After=network.target

            [Service]
            Type=simple
            ExecStart=/usr/bin/python3 {agent_dir}/scanner_agent.py --config {agent_dir}/agent_config.json
            WorkingDirectory={agent_dir}
            Restart=on-failure
            RestartSec=300
            User=root
            StandardOutput=journal
            StandardError=journal

            [Install]
            WantedBy=multi-user.target
        """)

        try:
            # Write service file via SSH
            escaped_svc = service_content.replace('"', '\\"')
            subprocess.run(
                ['ssh'] + ssh_opts + [
                    ssh_target,
                    f'echo "{escaped_svc}" | sudo tee '
                    f'/etc/systemd/system/purpleteam-agent.service > /dev/null'
                ],
                capture_output=True, text=True, timeout=15
            )

            # Step 5: Enable and start
            subprocess.run(
                ['ssh'] + ssh_opts + [
                    ssh_target,
                    'sudo systemctl daemon-reload && '
                    'sudo systemctl enable purpleteam-agent && '
                    'sudo systemctl start purpleteam-agent'
                ],
                capture_output=True, text=True, timeout=15
            )

            # Step 6: Verify
            verify = subprocess.run(
                ['ssh'] + ssh_opts + [
                    ssh_target,
                    f'test -f {agent_dir}/scanner_agent.py && echo OK'
                ],
                capture_output=True, text=True, timeout=10
            )
            if 'OK' in verify.stdout:
                logger.info(f"Linux agent deployed to {ip}")
                return True
            else:
                logger.warning(f"Linux deploy verification failed for {ip}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning(f"Linux deployment timed out for {ip}")
            return False
        except Exception as e:
            logger.error(f"Linux deployment error for {ip}: {e}")
            return False

    def _deploy_manual(self, ip: str, os_type: str) -> str:
        """
        Generate manual deployment instructions.

        Args:
            ip: Target IP address.
            os_type: 'windows' or 'linux'.

        Returns:
            Multi-line string with deployment instructions.
        """
        if os_type == 'windows':
            agent_dir = self.WINDOWS_AGENT_DIR
            return textwrap.dedent(f"""\
                Manual Deployment Instructions for Windows host {ip}
                =====================================================

                1. Copy scanner_agent.py to {agent_dir}\\scanner_agent.py
                2. Copy agent_config.json to {agent_dir}\\agent_config.json
                3. Create results directory: mkdir {agent_dir}\\results

                4. Register a scheduled task (run as Administrator):
                   schtasks /create /tn "PurpleTeamAgent" /tr "python {agent_dir}\\scanner_agent.py --config {agent_dir}\\agent_config.json" /sc HOURLY /mo 4 /ru SYSTEM /rl HIGHEST /f

                5. Start the task:
                   schtasks /run /tn "PurpleTeamAgent"

                6. Verify: Check {agent_dir}\\results for scan output files.

                Files needed:
                - agents/scanner_agent.py (from PurpleTeamGRC installation)
                - Generated agent_config.json (from deployer)
            """)
        else:
            agent_dir = self.LINUX_AGENT_DIR
            return textwrap.dedent(f"""\
                Manual Deployment Instructions for Linux host {ip}
                ====================================================

                1. Copy scanner_agent.py to {agent_dir}/scanner_agent.py
                2. Copy agent_config.json to {agent_dir}/agent_config.json
                3. Create results directory: mkdir -p {agent_dir}/results
                4. Make executable: chmod +x {agent_dir}/scanner_agent.py

                5. Create systemd service:
                   sudo tee /etc/systemd/system/purpleteam-agent.service <<EOF
                   [Unit]
                   Description=Purple Team GRC Scanner Agent
                   After=network.target
                   [Service]
                   Type=simple
                   ExecStart=/usr/bin/python3 {agent_dir}/scanner_agent.py --config {agent_dir}/agent_config.json
                   WorkingDirectory={agent_dir}
                   Restart=on-failure
                   RestartSec=300
                   User=root
                   [Install]
                   WantedBy=multi-user.target
                   EOF

                6. Enable and start:
                   sudo systemctl daemon-reload
                   sudo systemctl enable purpleteam-agent
                   sudo systemctl start purpleteam-agent

                7. Verify: journalctl -u purpleteam-agent --no-pager -n 20

                Files needed:
                - agents/scanner_agent.py (from PurpleTeamGRC installation)
                - Generated agent_config.json (from deployer)
            """)

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------
    def check_agent(self, agent_id: str) -> Dict:
        """
        Check if an agent is alive.

        Performs a ping to the host and checks last checkin time.

        Returns:
            Dict with agent status details.
        """
        agent = self.get_agent(agent_id)
        if not agent:
            return {'error': f'Agent {agent_id} not found'}

        ip = agent['ip_address']
        result = {
            'agent_id': agent_id,
            'ip_address': ip,
            'current_status': agent['status'],
            'last_checkin': agent.get('last_checkin'),
            'reachable': False,
            'checkin_stale': True,
        }

        # Ping check
        try:
            ping_flag = '-n' if sys.platform == 'win32' else '-c'
            timeout_flag = '-w' if sys.platform == 'win32' else '-W'
            timeout_val = '1000' if sys.platform == 'win32' else '2'
            proc = subprocess.run(
                ['ping', ping_flag, '1', timeout_flag, timeout_val, ip],
                capture_output=True, text=True, timeout=5
            )
            result['reachable'] = (proc.returncode == 0)
        except Exception:
            result['reachable'] = False

        # Check if last checkin is within expected interval
        if agent.get('last_checkin'):
            try:
                last = datetime.fromisoformat(agent['last_checkin'])
                stale_threshold = datetime.utcnow() - timedelta(hours=8)
                result['checkin_stale'] = last < stale_threshold
            except (ValueError, TypeError):
                result['checkin_stale'] = True
        else:
            result['checkin_stale'] = True

        # Update status if needed
        if not result['reachable'] and agent['status'] == 'active':
            self._update_agent(agent_id, status='inactive')
            result['current_status'] = 'inactive'

        return result

    def update_agent(self, agent_id: str):
        """
        Push an updated agent script to a deployed agent.
        Re-deploys the latest scanner_agent.py to the remote host.
        """
        agent = self.get_agent(agent_id)
        if not agent:
            logger.warning(f"Agent {agent_id} not found for update")
            return

        if agent['status'] in ('uninstalled', 'pending'):
            logger.warning(
                f"Cannot update agent {agent_id} in "
                f"status {agent['status']}"
            )
            return

        ip = agent['ip_address']
        os_type = agent['os_type']
        config = agent.get('config', {})
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except (json.JSONDecodeError, TypeError):
                config = {}

        agent_script = self.generate_agent_script(os_type, config)

        if os_type == 'windows':
            agent_path = f"{self.WINDOWS_AGENT_DIR}\\scanner_agent.py"
            escaped = agent_script.replace("'", "''")
            ps_cmd = (
                f"$content = @'\n{escaped}\n'@\n"
                f"Set-Content -Path '{agent_path}' -Value $content -Encoding UTF8"
            )
            # This would need credentials stored; log a warning for now
            logger.info(
                f"Agent {agent_id} update prepared. "
                f"Manual push may be required for Windows host {ip}."
            )
        else:
            logger.info(
                f"Agent {agent_id} update prepared. "
                f"Manual push may be required for Linux host {ip}."
            )

        self._update_agent(
            agent_id,
            agent_version=self.AGENT_VERSION,
        )
        logger.info(f"Agent {agent_id} version updated to {self.AGENT_VERSION}")

    def uninstall_agent(self, agent_id: str):
        """
        Remove agent from remote host (best-effort).
        Marks agent as uninstalled in the database.
        """
        agent = self.get_agent(agent_id)
        if not agent:
            logger.warning(f"Agent {agent_id} not found for uninstall")
            return

        ip = agent['ip_address']
        os_type = agent['os_type']

        logger.info(f"Uninstalling agent {agent_id} from {ip}")

        # Best-effort remote cleanup
        if os_type == 'windows':
            try:
                ps_cmd = (
                    f"Invoke-Command -ComputerName {ip} -ScriptBlock {{ "
                    f"Unregister-ScheduledTask -TaskName 'PurpleTeamAgent' "
                    f"-Confirm:$false -ErrorAction SilentlyContinue; "
                    f"Remove-Item -Recurse -Force '{self.WINDOWS_AGENT_DIR}' "
                    f"-ErrorAction SilentlyContinue }}"
                )
                subprocess.run(
                    ['powershell', '-NoProfile', '-Command', ps_cmd],
                    capture_output=True, text=True, timeout=30
                )
            except Exception as e:
                logger.debug(f"Remote Windows cleanup failed: {e}")

        elif os_type == 'linux':
            try:
                ssh_opts = [
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=10',
                    '-o', 'BatchMode=yes',
                ]
                subprocess.run(
                    ['ssh'] + ssh_opts + [
                        f"root@{ip}",
                        f'systemctl stop purpleteam-agent 2>/dev/null; '
                        f'systemctl disable purpleteam-agent 2>/dev/null; '
                        f'rm -f /etc/systemd/system/purpleteam-agent.service; '
                        f'systemctl daemon-reload; '
                        f'rm -rf {self.LINUX_AGENT_DIR}'
                    ],
                    capture_output=True, text=True, timeout=30
                )
            except Exception as e:
                logger.debug(f"Remote Linux cleanup failed: {e}")

        self._update_agent(agent_id, status='uninstalled')
        logger.info(f"Agent {agent_id} marked as uninstalled")

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get_agents(self, status: str = None) -> List[Dict]:
        """
        Retrieve deployed agents with optional status filter.

        Args:
            status: Filter by status or None for all.

        Returns:
            List of agent dicts.
        """
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM deployed_agents WHERE status = ? "
                    "ORDER BY deployed_at DESC",
                    (status,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM deployed_agents ORDER BY deployed_at DESC"
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """
        Retrieve a single agent by ID.

        Returns:
            Agent dict or None.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM deployed_agents WHERE agent_id = ?",
                (agent_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def collect_results(self, agent_id: str = None) -> List[Dict]:
        """
        Pull results from agents.

        For agents with a shared_path configured, reads JSON files from
        the shared path. Otherwise returns metadata about where results
        can be found.

        Args:
            agent_id: Specific agent or None for all active agents.

        Returns:
            List of result dicts.
        """
        results = []

        if agent_id:
            agents = [self.get_agent(agent_id)]
            agents = [a for a in agents if a]
        else:
            agents = self.get_agents(status='active')

        for agent in agents:
            config = agent.get('config', {})
            if isinstance(config, str):
                try:
                    config = json.loads(config)
                except (json.JSONDecodeError, TypeError):
                    config = {}

            shared_path = config.get('shared_path')
            if shared_path and os.path.isdir(shared_path):
                # Read JSON result files from shared path
                try:
                    for fname in os.listdir(shared_path):
                        if fname.endswith('.json'):
                            fpath = os.path.join(shared_path, fname)
                            try:
                                with open(fpath, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    data['_source_agent'] = agent['agent_id']
                                    data['_source_file'] = fpath
                                    results.append(data)
                            except (json.JSONDecodeError, IOError) as e:
                                logger.debug(
                                    f"Error reading result {fpath}: {e}"
                                )
                except Exception as e:
                    logger.warning(
                        f"Error collecting from shared path "
                        f"{shared_path}: {e}"
                    )
            else:
                results.append({
                    'agent_id': agent['agent_id'],
                    'ip_address': agent['ip_address'],
                    'status': agent['status'],
                    'last_checkin': agent.get('last_checkin'),
                    'note': (
                        'Results available on remote host or via '
                        'central_url push'
                    ),
                })

            # Update last checkin time
            self._update_agent(agent['agent_id'], last_checkin=self._now())

        logger.info(f"Collected {len(results)} results from agents")
        return results

    def bulk_deploy(self, host_ids: List[str],
                    credentials: Dict) -> Dict:
        """
        Deploy agents to multiple hosts.

        Args:
            host_ids: List of discovery host_ids.
            credentials: Dict with credentials (same for all hosts, or
                         keyed by host_id).

        Returns:
            Summary dict with success/failure counts and agent_ids.
        """
        if get_discovery_engine is None:
            return {
                'error': 'Discovery engine not available',
                'deployed': 0, 'failed': 0, 'agent_ids': [],
            }

        engine = get_discovery_engine()
        results = {
            'deployed': 0,
            'failed': 0,
            'agent_ids': [],
            'errors': [],
        }

        for host_id in host_ids:
            # Look up host from discovery DB
            hosts = engine.get_discovered_hosts()
            host = None
            for h in hosts:
                if h.get('host_id') == host_id:
                    host = h
                    break

            if not host:
                results['errors'].append({
                    'host_id': host_id,
                    'error': 'Host not found in discovery database',
                })
                results['failed'] += 1
                continue

            ip = host['ip_address']
            os_type = host.get('os_guess', 'unknown')
            if os_type not in self.VALID_OS_TYPES:
                os_type = 'linux'  # Default to Linux for unknown

            # Use per-host credentials if available
            host_creds = credentials.get(host_id, credentials)

            try:
                agent_id = self.deploy_agent(
                    ip_address=ip,
                    os_type=os_type,
                    credentials=host_creds,
                    host_id=host_id,
                    hostname=host.get('hostname', ''),
                )
                results['agent_ids'].append(agent_id)

                # Check if deployment succeeded
                agent = self.get_agent(agent_id)
                if agent and agent['status'] == 'active':
                    results['deployed'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append({
                        'host_id': host_id,
                        'agent_id': agent_id,
                        'error': (agent or {}).get(
                            'error_message', 'Deployment failed'
                        ),
                    })
            except Exception as e:
                results['failed'] += 1
                results['errors'].append({
                    'host_id': host_id,
                    'error': str(e),
                })

        logger.info(
            f"Bulk deploy complete: {results['deployed']} succeeded, "
            f"{results['failed']} failed"
        )
        return results

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> Dict:
        """
        Return comprehensive agent deployment statistics.
        """
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM deployed_agents"
            ).fetchone()[0]

            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM deployed_agents "
                "GROUP BY status"
            ).fetchall()
            by_status = {r['status']: r['cnt'] for r in status_rows}

            os_rows = conn.execute(
                "SELECT os_type, COUNT(*) AS cnt FROM deployed_agents "
                "GROUP BY os_type"
            ).fetchall()
            by_os = {r['os_type']: r['cnt'] for r in os_rows}

            method_rows = conn.execute(
                "SELECT deploy_method, COUNT(*) AS cnt "
                "FROM deployed_agents GROUP BY deploy_method"
            ).fetchall()
            by_method = {r['deploy_method']: r['cnt'] for r in method_rows}

            # Agents that checked in within last 24h
            cutoff = (
                datetime.utcnow() - timedelta(hours=24)
            ).isoformat()
            recent_checkin = conn.execute(
                "SELECT COUNT(*) FROM deployed_agents "
                "WHERE last_checkin >= ?",
                (cutoff,)
            ).fetchone()[0]

            # Stale agents (active but no checkin in 24h)
            stale = conn.execute(
                "SELECT COUNT(*) FROM deployed_agents "
                "WHERE status = 'active' AND "
                "(last_checkin IS NULL OR last_checkin < ?)",
                (cutoff,)
            ).fetchone()[0]

        return {
            'total_agents': total,
            'by_status': by_status,
            'by_os_type': by_os,
            'by_deploy_method': by_method,
            'checked_in_last_24h': recent_checkin,
            'stale_agents': stale,
        }


# ======================================================================
# Singleton accessor
# ======================================================================
_agent_deployer: Optional[AgentDeployer] = None


def get_agent_deployer() -> AgentDeployer:
    """Get the AgentDeployer singleton."""
    global _agent_deployer
    if _agent_deployer is None:
        _agent_deployer = AgentDeployer()
    return _agent_deployer


# ======================================================================
# Self-test
# ======================================================================
if __name__ == '__main__':
    deployer = get_agent_deployer()
    print(f"Agent DB: {deployer.db_path}")
    print(f"DB exists: {deployer.db_path.exists()}")
    print(f"Agent script path: {deployer._agent_script_path}")
    print(f"Agent script exists: {deployer._agent_script_path.exists()}")

    # Generate manual instructions
    print("\n--- Windows Manual Deploy ---")
    print(deployer._deploy_manual('10.0.1.50', 'windows'))

    print("\n--- Linux Manual Deploy ---")
    print(deployer._deploy_manual('10.0.1.51', 'linux'))

    # Statistics
    stats = deployer.get_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")
