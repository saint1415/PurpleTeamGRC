#!/usr/bin/env python3
"""
Purple Team Platform - Tool Discovery & Management
Auto-detect available security tools and provide installation guidance.
Systems Thinking: Openness - adapt to available tools in the environment.
"""

import os
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable

try:
    from .tui import tui, C
except ImportError:
    from tui import tui, C

try:
    from .paths import paths
except ImportError:
    from paths import paths


@dataclass
class ToolInfo:
    """Information about a security tool."""
    name: str
    description: str
    category: str
    required: bool = False
    check_cmd: str = None  # Command to verify installation
    version_cmd: str = None  # Command to get version
    install_apt: str = None  # apt package name
    install_cmd: str = None  # Alternative install command
    install_cmd_windows: str = None  # Windows install command (winget/choco)
    install_url: str = None  # Documentation/download URL
    path: Optional[str] = None
    version: Optional[str] = None
    available: bool = False
    in_tools_dir: bool = False  # Installed in our tools/ directory


# Tool definitions organized by category
TOOLS: Dict[str, ToolInfo] = {
    # === SCANNING & RECONNAISSANCE ===
    'nmap': ToolInfo(
        name='nmap',
        description='Network exploration and port scanning',
        category='Scanning',
        required=True,
        check_cmd='nmap --version',
        version_cmd='nmap --version | head -1',
        install_apt='nmap',
    ),
    'masscan': ToolInfo(
        name='masscan',
        description='Fast port scanner (async)',
        category='Scanning',
        check_cmd='masscan --version',
        version_cmd='masscan --version 2>&1 | head -1',
        install_apt='masscan',
    ),
    'nikto': ToolInfo(
        name='nikto',
        description='Web server vulnerability scanner',
        category='Scanning',
        required=True,
        check_cmd='nikto -Version',
        version_cmd='nikto -Version 2>&1 | grep -i version | head -1',
        install_apt='nikto',
    ),
    'nuclei': ToolInfo(
        name='nuclei',
        description='Template-based vulnerability scanner',
        category='Scanning',
        required=True,
        check_cmd='nuclei -version',
        version_cmd='nuclei -version 2>&1 | head -1',
        install_apt='nuclei',
        install_cmd='go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        install_url='https://github.com/projectdiscovery/nuclei/releases',
    ),
    'testssl.sh': ToolInfo(
        name='testssl.sh',
        description='SSL/TLS configuration testing',
        category='Scanning',
        required=True,
        check_cmd='testssl.sh --version',
        version_cmd='testssl.sh --version 2>&1 | head -1',
        install_apt='testssl.sh',
        install_url='https://github.com/drwetter/testssl.sh',
    ),
    'wpscan': ToolInfo(
        name='wpscan',
        description='WordPress security scanner',
        category='Scanning',
        check_cmd='wpscan --version',
        version_cmd='wpscan --version 2>&1 | head -1',
        install_apt='wpscan',
    ),

    # === VULNERABILITY ASSESSMENT ===
    'openvas': ToolInfo(
        name='openvas',
        description='Open Vulnerability Assessment Scanner',
        category='Vulnerability',
        check_cmd='gvm-check-setup 2>/dev/null || openvas-check-setup 2>/dev/null',
        install_apt='openvas',
        install_url='https://greenbone.github.io/docs/',
    ),
    'lynis': ToolInfo(
        name='lynis',
        description='Security auditing and hardening',
        category='Vulnerability',
        check_cmd='lynis --version',
        version_cmd='lynis --version 2>&1 | head -1',
        install_apt='lynis',
    ),
    'trivy': ToolInfo(
        name='trivy',
        description='Container/filesystem vulnerability scanner',
        category='Vulnerability',
        check_cmd='trivy --version',
        version_cmd='trivy --version 2>&1 | head -1',
        install_url='https://github.com/aquasecurity/trivy',
    ),

    # === RED TEAM / ATTACK SIMULATION ===
    'metasploit': ToolInfo(
        name='metasploit',
        description='Penetration testing framework',
        category='Red Team',
        check_cmd='msfconsole --version',
        version_cmd='msfconsole --version 2>&1 | head -1',
        install_apt='metasploit-framework',
    ),
    'caldera': ToolInfo(
        name='caldera',
        description='MITRE ATT&CK automation platform',
        category='Red Team',
        check_cmd='test -d /opt/caldera || test -d ~/caldera',
        install_url='https://github.com/mitre/caldera',
    ),
    'atomic-red-team': ToolInfo(
        name='atomic-red-team',
        description='ATT&CK technique testing library',
        category='Red Team',
        check_cmd='test -d /opt/atomic-red-team || test -d ~/AtomicRedTeam',
        install_url='https://github.com/redcanaryco/atomic-red-team',
    ),
    'crackmapexec': ToolInfo(
        name='crackmapexec',
        description='Network protocol attack tool',
        category='Red Team',
        check_cmd='crackmapexec --version',
        version_cmd='crackmapexec --version 2>&1 | head -1',
        install_apt='crackmapexec',
    ),
    'impacket': ToolInfo(
        name='impacket',
        description='Network protocol tools',
        category='Red Team',
        check_cmd='python3 -c "import impacket" 2>/dev/null',
        install_apt='python3-impacket',
    ),
    'bloodhound': ToolInfo(
        name='bloodhound',
        description='Active Directory attack path analysis',
        category='Red Team',
        check_cmd='bloodhound --version 2>/dev/null || test -f /opt/BloodHound/BloodHound',
        install_apt='bloodhound',
    ),

    # === BLUE TEAM / DETECTION ===
    'yara': ToolInfo(
        name='yara',
        description='Malware pattern matching',
        category='Blue Team',
        check_cmd='yara --version',
        version_cmd='yara --version 2>&1',
        install_apt='yara',
    ),
    'clamav': ToolInfo(
        name='clamav',
        description='Antivirus engine',
        category='Blue Team',
        check_cmd='clamscan --version',
        version_cmd='clamscan --version 2>&1 | head -1',
        install_apt='clamav',
    ),
    'rkhunter': ToolInfo(
        name='rkhunter',
        description='Rootkit detection',
        category='Blue Team',
        check_cmd='rkhunter --version',
        version_cmd='rkhunter --version 2>&1 | head -1',
        install_apt='rkhunter',
    ),
    'chkrootkit': ToolInfo(
        name='chkrootkit',
        description='Rootkit checker',
        category='Blue Team',
        check_cmd='chkrootkit -V',
        version_cmd='chkrootkit -V 2>&1 | head -1',
        install_apt='chkrootkit',
    ),
    'aide': ToolInfo(
        name='aide',
        description='File integrity monitoring',
        category='Blue Team',
        check_cmd='aide --version',
        version_cmd='aide --version 2>&1 | head -1',
        install_apt='aide',
    ),
    'suricata': ToolInfo(
        name='suricata',
        description='Network IDS/IPS',
        category='Blue Team',
        check_cmd='suricata --build-info',
        version_cmd='suricata -V 2>&1 | head -1',
        install_apt='suricata',
    ),
    'zeek': ToolInfo(
        name='zeek',
        description='Network analysis framework',
        category='Blue Team',
        check_cmd='zeek --version',
        version_cmd='zeek --version 2>&1 | head -1',
        install_apt='zeek',
    ),

    # === FORENSICS ===
    'volatility': ToolInfo(
        name='volatility',
        description='Memory forensics',
        category='Forensics',
        check_cmd='vol.py --help 2>/dev/null || volatility --help 2>/dev/null',
        install_apt='volatility3',
    ),
    'autopsy': ToolInfo(
        name='autopsy',
        description='Digital forensics platform',
        category='Forensics',
        check_cmd='test -f /usr/bin/autopsy || test -d /opt/autopsy',
        install_apt='autopsy',
    ),
    'binwalk': ToolInfo(
        name='binwalk',
        description='Firmware analysis',
        category='Forensics',
        check_cmd='binwalk --help',
        version_cmd='binwalk --help 2>&1 | head -1',
        install_apt='binwalk',
    ),

    # === NETWORK ANALYSIS ===
    'wireshark': ToolInfo(
        name='wireshark',
        description='Network protocol analyzer',
        category='Network',
        check_cmd='tshark --version',
        version_cmd='tshark --version 2>&1 | head -1',
        install_apt='wireshark',
    ),
    'tcpdump': ToolInfo(
        name='tcpdump',
        description='Packet capture utility',
        category='Network',
        check_cmd='tcpdump --version',
        version_cmd='tcpdump --version 2>&1 | head -1',
        install_apt='tcpdump',
    ),

    # === PASSWORD / CRYPTO ===
    'hashcat': ToolInfo(
        name='hashcat',
        description='Password recovery',
        category='Crypto',
        check_cmd='hashcat --version',
        version_cmd='hashcat --version 2>&1',
        install_apt='hashcat',
    ),
    'john': ToolInfo(
        name='john',
        description='John the Ripper password cracker',
        category='Crypto',
        check_cmd='john --help',
        version_cmd='john --help 2>&1 | head -1',
        install_apt='john',
    ),
    'hydra': ToolInfo(
        name='hydra',
        description='Network login cracker',
        category='Crypto',
        check_cmd='hydra -h',
        version_cmd='hydra -h 2>&1 | head -1',
        install_apt='hydra',
    ),

    # === OSINT ===
    'amass': ToolInfo(
        name='amass',
        description='Attack surface mapping',
        category='OSINT',
        check_cmd='amass -version',
        version_cmd='amass -version 2>&1',
        install_apt='amass',
    ),
    'theharvester': ToolInfo(
        name='theharvester',
        description='Email/subdomain harvester',
        category='OSINT',
        check_cmd='theHarvester -h 2>/dev/null || theharvester -h 2>/dev/null',
        install_apt='theharvester',
    ),
    'maltego': ToolInfo(
        name='maltego',
        description='OSINT and forensics platform',
        category='OSINT',
        check_cmd='test -f /usr/bin/maltego || test -d /opt/Maltego',
        install_apt='maltego',
    ),

    # === WEB APPLICATION ===
    'burpsuite': ToolInfo(
        name='burpsuite',
        description='Web application security testing',
        category='Web',
        check_cmd='test -f /usr/bin/burpsuite || test -d /opt/BurpSuite',
        install_apt='burpsuite',
    ),
    'zaproxy': ToolInfo(
        name='zaproxy',
        description='OWASP ZAP web scanner',
        category='Web',
        check_cmd='zap.sh -version 2>/dev/null || test -d /usr/share/zaproxy',
        install_apt='zaproxy',
    ),
    'sqlmap': ToolInfo(
        name='sqlmap',
        description='SQL injection detection',
        category='Web',
        check_cmd='sqlmap --version',
        version_cmd='sqlmap --version 2>&1 | head -1',
        install_apt='sqlmap',
    ),
    'gobuster': ToolInfo(
        name='gobuster',
        description='Directory/DNS bruteforcing',
        category='Web',
        check_cmd='gobuster --help',
        version_cmd='gobuster --help 2>&1 | head -1',
        install_apt='gobuster',
    ),
    'dirb': ToolInfo(
        name='dirb',
        description='Web content scanner',
        category='Web',
        check_cmd='dirb 2>&1 | head -1',
        install_apt='dirb',
    ),

    # === WINDOWS SYSINTERNALS (portable, bundled via bundle-tools.py) ===
    'sigcheck': ToolInfo(
        name='sigcheck',
        description='File signature verification',
        category='Windows Sysinternals',
        check_cmd='sigcheck64.exe -nobanner -accepteula /?',
    ),
    'autoruns': ToolInfo(
        name='autoruns',
        description='Autostart entry analysis (persistence detection)',
        category='Windows Sysinternals',
        check_cmd='autorunsc64.exe -accepteula /?',
    ),
    'tcpview': ToolInfo(
        name='tcpview',
        description='TCP/UDP endpoint viewer',
        category='Windows Sysinternals',
        check_cmd='tcpvcon.exe -accepteula /?',
    ),
    'accesschk': ToolInfo(
        name='accesschk',
        description='Permission and access auditing',
        category='Windows Sysinternals',
        check_cmd='accesschk64.exe -accepteula /?',
    ),
    'handle': ToolInfo(
        name='handle',
        description='Open handle listing',
        category='Windows Sysinternals',
        check_cmd='handle64.exe -accepteula /?',
    ),
    'strings_sys': ToolInfo(
        name='strings_sys',
        description='Binary string extraction',
        category='Windows Sysinternals',
        check_cmd='strings64.exe -accepteula /?',
    ),
    'listdlls': ToolInfo(
        name='listdlls',
        description='Loaded DLL listing (DLL hijacking detection)',
        category='Windows Sysinternals',
        check_cmd='listdlls64.exe -accepteula /?',
    ),
}


class ToolDiscovery:
    """Discover and manage security tools."""

    def __init__(self):
        self.tools = TOOLS.copy()
        self.discovered = False
        self._check_local_tools_dir()

    def _check_local_tools_dir(self):
        """Check for tools in our local tools directory."""
        tools_dir = paths.home / 'tools'
        if not tools_dir.exists():
            return

        # Check for nuclei
        for name in ('nuclei', 'nuclei.exe'):
            nuclei_path = tools_dir / name
            if nuclei_path.exists():
                self.tools['nuclei'].in_tools_dir = True
                self.tools['nuclei'].path = str(nuclei_path)
                break

        # Check for testssl.sh
        testssl_path = tools_dir / 'testssl.sh' / 'testssl.sh'
        if not testssl_path.exists():
            testssl_path = tools_dir / 'testssl' / 'testssl.sh'
        if testssl_path.exists():
            self.tools['testssl.sh'].in_tools_dir = True
            self.tools['testssl.sh'].path = str(testssl_path)

        # Check for nmap portable
        nmap_path = tools_dir / 'nmap' / 'nmap.exe'
        if nmap_path.exists():
            self.tools['nmap'].in_tools_dir = True
            self.tools['nmap'].path = str(nmap_path)

        # Check for YARA
        for name in ('yara' / Path('yara64.exe'), 'yara' / Path('yara.exe')):
            yara_path = tools_dir / name
            if yara_path.exists():
                if 'yara' in self.tools:
                    self.tools['yara'].in_tools_dir = True
                    self.tools['yara'].path = str(yara_path)
                break

        # Check for gobuster
        gobuster_dir = tools_dir / 'gobuster'
        if gobuster_dir.exists():
            for name in ('gobuster.exe', 'gobuster'):
                gob_path = gobuster_dir / name
                if gob_path.exists():
                    self.tools['gobuster'].in_tools_dir = True
                    self.tools['gobuster'].path = str(gob_path)
                    break

        # Check for amass
        amass_dir = tools_dir / 'amass'
        if amass_dir.exists():
            for name in ('amass.exe', 'amass'):
                amass_path = amass_dir / name
                if amass_path.exists():
                    self.tools['amass'].in_tools_dir = True
                    self.tools['amass'].path = str(amass_path)
                    break

        # Check for Sysinternals tools
        sysinternals_dir = tools_dir / 'sysinternals'
        if sysinternals_dir.exists():
            sysinternals_map = {
                'sigcheck': ['sigcheck64.exe', 'sigcheck.exe'],
                'autoruns': ['autorunsc64.exe', 'autorunsc.exe'],
                'tcpview': ['tcpvcon.exe', 'tcpview.exe'],
                'accesschk': ['accesschk64.exe', 'accesschk.exe'],
                'handle': ['handle64.exe', 'handle.exe'],
                'strings_sys': ['strings64.exe', 'strings.exe'],
                'listdlls': ['listdlls64.exe', 'listdlls.exe'],
            }
            for tool_name, exe_names in sysinternals_map.items():
                if tool_name in self.tools:
                    for exe_name in exe_names:
                        exe_path = sysinternals_dir / exe_name
                        if exe_path.exists():
                            self.tools[tool_name].in_tools_dir = True
                            self.tools[tool_name].path = str(exe_path)
                            break

    def _run_cmd(self, cmd: str) -> tuple:
        """Run a command and return (success, output).
        Uses shell=False with shlex for security when possible.
        Falls back to shell=True for commands requiring shell features.
        """
        import shlex
        import sys as _sys

        try:
            # Use shell=False when possible (security fix)
            if _sys.platform != 'win32' and not any(c in cmd for c in ['|', '&&', '||', '>', '<', ';', '2>']):
                args = shlex.split(cmd)
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "timeout"
        except Exception as e:
            return False, str(e)

    def check_tool(self, name: str) -> bool:
        """Check if a specific tool is available."""
        if name not in self.tools:
            return False

        tool = self.tools[name]

        # First check if it's in our tools directory
        if tool.in_tools_dir and tool.path:
            tool.available = True
            if tool.version_cmd:
                version_cmd = tool.version_cmd.replace(name, tool.path)
                success, output = self._run_cmd(version_cmd)
                if success:
                    tool.version = output
            return True

        # Check Windows-specific paths
        import sys as _sys
        if _sys.platform == 'win32':
            win_paths = self._get_windows_tool_paths(name)
            for wp in win_paths:
                if wp.exists():
                    tool.path = str(wp)
                    tool.available = True
                    return True

        # Check via which
        path = shutil.which(name)
        if path:
            tool.path = path
            tool.available = True

            # Get version if possible
            if tool.version_cmd:
                success, output = self._run_cmd(tool.version_cmd)
                if success:
                    tool.version = output
            return True

        # Check via check command
        if tool.check_cmd:
            success, _ = self._run_cmd(tool.check_cmd)
            if success:
                tool.available = True
                return True

        tool.available = False
        return False

    def discover_all(self, show_progress: bool = True) -> Dict[str, ToolInfo]:
        """Discover all tools."""
        total = len(self.tools)

        for i, name in enumerate(self.tools.keys()):
            if show_progress:
                tui.progress_bar(i + 1, total, label="Discovering tools")
            self.check_tool(name)

        if show_progress:
            print()  # New line after progress bar

        self.discovered = True
        return self.tools

    def get_available(self) -> Dict[str, ToolInfo]:
        """Get all available tools."""
        if not self.discovered:
            self.discover_all(show_progress=False)
        return {k: v for k, v in self.tools.items() if v.available}

    def get_missing(self) -> Dict[str, ToolInfo]:
        """Get all missing tools."""
        if not self.discovered:
            self.discover_all(show_progress=False)
        return {k: v for k, v in self.tools.items() if not v.available}

    def get_required_missing(self) -> Dict[str, ToolInfo]:
        """Get missing required tools."""
        if not self.discovered:
            self.discover_all(show_progress=False)
        return {k: v for k, v in self.tools.items() if v.required and not v.available}

    def get_by_category(self) -> Dict[str, List[ToolInfo]]:
        """Get tools organized by category."""
        categories = {}
        for tool in self.tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)
        return categories

    def display_status(self):
        """Display tool discovery status."""
        if not self.discovered:
            self.discover_all()

        categories = self.get_by_category()

        for category, tools in sorted(categories.items()):
            available = [t for t in tools if t.available]
            missing = [t for t in tools if not t.available]

            color = C.GREEN if len(missing) == 0 else (C.YELLOW if len(available) > 0 else C.RED)
            tui.section(f"{category} ({len(available)}/{len(tools)})", color)

            for tool in sorted(tools, key=lambda t: t.name):
                if tool.available:
                    version = f" ({tool.version})" if tool.version else ""
                    location = f" [{tool.path}]" if tool.path else ""
                    tui.status(tool.name, f"{tool.description}{version}", ok=True)
                else:
                    tui.status(tool.name, f"{tool.description} - NOT FOUND", ok=False)

            tui.section_end(color)

    def _get_windows_tool_paths(self, name: str) -> list:
        """Get Windows-specific tool installation paths."""
        from pathlib import Path as WinPath
        prog = os.environ.get('ProgramFiles', r'C:\Program Files')
        prog_x86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')
        local = os.environ.get('LOCALAPPDATA', '')

        win_paths = {
            'nmap': [
                WinPath(prog) / 'Nmap' / 'nmap.exe',
                WinPath(prog_x86) / 'Nmap' / 'nmap.exe',
            ],
            'wireshark': [
                WinPath(prog) / 'Wireshark' / 'tshark.exe',
            ],
            'openvas': [
                WinPath(prog) / 'Greenbone' / 'gvm-cli.exe',
            ],
        }

        return win_paths.get(name, [])

    def install_tool(self, name: str) -> bool:
        """Attempt to install a tool."""
        if name not in self.tools:
            tui.error(f"Unknown tool: {name}")
            return False

        tool = self.tools[name]
        tui.info(f"Installing {tool.name}...")

        import sys as _sys

        # Try Windows package managers first
        if _sys.platform == 'win32':
            if tool.install_cmd_windows:
                tui.info(f"Installing via Windows: {tool.install_cmd_windows}")
                result = subprocess.run(tool.install_cmd_windows, shell=True)
                if result.returncode == 0:
                    self.check_tool(name)
                    if tool.available:
                        tui.success(f"{tool.name} installed successfully")
                        return True
            elif shutil.which('winget'):
                tui.info(f"Trying winget install: {tool.name}")
                result = subprocess.run(f"winget install {tool.name}", shell=True)
                if result.returncode == 0:
                    self.check_tool(name)
                    if tool.available:
                        tui.success(f"{tool.name} installed successfully")
                        return True

        # Try apt first (Linux)
        if tool.install_apt:
            if shutil.which('apt'):
                tui.info(f"Installing via apt: {tool.install_apt}")
                result = subprocess.run(
                    f"sudo apt update && sudo apt install -y {tool.install_apt}",
                    shell=True
                )
                if result.returncode == 0:
                    self.check_tool(name)
                    if tool.available:
                        tui.success(f"{tool.name} installed successfully")
                        return True

        # Try install command
        if tool.install_cmd:
            tui.info(f"Running: {tool.install_cmd}")
            result = subprocess.run(tool.install_cmd, shell=True)
            if result.returncode == 0:
                self.check_tool(name)
                if tool.available:
                    tui.success(f"{tool.name} installed successfully")
                    return True

        # Provide manual instructions
        tui.warning(f"Automatic installation failed for {tool.name}")
        if tool.install_url:
            tui.info(f"Manual installation: {tool.install_url}")
        if tool.install_apt and _sys.platform != 'win32':
            tui.info(f"Try: sudo apt install {tool.install_apt}")

        return False

    def install_required(self) -> bool:
        """Install all missing required tools."""
        missing = self.get_required_missing()
        if not missing:
            tui.success("All required tools are installed")
            return True

        tui.warning(f"Missing {len(missing)} required tools: {', '.join(missing.keys())}")

        all_success = True
        for name in missing:
            if not self.install_tool(name):
                all_success = False

        return all_success


# Singleton instance
tool_discovery = ToolDiscovery()


if __name__ == "__main__":
    # Demo
    tui.banner("TOOL DISCOVERY", "Scanning system for security tools")
    print()
    tool_discovery.discover_all()
    print()
    tool_discovery.display_status()

    print()
    available = tool_discovery.get_available()
    missing = tool_discovery.get_missing()
    required_missing = tool_discovery.get_required_missing()

    tui.info(f"Available: {len(available)} tools")
    tui.info(f"Missing: {len(missing)} tools")
    if required_missing:
        tui.warning(f"Missing required: {', '.join(required_missing.keys())}")
