#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Platform Detection
Cross-platform support for Windows 11, Linux, and macOS.
Deployment mode detection: portable (USB), installed, cicd.
"""

import os
import sys
import platform
import ctypes
import shutil
from pathlib import Path
from typing import Optional

try:
    from .logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger('platform')


class PlatformInfo:
    """Detects and provides platform-specific information."""

    _instance: Optional['PlatformInfo'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self._os = platform.system().lower()
        self._arch = platform.machine()
        self._release = platform.release()
        self._version = platform.version()
        self._is_wsl = self._detect_wsl()
        self._is_admin = self._detect_admin()

    def _detect_wsl(self) -> bool:
        """Detect if running under Windows Subsystem for Linux."""
        if self._os != 'linux':
            return False
        try:
            with open('/proc/version', 'r') as f:
                version = f.read().lower()
                return 'microsoft' in version or 'wsl' in version
        except (OSError, IOError):
            return False

    def _detect_admin(self) -> bool:
        """Detect if running with admin/root privileges."""
        if self._os == 'windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except (AttributeError, OSError):
                return False
        else:
            return os.geteuid() == 0

    @property
    def is_windows(self) -> bool:
        return self._os == 'windows'

    @property
    def is_linux(self) -> bool:
        return self._os == 'linux'

    @property
    def is_macos(self) -> bool:
        return self._os == 'darwin'

    @property
    def is_wsl(self) -> bool:
        return self._is_wsl

    @property
    def is_admin(self) -> bool:
        return self._is_admin

    @property
    def os_name(self) -> str:
        if self.is_windows:
            return 'Windows'
        elif self.is_wsl:
            return 'WSL (Linux on Windows)'
        elif self.is_linux:
            return 'Linux'
        elif self.is_macos:
            return 'macOS'
        return platform.system()

    @property
    def architecture(self) -> str:
        return self._arch

    @property
    def os_version(self) -> str:
        return self._version

    def get_available_package_manager(self) -> Optional[str]:
        """Detect which package manager is available."""
        managers = {
            'apt': 'apt',
            'dnf': 'dnf',
            'yum': 'yum',
            'pacman': 'pacman',
            'zypper': 'zypper',
            'brew': 'brew',
        }

        if self.is_windows:
            if shutil.which('winget'):
                return 'winget'
            if shutil.which('choco'):
                return 'choco'
            return None

        for cmd, name in managers.items():
            if shutil.which(cmd):
                return name

        return None

    def get_platform_tool_name(self, tool: str) -> str:
        """Return platform-specific binary name."""
        if self.is_windows:
            win_tools = {
                'nmap': 'nmap.exe',
                'nikto': 'nikto.pl',
                'python3': 'python.exe',
                'testssl.sh': 'testssl.sh',
            }
            return win_tools.get(tool, f"{tool}.exe")
        return tool

    def get_platform_tool_paths(self) -> list:
        """Get additional tool search paths for this platform."""
        paths = []

        if self.is_windows:
            prog_files = os.environ.get('ProgramFiles', r'C:\Program Files')
            prog_x86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')
            paths.extend([
                Path(prog_files) / 'Nmap',
                Path(prog_files) / 'Wireshark',
                Path(prog_files) / 'Greenbone',
                Path(prog_x86) / 'Nmap',
                Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs',
            ])
        elif self.is_macos:
            paths.extend([
                Path('/opt/homebrew/bin'),
                Path('/usr/local/bin'),
                Path('/opt/local/bin'),
            ])

        return [p for p in paths if p.exists()]

    def get_usb_paths(self) -> list:
        """Detect USB drive mount points."""
        usb_paths = []

        if self.is_windows:
            # Check drive letters D: through Z:
            import string
            for letter in string.ascii_uppercase[3:]:
                drive = Path(f"{letter}:\\")
                if drive.exists():
                    try:
                        # Check if removable
                        import ctypes
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\")
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            usb_paths.append(drive)
                    except (AttributeError, OSError):
                        pass
        elif self.is_linux:
            # Check common mount points
            for mount_base in ['/run/media', '/media', '/mnt']:
                mount_path = Path(mount_base)
                if mount_path.exists():
                    for user_dir in mount_path.iterdir():
                        if user_dir.is_dir():
                            for device in user_dir.iterdir():
                                if device.is_dir():
                                    usb_paths.append(device)
        elif self.is_macos:
            volumes = Path('/Volumes')
            if volumes.exists():
                for vol in volumes.iterdir():
                    if vol.name != 'Macintosh HD' and vol.is_dir():
                        usb_paths.append(vol)

        return usb_paths

    @property
    def deployment_mode(self) -> str:
        """Detect deployment mode: portable, installed, or cicd.

        - portable: Running from USB drive (no cloud creds, no external AI)
        - cicd: Running in CI/CD pipeline (headless, SARIF output)
        - installed: Fixed system installation (full features)
        """
        # CI/CD detection: check common CI environment variables
        ci_vars = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'JENKINS_URL',
                    'CIRCLECI', 'TRAVIS', 'BITBUCKET_PIPELINE', 'TF_BUILD',
                    'CODEBUILD_BUILD_ID', 'BUILDKITE']
        for var in ci_vars:
            if os.environ.get(var):
                return 'cicd'

        # USB/portable detection: check if running from removable media
        try:
            script_path = Path(__file__).resolve()
            script_str = str(script_path).lower()
            # Common USB mount patterns
            usb_indicators = ['/run/media/', '/media/', '/mnt/usb',
                              '/volumes/']
            for indicator in usb_indicators:
                if indicator in script_str:
                    return 'portable'
            # Windows removable drive detection
            if self.is_windows:
                drive_letter = str(script_path)[:3]
                try:
                    import ctypes
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_letter)
                    if drive_type == 2:  # DRIVE_REMOVABLE
                        return 'portable'
                except (AttributeError, OSError):
                    pass
        except Exception:
            pass

        return 'installed'

    @property
    def is_portable(self) -> bool:
        """Check if running in portable (USB) mode."""
        return self.deployment_mode == 'portable'

    @property
    def is_installed(self) -> bool:
        """Check if running in installed (fixed system) mode."""
        return self.deployment_mode == 'installed'

    @property
    def is_cicd(self) -> bool:
        """Check if running in CI/CD pipeline mode."""
        return self.deployment_mode == 'cicd'

    def get_summary(self) -> dict:
        """Get platform summary."""
        return {
            'os': self.os_name,
            'architecture': self.architecture,
            'version': self.os_version,
            'wsl': self.is_wsl,
            'admin': self.is_admin,
            'package_manager': self.get_available_package_manager(),
            'usb_paths': [str(p) for p in self.get_usb_paths()],
            'deployment_mode': self.deployment_mode,
        }


# Singleton accessor
_platform_info: Optional[PlatformInfo] = None


def get_platform_info() -> PlatformInfo:
    """Get the platform info singleton."""
    global _platform_info
    if _platform_info is None:
        _platform_info = PlatformInfo()
    return _platform_info


if __name__ == '__main__':
    pi = get_platform_info()
    print("Platform Detection initialized")
    print()

    summary = pi.get_summary()
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print(f"\nDeployment mode: {pi.deployment_mode}")
    print(f"  is_portable:  {pi.is_portable}")
    print(f"  is_installed: {pi.is_installed}")
    print(f"  is_cicd:      {pi.is_cicd}")

    print(f"\nPlatform tool paths:")
    for p in pi.get_platform_tool_paths():
        print(f"  {p}")

    print(f"\nTool name examples:")
    for tool in ['nmap', 'nikto', 'python3']:
        print(f"  {tool} -> {pi.get_platform_tool_name(tool)}")
