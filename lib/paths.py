#!/usr/bin/env python3
"""
Purple Team Portable - Path Resolver
Provides portable, relative path resolution for all components.
All paths are relative to PURPLE_TEAM_HOME (auto-detected or env var).
"""

import os
import sys
from pathlib import Path
from typing import Optional

class PortablePaths:
    """Portable path resolver - works from any installation location."""

    _instance: Optional['PortablePaths'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._resolve_home()

    def _resolve_home(self):
        """Resolve PURPLE_TEAM_HOME from environment or auto-detect."""
        # Priority 1: Environment variable
        if 'PURPLE_TEAM_HOME' in os.environ:
            self.home = Path(os.environ['PURPLE_TEAM_HOME']).resolve()
        else:
            # Priority 2: Auto-detect from this file's location
            # This file is in lib/, so parent is home
            self.home = Path(__file__).resolve().parent.parent

        # Validate home directory
        if not (self.home / 'lib' / 'paths.py').exists():
            raise RuntimeError(
                f"Invalid PURPLE_TEAM_HOME: {self.home}\n"
                f"Expected to find lib/paths.py in the installation directory."
            )

    @property
    def bin(self) -> Path:
        """Launcher scripts and executables."""
        return self.home / 'bin'

    @property
    def lib(self) -> Path:
        """Shared Python libraries."""
        return self.home / 'lib'

    @property
    def scanners(self) -> Path:
        """Scanner modules."""
        return self.home / 'scanners'

    @property
    def utilities(self) -> Path:
        """Utility scripts."""
        return self.home / 'utilities'

    @property
    def config(self) -> Path:
        """Configuration directory."""
        return self.home / 'config'

    @property
    def config_templates(self) -> Path:
        """Configuration templates."""
        return self.home / 'config' / 'templates'

    @property
    def config_active(self) -> Path:
        """Active configuration file."""
        return self.home / 'config' / 'active' / 'config.yaml'

    @property
    def data(self) -> Path:
        """Data directory (results, evidence, logs)."""
        return self.home / 'data'

    @property
    def results(self) -> Path:
        """Scan results storage."""
        return self.home / 'data' / 'results'

    @property
    def evidence(self) -> Path:
        """Evidence collection and database."""
        return self.home / 'data' / 'evidence'

    @property
    def evidence_db(self) -> Path:
        """SQLite evidence database."""
        return self.home / 'data' / 'evidence' / 'evidence.db'

    @property
    def logs(self) -> Path:
        """Execution logs."""
        return self.home / 'data' / 'logs'

    @property
    def reports(self) -> Path:
        """Generated reports."""
        return self.home / 'data' / 'reports'

    @property
    def archives(self) -> Path:
        """Archived results (compressed, long-term storage)."""
        return self.home / 'data' / 'archives'

    @property
    def docs(self) -> Path:
        """Documentation."""
        return self.home / 'docs'

    @property
    def tools(self) -> Path:
        """Bundled external tools (if portable)."""
        return self.home / 'tools'

    @property
    def venv(self) -> Path:
        """Python virtual environment."""
        return self.home / 'venv'

    @property
    def venv_python(self) -> Path:
        """Python interpreter in venv."""
        if sys.platform == 'win32':
            return self.venv / 'Scripts' / 'python.exe'
        return self.venv / 'bin' / 'python3'

    def session_dir(self, session_id: str) -> Path:
        """Get directory for a specific scan session."""
        path = self.results / session_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def log_file(self, name: str) -> Path:
        """Get path for a log file."""
        self.logs.mkdir(parents=True, exist_ok=True)
        return self.logs / f"{name}.log"

    def report_file(self, name: str, ext: str = 'html') -> Path:
        """Get path for a report file."""
        self.reports.mkdir(parents=True, exist_ok=True)
        return self.reports / f"{name}.{ext}"

    def archive_file(self, name: str) -> Path:
        """Get path for an archive file (.zip on Windows, .tar.gz elsewhere)."""
        self.archives.mkdir(parents=True, exist_ok=True)
        ext = '.zip' if sys.platform == 'win32' else '.tar.gz'
        return self.archives / f"{name}{ext}"

    def ensure_directories(self):
        """Create all required directories if they don't exist."""
        dirs = [
            self.bin, self.lib, self.scanners, self.utilities,
            self.config, self.config_templates, self.config_active.parent,
            self.data, self.results, self.evidence, self.logs,
            self.reports, self.archives, self.docs, self.tools
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def find_tool(self, tool_name: str) -> Optional[Path]:
        """
        Find an external tool (nmap, nikto, nuclei, testssl.sh).
        Checks: 1) bundled tools/, 2) platform-specific paths, 3) system PATH
        """
        # Check bundled tools first
        bundled = self.tools / tool_name
        if bundled.exists() and os.access(bundled, os.X_OK):
            return bundled

        # On Windows, also check with .exe extension
        if sys.platform == 'win32':
            bundled_exe = self.tools / f"{tool_name}.exe"
            if bundled_exe.exists():
                return bundled_exe

            # Check common Windows install locations
            win_paths = [
                Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Nmap' / f'{tool_name}.exe',
                Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Nmap' / f'{tool_name}.exe',
            ]
            for wp in win_paths:
                if wp.exists():
                    return wp

        # Check system PATH
        import shutil
        system_path = shutil.which(tool_name)
        if system_path:
            return Path(system_path)

        return None

    def require_tool(self, tool_name: str) -> Path:
        """Find a tool or raise error if not found."""
        path = self.find_tool(tool_name)
        if path is None:
            raise FileNotFoundError(
                f"Required tool not found: {tool_name}\n"
                f"Install it system-wide or place in: {self.tools / tool_name}"
            )
        return path

    def __str__(self) -> str:
        return f"PortablePaths(home={self.home})"

    def __repr__(self) -> str:
        return self.__str__()


# Singleton instance for easy import
paths = PortablePaths()

# Convenience exports
PURPLE_TEAM_HOME = paths.home
BIN_DIR = paths.bin
LIB_DIR = paths.lib
SCANNERS_DIR = paths.scanners
UTILITIES_DIR = paths.utilities
CONFIG_DIR = paths.config
CONFIG_FILE = paths.config_active
RESULTS_DIR = paths.results
EVIDENCE_DIR = paths.evidence
EVIDENCE_DB = paths.evidence_db
LOGS_DIR = paths.logs
REPORTS_DIR = paths.reports
ARCHIVES_DIR = paths.archives
DOCS_DIR = paths.docs
TOOLS_DIR = paths.tools


def setup_python_path():
    """Add lib directory to Python path for imports."""
    lib_str = str(paths.lib)
    if lib_str not in sys.path:
        sys.path.insert(0, lib_str)


def get_paths() -> PortablePaths:
    """Get the singleton paths instance."""
    return paths


if __name__ == '__main__':
    # Self-test
    p = get_paths()
    print(f"Purple Team Home: {p.home}")
    print(f"Scanners: {p.scanners}")
    print(f"Results: {p.results}")
    print(f"Evidence DB: {p.evidence_db}")
    print(f"Config: {p.config_active}")
    p.ensure_directories()
    print("All directories created successfully.")
