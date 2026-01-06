#!/usr/bin/env python3
"""
Purple Team GRC Platform v3.0 - Path Helper
Dynamic Base Directory Detection for Dual Installation Support

This module provides dynamic path detection to support both:
- System-wide installation: /opt/purple-team/
- User installation: ~/purple-team/

Priority: System installation first, then user installation as fallback.

Usage:
    from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR
    
    # Use the constants in your scripts
    output_file = RESULTS_DIR / "scan_results.json"
"""

import os
import sys
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_actual_user_home():
    """
    Get the actual user's home directory, even when running with sudo.
    
    When scripts run with sudo, get_actual_user_home() returns /root instead of
    the actual user's home directory. This function detects the real user.
    
    Returns:
        Path: Actual user's home directory
    """
    # Check if running with sudo
    sudo_user = os.environ.get('SUDO_USER')
    
    if sudo_user:
        # Running with sudo - get the actual user's home
        import pwd
        try:
            user_info = pwd.getpwnam(sudo_user)
            actual_home = Path(user_info.pw_dir)
            logger.debug(f"Detected sudo user: {sudo_user}, home: {actual_home}")
            return actual_home
        except KeyError:
            logger.warning(f"Could not find home for sudo user: {sudo_user}")
            # Fallback to environment variable
            return Path(os.path.expanduser(f"~{sudo_user}"))
    
    # Not running with sudo - use normal home
    return get_actual_user_home()


def get_base_dir():
    """
    Detect base directory dynamically with fallback support.
    
    Priority order:
    1. /opt/purple-team (system-wide installation)
    2. ~/purple-team (user installation)
    3. Script's parent directory (development mode)
    
    Returns:
        Path: Base directory path
        
    Raises:
        RuntimeError: If no valid installation found
    """
    # Check system-wide installation
    system_path = Path("/opt/purple-team")
    if system_path.exists() and system_path.is_dir():
        if (system_path / "scanners").exists():
            logger.debug(f"Using system installation: {system_path}")
            return system_path
        else:
            logger.warning(f"System path exists but missing scanners directory: {system_path}")
    
    # Check user installation
    user_path = get_actual_user_home() / "purple-team"
    if user_path.exists() and user_path.is_dir():
        if (user_path / "scanners").exists():
            logger.debug(f"Using user installation: {user_path}")
            return user_path
        else:
            logger.warning(f"User path exists but missing scanners directory: {user_path}")
    
    # Fallback: try to detect from script location (development mode)
    try:
        script_path = Path(__file__).resolve().parent.parent
        if (script_path / "scanners").exists():
            logger.debug(f"Using development path: {script_path}")
            return script_path
    except NameError:
        pass
    
    # No valid installation found
    error_msg = (
        "Purple Team installation not found!\n"
        "Searched locations:\n"
        f"  - System: {system_path}\n"
        f"  - User: {user_path}\n"
        "Please run master_setup.sh to install the platform."
    )
    logger.error(error_msg)
    raise RuntimeError(error_msg)


def get_config_file():
    """
    Get path to user configuration file.
    
    User config is always in ~/.purple-team/config.yaml regardless of
    which installation (system or user) is being used.
    
    Returns:
        Path: Configuration file path
    """
    config_path = get_actual_user_home() / ".purple-team" / "config.yaml"
    
    # Ensure parent directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # If config doesn't exist, try to create from template
    if not config_path.exists():
        base_dir = get_base_dir()
        template_path = base_dir / "config" / "templates" / "config-template.yaml"
        
        if template_path.exists():
            import shutil
            shutil.copy(template_path, config_path)
            logger.info(f"Created config file from template: {config_path}")
        else:
            logger.warning(f"Config file not found and no template available: {config_path}")
    
    return config_path


def get_results_dir():
    """
    Get path to results directory (user-specific).
    
    Results are always stored in user directory to avoid permission issues.
    
    Returns:
        Path: Results directory path
    """
    results_path = get_actual_user_home() / ".purple-team" / "results"
    results_path.mkdir(parents=True, exist_ok=True)
    return results_path


def get_logs_dir():
    """
    Get path to logs directory (user-specific).
    
    Logs are always stored in user directory for easy access.
    
    Returns:
        Path: Logs directory path
    """
    logs_path = get_actual_user_home() / ".purple-team" / "logs"
    logs_path.mkdir(parents=True, exist_ok=True)
    return logs_path


def get_evidence_dir():
    """
    Get path to evidence directory (user-specific).
    
    Evidence is stored per-user for client separation.
    
    Returns:
        Path: Evidence directory path
    """
    evidence_path = get_actual_user_home() / ".purple-team" / "evidence"
    evidence_path.mkdir(parents=True, exist_ok=True)
    return evidence_path


def get_reports_dir():
    """
    Get path to reports directory (user-specific).
    
    Returns:
        Path: Reports directory path
    """
    reports_path = get_actual_user_home() / ".purple-team" / "reports"
    reports_path.mkdir(parents=True, exist_ok=True)
    return reports_path


def get_venv_path():
    """
    Get path to Python virtual environment.
    
    Returns:
        Path: Virtual environment directory path
    """
    base_dir = get_base_dir()
    return base_dir / "venv"


def verify_installation():
    """
    Verify that the installation is complete and valid.
    
    Returns:
        dict: Installation verification results
    """
    results = {
        'valid': True,
        'base_dir': None,
        'missing_dirs': [],
        'warnings': []
    }
    
    try:
        base_dir = get_base_dir()
        results['base_dir'] = str(base_dir)
        
        # Check required directories
        required_dirs = ['scanners', 'utilities', 'bin', 'config']
        for dir_name in required_dirs:
            dir_path = base_dir / dir_name
            if not dir_path.exists():
                results['missing_dirs'].append(dir_name)
                results['valid'] = False
        
        # Check user directories
        user_dirs = [
            get_actual_user_home() / ".purple-team",
            get_results_dir(),
            get_logs_dir(),
            get_evidence_dir()
        ]
        
        for user_dir in user_dirs:
            if not user_dir.exists():
                results['warnings'].append(f"User directory missing: {user_dir}")
        
        # Check config file
        config_file = get_config_file()
        if not config_file.exists():
            results['warnings'].append("Configuration file missing")
        
    except RuntimeError as e:
        results['valid'] = False
        results['warnings'].append(str(e))
    
    return results


# ============================================================================
# GLOBAL CONSTANTS - Import these in your scripts
# ============================================================================

try:
    BASE_DIR = get_base_dir()
    CONFIG_FILE = get_config_file()
    RESULTS_DIR = get_results_dir()
    LOGS_DIR = get_logs_dir()
    EVIDENCE_DIR = get_evidence_dir()
    REPORTS_DIR = get_reports_dir()
    VENV_PATH = get_venv_path()
    
    # Log successful initialization
    logger.debug(f"Path helper initialized: BASE_DIR={BASE_DIR}")
    
except RuntimeError as e:
    # If initialization fails, set to None and let the importing script handle it
    BASE_DIR = None
    CONFIG_FILE = None
    RESULTS_DIR = None
    LOGS_DIR = None
    EVIDENCE_DIR = None
    REPORTS_DIR = None
    VENV_PATH = None
    
    logger.error(f"Path helper initialization failed: {e}")


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_script_name():
    """Get the name of the calling script."""
    import inspect
    frame = inspect.stack()[1]
    return Path(frame.filename).name


def ensure_dir(path):
    """
    Ensure a directory exists, create if it doesn't.
    
    Args:
        path: Path object or string
        
    Returns:
        Path: The directory path
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_timestamp():
    """
    Get current timestamp in standard format.
    
    Returns:
        str: Timestamp string (YYYY-MM-DD_HH-MM-SS)
    """
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_datestamp():
    """
    Get current datestamp in standard format.
    
    Returns:
        str: Datestamp string (YYYY-MM-DD)
    """
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d")


# ============================================================================
# MAIN - For testing/verification
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Purple Team GRC Platform - Path Helper Verification")
    print("=" * 70)
    print()
    
    # Run verification
    results = verify_installation()
    
    print(f"Installation Valid: {'âœ… YES' if results['valid'] else 'âŒ NO'}")
    print()
    
    if results['base_dir']:
        print(f"Base Directory: {results['base_dir']}")
        print(f"Config File: {CONFIG_FILE}")
        print(f"Results Directory: {RESULTS_DIR}")
        print(f"Logs Directory: {LOGS_DIR}")
        print(f"Evidence Directory: {EVIDENCE_DIR}")
        print(f"Reports Directory: {REPORTS_DIR}")
        print(f"Virtual Environment: {VENV_PATH}")
        print()
    
    if results['missing_dirs']:
        print("âŒ Missing Directories:")
        for dir_name in results['missing_dirs']:
            print(f"  - {dir_name}")
        print()
    
    if results['warnings']:
        print("âš ï¸  Warnings:")
        for warning in results['warnings']:
            print(f"  - {warning}")
        print()
    
    if results['valid']:
        print("âœ… Installation verified successfully!")
    else:
        print("âŒ Installation verification failed!")
        print("   Run: sudo ./master_setup.sh")
    
    print()
