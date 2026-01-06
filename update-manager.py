#!/usr/bin/env python3
"""
Purple Team GRC Platform v3.0 - Update Manager
Checks for and installs system updates, Python packages, and platform updates

Usage:
    sudo python3 update-manager.py [--check-only] [--auto-yes]
"""

import subprocess
import sys
from datetime import datetime

class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'

def check_system_updates():
    """Check for system package updates"""
    print(f"\n{Colors.BOLD}Checking system updates...{Colors.NC}")
    
    # Update package lists
    subprocess.run(['apt', 'update'], capture_output=True)
    
    # Get upgradable packages
    result = subprocess.run(
        ['apt', 'list', '--upgradable'],
        capture_output=True,
        text=True
    )
    
    upgradable = []
    for line in result.stdout.split('\n'):
        if '/' in line and 'upgradable' in line:
            pkg = line.split('/')[0]
            upgradable.append(pkg)
    
    if upgradable:
        print(f"  {Colors.YELLOW}{len(upgradable)} packages can be upgraded{Colors.NC}")
        return upgradable
    else:
        print(f"  {Colors.GREEN}✓ System is up to date{Colors.NC}")
        return []

def install_system_updates(auto_yes=False):
    """Install system updates"""
    print(f"\n{Colors.BOLD}Installing system updates...{Colors.NC}")
    
    if not auto_yes:
        response = input("Proceed with system upgrade? [Y/n]: ")
        if response.lower() not in ['y', 'yes', '']:
            print("Skipped")
            return False
    
    result = subprocess.run(['apt', 'upgrade', '-y'])
    return result.returncode == 0

def check_python_updates():
    """Check for Python package updates"""
    print(f"\n{Colors.BOLD}Checking Python packages...{Colors.NC}")
    
    result = subprocess.run(
        ['pip', 'list', '--outdated'],
        capture_output=True,
        text=True
    )
    
    outdated = []
    for line in result.stdout.split('\n')[2:]:  # Skip headers
        if line.strip():
            parts = line.split()
            if len(parts) >= 3:
                outdated.append(parts[0])
    
    if outdated:
        print(f"  {Colors.YELLOW}{len(outdated)} Python packages can be upgraded{Colors.NC}")
        return outdated
    else:
        print(f"  {Colors.GREEN}✓ Python packages up to date{Colors.NC}")
        return []

def install_python_updates(packages, auto_yes=False):
    """Install Python package updates"""
    if not packages:
        return True
    
    print(f"\n{Colors.BOLD}Upgrading Python packages...{Colors.NC}")
    
    if not auto_yes:
        response = input(f"Upgrade {len(packages)} packages? [Y/n]: ")
        if response.lower() not in ['y', 'yes', '']:
            print("Skipped")
            return False
    
    for pkg in packages:
        print(f"  Upgrading {pkg}...")
        subprocess.run(['pip', 'install', '--upgrade', pkg], capture_output=True)
    
    print(f"  {Colors.GREEN}✓ Python packages upgraded{Colors.NC}")
    return True

def main():
    """Main execution"""
    check_only = '--check-only' in sys.argv
    auto_yes = '--auto-yes' in sys.argv
    
    print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}")
    print(f"{Colors.BLUE}Purple Team Update Manager{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}")
    
    # Check system updates
    sys_updates = check_system_updates()
    
    # Check Python updates
    py_updates = check_python_updates()
    
    if check_only:
        print(f"\n{Colors.BLUE}Check complete (no changes made){Colors.NC}\n")
        return
    
    # Install updates
    if sys_updates:
        install_system_updates(auto_yes)
    
    if py_updates:
        install_python_updates(py_updates, auto_yes)
    
    print(f"\n{Colors.GREEN}Update process complete!{Colors.NC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Cancelled{Colors.NC}")
        sys.exit(130)
