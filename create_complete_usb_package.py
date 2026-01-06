#!/usr/bin/env python3
"""
Purple Team GRC Platform v4.1
Complete USB Package Builder

Packages ALL files from current directory into PurpleTeamUSB folder
Ready for client site deployment

Usage:
  sudo python3 create_complete_usb_package.py
"""

import os
import sys
import shutil
from pathlib import Path
from datetime import datetime
import json

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    NC = '\033[0m'

def print_header():
    """Print header"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.CYAN}   Purple Team GRC Platform - Complete USB Package Builder{Colors.NC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.NC}\n")

def create_usb_package():
    """Create complete USB package from current directory"""
    
    # Get current directory
    source_dir = Path.cwd()
    package_dir = source_dir / "PurpleTeamUSB"
    
    print(f"{Colors.CYAN}Source directory: {source_dir}{Colors.NC}")
    print(f"{Colors.CYAN}Package directory: {package_dir}{Colors.NC}\n")
    
    # Clean existing package
    if package_dir.exists():
        print(f"{Colors.YELLOW}Removing existing PurpleTeamUSB folder...{Colors.NC}")
        shutil.rmtree(package_dir)
        print()
    
    # Create package structure
    print(f"{Colors.CYAN}Creating package structure...{Colors.NC}\n")
    
    categories = {
        'scanners': [],
        'utilities': [],
        'utils': [],
        'config': [],
        'docs': [],
        'install': []
    }
    
    # Scanner files
    scanner_patterns = [
        'network_scanner.py',
        'vulnerability_scanner.py', 
        'compliance_checker.py',
        'quick_scan.py',
        'complete_assessment.py',
        'integrated_grc_scanner.py',
        'zero_config_discovery.py'
    ]
    
    # Utility files
    utility_patterns = [
        'executive_report_generator.py',
        'evidence_manager.py',
        'recommendations_engine.py',
        'results_organizer.py',
        'risk_scorer.py',
        'report_emailer.py',
        'questionnaire_responder.py',
        'dashboard_app.py'
    ]
    
    # Helper/Utils files (everything else .py, .sh, or executables)
    util_patterns = [
        'path_helper.py',
        'enhanced_progress.py',
        'vulnerability_formatter.py',
        'network-detector.py',
        'pre-flight-checker.py',
        'update-manager.py',
        'sync-manager.sh',
        'purple-team-launcher',
        'purple-team-gui',
        'asset_inventory_tracker.py',
        'backup_restore.py',
        'cert_expiration_monitor.py',
        'config_change_detector.py',
        'exploit_validator.py',
        'finding_deduplicator.py',
        'health_check_monitor.py',
        'patch_status_checker.py',
        'port_change_detector.py',
        'scheduler.py',
        'service_availability_monitor.py',
        'test_gui.py',
        'enhanced_compliance_checker.py',
        'enhanced_compliance_checker_clean.py'
    ]
    
    # Config files
    config_patterns = [
        'config.yaml',
        'config-template.yaml',
        'config-healthcare.yaml',
        'config-finance.yaml',
        'config-retail.yaml',
        'config-government.yaml',
        'config-comprehensive.yaml'
    ]
    
    # Documentation files
    doc_patterns = [
        'README.md',
        'CHANGELOG.md',
        'FILE_MANIFEST.md',
        'INSTALL.md',
        'Purple_Team_Deployment_Guide_v3_DARK.html'
    ]
    
    # Install scripts
    install_patterns = [
        'master_setup.sh',
        'requirements.txt'
    ]
    
    # Create directories
    for category in categories.keys():
        (package_dir / category).mkdir(parents=True, exist_ok=True)
    
    # Copy files by category
    copied_files = {k: [] for k in categories.keys()}
    
    print(f"{Colors.CYAN}Copying files...{Colors.NC}\n")
    
    # Copy scanners
    for pattern in scanner_patterns:
        src = source_dir / pattern
        if src.exists():
            dest = package_dir / 'scanners' / pattern
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            copied_files['scanners'].append(pattern)
            print(f"  {Colors.GREEN}✓{Colors.NC} scanners/{pattern}")
    
    # Copy utilities
    for pattern in utility_patterns:
        src = source_dir / pattern
        if src.exists():
            dest = package_dir / 'utilities' / pattern
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            copied_files['utilities'].append(pattern)
            print(f"  {Colors.GREEN}✓{Colors.NC} utilities/{pattern}")
    
    # Copy utils
    for pattern in util_patterns:
        src = source_dir / pattern
        if src.exists():
            dest = package_dir / 'utils' / pattern
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            copied_files['utils'].append(pattern)
            print(f"  {Colors.GREEN}✓{Colors.NC} utils/{pattern}")
    
    # Copy configs
    for pattern in config_patterns:
        src = source_dir / pattern
        if src.exists():
            dest = package_dir / 'config' / pattern
            shutil.copy2(src, dest)
            copied_files['config'].append(pattern)
            print(f"  {Colors.GREEN}✓{Colors.NC} config/{pattern}")
    
    # Copy docs
    for pattern in doc_patterns:
        src = source_dir / pattern
        if src.exists():
            dest = package_dir / 'docs' / pattern
            shutil.copy2(src, dest)
            copied_files['docs'].append(pattern)
            print(f"  {Colors.GREEN}✓{Colors.NC} docs/{pattern}")
    
    # Copy install scripts
    for pattern in install_patterns:
        src = source_dir / pattern
        if src.exists():
            dest = package_dir / 'install' / pattern
            shutil.copy2(src, dest)
            if pattern.endswith('.sh'):
                os.chmod(dest, 0o755)
            copied_files['install'].append(pattern)
            print(f"  {Colors.GREEN}✓{Colors.NC} install/{pattern}")
    
    print()
    
    # Create master installer if not exists
    master_installer = package_dir / 'install' / 'INSTALL.sh'
    if not master_installer.exists():
        create_master_installer(master_installer, package_dir)
        print(f"  {Colors.GREEN}✓{Colors.NC} Created install/INSTALL.sh\n")
    
    # Create README if needed
    create_usb_readme(package_dir)
    print(f"  {Colors.GREEN}✓{Colors.NC} Created USB_README.txt\n")
    
    # Create manifest
    create_manifest(package_dir, copied_files)
    print(f"  {Colors.GREEN}✓{Colors.NC} Created PACKAGE_MANIFEST.json\n")
    
    # Calculate size
    total_size = 0
    file_count = 0
    for root, dirs, files in os.walk(package_dir):
        for file in files:
            filepath = Path(root) / file
            total_size += filepath.stat().st_size
            file_count += 1
    
    size_mb = total_size / (1024 * 1024)
    
    # Summary
    print(f"{Colors.CYAN}{'='*70}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.CYAN}   USB PACKAGE COMPLETE!{Colors.NC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.NC}\n")
    
    print(f"{Colors.BOLD}Package Location:{Colors.NC} {package_dir}")
    print(f"{Colors.BOLD}Total Files:{Colors.NC} {file_count}")
    print(f"{Colors.BOLD}Package Size:{Colors.NC} {size_mb:.2f} MB\n")
    
    for category, files in copied_files.items():
        if files:
            print(f"  {Colors.CYAN}{category}:{Colors.NC} {len(files)} files")
    
    print(f"\n{Colors.GREEN}✓ Ready for USB deployment!{Colors.NC}")
    print(f"\n{Colors.YELLOW}Next Steps:{Colors.NC}")
    print(f"  1. Copy PurpleTeamUSB/ folder to USB drive")
    print(f"  2. On target Kali Purple system:")
    print(f"     cd /media/$USER/*/PurpleTeamUSB")
    print(f"     sudo bash install/INSTALL.sh")
    print(f"  3. Launch: purple-team\n")

def create_master_installer(filepath, package_dir):
    """Create master installation script"""
    installer = """#!/bin/bash
#
# Purple Team GRC Platform v4.1 - Master Installer
# Complete installation from USB
#

set -e

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'
NC='\\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Header
echo -e "\\n${CYAN}${'='*70}${NC}"
echo -e "${CYAN}   Purple Team GRC Platform v4.1 - Installation${NC}"
echo -e "${CYAN}${'='*70}${NC}\\n"

# Get USB directory
USB_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
echo -e "${CYAN}Installing from: $USB_DIR${NC}\\n"

# Confirm
read -p "Install to /opt/purple-team? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo -e "${YELLOW}Cancelled${NC}"
    exit 0
fi

# Create directories
echo -e "${CYAN}Creating directories...${NC}"
mkdir -p /opt/purple-team/{scanners,utilities,utils,config,logs}

# Copy files
echo -e "${CYAN}Installing scanners...${NC}"
cp -v "$USB_DIR/scanners/"*.py /opt/purple-team/scanners/ 2>/dev/null || true

echo -e "${CYAN}Installing utilities...${NC}"
cp -v "$USB_DIR/utilities/"*.py /opt/purple-team/utilities/ 2>/dev/null || true

echo -e "${CYAN}Installing utils...${NC}"
cp -v "$USB_DIR/utils/"* /opt/purple-team/utils/ 2>/dev/null || true

echo -e "${CYAN}Installing configs...${NC}"
cp -v "$USB_DIR/config/"* /opt/purple-team/config/ 2>/dev/null || true

# Set permissions
echo -e "${CYAN}Setting permissions...${NC}"
chmod +x /opt/purple-team/scanners/*.py 2>/dev/null || true
chmod +x /opt/purple-team/utilities/*.py 2>/dev/null || true
chmod +x /opt/purple-team/utils/* 2>/dev/null || true

# Create venv
echo -e "${CYAN}Creating virtual environment...${NC}"
python3 -m venv /opt/purple-team/venv

# Install dependencies
if [ -f "$USB_DIR/install/requirements.txt" ]; then
    echo -e "${CYAN}Installing dependencies...${NC}"
    /opt/purple-team/venv/bin/pip install --upgrade pip
    /opt/purple-team/venv/bin/pip install -r "$USB_DIR/install/requirements.txt"
fi

# User directories
echo -e "${CYAN}Creating user directories...${NC}"
mkdir -p ~/.purple-team/{results,reports,logs,config}

# Copy user config
if [ ! -f ~/.purple-team/config.yaml ]; then
    cp /opt/purple-team/config/config-template.yaml ~/.purple-team/config.yaml 2>/dev/null || true
fi

# Create launcher
echo -e "${CYAN}Creating launcher...${NC}"
ln -sf /opt/purple-team/utils/purple-team-launcher /usr/local/bin/purple-team

# Success
echo -e "\\n${GREEN}${'='*70}${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}${'='*70}${NC}\\n"
echo -e "Launch with: ${CYAN}purple-team${NC}\\n"
"""
    
    with open(filepath, 'w') as f:
        f.write(installer)
    
    os.chmod(filepath, 0o755)

def create_usb_readme(package_dir):
    """Create USB README"""
    readme = f"""═══════════════════════════════════════════════════════════════════
   PURPLE TEAM GRC PLATFORM v4.1 - USB DEPLOYMENT PACKAGE
═══════════════════════════════════════════════════════════════════

Package Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

QUICK START:

1. Insert USB into Kali Purple system
2. cd /media/$USER/*/PurpleTeamUSB
3. sudo bash install/INSTALL.sh
4. Launch: purple-team

═══════════════════════════════════════════════════════════════════

PACKAGE CONTENTS:

scanners/       Network, vulnerability, and compliance scanners
utilities/      Report generators and analysis tools
utils/          Helper scripts and launchers
config/         Configuration templates (healthcare, finance, etc.)
docs/           Documentation and deployment guides
install/        Installation scripts and requirements

═══════════════════════════════════════════════════════════════════

FEATURES:

✓ Complete Assessment Workflow (Quick/Standard/Deep)
✓ Smart Recommendations Engine
✓ Enhanced Compliance Reports (SOC2, NIST, ISO27001, PCI-DSS, HIPAA)
✓ Network Auto-Detection (wired + wireless)
✓ Results Organizer (session-based folders)
✓ Terminal & GUI Launchers

═══════════════════════════════════════════════════════════════════

For complete documentation, see docs/Purple_Team_Deployment_Guide_v3_DARK.html

═══════════════════════════════════════════════════════════════════
"""
    
    with open(package_dir / 'USB_README.txt', 'w') as f:
        f.write(readme)

def create_manifest(package_dir, copied_files):
    """Create package manifest"""
    manifest = {
        'package_version': '4.1',
        'created': datetime.now().isoformat(),
        'created_by': os.getenv('USER', 'unknown'),
        'contents': copied_files,
        'total_files': sum(len(files) for files in copied_files.values())
    }
    
    with open(package_dir / 'PACKAGE_MANIFEST.json', 'w') as f:
        json.dump(manifest, f, indent=2)

def main():
    """Main entry point"""
    
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}Note: Running without root. Some file permissions may not be set correctly.{Colors.NC}\n")
    
    print_header()
    create_usb_package()

if __name__ == '__main__':
    main()
