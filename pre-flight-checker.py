#!/usr/bin/env python3
"""
Purple Team GRC Platform v3.0 - Pre-Flight Checker
Comprehensive validation of tools, dependencies, and system configuration

Validates:
- Kali Purple installation
- Python version
- Defensive tools (Suricata, Zeek, Wazuh, etc.)
- Offensive tools (nmap, nikto, metasploit, etc.)
- Python dependencies
- Disk space
- System resources

Usage:
    sudo python3 pre-flight-checker.py [--verbose] [--json]
"""

import subprocess
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime

# Colors
class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'


class PreFlightChecker:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'unknown',
            'checks': {},
            'warnings': [],
            'errors': [],
            'missing_tools': []
        }
    
    def check_kali_purple(self):
        """Verify Kali Purple installation"""
        print(f"\n{Colors.BOLD}Checking Kali Purple Installation...{Colors.NC}")
        
        try:
            # Check OS release
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
            
            is_kali = 'kali' in os_release.lower()
            
            # Check for purple metapackage
            result = subprocess.run(
                ['dpkg', '-l', 'kali-linux-purple'],
                capture_output=True,
                text=True
            )
            has_purple_pkg = result.returncode == 0
            
            if is_kali and has_purple_pkg:
                print(f"  {Colors.GREEN}✓{Colors.NC} Kali Purple detected")
                self.results['checks']['kali_purple'] = 'pass'
                return True
            elif is_kali:
                print(f"  {Colors.YELLOW}⚠{Colors.NC}  Kali Linux detected but not Kali Purple")
                self.results['warnings'].append("Running standard Kali, not Kali Purple")
                self.results['checks']['kali_purple'] = 'warn'
                return False
            else:
                print(f"  {Colors.RED}✗{Colors.NC} Not running Kali Linux")
                self.results['errors'].append("Not running Kali Linux")
                self.results['checks']['kali_purple'] = 'fail'
                return False
                
        except Exception as e:
            print(f"  {Colors.RED}✗{Colors.NC} Error checking OS: {e}")
            self.results['errors'].append(f"OS check failed: {e}")
            return False
    
    def check_python_version(self):
        """Check Python version"""
        print(f"\n{Colors.BOLD}Checking Python Version...{Colors.NC}")
        
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"
        
        if version.major == 3 and version.minor >= 10:
            print(f"  {Colors.GREEN}✓{Colors.NC} Python {version_str} (compatible)")
            self.results['checks']['python_version'] = 'pass'
            self.results['python_version'] = version_str
            return True
        else:
            print(f"  {Colors.RED}✗{Colors.NC} Python {version_str} (requires 3.10+)")
            self.results['errors'].append(f"Python {version_str} is too old (need 3.10+)")
            self.results['checks']['python_version'] = 'fail'
            return False
    
    def check_disk_space(self):
        """Check available disk space"""
        print(f"\n{Colors.BOLD}Checking Disk Space...{Colors.NC}")
        
        try:
            stat = shutil.disk_usage('/')
            free_gb = stat.free / (1024**3)
            
            if free_gb >= 50:
                print(f"  {Colors.GREEN}✓{Colors.NC} {free_gb:.1f}GB free (excellent)")
                self.results['checks']['disk_space'] = 'pass'
            elif free_gb >= 20:
                print(f"  {Colors.YELLOW}⚠{Colors.NC}  {free_gb:.1f}GB free (adequate)")
                self.results['warnings'].append(f"Low disk space: {free_gb:.1f}GB")
                self.results['checks']['disk_space'] = 'warn'
            else:
                print(f"  {Colors.RED}✗{Colors.NC} {free_gb:.1f}GB free (insufficient)")
                self.results['errors'].append(f"Insufficient disk space: {free_gb:.1f}GB")
                self.results['checks']['disk_space'] = 'fail'
            
            self.results['disk_space_gb'] = round(free_gb, 1)
            return free_gb >= 20
            
        except Exception as e:
            print(f"  {Colors.RED}✗{Colors.NC} Error checking disk space: {e}")
            return False
    
    def check_tool(self, tool_name, package_name=None):
        """Check if a tool is installed"""
        if package_name is None:
            package_name = tool_name
        
        # Check if command exists
        if shutil.which(tool_name):
            if self.verbose:
                print(f"  {Colors.GREEN}✓{Colors.NC} {tool_name}")
            return True
        else:
            print(f"  {Colors.RED}✗{Colors.NC} {tool_name} - not found")
            self.results['missing_tools'].append({
                'name': tool_name,
                'package': package_name
            })
            return False
    
    def check_defensive_tools(self):
        """Check defensive security tools (Kali Purple)"""
        print(f"\n{Colors.BOLD}Checking Defensive Tools...{Colors.NC}")
        
        tools = [
            ('suricata', 'IDS/IPS'),
            ('zeek', 'Network analysis'),
            ('wazuh-control', 'SIEM/EDR'),
        ]
        
        found = 0
        for tool, desc in tools:
            if self.check_tool(tool):
                found += 1
        
        self.results['defensive_tools'] = {
            'total': len(tools),
            'found': found,
            'missing': len(tools) - found
        }
        
        return found > 0
    
    def check_offensive_tools(self):
        """Check offensive security tools (standard Kali)"""
        print(f"\n{Colors.BOLD}Checking Offensive Tools...{Colors.NC}")
        
        tools = [
            'nmap',
            'nikto',
            'sqlmap',
            'nuclei',
            'metasploit-framework',
        ]
        
        found = 0
        for tool in tools:
            if self.check_tool(tool):
                found += 1
        
        self.results['offensive_tools'] = {
            'total': len(tools),
            'found': found,
            'missing': len(tools) - found
        }
        
        return found >= 3
    
    def check_python_packages(self):
        """Check Python dependencies"""
        print(f"\n{Colors.BOLD}Checking Python Packages...{Colors.NC}")
        
        required_packages = [
            'yaml',
            'requests',
            'flask',
        ]
        
        missing = []
        for package in required_packages:
            try:
                __import__(package)
                if self.verbose:
                    print(f"  {Colors.GREEN}✓{Colors.NC} {package}")
            except ImportError:
                print(f"  {Colors.RED}✗{Colors.NC} {package} - not installed")
                missing.append(package)
        
        self.results['python_packages'] = {
            'total': len(required_packages),
            'found': len(required_packages) - len(missing),
            'missing': missing
        }
        
        return len(missing) == 0
    
    def generate_summary(self):
        """Generate summary report"""
        print(f"\n{Colors.BLUE}{'=' * 70}{Colors.NC}")
        print(f"{Colors.BLUE}Pre-Flight Check Summary{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}\n")
        
        # Overall status
        if len(self.results['errors']) == 0:
            if len(self.results['warnings']) == 0:
                print(f"Overall Status: {Colors.GREEN}✓ PASS{Colors.NC}")
                self.results['overall_status'] = 'pass'
            else:
                print(f"Overall Status: {Colors.YELLOW}⚠ PASS WITH WARNINGS{Colors.NC}")
                self.results['overall_status'] = 'warn'
        else:
            print(f"Overall Status: {Colors.RED}✗ FAIL{Colors.NC}")
            self.results['overall_status'] = 'fail'
        
        # Errors
        if self.results['errors']:
            print(f"\n{Colors.RED}Errors:{Colors.NC}")
            for error in self.results['errors']:
                print(f"  • {error}")
        
        # Warnings
        if self.results['warnings']:
            print(f"\n{Colors.YELLOW}Warnings:{Colors.NC}")
            for warning in self.results['warnings']:
                print(f"  • {warning}")
        
        # Missing tools
        if self.results['missing_tools']:
            print(f"\n{Colors.YELLOW}Missing Tools:{Colors.NC}")
            for tool in self.results['missing_tools']:
                print(f"  • {tool['name']} (install: sudo apt install {tool['package']})")
        
        print()
    
    def run_all_checks(self):
        """Run all pre-flight checks"""
        print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}")
        print(f"{Colors.BLUE}Purple Team GRC Platform v3.0 - Pre-Flight Checks{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 70}{Colors.NC}")
        
        self.check_kali_purple()
        self.check_python_version()
        self.check_disk_space()
        self.check_defensive_tools()
        self.check_offensive_tools()
        self.check_python_packages()
        
        self.generate_summary()
        
        return self.results


def main():
    """Main execution"""
    verbose = '--verbose' in sys.argv
    json_output = '--json' in sys.argv
    
    checker = PreFlightChecker(verbose=verbose)
    results = checker.run_all_checks()
    
    if json_output:
        print(json.dumps(results, indent=2))
    
    # Exit with appropriate code
    if results['overall_status'] == 'fail':
        sys.exit(1)
    elif results['overall_status'] == 'warn':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Cancelled by user{Colors.NC}")
        sys.exit(130)
