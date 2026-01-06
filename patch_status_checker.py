#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

PATCH_DIR = RESULTS_DIR / 'patch-tracking'
REPORTS_DIR = PATCH_DIR / 'reports'
"""
Patch Status Checker
Tracks patch status across systems and identifies what needs updating

Checks:
- Operating system patches
- Application updates
- Package versions
- Security updates
"""

import subprocess
import json
from pathlib import Path
from datetime import datetime
import logging
import re

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths already defined at top of file (lines 11-12)


class PatchStatusChecker:
    """Check patch status across systems"""
    
    def __init__(self):
        PATCH_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    def check_os_patches_debian(self):
        """Check Debian/Ubuntu/Kali system patches"""
        
        logger.info("Checking OS patches (Debian-based)...")
        
        patches = {
            'total_updates': 0,
            'security_updates': 0,
            'packages': [],
            'last_update': None
        }
        
        try:
            # Update package list
            subprocess.run(
                ['apt-get', 'update'],
                capture_output=True,
                timeout=120
            )
            
            # Check for upgradable packages
            result = subprocess.run(
                ['apt', 'list', '--upgradable'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            for line in result.stdout.split('\n'):
                if '/' in line and '[upgradable' in line:
                    parts = line.split('/')
                    if len(parts) >= 2:
                        package_name = parts[0]
                        
                        # Check if security update
                        is_security = 'security' in line.lower()
                        
                        # Extract version info
                        version_match = re.search(r'(\S+)\s+\[upgradable from:\s+(\S+)\]', line)
                        if version_match:
                            new_version = version_match.group(1)
                            current_version = version_match.group(2)
                        else:
                            new_version = 'Unknown'
                            current_version = 'Unknown'
                        
                        patches['packages'].append({
                            'name': package_name,
                            'current_version': current_version,
                            'available_version': new_version,
                            'is_security': is_security,
                            'severity': 'high' if is_security else 'medium'
                        })
                        
                        patches['total_updates'] += 1
                        if is_security:
                            patches['security_updates'] += 1
            
            # Get last update time
            apt_history = Path('/var/log/apt/history.log')
            if apt_history.exists():
                mtime = datetime.fromtimestamp(apt_history.stat().st_mtime)
                patches['last_update'] = mtime.isoformat()
        
        except Exception as e:
            logger.error(f"Error checking OS patches: {e}")
            patches['error'] = str(e)
        
        return patches
    
    def check_python_packages(self):
        """Check outdated Python packages"""
        
        logger.info("Checking Python packages...")
        
        packages = {
            'total_outdated': 0,
            'packages': []
        }
        
        try:
            # List outdated packages
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                outdated = json.loads(result.stdout)
                
                for pkg in outdated:
                    packages['packages'].append({
                        'name': pkg['name'],
                        'current_version': pkg['version'],
                        'available_version': pkg['latest_version'],
                        'type': pkg.get('latest_filetype', 'unknown')
                    })
                    packages['total_outdated'] += 1
        
        except Exception as e:
            logger.error(f"Error checking Python packages: {e}")
            packages['error'] = str(e)
        
        return packages
    
    def check_security_tools(self):
        """Check versions of security tools"""
        
        logger.info("Checking security tools...")
        
        tools = {
            'tools_checked': [],
            'outdated': []
        }
        
        # Define security tools to check
        security_tools = {
            'nmap': r'Nmap version (\S+)',
            'nuclei': r'v(\S+)',
            'nikto': r'Nikto (\S+)',
            'metasploit': r'(\d+\.\d+\.\d+)'
        }
        
        for tool, version_regex in security_tools.items():
            try:
                # Get version
                result = subprocess.run(
                    [tool, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                output = result.stdout + result.stderr
                match = re.search(version_regex, output)
                
                if match:
                    version = match.group(1)
                    tools['tools_checked'].append({
                        'tool': tool,
                        'version': version,
                        'status': 'installed'
                    })
                else:
                    tools['tools_checked'].append({
                        'tool': tool,
                        'version': 'unknown',
                        'status': 'installed'
                    })
            
            except FileNotFoundError:
                tools['tools_checked'].append({
                    'tool': tool,
                    'version': None,
                    'status': 'not_installed'
                })
            except Exception as e:
                logger.debug(f"Error checking {tool}: {e}")
        
        return tools
    
    def check_kernel_version(self):
        """Check if kernel is up to date"""
        
        logger.info("Checking kernel version...")
        
        kernel_info = {}
        
        try:
            # Current kernel
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True,
                timeout=5
            )
            current_kernel = result.stdout.strip()
            
            # Available kernels
            result = subprocess.run(
                ['dpkg', '-l', 'linux-image-*'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            installed_kernels = []
            for line in result.stdout.split('\n'):
                if line.startswith('ii'):
                    parts = line.split()
                    if len(parts) >= 2:
                        installed_kernels.append(parts[1])
            
            kernel_info = {
                'current': current_kernel,
                'installed': installed_kernels,
                'is_latest': current_kernel in result.stdout
            }
        
        except Exception as e:
            logger.error(f"Error checking kernel: {e}")
            kernel_info['error'] = str(e)
        
        return kernel_info
    
    def generate_patch_plan(self, results):
        """Generate recommended patching plan"""
        
        plan = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        # OS security updates are critical
        if results.get('os_patches', {}).get('security_updates', 0) > 0:
            for pkg in results['os_patches'].get('packages', []):
                if pkg.get('is_security'):
                    plan['critical'].append({
                        'action': 'update_package',
                        'package': pkg['name'],
                        'reason': 'Security update',
                        'command': f"apt-get install {pkg['name']}"
                    })
        
        # Other OS updates are high priority
        if results.get('os_patches', {}).get('total_updates', 0) > 0:
            non_security = [p for p in results['os_patches'].get('packages', []) 
                          if not p.get('is_security')]
            
            if non_security:
                plan['high'].append({
                    'action': 'update_system',
                    'count': len(non_security),
                    'reason': 'System updates available',
                    'command': 'apt-get upgrade'
                })
        
        # Python packages are medium priority
        if results.get('python_packages', {}).get('total_outdated', 0) > 0:
            plan['medium'].append({
                'action': 'update_python_packages',
                'count': results['python_packages']['total_outdated'],
                'reason': 'Outdated Python packages',
                'command': 'pip list --outdated | grep -v "^Package" | cut -d " " -f1 | xargs pip install -U'
            })
        
        # Security tools are low priority (unless critical)
        tool_updates = [t for t in results.get('security_tools', {}).get('tools_checked', [])
                       if t.get('status') == 'not_installed']
        
        if tool_updates:
            plan['low'].append({
                'action': 'install_tools',
                'tools': [t['tool'] for t in tool_updates],
                'reason': 'Missing security tools'
            })
        
        return plan
    
    def run_full_check(self):
        """Run complete patch status check"""
        
        logger.info("Starting full patch status check...")
        
        results = {
            'scan_time': datetime.now().isoformat(),
            'os_patches': self.check_os_patches_debian(),
            'python_packages': self.check_python_packages(),
            'security_tools': self.check_security_tools(),
            'kernel': self.check_kernel_version()
        }
        
        # Generate patch plan
        results['patch_plan'] = self.generate_patch_plan(results)
        
        # Calculate summary
        results['summary'] = {
            'total_updates': results['os_patches'].get('total_updates', 0),
            'security_updates': results['os_patches'].get('security_updates', 0),
            'python_outdated': results['python_packages'].get('total_outdated', 0),
            'critical_actions': len(results['patch_plan']['critical']),
            'high_actions': len(results['patch_plan']['high'])
        }
        
        return results
    
    def generate_report(self, results):
        """Generate patch status report"""
        
        report = []
        report.append("=" * 70)
        report.append("PATCH STATUS REPORT")
        report.append("=" * 70)
        report.append(f"Scan Time: {results['scan_time']}")
        report.append("")
        
        # Summary
        summary = results['summary']
        report.append("SUMMARY:")
        report.append(f"  Total OS Updates Available: {summary['total_updates']}")
        report.append(f"  Security Updates: {summary['security_updates']}")
        report.append(f"  Outdated Python Packages: {summary['python_outdated']}")
        report.append(f"  Critical Actions Required: {summary['critical_actions']}")
        report.append(f"  High Priority Actions: {summary['high_actions']}")
        report.append("")
        
        # OS Patches
        os_patches = results.get('os_patches', {})
        if os_patches.get('security_updates', 0) > 0:
            report.append("Ã°Å¸Å¡Â¨ SECURITY UPDATES AVAILABLE:")
            report.append("-" * 70)
            for pkg in os_patches.get('packages', []):
                if pkg.get('is_security'):
                    report.append(f"  {pkg['name']}: {pkg['current_version']} Ã¢â€ â€™ {pkg['available_version']}")
            report.append("")
        
        # Patch Plan
        plan = results.get('patch_plan', {})
        if plan.get('critical'):
            report.append("CRITICAL ACTIONS REQUIRED:")
            report.append("-" * 70)
            for action in plan['critical']:
                report.append(f"  Ã¢â‚¬Â¢ {action['reason']}: {action.get('package', 'N/A')}")
                report.append(f"    Command: {action['command']}")
            report.append("")
        
        if plan.get('high'):
            report.append("HIGH PRIORITY ACTIONS:")
            report.append("-" * 70)
            for action in plan['high']:
                report.append(f"  Ã¢â‚¬Â¢ {action['reason']}")
                report.append(f"    Command: {action['command']}")
            report.append("")
        
        # Last update
        if os_patches.get('last_update'):
            report.append(f"Last System Update: {os_patches['last_update']}")
        
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def save_report(self, results):
        """Save patch status report"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save JSON
        json_file = REPORTS_DIR / f'patch_status_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save text report
        txt_file = REPORTS_DIR / f'patch_status_{timestamp}.txt'
        with open(txt_file, 'w') as f:
            f.write(self.generate_report(results))
        
        logger.info(f"Report saved: {txt_file}")
        return txt_file

def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Patch Status Checker')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--save', action='store_true', help='Save report')
    parser.add_argument('--plan-only', action='store_true', help='Show patch plan only')
    
    args = parser.parse_args()
    
    checker = PatchStatusChecker()
    results = checker.run_full_check()
    
    if args.json:
        print(json.dumps(results, indent=2))
    elif args.plan_only:
        print("\nRECOMMENDED PATCH PLAN:")
        print("=" * 70)
        plan = results['patch_plan']
        for priority in ['critical', 'high', 'medium', 'low']:
            if plan.get(priority):
                print(f"\n{priority.upper()}:")
                for action in plan[priority]:
                    print(f"  Ã¢â‚¬Â¢ {action.get('reason', 'Update')}")
                    if 'command' in action:
                        print(f"    $ {action['command']}")
    else:
        print(checker.generate_report(results))
    
    if args.save:
        checker.save_report(results)
    
    # Exit code based on security updates
    if results['summary']['security_updates'] > 0:
        exit(1)  # Security updates available
    else:
        exit(0)

if __name__ == '__main__':
    main()
