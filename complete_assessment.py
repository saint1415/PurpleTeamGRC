#!/usr/bin/env python3
"""
Purple Team GRC Platform v4.0
Complete Assessment Workflow - One-Command Full Security Assessment

This script orchestrates a complete security assessment:
1. Network Discovery
2. Full Network Scan
3. Vulnerability Assessment
4. Compliance Check
5. Executive Report Generation
6. Evidence Package Creation

Usage:
  sudo python3 complete_assessment.py [--quick|--standard|--deep]
"""

import sys
import subprocess
import time
from datetime import datetime
from pathlib import Path
import json

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, RESULTS_DIR, REPORTS_DIR

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'

class CompleteAssessment:
    """Orchestrate complete security assessment workflow"""
    
    def __init__(self, mode='standard'):
        self.mode = mode  # quick, standard, deep
        self.start_time = datetime.now()
        self.results = {
            'assessment_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'mode': mode,
            'start_time': self.start_time.isoformat(),
            'steps_completed': [],
            'steps_failed': [],
            'findings_summary': {}
        }
        
        # Define assessment profiles
        self.profiles = {
            'quick': {
                'name': 'Quick Assessment',
                'duration': '15-20 minutes',
                'steps': ['network_discovery', 'quick_scan', 'compliance_check', 'exec_report']
            },
            'standard': {
                'name': 'Standard Assessment',
                'duration': '45-60 minutes',
                'steps': ['network_discovery', 'full_network_scan', 'quick_vuln_scan', 'compliance_check', 'exec_report', 'evidence_package']
            },
            'deep': {
                'name': 'Deep Assessment',
                'duration': '2-4 hours',
                'steps': ['network_discovery', 'full_network_scan', 'full_vuln_scan', 'compliance_check', 'exec_report', 'evidence_package']
            }
        }
    
    def print_banner(self):
        """Print assessment banner"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.CYAN}   PURPLE TEAM GRC PLATFORM v4.0 - COMPLETE ASSESSMENT{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}\n")
        
        profile = self.profiles[self.mode]
        print(f"{Colors.BOLD}Assessment Mode:{Colors.NC} {profile['name']}")
        print(f"{Colors.BOLD}Estimated Duration:{Colors.NC} {profile['duration']}")
        print(f"{Colors.BOLD}Assessment ID:{Colors.NC} {self.results['assessment_id']}")
        print(f"{Colors.BOLD}Started:{Colors.NC} {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"{Colors.CYAN}Assessment Steps:{Colors.NC}")
        for i, step in enumerate(profile['steps'], 1):
            step_name = step.replace('_', ' ').title()
            print(f"  {i}. {step_name}")
        print()
    
    def print_step_header(self, step_num, total_steps, step_name, eta_minutes):
        """Print step header with progress"""
        progress = int((step_num / total_steps) * 100)
        bar_length = 50
        filled = int((progress / 100) * bar_length)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'─'*70}{Colors.NC}")
        print(f"{Colors.BOLD}STEP {step_num}/{total_steps}: {step_name.upper()}{Colors.NC}")
        print(f"{Colors.CYAN}Progress: [{bar}] {progress}%{Colors.NC}")
        print(f"{Colors.YELLOW}ETA: ~{eta_minutes} minutes{Colors.NC}")
        print(f"{Colors.BLUE}{'─'*70}{Colors.NC}\n")
    
    def run_script(self, script_path, args=""):
        """Execute a script and capture result"""
        venv_python = BASE_DIR / "venv" / "bin" / "python3"
        
        if not venv_python.exists():
            venv_python = "python3"
        
        cmd = f"sudo {venv_python} {script_path} {args}"
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=False,  # Show output in real-time
                text=True,
                timeout=3600  # 1 hour timeout
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}✗ Script timeout after 1 hour{Colors.NC}")
            return False
        except Exception as e:
            print(f"{Colors.RED}✗ Error: {e}{Colors.NC}")
            return False
    
    def step_network_discovery(self, step_num, total_steps):
        """Step 1: Network Discovery"""
        self.print_step_header(step_num, total_steps, "Network Discovery & Auto-Detection", 2)
        
        script = BASE_DIR / "utils" / "network-detector.py"
        success = self.run_script(script)
        
        if success:
            self.results['steps_completed'].append('network_discovery')
            print(f"\n{Colors.GREEN}✓ Network discovery completed{Colors.NC}")
        else:
            self.results['steps_failed'].append('network_discovery')
            print(f"\n{Colors.RED}✗ Network discovery failed{Colors.NC}")
        
        return success
    
    def step_full_network_scan(self, step_num, total_steps):
        """Step 2: Full Network Scan"""
        self.print_step_header(step_num, total_steps, "Full Network Scan", 30)
        
        script = BASE_DIR / "scanners" / "network_scanner.py"
        success = self.run_script(script)
        
        if success:
            self.results['steps_completed'].append('full_network_scan')
            print(f"\n{Colors.GREEN}✓ Network scan completed{Colors.NC}")
        else:
            self.results['steps_failed'].append('full_network_scan')
            print(f"\n{Colors.RED}✗ Network scan failed{Colors.NC}")
        
        return success
    
    def step_quick_vuln_scan(self, step_num, total_steps):
        """Step 3a: Quick Vulnerability Scan"""
        self.print_step_header(step_num, total_steps, "Quick Vulnerability Scan (Sample)", 15)
        
        script = BASE_DIR / "scanners" / "vulnerability_scanner.py"
        success = self.run_script(script)
        
        if success:
            self.results['steps_completed'].append('quick_vuln_scan')
            print(f"\n{Colors.GREEN}✓ Vulnerability scan completed{Colors.NC}")
        else:
            self.results['steps_failed'].append('quick_vuln_scan')
            print(f"\n{Colors.RED}✗ Vulnerability scan failed{Colors.NC}")
        
        return success
    
    def step_full_vuln_scan(self, step_num, total_steps):
        """Step 3b: Full Vulnerability Scan"""
        self.print_step_header(step_num, total_steps, "Full Vulnerability Scan (Comprehensive)", 120)
        
        script = BASE_DIR / "scanners" / "vulnerability_scanner.py"
        success = self.run_script(script, "--full")
        
        if success:
            self.results['steps_completed'].append('full_vuln_scan')
            print(f"\n{Colors.GREEN}✓ Full vulnerability scan completed{Colors.NC}")
        else:
            self.results['steps_failed'].append('full_vuln_scan')
            print(f"\n{Colors.RED}✗ Full vulnerability scan failed{Colors.NC}")
        
        return success
    
    def step_compliance_check(self, step_num, total_steps):
        """Step 4: Compliance Check"""
        self.print_step_header(step_num, total_steps, "Compliance Framework Analysis", 3)
        
        script = BASE_DIR / "scanners" / "compliance_checker.py"
        success = self.run_script(script)
        
        if success:
            self.results['steps_completed'].append('compliance_check')
            print(f"\n{Colors.GREEN}✓ Compliance check completed{Colors.NC}")
        else:
            self.results['steps_failed'].append('compliance_check')
            print(f"\n{Colors.RED}✗ Compliance check failed{Colors.NC}")
        
        return success
    
    def step_exec_report(self, step_num, total_steps):
        """Step 5: Executive Report"""
        self.print_step_header(step_num, total_steps, "Executive Report Generation", 1)
        
        script = BASE_DIR / "utilities" / "executive_report_generator.py"
        success = self.run_script(script)
        
        if success:
            self.results['steps_completed'].append('exec_report')
            print(f"\n{Colors.GREEN}✓ Executive report generated{Colors.NC}")
        else:
            self.results['steps_failed'].append('exec_report')
            print(f"\n{Colors.RED}✗ Executive report generation failed{Colors.NC}")
        
        return success
    
    def step_evidence_package(self, step_num, total_steps):
        """Step 6: Evidence Package"""
        self.print_step_header(step_num, total_steps, "Evidence Package Creation", 2)
        
        script = BASE_DIR / "utilities" / "evidence_manager.py"
        success = self.run_script(script)
        
        if success:
            self.results['steps_completed'].append('evidence_package')
            print(f"\n{Colors.GREEN}✓ Evidence package created{Colors.NC}")
        else:
            self.results['steps_failed'].append('evidence_package')
            print(f"\n{Colors.RED}✗ Evidence package creation failed{Colors.NC}")
        
        return success
    
    def print_summary(self):
        """Print assessment summary"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.CYAN}   ASSESSMENT COMPLETE{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.NC}\n")
        
        print(f"{Colors.BOLD}Assessment ID:{Colors.NC} {self.results['assessment_id']}")
        print(f"{Colors.BOLD}Duration:{Colors.NC} {duration}")
        print(f"{Colors.BOLD}Completed Steps:{Colors.NC} {len(self.results['steps_completed'])}")
        print(f"{Colors.BOLD}Failed Steps:{Colors.NC} {len(self.results['steps_failed'])}\n")
        
        if self.results['steps_completed']:
            print(f"{Colors.GREEN}✓ Completed:{Colors.NC}")
            for step in self.results['steps_completed']:
                print(f"  • {step.replace('_', ' ').title()}")
            print()
        
        if self.results['steps_failed']:
            print(f"{Colors.RED}✗ Failed:{Colors.NC}")
            for step in self.results['steps_failed']:
                print(f"  • {step.replace('_', ' ').title()}")
            print()
        
        # Save assessment results
        results_file = RESULTS_DIR / f"complete_assessment_{self.results['assessment_id']}.json"
        self.results['end_time'] = end_time.isoformat()
        self.results['duration_seconds'] = duration.total_seconds()
        
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"{Colors.CYAN}📄 Assessment results saved:{Colors.NC} {results_file}\n")
        
        # Smart recommendations
        self.print_recommendations()
    
    def print_recommendations(self):
        """Print smart next-step recommendations"""
        print(f"{Colors.BOLD}{Colors.YELLOW}📊 RECOMMENDED NEXT STEPS:{Colors.NC}\n")
        
        if 'compliance_check' in self.results['steps_completed']:
            print(f"  1. Review compliance report for non-compliant controls")
            print(f"  2. Address critical findings within 7 days")
        
        if 'full_network_scan' in self.results['steps_completed']:
            print(f"  3. Update asset inventory with discovered hosts")
            print(f"  4. Tag hosts by criticality (production/staging/dev)")
        
        if 'quick_vuln_scan' in self.results['steps_completed'] or 'full_vuln_scan' in self.results['steps_completed']:
            print(f"  5. Generate remediation scripts for high-severity findings")
            print(f"  6. Schedule follow-up scan in 30 days")
        
        print(f"\n  {Colors.CYAN}💡 Tip:{Colors.NC} Run '{Colors.BOLD}purple-team{Colors.NC}' menu for individual tasks")
        print(f"  {Colors.CYAN}💡 Tip:{Colors.NC} View reports in: {REPORTS_DIR}")
        print()
    
    def run(self):
        """Execute complete assessment"""
        self.print_banner()
        
        # Confirm start
        response = input(f"{Colors.YELLOW}Start {self.profiles[self.mode]['name']}? [Y/n]:{Colors.NC} ")
        if response.lower() == 'n':
            print(f"{Colors.YELLOW}Assessment cancelled{Colors.NC}")
            return
        
        print()
        
        # Get step list for this profile
        steps = self.profiles[self.mode]['steps']
        total_steps = len(steps)
        
        # Execute steps
        step_num = 1
        for step in steps:
            if step == 'network_discovery':
                if not self.step_network_discovery(step_num, total_steps):
                    print(f"\n{Colors.RED}Critical step failed. Aborting assessment.{Colors.NC}")
                    break
            elif step == 'full_network_scan':
                self.step_full_network_scan(step_num, total_steps)
            elif step == 'quick_vuln_scan':
                self.step_quick_vuln_scan(step_num, total_steps)
            elif step == 'full_vuln_scan':
                self.step_full_vuln_scan(step_num, total_steps)
            elif step == 'compliance_check':
                self.step_compliance_check(step_num, total_steps)
            elif step == 'exec_report':
                self.step_exec_report(step_num, total_steps)
            elif step == 'evidence_package':
                self.step_evidence_package(step_num, total_steps)
            
            step_num += 1
            time.sleep(1)  # Brief pause between steps
        
        # Print summary
        self.print_summary()

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Purple Team Complete Assessment Workflow'
    )
    parser.add_argument(
        '--mode',
        choices=['quick', 'standard', 'deep'],
        default='standard',
        help='Assessment mode (default: standard)'
    )
    parser.add_argument(
        '--quick',
        action='store_const',
        const='quick',
        dest='mode',
        help='Quick assessment (15-20 min)'
    )
    parser.add_argument(
        '--deep',
        action='store_const',
        const='deep',
        dest='mode',
        help='Deep assessment (2-4 hours)'
    )
    
    args = parser.parse_args()
    
    assessment = CompleteAssessment(mode=args.mode)
    assessment.run()

if __name__ == '__main__':
    main()
