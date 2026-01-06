#!/usr/bin/env python3
"""
Purple Team GRC Platform v4.0
Enhanced Progress Indicators Module

Provides rich, real-time progress feedback with:
- Progress bars with percentage
- ETA calculations
- Current activity descriptions
- Finding summaries
- Color-coded status

Usage:
  from enhanced_progress import ProgressTracker
  
  tracker = ProgressTracker(total_items=100, task_name="Network Scan")
  for i in range(100):
      tracker.update(current=i+1, status="Scanning 192.168.1.{i}")
"""

import sys
import time
from datetime import datetime, timedelta

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    NC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

class ProgressTracker:
    """Enhanced progress tracking with rich visual feedback"""
    
    def __init__(self, total_items, task_name="Task", show_eta=True, show_findings=True):
        self.total_items = total_items
        self.task_name = task_name
        self.show_eta = show_eta
        self.show_findings = show_findings
        self.current_item = 0
        self.start_time = datetime.now()
        self.findings = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        self.last_update = datetime.now()
    
    def update(self, current=None, status="", finding_severity=None):
        """Update progress with current status"""
        if current is not None:
            self.current_item = current
        else:
            self.current_item += 1
        
        # Track findings
        if finding_severity and finding_severity in self.findings:
            self.findings[finding_severity] += 1
        
        # Calculate progress
        progress_pct = int((self.current_item / self.total_items) * 100)
        
        # Calculate ETA
        elapsed = datetime.now() - self.start_time
        if self.current_item > 0 and self.show_eta:
            rate = elapsed.total_seconds() / self.current_item
            remaining_items = self.total_items - self.current_item
            eta_seconds = rate * remaining_items
            eta = timedelta(seconds=int(eta_seconds))
            eta_str = str(eta)
        else:
            eta_str = "Calculating..."
        
        # Build progress bar
        bar_length = 40
        filled = int((progress_pct / 100) * bar_length)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        # Clear line and print progress
        sys.stdout.write('\r\033[K')  # Clear line
        
        output = f"{Colors.BOLD}{self.task_name}:{Colors.NC} "
        output += f"[{Colors.CYAN}{bar}{Colors.NC}] "
        output += f"{Colors.BOLD}{progress_pct}%{Colors.NC} "
        output += f"({self.current_item}/{self.total_items})"
        
        if self.show_eta and self.current_item > 0:
            output += f" {Colors.YELLOW}ETA: {eta_str}{Colors.NC}"
        
        if status:
            output += f"\n{Colors.DIM}  → {status}{Colors.NC}"
        
        if self.show_findings and sum(self.findings.values()) > 0:
            findings_str = self._format_findings()
            output += f"\n{Colors.DIM}  📊 {findings_str}{Colors.NC}"
        
        sys.stdout.write(output)
        sys.stdout.flush()
        
        self.last_update = datetime.now()
    
    def _format_findings(self):
        """Format findings summary"""
        parts = []
        if self.findings['critical'] > 0:
            parts.append(f"{Colors.RED}🔴 {self.findings['critical']} critical{Colors.NC}")
        if self.findings['high'] > 0:
            parts.append(f"{Colors.YELLOW}🟠 {self.findings['high']} high{Colors.NC}")
        if self.findings['medium'] > 0:
            parts.append(f"{Colors.YELLOW}🟡 {self.findings['medium']} medium{Colors.NC}")
        if self.findings['low'] > 0:
            parts.append(f"{Colors.CYAN}⚪ {self.findings['low']} low{Colors.NC}")
        
        return ", ".join(parts) if parts else "No findings"
    
    def complete(self, final_message="Complete"):
        """Mark progress as complete"""
        elapsed = datetime.now() - self.start_time
        
        sys.stdout.write('\r\033[K')  # Clear line
        
        output = f"{Colors.GREEN}✓ {self.task_name} complete!{Colors.NC} "
        output += f"({self.total_items} items in {elapsed})"
        
        if self.show_findings and sum(self.findings.values()) > 0:
            output += f"\n  📊 Final: {self._format_findings()}"
        
        if final_message and final_message != "Complete":
            output += f"\n  {Colors.CYAN}→ {final_message}{Colors.NC}"
        
        print(output)
        print()  # New line after completion
    
    def error(self, error_message):
        """Show error message"""
        sys.stdout.write('\r\033[K')  # Clear line
        print(f"{Colors.RED}✗ {self.task_name} failed: {error_message}{Colors.NC}\n")

class ScanProgress:
    """Specialized progress tracker for security scans"""
    
    def __init__(self, scan_type, total_hosts):
        self.scan_type = scan_type
        self.total_hosts = total_hosts
        self.current_host = 0
        self.tracker = ProgressTracker(
            total_items=total_hosts,
            task_name=f"{scan_type} Scan",
            show_eta=True,
            show_findings=True
        )
    
    def update_host(self, host_ip, ports_found=0, services_found=None, vulnerabilities=None):
        """Update progress for current host"""
        self.current_host += 1
        
        status_parts = [f"Scanning {host_ip}"]
        
        if ports_found > 0:
            status_parts.append(f"{ports_found} ports")
        
        if services_found:
            status_parts.append(f"Services: {', '.join(services_found[:3])}")
        
        status = " | ".join(status_parts)
        
        # Track vulnerability severity if provided
        severity = None
        if vulnerabilities:
            if vulnerabilities.get('critical', 0) > 0:
                severity = 'critical'
            elif vulnerabilities.get('high', 0) > 0:
                severity = 'high'
            elif vulnerabilities.get('medium', 0) > 0:
                severity = 'medium'
            elif vulnerabilities.get('low', 0) > 0:
                severity = 'low'
        
        self.tracker.update(current=self.current_host, status=status, finding_severity=severity)
    
    def complete(self, summary_message=None):
        """Complete the scan"""
        if summary_message:
            self.tracker.complete(summary_message)
        else:
            total_findings = sum(self.tracker.findings.values())
            msg = f"{total_findings} total findings across {self.total_hosts} hosts"
            self.tracker.complete(msg)

class MultiStepProgress:
    """Progress tracker for multi-step workflows"""
    
    def __init__(self, steps):
        """
        Initialize multi-step progress
        
        Args:
            steps: List of step names or dict with {name: estimated_minutes}
        """
        self.steps = steps if isinstance(steps, list) else list(steps.keys())
        self.step_times = steps if isinstance(steps, dict) else {s: 5 for s in steps}
        self.current_step = 0
        self.start_time = datetime.now()
        self.step_start_time = datetime.now()
    
    def start_step(self, step_name=None):
        """Start next step"""
        if step_name:
            self.current_step = self.steps.index(step_name)
        
        step = self.steps[self.current_step]
        total_steps = len(self.steps)
        progress = int(((self.current_step + 1) / total_steps) * 100)
        
        # Progress bar for overall workflow
        bar_length = 50
        filled = int((progress / 100) * bar_length)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'─'*70}{Colors.NC}")
        print(f"{Colors.BOLD}STEP {self.current_step + 1}/{total_steps}: {step.upper()}{Colors.NC}")
        print(f"{Colors.CYAN}Overall Progress: [{bar}] {progress}%{Colors.NC}")
        
        # Show ETA
        est_minutes = self.step_times.get(step, 5)
        print(f"{Colors.YELLOW}Estimated time: ~{est_minutes} minutes{Colors.NC}")
        print(f"{Colors.BLUE}{'─'*70}{Colors.NC}\n")
        
        self.step_start_time = datetime.now()
    
    def complete_step(self, message=None):
        """Complete current step"""
        step = self.steps[self.current_step]
        elapsed = datetime.now() - self.step_start_time
        
        msg = message if message else f"{step} completed"
        print(f"\n{Colors.GREEN}✓ {msg}{Colors.NC} (took {elapsed})\n")
        
        self.current_step += 1
    
    def complete_workflow(self):
        """Complete entire workflow"""
        total_elapsed = datetime.now() - self.start_time
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.GREEN}✓ WORKFLOW COMPLETE{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*70}{Colors.NC}")
        print(f"\n{Colors.BOLD}Total time:{Colors.NC} {total_elapsed}")
        print(f"{Colors.BOLD}Steps completed:{Colors.NC} {len(self.steps)}\n")

# Utility functions for quick use

def show_spinner(message, duration=2):
    """Show a simple spinner animation"""
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    i = 0
    
    while time.time() < end_time:
        sys.stdout.write(f'\r{Colors.CYAN}{spinner[i % len(spinner)]}{Colors.NC} {message}')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write('\r\033[K')  # Clear line
    print(f"{Colors.GREEN}✓{Colors.NC} {message}")

def show_progress_bar(current, total, prefix='Progress', suffix='Complete', length=50):
    """Simple progress bar function"""
    percent = int((current / total) * 100)
    filled = int(length * current // total)
    bar = '█' * filled + '░' * (length - filled)
    
    sys.stdout.write(f'\r{prefix}: [{Colors.CYAN}{bar}{Colors.NC}] {percent}% {suffix}')
    sys.stdout.flush()
    
    if current == total:
        print()  # New line on completion

# Example usage
if __name__ == '__main__':
    import random
    
    print(f"{Colors.BOLD}Enhanced Progress Indicators Demo{Colors.NC}\n")
    
    # Demo 1: Basic progress tracker
    print(f"{Colors.BOLD}Demo 1: Basic Progress Tracker{Colors.NC}")
    tracker = ProgressTracker(total_items=20, task_name="File Processing")
    for i in range(20):
        tracker.update(status=f"Processing file_{i+1}.txt")
        time.sleep(0.2)
    tracker.complete("All files processed successfully")
    
    time.sleep(1)
    
    # Demo 2: Scan progress with findings
    print(f"\n{Colors.BOLD}Demo 2: Security Scan with Findings{Colors.NC}")
    scan = ScanProgress(scan_type="Network", total_hosts=10)
    
    hosts = [f"192.168.1.{i}" for i in range(100, 110)]
    for host in hosts:
        ports = random.randint(0, 5)
        services = ['http', 'ssh', 'smtp', 'telnet'][:random.randint(0, 3)]
        
        # Randomly add findings
        vuln = None
        if random.random() > 0.7:
            vuln = {'critical': random.randint(0, 1), 'high': random.randint(0, 2)}
        
        scan.update_host(host, ports_found=ports, services_found=services, vulnerabilities=vuln)
        time.sleep(0.3)
    
    scan.complete()
    
    time.sleep(1)
    
    # Demo 3: Multi-step workflow
    print(f"\n{Colors.BOLD}Demo 3: Multi-Step Workflow{Colors.NC}")
    workflow = MultiStepProgress({
        'Initialize': 1,
        'Scan Network': 5,
        'Analyze Results': 2,
        'Generate Report': 1
    })
    
    for step in ['Initialize', 'Scan Network', 'Analyze Results', 'Generate Report']:
        workflow.start_step(step)
        time.sleep(1)
        workflow.complete_step()
    
    workflow.complete_workflow()
    
    print(f"\n{Colors.GREEN}✓ Demo complete!{Colors.NC}\n")
