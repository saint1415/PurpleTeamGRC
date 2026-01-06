#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR, EVIDENCE_DIR

EVIDENCE_DB = EVIDENCE_DIR / 'evidence.db'
RISK_DB = RESULTS_DIR / 'risk' / 'risk.db'
LOG_DIR = LOGS_DIR
"""
Health Check Monitor
Monitors the Purple Team platform for issues and sends alerts

Checks:
- Service status (dashboard, scheduler)
- Disk space
- Recent scan activity
- Database accessibility
- Log file growth
"""

import subprocess
import psutil
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import json
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths already defined at top of file (lines 11-12)


class HealthCheckMonitor:
    """Monitor platform health and report issues"""
    
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.info = []
    
    def check_services(self):
        """Check if systemd services are running"""
        
        services = [
            'purple-team-dashboard',
            'purple-team-scheduler'
        ]
        
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.stdout.strip() == 'active':
                    self.info.append(f"Ã¢Å“â€œ Service {service} is running")
                else:
                    self.issues.append(f"Ã¢Å“â€” Service {service} is NOT running")
                    
            except Exception as e:
                self.warnings.append(f"Ã¢Å¡Â  Could not check service {service}: {e}")
    
    def check_disk_space(self):
        """Check available disk space"""
        
        try:
            usage = psutil.disk_usage('/')
            percent_used = usage.percent
            
            if percent_used > 90:
                self.issues.append(f"Ã¢Å“â€” Disk space critical: {percent_used}% used")
            elif percent_used > 75:
                self.warnings.append(f"Ã¢Å¡Â  Disk space warning: {percent_used}% used")
            else:
                self.info.append(f"Ã¢Å“â€œ Disk space OK: {percent_used}% used")
                
        except Exception as e:
            self.warnings.append(f"Ã¢Å¡Â  Could not check disk space: {e}")
    
    def check_recent_scans(self):
        """Check if scans have run recently"""
        
        # Check for recent scan files
        scan_types = [
            ('vulnerability', 24),  # Should run daily
            ('network', 72),        # Should run every 3 days
            ('compliance', 24)      # Should run daily
        ]
        
        for scan_type, max_hours_old in scan_types:
            try:
                pattern = f'{scan_type}_scan_*.html'
                scan_files = list(BASE_DIR.glob(f'reports/{pattern}'))
                
                if not scan_files:
                    self.warnings.append(f"Ã¢Å¡Â  No {scan_type} scans found")
                    continue
                
                latest_scan = max(scan_files, key=lambda p: p.stat().st_mtime)
                hours_old = (datetime.now().timestamp() - latest_scan.stat().st_mtime) / 3600
                
                if hours_old > max_hours_old:
                    self.warnings.append(
                        f"Ã¢Å¡Â  Last {scan_type} scan is {hours_old:.1f} hours old"
                    )
                else:
                    self.info.append(
                        f"Ã¢Å“â€œ {scan_type.capitalize()} scan is recent ({hours_old:.1f}h old)"
                    )
                    
            except Exception as e:
                self.warnings.append(f"Ã¢Å¡Â  Could not check {scan_type} scans: {e}")
    
    def check_databases(self):
        """Check database accessibility"""
        
        databases = [
            ('Evidence', EVIDENCE_DB),
            ('Risk', RISK_DB)
        ]
        
        for name, db_path in databases:
            try:
                if not db_path.exists():
                    self.warnings.append(f"Ã¢Å¡Â  {name} database not found: {db_path}")
                    continue
                
                # Try to connect and query
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                conn.close()
                
                self.info.append(f"Ã¢Å“â€œ {name} database accessible ({len(tables)} tables)")
                
            except Exception as e:
                self.issues.append(f"Ã¢Å“â€” {name} database error: {e}")
    
    def check_log_files(self):
        """Check log file sizes"""
        
        try:
            if not LOG_DIR.exists():
                self.warnings.append(f"Ã¢Å¡Â  Log directory not found: {LOG_DIR}")
                return
            
            total_size = 0
            large_logs = []
            
            for log_file in LOG_DIR.glob('*.log'):
                size_mb = log_file.stat().st_size / (1024 * 1024)
                total_size += size_mb
                
                if size_mb > 100:  # Log file > 100MB
                    large_logs.append(f"{log_file.name} ({size_mb:.1f}MB)")
            
            if large_logs:
                self.warnings.append(
                    f"Ã¢Å¡Â  Large log files detected: {', '.join(large_logs)}"
                )
            
            if total_size > 1000:  # Total logs > 1GB
                self.warnings.append(
                    f"Ã¢Å¡Â  Total log size is large: {total_size:.1f}MB"
                )
            else:
                self.info.append(f"Ã¢Å“â€œ Log files OK: {total_size:.1f}MB total")
                
        except Exception as e:
            self.warnings.append(f"Ã¢Å¡Â  Could not check log files: {e}")
    
    def check_python_dependencies(self):
        """Check if required Python packages are installed"""
        
        required_packages = [
            'python-nmap',
            'requests',
            'flask',
            'pyyaml',
            'openpyxl'
        ]
        
        missing = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing.append(package)
        
        if missing:
            self.issues.append(
                f"Ã¢Å“â€” Missing Python packages: {', '.join(missing)}"
            )
        else:
            self.info.append(f"Ã¢Å“â€œ All required Python packages installed")
    
    def check_system_resources(self):
        """Check CPU and memory usage"""
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                self.warnings.append(f"Ã¢Å¡Â  High CPU usage: {cpu_percent}%")
            else:
                self.info.append(f"Ã¢Å“â€œ CPU usage OK: {cpu_percent}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                self.warnings.append(f"Ã¢Å¡Â  High memory usage: {memory.percent}%")
            else:
                self.info.append(f"Ã¢Å“â€œ Memory usage OK: {memory.percent}%")
                
        except Exception as e:
            self.warnings.append(f"Ã¢Å¡Â  Could not check system resources: {e}")
    
    def run_all_checks(self):
        """Run all health checks"""
        
        logger.info("Starting health checks...")
        
        self.check_services()
        self.check_disk_space()
        self.check_recent_scans()
        self.check_databases()
        self.check_log_files()
        self.check_python_dependencies()
        self.check_system_resources()
        
        return self.generate_report()
    
    def generate_report(self):
        """Generate health check report"""
        
        status = 'HEALTHY' if not self.issues else 'UNHEALTHY'
        if self.warnings and not self.issues:
            status = 'WARNING'
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'status': status,
            'issues': self.issues,
            'warnings': self.warnings,
            'info': self.info,
            'summary': {
                'critical_issues': len(self.issues),
                'warnings': len(self.warnings),
                'checks_passed': len(self.info)
            }
        }
        
        return report
    
    def print_report(self, report):
        """Print health check report to console"""
        
        print("\n" + "="*70)
        print("PURPLE TEAM PLATFORM - HEALTH CHECK REPORT")
        print("="*70)
        print(f"Status: {report['status']}")
        print(f"Time: {report['timestamp']}")
        print(f"Critical Issues: {report['summary']['critical_issues']}")
        print(f"Warnings: {report['summary']['warnings']}")
        print(f"Checks Passed: {report['summary']['checks_passed']}")
        print("="*70)
        
        if report['issues']:
            print("\nÃ°Å¸Å¡Â¨ CRITICAL ISSUES:")
            for issue in report['issues']:
                print(f"  {issue}")
        
        if report['warnings']:
            print("\nÃ¢Å¡Â Ã¯Â¸Â  WARNINGS:")
            for warning in report['warnings']:
                print(f"  {warning}")
        
        if report['info']:
            print("\nÃ¢Å“â€¦ PASSED CHECKS:")
            for info in report['info']:
                print(f"  {info}")
        
        print("\n" + "="*70)
    
    def save_report(self, report, output_file=None):
        """Save health check report to file"""
        
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = BASE_DIR / f'reports/health_check_{timestamp}.json'
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Health check report saved to {output_file}")
        return output_file

def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Purple Team Platform Health Check')
    parser.add_argument('--quiet', action='store_true', 
                       help='Only show issues and warnings')
    parser.add_argument('--save', action='store_true',
                       help='Save report to file')
    parser.add_argument('--json', action='store_true',
                       help='Output as JSON')
    
    args = parser.parse_args()
    
    monitor = HealthCheckMonitor()
    report = monitor.run_all_checks()
    
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if args.quiet:
            # Only print issues and warnings
            if report['issues']:
                print("\nÃ°Å¸Å¡Â¨ CRITICAL ISSUES:")
                for issue in report['issues']:
                    print(f"  {issue}")
            
            if report['warnings']:
                print("\nÃ¢Å¡Â Ã¯Â¸Â  WARNINGS:")
                for warning in report['warnings']:
                    print(f"  {warning}")
            
            if not report['issues'] and not report['warnings']:
                print("\nÃ¢Å“â€¦ All health checks passed!")
        else:
            monitor.print_report(report)
    
    if args.save:
        monitor.save_report(report)
    
    # Exit code based on status
    if report['issues']:
        exit(1)  # Critical issues
    elif report['warnings']:
        exit(2)  # Warnings only
    else:
        exit(0)  # All good

if __name__ == '__main__':
    main()
