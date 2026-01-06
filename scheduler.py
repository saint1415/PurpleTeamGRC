#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

"""
Purple Team Scan Scheduler
Handles automated scheduling and execution of security scans
"""

import schedule
import time
import yaml
import logging
import subprocess
import json
from datetime import datetime
from pathlib import Path
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(LOGS_DIR / 'scheduler.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Paths

SCANNERS_DIR = BASE_DIR / 'scanners'

class ScanScheduler:
    """Manages scheduling and execution of security scans"""
    
    def __init__(self):
        self.config = self.load_config()
        self.setup_schedules()
        
    def load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = yaml.safe_load(f)
            logger.info("Configuration loaded successfully")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def setup_schedules(self):
        """Setup scheduled scans based on configuration"""
        schedule_config = self.config.get('schedule', {})
        
        # Vulnerability Scan
        vuln_scan = schedule_config.get('vulnerability_scan', {})
        if vuln_scan.get('enabled', False):
            day = vuln_scan.get('day', 'Monday')
            time_str = vuln_scan.get('time', '02:00')
            getattr(schedule.every(), day.lower()).at(time_str).do(
                self.run_vulnerability_scan
            )
            logger.info(f"Scheduled vulnerability scan: {day} at {time_str}")
        
        # Network Scan
        net_scan = schedule_config.get('network_scan', {})
        if net_scan.get('enabled', False):
            day = net_scan.get('day', 'Wednesday')
            time_str = net_scan.get('time', '02:00')
            getattr(schedule.every(), day.lower()).at(time_str).do(
                self.run_network_scan
            )
            logger.info(f"Scheduled network scan: {day} at {time_str}")
        
        # Compliance Check
        comp_check = schedule_config.get('compliance_check', {})
        if comp_check.get('enabled', False):
            day = comp_check.get('day', 'Friday')
            time_str = comp_check.get('time', '02:00')
            getattr(schedule.every(), day.lower()).at(time_str).do(
                self.run_compliance_check
            )
            logger.info(f"Scheduled compliance check: {day} at {time_str}")
    
    def run_vulnerability_scan(self):
        """Execute vulnerability scanning"""
        logger.info("Starting scheduled vulnerability scan")
        try:
            result = subprocess.run(
                [sys.executable, str(SCANNERS_DIR / 'vulnerability_scanner.py')],
                capture_output=True,
                text=True,
                timeout=7200  # 2 hour timeout
            )
            if result.returncode == 0:
                logger.info("Vulnerability scan completed successfully")
            else:
                logger.error(f"Vulnerability scan failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Vulnerability scan timed out")
        except Exception as e:
            logger.error(f"Error running vulnerability scan: {e}")
    
    def run_network_scan(self):
        """Execute network scanning"""
        logger.info("Starting scheduled network scan")
        try:
            result = subprocess.run(
                [sys.executable, str(SCANNERS_DIR / 'network_scanner.py')],
                capture_output=True,
                text=True,
                timeout=7200  # 2 hour timeout
            )
            if result.returncode == 0:
                logger.info("Network scan completed successfully")
            else:
                logger.error(f"Network scan failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Network scan timed out")
        except Exception as e:
            logger.error(f"Error running network scan: {e}")
    
    def run_compliance_check(self):
        """Execute compliance checking"""
        logger.info("Starting scheduled compliance check")
        try:
            result = subprocess.run(
                [sys.executable, str(SCANNERS_DIR / 'compliance_checker.py')],
                capture_output=True,
                text=True,
                timeout=7200  # 2 hour timeout
            )
            if result.returncode == 0:
                logger.info("Compliance check completed successfully")
            else:
                logger.error(f"Compliance check failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("Compliance check timed out")
        except Exception as e:
            logger.error(f"Error running compliance check: {e}")
    
    def run(self):
        """Main scheduler loop"""
        logger.info("Scan scheduler started")
        logger.info(f"Next scheduled scans:")
        for job in schedule.jobs:
            logger.info(f"  - {job}")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

def main():
    """Main entry point"""
    try:
        scheduler = ScanScheduler()
        scheduler.run()
    except KeyboardInterrupt:
        logger.info("Scheduler stopped by user")
    except Exception as e:
        logger.error(f"Scheduler error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
