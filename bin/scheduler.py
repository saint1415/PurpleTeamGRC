#!/usr/bin/env python3
"""
Purple Team Portable - Scheduler
Configures cron-based scheduled scans with human-paced execution.
Runs between 6-8pm with randomized start times.
Fully portable - works from any installation location including USB.
"""

import os
import sys
import random
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

# Set up paths - auto-detect from script location
SCRIPT_DIR = Path(__file__).resolve().parent
PURPLE_TEAM_HOME = SCRIPT_DIR.parent
sys.path.insert(0, str(PURPLE_TEAM_HOME / 'lib'))

from paths import paths
from config import config
from logger import get_logger

logger = get_logger('scheduler')


class ScanScheduler:
    """Manages scheduled security scans."""

    CRON_MARKER = "# Purple Team Portable Scheduled Scan"

    def __init__(self):
        self.home = PURPLE_TEAM_HOME
        self.config = config

    def setup_monthly_scan(self, day_of_month: int = 1,
                            assessment_type: str = 'standard') -> bool:
        """
        Set up monthly scheduled scans.

        Args:
            day_of_month: Day of month to run (1-28)
            assessment_type: 'quick', 'standard', or 'deep'
        """
        if sys.platform == 'win32':
            logger.error("Cron scheduling not available on Windows. Use Task Scheduler instead.")
            print("Windows: Use Task Scheduler to schedule:")
            print(f"  {sys.executable} {self.home / 'bin' / 'purple-launcher'} {assessment_type}")
            return False

        # Validate day
        if day_of_month < 1 or day_of_month > 28:
            logger.error("Day must be between 1 and 28")
            return False

        # Get random minute within 6-8pm window (18:00-20:00)
        hour = random.randint(18, 19)
        minute = random.randint(0, 59)

        # Build cron command - use absolute path for cron
        scan_script = self.home / 'bin' / 'run-scheduled-scan.sh'
        log_file = paths.logs / 'scheduled_scan.log'

        # Ensure the scan script exists and is portable
        create_scan_script()

        cron_line = f"{minute} {hour} {day_of_month} * * {scan_script} {assessment_type} >> {log_file} 2>&1 {self.CRON_MARKER}"

        # Remove existing Purple Team cron entries
        self._remove_existing_cron()

        # Add new cron entry
        try:
            # Get current crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""

            # Add new entry
            new_cron = current_cron.rstrip() + "\n" + cron_line + "\n"

            # Install new crontab
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(new_cron)

            if process.returncode == 0:
                logger.info(f"Scheduled {assessment_type} scan for day {day_of_month} at {hour}:{minute:02d}")
                print(f"\n✓ Scheduled monthly {assessment_type} scan")
                print(f"  Day: {day_of_month} of each month")
                print(f"  Time: {hour}:{minute:02d} (randomized within 6-8pm window)")
                print(f"  Log: {log_file}")
                print(f"\n  NOTE: Cron uses absolute path: {scan_script}")
                print(f"  If you move the installation, re-run: bin/purple-team schedule")
                return True
            else:
                logger.error("Failed to install crontab")
                return False

        except Exception as e:
            logger.error(f"Failed to set up cron: {e}")
            return False

    def _remove_existing_cron(self):
        """Remove existing Purple Team cron entries."""
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode != 0:
                return

            lines = result.stdout.split('\n')
            new_lines = [l for l in lines if self.CRON_MARKER not in l]
            new_cron = '\n'.join(new_lines)

            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(new_cron)

        except Exception as e:
            logger.warning(f"Could not clean existing cron: {e}")

    def get_status(self) -> dict:
        """Get current schedule status."""
        status = {
            'scheduled': False,
            'schedule': None,
            'last_run': None,
            'next_run': None
        }

        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if self.CRON_MARKER in line:
                        status['scheduled'] = True
                        # Parse schedule
                        parts = line.split()
                        if len(parts) >= 5:
                            minute, hour, day = parts[0], parts[1], parts[2]
                            status['schedule'] = f"Day {day} at {hour}:{minute}"

                            # Calculate next run
                            now = datetime.now()
                            next_day = int(day)
                            next_hour = int(hour)
                            next_minute = int(minute)

                            next_run = now.replace(day=next_day, hour=next_hour,
                                                   minute=next_minute, second=0)
                            if next_run < now:
                                # Next month
                                if now.month == 12:
                                    next_run = next_run.replace(year=now.year + 1, month=1)
                                else:
                                    next_run = next_run.replace(month=now.month + 1)

                            status['next_run'] = next_run.isoformat()
                        break

            # Check last run
            log_file = paths.logs / 'scheduled_scan.log'
            if log_file.exists():
                stat = log_file.stat()
                status['last_run'] = datetime.fromtimestamp(stat.st_mtime).isoformat()

        except Exception as e:
            logger.warning(f"Could not get status: {e}")

        return status

    def remove_schedule(self) -> bool:
        """Remove scheduled scans."""
        self._remove_existing_cron()
        logger.info("Removed scheduled scans")
        print("✓ Scheduled scans removed")
        return True

    def run_now(self, assessment_type: str = 'standard'):
        """Run a scan immediately."""
        logger.info(f"Running {assessment_type} scan now")

        scan_script = self.home / 'bin' / 'run-scheduled-scan.sh'
        subprocess.run([str(scan_script), assessment_type])


def create_scan_script():
    """Create the scheduled scan runner script - fully portable version."""
    script_path = PURPLE_TEAM_HOME / 'bin' / 'run-scheduled-scan.sh'

    # This script auto-detects its location - no hardcoded paths
    script_content = '''#!/usr/bin/env bash
#
# Purple Team Portable - Scheduled Scan Runner
# Called by cron to execute scheduled assessments
# Fully portable - auto-detects installation location
#

# Auto-detect installation directory from script location
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

# Set PURPLE_TEAM_HOME to parent of bin/
export PURPLE_TEAM_HOME="$(dirname "$SCRIPT_DIR")"
export PYTHONPATH="$PURPLE_TEAM_HOME/lib:$PYTHONPATH"

ASSESSMENT_TYPE="${1:-standard}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "========================================"
echo "Purple Team Scheduled Scan"
echo "Started: $(date)"
echo "Type: $ASSESSMENT_TYPE"
echo "Location: $PURPLE_TEAM_HOME"
echo "========================================"

# Check if virtual environment exists
if [ -f "$PURPLE_TEAM_HOME/venv/bin/python3" ]; then
    PYTHON="$PURPLE_TEAM_HOME/venv/bin/python3"
else
    PYTHON="python3"
fi

# Run assessment
$PYTHON -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
sys.path.insert(0, '$PURPLE_TEAM_HOME/utilities')

from orchestrator import AssessmentOrchestrator

orchestrator = AssessmentOrchestrator()
results = orchestrator.run_full_assessment(assessment_type='$ASSESSMENT_TYPE')

print(f'\\nAssessment complete!')
print(f'Session: {results.get(\"session_id\")}')
print(f'Total findings: {results.get(\"summary\", {}).get(\"total_findings\", 0)}')
"

# Generate reports
$PYTHON -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
sys.path.insert(0, '$PURPLE_TEAM_HOME/utilities')

from reporter import ReportGenerator
from config import config

reporter = ReportGenerator()
for fw in config.get_frameworks():
    try:
        reporter.generate_compliance_report(fw)
    except Exception as e:
        print(f'Report generation error for {fw}: {e}')
"

echo "========================================"
echo "Completed: $(date)"
echo "========================================"
'''

    script_path.parent.mkdir(parents=True, exist_ok=True)
    with open(script_path, 'w') as f:
        f.write(script_content)

    if sys.platform != 'win32':
        os.chmod(script_path, 0o755)
    logger.info(f"Created portable scan script: {script_path}")


def interactive_setup():
    """Interactive schedule setup."""
    print("\n" + "=" * 50)
    print("Purple Team Portable - Schedule Setup")
    print("=" * 50)

    scheduler = ScanScheduler()

    # Check current status
    status = scheduler.get_status()
    if status['scheduled']:
        print(f"\nCurrent schedule: {status['schedule']}")
        print(f"Next run: {status['next_run']}")
        response = input("\nModify schedule? (y/n): ").lower()
        if response != 'y':
            return

    # Get preferences
    print("\nAssessment types:")
    print("  1) Quick (15-30 min)")
    print("  2) Standard (1-2 hours)")
    print("  3) Deep (2-4 hours)")

    type_choice = input("\nSelect type [2]: ").strip() or "2"
    assessment_types = {'1': 'quick', '2': 'standard', '3': 'deep'}
    assessment_type = assessment_types.get(type_choice, 'standard')

    day_input = input("Day of month (1-28) [1]: ").strip() or "1"
    try:
        day_of_month = int(day_input)
    except ValueError:
        day_of_month = 1

    print(f"\nSetting up {assessment_type} scan on day {day_of_month}...")
    print("(Start time will be randomized between 6-8pm)")

    # Set up cron
    scheduler.setup_monthly_scan(day_of_month, assessment_type)


def main():
    parser = argparse.ArgumentParser(description='Purple Team Scan Scheduler')
    parser.add_argument('--setup', action='store_true', help='Interactive setup')
    parser.add_argument('--status', action='store_true', help='Show schedule status')
    parser.add_argument('--remove', action='store_true', help='Remove schedule')
    parser.add_argument('--run-now', action='store_true', help='Run scan immediately')
    parser.add_argument('--type', choices=['quick', 'standard', 'deep'],
                       default='standard', help='Assessment type')

    args = parser.parse_args()

    scheduler = ScanScheduler()

    if args.status:
        status = scheduler.get_status()
        print("\nSchedule Status:")
        print(f"  Scheduled: {'Yes' if status['scheduled'] else 'No'}")
        if status['scheduled']:
            print(f"  Schedule: {status['schedule']}")
            print(f"  Next run: {status['next_run']}")
        if status['last_run']:
            print(f"  Last run: {status['last_run']}")

    elif args.remove:
        scheduler.remove_schedule()

    elif args.run_now:
        create_scan_script()
        scheduler.run_now(args.type)

    elif args.setup:
        interactive_setup()

    else:
        interactive_setup()


if __name__ == '__main__':
    main()
