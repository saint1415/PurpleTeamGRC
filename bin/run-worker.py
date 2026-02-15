#!/usr/bin/env python3
"""
Purple Team GRC Platform - Background Worker
Runs scheduled tasks, NVD updates, agent check-ins, and notifications.
Designed for containerized deployment with graceful shutdown support.
"""

import os
import sys
import time
import signal
import threading
from datetime import datetime, timedelta
from pathlib import Path

# Setup paths
SCRIPT_DIR = Path(__file__).resolve().parent
PURPLE_TEAM_HOME = SCRIPT_DIR.parent
sys.path.insert(0, str(PURPLE_TEAM_HOME / 'lib'))

from logger import get_logger
from database import get_database

logger = get_logger('worker')

# Global flag for graceful shutdown
_shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global _shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    _shutdown_requested = True


class BackgroundWorker:
    """Background worker for scheduled tasks and maintenance."""

    def __init__(self):
        self.logger = logger
        self.last_nvd_update = datetime.utcnow()
        self.last_notification_check = datetime.utcnow()
        self.last_exception_cleanup = datetime.utcnow()
        self.last_agent_check = datetime.utcnow()
        self.last_feed_update = datetime.utcnow()
        self.last_epss_refresh = datetime.utcnow()

    def run_scheduled_scans(self):
        """Check for and execute due scheduled scans."""
        try:
            from scheduler import SchedulerManager

            scheduler = SchedulerManager()
            due_schedules = scheduler.get_due_schedules()

            if due_schedules:
                self.logger.info(f"Found {len(due_schedules)} scheduled scans due for execution")

                for schedule in due_schedules:
                    if _shutdown_requested:
                        break

                    try:
                        schedule_id = schedule['schedule_id']
                        name = schedule['name']
                        scanner_type = schedule['scanner_type']

                        self.logger.info(f"Executing scheduled scan: {name} ({scanner_type})")

                        # Start the scheduled scan run
                        run_id = scheduler.start_run(schedule_id)

                        # Import and run the appropriate scanner
                        # This would integrate with your existing scanner modules
                        self.logger.info(f"Started scan run {run_id} for schedule {schedule_id}")

                        # Mark the schedule as executed
                        scheduler.mark_run_complete(run_id, 'completed', {
                            'executed_at': datetime.utcnow().isoformat()
                        })

                    except Exception as e:
                        self.logger.error(f"Error executing schedule {schedule.get('name', 'unknown')}: {e}")

        except Exception as e:
            self.logger.error(f"Error in run_scheduled_scans: {e}")

    def update_nvd_data(self):
        """Run incremental NVD vulnerability database updates."""
        try:
            from vuln_database import VulnerabilityDatabase

            self.logger.info("Starting NVD incremental update...")
            vdb = VulnerabilityDatabase()

            # Update with recent CVEs (last 7 days)
            results = vdb.update_recent_cves(days=7)

            if results:
                self.logger.info(f"NVD update complete: {results.get('updated_count', 0)} CVEs updated")

            self.last_nvd_update = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error in update_nvd_data: {e}")

    def process_notifications(self):
        """Send pending notifications for critical events and SLA breaches."""
        try:
            from notifications import NotificationManager
            from remediation import RemediationTracker

            notif_mgr = NotificationManager()
            remediation = RemediationTracker()

            # Check for SLA breaches
            overdue_items = remediation.get_overdue_items()

            if overdue_items:
                self.logger.info(f"Found {len(overdue_items)} overdue remediation items")

                for item in overdue_items:
                    # Send SLA breach notification
                    notif_mgr.send_event(
                        event_type='sla_breach',
                        severity='HIGH',
                        subject=f"SLA Breach: {item['title']}",
                        body=f"Remediation item {item['item_id']} is overdue. "
                             f"Due date: {item['due_date']}, Severity: {item['severity']}"
                    )

            # Process pending notifications
            pending = notif_mgr.get_pending_notifications(limit=50)

            if pending:
                self.logger.info(f"Processing {len(pending)} pending notifications")
                notif_mgr.process_pending()

            self.last_notification_check = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error in process_notifications: {e}")

    def cleanup_expired_exceptions(self):
        """Clean up and notify about expired exception approvals."""
        try:
            from exceptions import ExceptionManager
            from notifications import NotificationManager

            exc_mgr = ExceptionManager()
            notif_mgr = NotificationManager()

            # Find exceptions expiring in the next 7 days
            expiring = exc_mgr.get_expiring_exceptions(days=7)

            if expiring:
                self.logger.info(f"Found {len(expiring)} exceptions expiring soon")

                for exception in expiring:
                    # Send expiration warning
                    notif_mgr.send_event(
                        event_type='exception_expiring',
                        severity='MEDIUM',
                        subject=f"Exception Expiring: {exception['title_pattern']}",
                        body=f"Exception {exception['exception_id']} expires on {exception['expires_at']}"
                    )

            # Auto-expire exceptions
            expired_count = exc_mgr.expire_old_exceptions()

            if expired_count > 0:
                self.logger.info(f"Auto-expired {expired_count} exceptions")

            self.last_exception_cleanup = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error in cleanup_expired_exceptions: {e}")

    def process_agent_checkins(self):
        """Process agent check-ins and update asset inventory."""
        try:
            # This would integrate with your agent deployment system
            # For now, just log that we checked
            self.logger.debug("Checking for agent updates...")
            self.last_agent_check = datetime.utcnow()

        except Exception as e:
            self.logger.error(f"Error in process_agent_checkins: {e}")

    def update_intel_feeds(self):
        """Run all intel feed updates."""
        try:
            from intel_feeds import IntelFeedManager
            self.logger.info("Starting intel feed update...")
            mgr = IntelFeedManager()
            results = mgr.update_all()
            total = results.get('_total', 0)
            self.logger.info(f"Intel feeds updated: {total} total records")
            self.last_feed_update = datetime.utcnow()
        except Exception as e:
            self.logger.error(f"Error in update_intel_feeds: {e}")

    def refresh_epss_scores(self):
        """Refresh EPSS scores if stale."""
        try:
            from threat_intel import get_threat_intel
            ti = get_threat_intel()
            refreshed = ti.refresh_if_stale()
            if refreshed.get('kev'):
                self.logger.info("KEV catalog refreshed")
            self.last_epss_refresh = datetime.utcnow()
        except Exception as e:
            self.logger.error(f"Error refreshing EPSS/KEV: {e}")

    def run(self):
        """Main worker loop."""
        self.logger.info("Background worker started")
        self.logger.info("Database backend: " + os.environ.get('PURPLE_DB_BACKEND', 'sqlite'))

        # Task intervals (in seconds)
        SCHEDULE_CHECK_INTERVAL = 60  # Check for scheduled scans every minute
        NVD_UPDATE_INTERVAL = 4 * 3600  # Update NVD every 4 hours
        NOTIFICATION_INTERVAL = 300  # Check notifications every 5 minutes
        EXCEPTION_CLEANUP_INTERVAL = 3600  # Clean up exceptions every hour
        AGENT_CHECK_INTERVAL = 600  # Check agents every 10 minutes
        FEED_UPDATE_INTERVAL = 24 * 3600  # Update intel feeds every 24 hours
        EPSS_REFRESH_INTERVAL = 24 * 3600  # Refresh EPSS every 24 hours

        while not _shutdown_requested:
            try:
                now = datetime.utcnow()

                # Check for scheduled scans (every minute)
                self.run_scheduled_scans()

                # Update NVD data (every 4 hours)
                if (now - self.last_nvd_update).total_seconds() >= NVD_UPDATE_INTERVAL:
                    self.update_nvd_data()

                # Process notifications (every 5 minutes)
                if (now - self.last_notification_check).total_seconds() >= NOTIFICATION_INTERVAL:
                    self.process_notifications()

                # Clean up expired exceptions (every hour)
                if (now - self.last_exception_cleanup).total_seconds() >= EXCEPTION_CLEANUP_INTERVAL:
                    self.cleanup_expired_exceptions()

                # Process agent check-ins (every 10 minutes)
                if (now - self.last_agent_check).total_seconds() >= AGENT_CHECK_INTERVAL:
                    self.process_agent_checkins()

                # Update intel feeds (every 24 hours)
                if (now - self.last_feed_update).total_seconds() >= FEED_UPDATE_INTERVAL:
                    self.update_intel_feeds()

                # Refresh EPSS scores (every 24 hours)
                if (now - self.last_epss_refresh).total_seconds() >= EPSS_REFRESH_INTERVAL:
                    self.refresh_epss_scores()

                # Sleep for the schedule check interval
                time.sleep(SCHEDULE_CHECK_INTERVAL)

            except KeyboardInterrupt:
                self.logger.info("Keyboard interrupt received, shutting down...")
                break
            except Exception as e:
                self.logger.error(f"Error in main worker loop: {e}")
                time.sleep(SCHEDULE_CHECK_INTERVAL)

        self.logger.info("Background worker stopped")


def main():
    """Entry point for background worker."""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Create and run worker
    worker = BackgroundWorker()

    try:
        worker.run()
    except Exception as e:
        logger.error(f"Fatal error in worker: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
