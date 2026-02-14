#!/usr/bin/env python3
"""
Purple Team GRC - Scheduled Scanning Module
Manages scan schedules with cron-like expressions, tracks execution history,
and provides a scheduler loop for automated scanning operations.
"""

import json
import sqlite3
import uuid
import time
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
except ImportError:
    from paths import paths


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SCANNER_TYPES = (
    "windows", "linux", "network", "ad", "cloud", "container", "sbom", "full"
)
VALID_SCAN_TYPES = ("quick", "standard", "deep")
VALID_RUN_STATUSES = ("running", "completed", "failed")

logger = logging.getLogger("purpleteam.scheduler")


# ---------------------------------------------------------------------------
# Cron Parser
# ---------------------------------------------------------------------------

class CronParser:
    """
    Minimal cron expression parser.

    Supports five fields: minute, hour, day-of-month, month, day-of-week.
    Each field may contain:
        *       - any value
        */N     - every N units
        N       - exact value
        N-M     - inclusive range
        N,M,O   - list of values (combinations of the above)
    Day-of-week: 0 = Monday ... 6 = Sunday (ISO weekday convention).
    """

    FIELD_NAMES = ("minute", "hour", "day", "month", "weekday")
    FIELD_RANGES = {
        "minute":  (0, 59),
        "hour":    (0, 23),
        "day":     (1, 31),
        "month":   (1, 12),
        "weekday": (0, 6),
    }

    def __init__(self, expression: str):
        parts = expression.strip().split()
        if len(parts) != 5:
            raise ValueError(
                f"Cron expression must have 5 fields, got {len(parts)}: {expression}"
            )
        self.expression = expression
        self.fields: Dict[str, set] = {}
        for name, part in zip(self.FIELD_NAMES, parts):
            self.fields[name] = self._parse_field(part, name)

    # ---- internal helpers ------------------------------------------------

    def _parse_field(self, token: str, field_name: str) -> set:
        """Parse a single cron field token into a set of valid integers."""
        lo, hi = self.FIELD_RANGES[field_name]
        result: set = set()

        for sub in token.split(","):
            sub = sub.strip()
            if sub == "*":
                result.update(range(lo, hi + 1))
            elif sub.startswith("*/"):
                step = int(sub[2:])
                if step <= 0:
                    raise ValueError(f"Invalid step value in '{token}'")
                result.update(range(lo, hi + 1, step))
            elif "-" in sub:
                a, b = sub.split("-", 1)
                a, b = int(a), int(b)
                if a < lo or b > hi or a > b:
                    raise ValueError(
                        f"Range {a}-{b} out of bounds for {field_name} ({lo}-{hi})"
                    )
                result.update(range(a, b + 1))
            else:
                val = int(sub)
                if val < lo or val > hi:
                    raise ValueError(
                        f"Value {val} out of bounds for {field_name} ({lo}-{hi})"
                    )
                result.add(val)

        return result

    # ---- public API ------------------------------------------------------

    def matches(self, dt: datetime) -> bool:
        """Return True if *dt* matches this cron expression."""
        # ISO weekday: Monday=1 .. Sunday=7; we use 0-6
        iso_wd = dt.isoweekday() % 7  # Mon=1%7=1 .. Sun=7%7=0 -> shift
        wd = (dt.isoweekday() - 1) % 7  # Mon=0 .. Sun=6
        return (
            dt.minute in self.fields["minute"]
            and dt.hour in self.fields["hour"]
            and dt.day in self.fields["day"]
            and dt.month in self.fields["month"]
            and wd in self.fields["weekday"]
        )

    def next_occurrence(self, after: Optional[datetime] = None) -> datetime:
        """
        Calculate the next datetime that matches the cron expression,
        starting strictly after *after* (defaults to now).

        Searches minute-by-minute up to ~400 days out before giving up.
        """
        if after is None:
            after = datetime.utcnow()

        # Start from the next whole minute
        candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Safety limit: search up to 400 days
        limit = candidate + timedelta(days=400)

        while candidate < limit:
            # Fast-skip: wrong month
            if candidate.month not in self.fields["month"]:
                # Jump to 1st of next month
                if candidate.month == 12:
                    candidate = candidate.replace(
                        year=candidate.year + 1, month=1, day=1, hour=0, minute=0
                    )
                else:
                    candidate = candidate.replace(
                        month=candidate.month + 1, day=1, hour=0, minute=0
                    )
                continue

            # Fast-skip: wrong day
            if candidate.day not in self.fields["day"]:
                candidate = candidate.replace(hour=0, minute=0) + timedelta(days=1)
                continue

            # Fast-skip: wrong weekday
            wd = (candidate.isoweekday() - 1) % 7
            if wd not in self.fields["weekday"]:
                candidate = candidate.replace(hour=0, minute=0) + timedelta(days=1)
                continue

            # Fast-skip: wrong hour
            if candidate.hour not in self.fields["hour"]:
                candidate = candidate.replace(minute=0) + timedelta(hours=1)
                continue

            # Check minute
            if candidate.minute in self.fields["minute"]:
                return candidate

            candidate += timedelta(minutes=1)

        raise RuntimeError(
            f"Could not find next occurrence for '{self.expression}' "
            f"within 400 days of {after.isoformat()}"
        )


# ---------------------------------------------------------------------------
# Scheduler Manager
# ---------------------------------------------------------------------------

class SchedulerManager:
    """Manages scan schedules, run history, and the scheduler loop."""

    _instance: Optional["SchedulerManager"] = None

    def __init__(self):
        self.db_path = paths.data / "scheduler.db"
        self._ensure_db()
        self._lock = threading.Lock()
        self._running = False

    # ---- database setup --------------------------------------------------

    def _ensure_db(self):
        """Create database and tables if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schedules (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    schedule_id     TEXT UNIQUE NOT NULL,
                    name            TEXT NOT NULL,
                    description     TEXT DEFAULT '',
                    scanner_type    TEXT NOT NULL,
                    scan_type       TEXT NOT NULL DEFAULT 'standard',
                    targets         TEXT DEFAULT '[]',
                    cron_expression TEXT NOT NULL,
                    enabled         INTEGER DEFAULT 1,
                    last_run        TEXT,
                    next_run        TEXT,
                    run_count       INTEGER DEFAULT 0,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
                    created_by      TEXT DEFAULT 'system'
                );

                CREATE TABLE IF NOT EXISTS schedule_runs (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id       TEXT UNIQUE NOT NULL,
                    schedule_id  TEXT NOT NULL,
                    started_at   TEXT NOT NULL,
                    completed_at TEXT,
                    status       TEXT NOT NULL DEFAULT 'running',
                    session_id   TEXT,
                    summary      TEXT DEFAULT '{}',
                    FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
                );

                CREATE INDEX IF NOT EXISTS idx_schedules_enabled
                    ON schedules(enabled);
                CREATE INDEX IF NOT EXISTS idx_schedules_next_run
                    ON schedules(next_run);
                CREATE INDEX IF NOT EXISTS idx_runs_schedule
                    ON schedule_runs(schedule_id);
                CREATE INDEX IF NOT EXISTS idx_runs_status
                    ON schedule_runs(status);
            """)

    def _connect(self) -> sqlite3.Connection:
        """Return a connection with row-factory set."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _generate_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _now_iso() -> str:
        return datetime.utcnow().isoformat()

    # ---- cron ------------------------------------------------------------

    def calculate_next_run(self, cron_expression: str,
                           after: Optional[datetime] = None) -> datetime:
        """Parse *cron_expression* and return the next execution time."""
        parser = CronParser(cron_expression)
        return parser.next_occurrence(after)

    # ---- CRUD: schedules -------------------------------------------------

    def create_schedule(self, name: str, scanner_type: str,
                        cron_expression: str, **kwargs) -> str:
        """
        Create a new schedule and return its ID.

        Optional kwargs: description, scan_type, targets (list), enabled,
        created_by.
        """
        if scanner_type not in VALID_SCANNER_TYPES:
            raise ValueError(
                f"Invalid scanner_type '{scanner_type}'. "
                f"Must be one of {VALID_SCANNER_TYPES}"
            )

        scan_type = kwargs.get("scan_type", "standard")
        if scan_type not in VALID_SCAN_TYPES:
            raise ValueError(
                f"Invalid scan_type '{scan_type}'. Must be one of {VALID_SCAN_TYPES}"
            )

        # Validate cron expression by computing the next run
        next_run = self.calculate_next_run(cron_expression)

        schedule_id = self._generate_id()
        targets = kwargs.get("targets", [])
        if isinstance(targets, (list, tuple)):
            targets = json.dumps(list(targets))
        elif isinstance(targets, str):
            # Assume already JSON
            json.loads(targets)  # validate

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO schedules
                    (schedule_id, name, description, scanner_type, scan_type,
                     targets, cron_expression, enabled, next_run, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                schedule_id,
                name,
                kwargs.get("description", ""),
                scanner_type,
                scan_type,
                targets,
                cron_expression,
                1 if kwargs.get("enabled", True) else 0,
                next_run.isoformat(),
                kwargs.get("created_by", "system"),
            ))

        logger.info("Created schedule %s (%s)", schedule_id, name)
        return schedule_id

    def update_schedule(self, schedule_id: str, **kwargs):
        """
        Update an existing schedule.

        Accepted kwargs: name, description, scanner_type, scan_type, targets,
        cron_expression, enabled, created_by.
        """
        allowed = {
            "name", "description", "scanner_type", "scan_type", "targets",
            "cron_expression", "enabled", "created_by",
        }
        updates = []
        params: list = []

        for key, value in kwargs.items():
            if key not in allowed:
                continue
            if key == "scanner_type" and value not in VALID_SCANNER_TYPES:
                raise ValueError(f"Invalid scanner_type '{value}'")
            if key == "scan_type" and value not in VALID_SCAN_TYPES:
                raise ValueError(f"Invalid scan_type '{value}'")
            if key == "targets" and isinstance(value, (list, tuple)):
                value = json.dumps(list(value))
            if key == "enabled":
                value = 1 if value else 0
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return

        # Recalculate next_run if cron_expression changed
        if "cron_expression" in kwargs:
            nxt = self.calculate_next_run(kwargs["cron_expression"])
            updates.append("next_run = ?")
            params.append(nxt.isoformat())

        params.append(schedule_id)
        sql = f"UPDATE schedules SET {', '.join(updates)} WHERE schedule_id = ?"

        with self._connect() as conn:
            conn.execute(sql, params)

        logger.info("Updated schedule %s", schedule_id)

    def delete_schedule(self, schedule_id: str):
        """Delete a schedule and its run history."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM schedule_runs WHERE schedule_id = ?", (schedule_id,)
            )
            conn.execute(
                "DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,)
            )
        logger.info("Deleted schedule %s", schedule_id)

    def get_schedule(self, schedule_id: str) -> Optional[Dict]:
        """Retrieve a single schedule by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["enabled"] = bool(result.get("enabled"))
            try:
                result["targets"] = json.loads(result.get("targets", "[]"))
            except (json.JSONDecodeError, TypeError):
                result["targets"] = []
            return result

    def get_all_schedules(self, enabled_only: bool = True) -> List[Dict]:
        """Return all schedules, optionally filtered to enabled ones only."""
        with self._connect() as conn:
            if enabled_only:
                cursor = conn.execute(
                    "SELECT * FROM schedules WHERE enabled = 1 ORDER BY next_run ASC"
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM schedules ORDER BY next_run ASC"
                )
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["enabled"] = bool(d.get("enabled"))
                try:
                    d["targets"] = json.loads(d.get("targets", "[]"))
                except (json.JSONDecodeError, TypeError):
                    d["targets"] = []
                results.append(d)
            return results

    def get_due_schedules(self) -> List[Dict]:
        """Return enabled schedules whose next_run <= now."""
        now_iso = self._now_iso()
        with self._connect() as conn:
            cursor = conn.execute("""
                SELECT * FROM schedules
                WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?
                ORDER BY next_run ASC
            """, (now_iso,))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["enabled"] = bool(d.get("enabled"))
                try:
                    d["targets"] = json.loads(d.get("targets", "[]"))
                except (json.JSONDecodeError, TypeError):
                    d["targets"] = []
                results.append(d)
            return results

    # ---- run history -----------------------------------------------------

    def record_run(self, schedule_id: str, session_id: str,
                   status: str = "running", summary: Optional[Dict] = None) -> str:
        """
        Record a schedule run.  Returns the run_id.

        If *status* is 'completed' or 'failed', completed_at is set to now.
        Also updates schedule's last_run, next_run, and run_count.
        """
        if status not in VALID_RUN_STATUSES:
            raise ValueError(f"Invalid run status '{status}'")

        run_id = self._generate_id()
        now = self._now_iso()
        completed_at = now if status in ("completed", "failed") else None

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO schedule_runs
                    (run_id, schedule_id, started_at, completed_at, status,
                     session_id, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, schedule_id, now, completed_at, status,
                session_id, json.dumps(summary or {}),
            ))

            # Update the parent schedule
            schedule = conn.execute(
                "SELECT cron_expression FROM schedules WHERE schedule_id = ?",
                (schedule_id,)
            ).fetchone()

            if schedule:
                next_run = self.calculate_next_run(schedule["cron_expression"])
                conn.execute("""
                    UPDATE schedules
                    SET last_run = ?, next_run = ?, run_count = run_count + 1
                    WHERE schedule_id = ?
                """, (now, next_run.isoformat(), schedule_id))

        logger.info(
            "Recorded run %s for schedule %s (status=%s)", run_id, schedule_id, status
        )
        return run_id

    def update_run(self, run_id: str, status: str,
                   summary: Optional[Dict] = None):
        """Update an existing run record (e.g. mark completed/failed)."""
        if status not in VALID_RUN_STATUSES:
            raise ValueError(f"Invalid run status '{status}'")

        now = self._now_iso()
        with self._connect() as conn:
            if summary is not None:
                conn.execute("""
                    UPDATE schedule_runs
                    SET status = ?, completed_at = ?, summary = ?
                    WHERE run_id = ?
                """, (status, now, json.dumps(summary), run_id))
            else:
                conn.execute("""
                    UPDATE schedule_runs
                    SET status = ?, completed_at = ?
                    WHERE run_id = ?
                """, (status, now, run_id))

    def get_run_history(self, schedule_id: str, limit: int = 20) -> List[Dict]:
        """Return recent runs for a schedule."""
        with self._connect() as conn:
            cursor = conn.execute("""
                SELECT * FROM schedule_runs
                WHERE schedule_id = ?
                ORDER BY started_at DESC
                LIMIT ?
            """, (schedule_id, limit))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                try:
                    d["summary"] = json.loads(d.get("summary", "{}"))
                except (json.JSONDecodeError, TypeError):
                    d["summary"] = {}
                results.append(d)
            return results

    # ---- statistics ------------------------------------------------------

    def get_statistics(self) -> Dict:
        """Return aggregate statistics about schedules and runs."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM schedules"
            ).fetchone()[0]
            enabled = conn.execute(
                "SELECT COUNT(*) FROM schedules WHERE enabled = 1"
            ).fetchone()[0]
            total_runs = conn.execute(
                "SELECT COUNT(*) FROM schedule_runs"
            ).fetchone()[0]
            completed_runs = conn.execute(
                "SELECT COUNT(*) FROM schedule_runs WHERE status = 'completed'"
            ).fetchone()[0]
            failed_runs = conn.execute(
                "SELECT COUNT(*) FROM schedule_runs WHERE status = 'failed'"
            ).fetchone()[0]
            running_runs = conn.execute(
                "SELECT COUNT(*) FROM schedule_runs WHERE status = 'running'"
            ).fetchone()[0]

            # Runs in last 24 hours
            cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            runs_24h = conn.execute(
                "SELECT COUNT(*) FROM schedule_runs WHERE started_at >= ?",
                (cutoff_24h,)
            ).fetchone()[0]

            # Runs in last 7 days
            cutoff_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
            runs_7d = conn.execute(
                "SELECT COUNT(*) FROM schedule_runs WHERE started_at >= ?",
                (cutoff_7d,)
            ).fetchone()[0]

            # By scanner type
            by_scanner = {}
            cursor = conn.execute(
                "SELECT scanner_type, COUNT(*) as cnt FROM schedules GROUP BY scanner_type"
            )
            for row in cursor.fetchall():
                by_scanner[row[0]] = row[1]

            # Next upcoming schedule
            now_iso = datetime.utcnow().isoformat()
            next_due = conn.execute(
                "SELECT schedule_id, name, next_run FROM schedules "
                "WHERE enabled = 1 AND next_run IS NOT NULL AND next_run > ? "
                "ORDER BY next_run ASC LIMIT 1",
                (now_iso,)
            ).fetchone()

            return {
                "total_schedules": total,
                "enabled_schedules": enabled,
                "disabled_schedules": total - enabled,
                "total_runs": total_runs,
                "completed_runs": completed_runs,
                "failed_runs": failed_runs,
                "running_runs": running_runs,
                "runs_last_24h": runs_24h,
                "runs_last_7d": runs_7d,
                "by_scanner_type": by_scanner,
                "next_upcoming": dict(next_due) if next_due else None,
            }

    # ---- scheduler loop --------------------------------------------------

    def run_scheduler_loop(self, callback=None, interval: int = 60,
                           daemon: bool = True):
        """
        Check for due schedules every *interval* seconds.

        For each due schedule, invokes *callback(schedule_dict)* if provided.
        If no callback, logs a message for each due schedule.

        Set *daemon=True* to run in a background thread (returns the thread).
        Set *daemon=False* to block the current thread (runs forever).
        """
        def _loop():
            logger.info(
                "Scheduler loop started (interval=%ds, daemon=%s)",
                interval, daemon,
            )
            self._running = True
            while self._running:
                try:
                    due = self.get_due_schedules()
                    for schedule in due:
                        sid = schedule["schedule_id"]
                        logger.info(
                            "Schedule due: %s (%s)", schedule["name"], sid
                        )
                        if callback is not None:
                            try:
                                callback(schedule)
                            except Exception as exc:
                                logger.error(
                                    "Callback failed for schedule %s: %s",
                                    sid, exc,
                                )
                                self.record_run(
                                    sid, session_id="",
                                    status="failed",
                                    summary={"error": str(exc)},
                                )
                        else:
                            logger.info(
                                "No callback registered; skipping execution "
                                "of schedule %s", sid,
                            )
                            # Still advance next_run so we don't keep firing
                            self._advance_next_run(sid)
                except Exception as exc:
                    logger.error("Scheduler loop error: %s", exc)

                time.sleep(interval)

        if daemon:
            t = threading.Thread(target=_loop, name="PurpleTeam-Scheduler",
                                 daemon=True)
            t.start()
            return t
        else:
            _loop()

    def stop_scheduler_loop(self):
        """Signal the scheduler loop to stop."""
        self._running = False
        logger.info("Scheduler loop stop requested")

    def _advance_next_run(self, schedule_id: str):
        """Advance next_run for a schedule without recording a full run."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT cron_expression FROM schedules WHERE schedule_id = ?",
                (schedule_id,)
            ).fetchone()
            if row:
                nxt = self.calculate_next_run(row["cron_expression"])
                conn.execute(
                    "UPDATE schedules SET next_run = ? WHERE schedule_id = ?",
                    (nxt.isoformat(), schedule_id),
                )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_scheduler: Optional[SchedulerManager] = None


def get_scheduler() -> SchedulerManager:
    """Get the scheduler manager singleton."""
    global _scheduler
    if _scheduler is None:
        _scheduler = SchedulerManager()
    return _scheduler


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    sm = get_scheduler()
    print(f"Scheduler database: {sm.db_path}")
    print(f"Database exists: {sm.db_path.exists()}")

    # Test cron parsing
    cron = CronParser("0 2 * * 1")
    nxt = cron.next_occurrence()
    print(f"Next Monday 2am: {nxt.isoformat()}")

    cron2 = CronParser("*/15 * * * *")
    nxt2 = cron2.next_occurrence()
    print(f"Next 15-min interval: {nxt2.isoformat()}")

    cron3 = CronParser("30 9 1-15 * 0-4")
    nxt3 = cron3.next_occurrence()
    print(f"Next 9:30 on weekday in first half of month: {nxt3.isoformat()}")

    # Test schedule CRUD
    sid = sm.create_schedule(
        name="Weekly Network Scan",
        scanner_type="network",
        cron_expression="0 2 * * 1",
        description="Full network scan every Monday at 2 AM",
        scan_type="deep",
        targets=["192.168.1.0/24", "10.0.0.0/16"],
        created_by="admin",
    )
    print(f"Created schedule: {sid}")

    schedule = sm.get_schedule(sid)
    print(f"Schedule: {schedule['name']}, next_run: {schedule['next_run']}")

    # Update it
    sm.update_schedule(sid, description="Updated description", scan_type="quick")
    schedule = sm.get_schedule(sid)
    print(f"Updated scan_type: {schedule['scan_type']}")

    # Record a run
    run_id = sm.record_run(sid, session_id="SESSION-TEST-001", status="completed",
                           summary={"findings": 42, "critical": 3})
    print(f"Recorded run: {run_id}")

    # History
    history = sm.get_run_history(sid)
    print(f"Run history: {len(history)} entries")

    # Statistics
    stats = sm.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2, default=str)}")

    # All schedules
    all_sched = sm.get_all_schedules(enabled_only=False)
    print(f"Total schedules: {len(all_sched)}")

    # Due schedules
    due = sm.get_due_schedules()
    print(f"Due schedules: {len(due)}")

    # Cleanup
    sm.delete_schedule(sid)
    print("Schedule deleted")

    print("\nAll scheduler tests passed.")
