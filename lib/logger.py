#!/usr/bin/env python3
"""
Purple Team Portable - Logging System
Provides consistent logging across all components with 365-day retention.
"""

import os
import gzip
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler

try:
    from .paths import paths
    from .config import config
except ImportError:
    from paths import paths
    from config import config


class PurpleTeamLogger:
    """Centralized logging with rotation and compression."""

    _loggers: dict = {}

    @classmethod
    def get_logger(cls, name: str, level: int = logging.INFO) -> logging.Logger:
        """Get or create a logger for a component."""
        if name in cls._loggers:
            return cls._loggers[name]

        # Ensure log directory exists
        paths.logs.mkdir(parents=True, exist_ok=True)

        logger = logging.getLogger(f"purple-team.{name}")
        logger.setLevel(level)
        logger.handlers.clear()

        # File handler with rotation
        log_file = paths.logs / f"{name}.log"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB per file
            backupCount=365,  # Keep 365 rotated files
            encoding='utf-8'
        )
        file_handler.setLevel(level)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        cls._loggers[name] = logger
        return logger

    @classmethod
    def get_scan_logger(cls, session_id: str) -> logging.Logger:
        """Get logger for a specific scan session."""
        logger_name = f"scan.{session_id}"
        if logger_name in cls._loggers:
            return cls._loggers[logger_name]

        # Session-specific log in results directory
        session_dir = paths.session_dir(session_id)
        log_file = session_dir / "scan.log"

        logger = logging.getLogger(f"purple-team.{logger_name}")
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        cls._loggers[logger_name] = logger
        return logger

    @classmethod
    def compress_old_logs(cls, days_old: int = 30):
        """Compress log files older than specified days."""
        if not paths.logs.exists():
            return

        cutoff = datetime.now() - timedelta(days=days_old)

        for log_file in paths.logs.glob("*.log.*"):
            # Skip already compressed files
            if log_file.suffix == '.gz':
                continue

            file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
            if file_time < cutoff:
                gz_path = log_file.with_suffix(log_file.suffix + '.gz')
                with open(log_file, 'rb') as f_in:
                    with gzip.open(gz_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                log_file.unlink()

    @classmethod
    def cleanup_expired_logs(cls, retention_days: int = None):
        """Remove logs older than retention period."""
        if retention_days is None:
            retention_days = config.get_retention_days()

        if not paths.logs.exists():
            return

        cutoff = datetime.now() - timedelta(days=retention_days)

        for log_file in paths.logs.iterdir():
            if log_file.is_file():
                file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_time < cutoff:
                    log_file.unlink()


def get_logger(name: str) -> logging.Logger:
    """Get a logger by name."""
    return PurpleTeamLogger.get_logger(name)


def get_scan_logger(session_id: str) -> logging.Logger:
    """Get a scan session logger."""
    return PurpleTeamLogger.get_scan_logger(session_id)


# Main application logger
main_logger = get_logger('main')


def log_info(message: str):
    """Log info message to main logger."""
    main_logger.info(message)


def log_warning(message: str):
    """Log warning message to main logger."""
    main_logger.warning(message)


def log_error(message: str):
    """Log error message to main logger."""
    main_logger.error(message)


def log_debug(message: str):
    """Log debug message to main logger."""
    main_logger.debug(message)


if __name__ == '__main__':
    # Self-test
    logger = get_logger('test')
    logger.info("Test info message")
    logger.warning("Test warning message")
    logger.error("Test error message")
    print(f"Logs written to: {paths.logs}")
