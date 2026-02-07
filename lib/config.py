#!/usr/bin/env python3
"""
Purple Team Portable - Configuration Manager
Loads and manages configuration with 365-day retention defaults.
"""

import os
import yaml
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

try:
    from .paths import paths
except ImportError:
    from paths import paths


class Config:
    """Configuration manager with portable defaults."""

    _instance: Optional['Config'] = None

    # Default configuration with 365-day retention
    DEFAULTS = {
        'version': '4.0.0',
        'platform': {
            'name': 'Purple Team Portable',
            'mode': 'portable',
            'auto_detect_networks': True
        },
        'scanning': {
            'stealth_level': 3,  # 1-5 (1=aggressive, 5=paranoid)
            'delay_min_seconds': 30,
            'delay_max_seconds': 300,
            'concurrent_scans': 1,  # Human-paced: one at a time
            'timeout_minutes': 120,
            'excluded_hosts': [],
            'excluded_ports': []
        },
        'scheduling': {
            'enabled': False,
            'window_start': '18:00',  # 6pm
            'window_end': '20:00',    # 8pm
            'randomize_start': True,
            'frequency': 'monthly',
            'day_of_month': 1,
            'run_until_complete': True
        },
        'retention': {
            'days': 365,  # Full year retention
            'compress_after_days': 30,
            'archive_format': 'tar.gz',
            'auto_cleanup': True
        },
        'evidence': {
            'collect_screenshots': False,
            'hash_algorithm': 'sha256',
            'include_raw_output': True,
            'timestamp_format': '%Y-%m-%d %H:%M:%S UTC'
        },
        'compliance': {
            'frameworks': [
                'NIST-800-53',
                'HIPAA',
                'SOC1-Type2',
                'SOC2-Type2',
                'PCI-DSS-v4',
                'ISO27001-2022',
                'CMMC',
                'FedRAMP',
                'GDPR',
                'SOX'
            ],
            'auto_map_findings': True,
            'generate_attestations': True,
            'include_remediation': True
        },
        'reporting': {
            'formats': ['json', 'html', 'csv', 'pdf'],
            'executive_summary': True,
            'technical_details': True,
            'include_evidence_refs': True
        },
        'export': {
            'oscal': True,
            'scap': False,
            'csv_grc': True,
            'json_api': True
        },
        'network': {
            'auto_detect': True,
            'scan_ranges': [],  # Empty = auto-detect RFC1918
            'exclude_ranges': ['127.0.0.0/8'],
            'dns_resolution': True
        },
        'tools': {
            'nmap': {'enabled': True, 'extra_args': ''},
            'nikto': {'enabled': True, 'extra_args': ''},
            'nuclei': {'enabled': True, 'extra_args': '', 'templates': 'default'},
            'testssl': {'enabled': True, 'extra_args': ''}
        },
        'notifications': {
            'enabled': False,
            'email': {
                'enabled': False,
                'smtp_server': '',
                'smtp_port': 587,
                'use_tls': True,
                'recipients': []
            },
            'on_critical': True,
            'on_complete': True
        },
        'integrations': {
            'thehive': {'enabled': False, 'url': '', 'api_key': ''},
            'wazuh': {'enabled': False, 'url': '', 'api_key': ''},
            'siem': {'enabled': False, 'type': '', 'endpoint': ''}
        }
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config: Dict[str, Any] = {}
        self._load()

    def _load(self):
        """Load configuration from file or create defaults."""
        config_file = paths.config_active

        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    self._config = yaml.safe_load(f) or {}
                # Merge with defaults for any missing keys
                self._config = self._deep_merge(self.DEFAULTS.copy(), self._config)
            except Exception as e:
                print(f"Warning: Failed to load config, using defaults: {e}")
                self._config = self.DEFAULTS.copy()
        else:
            self._config = self.DEFAULTS.copy()
            self.save()  # Create default config file

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge override into base."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def save(self):
        """Save configuration to file."""
        config_file = paths.config_active
        config_file.parent.mkdir(parents=True, exist_ok=True)

        with open(config_file, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value using dot notation (e.g., 'scanning.stealth_level')."""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """Set a config value using dot notation."""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def get_frameworks(self) -> list:
        """Get list of enabled compliance frameworks."""
        return self.get('compliance.frameworks', [])

    def get_retention_days(self) -> int:
        """Get retention period in days."""
        return self.get('retention.days', 365)

    def get_scan_delay(self) -> tuple:
        """Get min/max delay between scan operations."""
        return (
            self.get('scanning.delay_min_seconds', 30),
            self.get('scanning.delay_max_seconds', 300)
        )

    def get_schedule_window(self) -> tuple:
        """Get scheduling window start/end times."""
        return (
            self.get('scheduling.window_start', '18:00'),
            self.get('scheduling.window_end', '20:00')
        )

    def is_tool_enabled(self, tool: str) -> bool:
        """Check if a scanning tool is enabled."""
        return self.get(f'tools.{tool}.enabled', False)

    def to_dict(self) -> Dict[str, Any]:
        """Return full config as dictionary."""
        return self._config.copy()

    def reload(self):
        """Reload configuration from file."""
        self._initialized = False
        self.__init__()


# Singleton instance
config = Config()


def get_config() -> Config:
    """Get the singleton config instance."""
    return config


def load_config() -> Dict[str, Any]:
    """Load and return config as dictionary."""
    return config.to_dict()


if __name__ == '__main__':
    # Self-test
    c = get_config()
    print(f"Config file: {paths.config_active}")
    print(f"Retention days: {c.get_retention_days()}")
    print(f"Frameworks: {c.get_frameworks()}")
    print(f"Scan delay: {c.get_scan_delay()}")
    print(f"Schedule window: {c.get_schedule_window()}")
