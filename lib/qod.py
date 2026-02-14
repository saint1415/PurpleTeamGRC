#!/usr/bin/env python3
"""
Purple Team Platform v6.0 - Quality of Detection (QoD) Scoring
OpenVAS-compatible QoD scale (0-100%) for detection confidence.
Maps each scanner and detection method to a standardized QoD score.
"""

from typing import Dict, List, Optional

try:
    from .logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger('qod')


# OpenVAS-compatible QoD scale
QOD_LEVELS = {
    100: 'Exploit confirmed',
    98: 'Remote vulnerability detection (active check)',
    97: 'Authenticated version check',
    95: 'Remote vulnerability detection (passive)',
    80: 'Remote analysis (fingerprinting)',
    70: 'Version-based detection (unauthenticated)',
    50: 'Remote detection (banner grab only)',
    30: 'Default/heuristic',
    1: 'General note',
}

# Scanner + detection method -> QoD mapping
SCANNER_QOD_MAP = {
    # Nuclei
    ('vulnerability', 'active_check'): 95,
    ('vulnerability', 'cve_template'): 95,
    ('vulnerability', 'misconfig'): 80,
    ('vulnerability', 'exposure'): 70,
    ('vulnerability', 'default_login'): 95,
    ('vulnerability', ''): 80,
    # Nmap
    ('network', 'port_scan'): 70,
    ('network', 'version_scan'): 70,
    ('network', 'script_vuln'): 80,
    ('network', 'os_detection'): 80,
    ('network', ''): 70,
    # Nikto web scanner
    ('web', 'active_check'): 80,
    ('web', 'banner_grab'): 50,
    ('web', ''): 50,
    # testssl.sh
    ('ssl', 'protocol_test'): 98,
    ('ssl', 'cipher_test'): 98,
    ('ssl', 'cert_check'): 98,
    ('ssl', ''): 98,
    # Compliance scanner
    ('compliance', 'policy_check'): 80,
    ('compliance', 'evidence_review'): 70,
    ('compliance', ''): 70,
    # Credential scanner (authenticated)
    ('credential', 'package_audit'): 97,
    ('credential', 'config_check'): 97,
    ('credential', 'service_audit'): 97,
    ('credential', 'user_audit'): 97,
    ('credential', 'file_integrity'): 97,
    ('credential', 'patch_level'): 97,
    ('credential', ''): 97,
    # Local scanners (authenticated by nature)
    ('lynis', ''): 97,
    ('rkhunter', ''): 97,
    # OpenVAS integration
    ('openvas', 'active_check'): 98,
    ('openvas', 'authenticated'): 97,
    ('openvas', 'remote_analysis'): 80,
    ('openvas', ''): 80,
    # Windows security scanner (local, authenticated by nature)
    ('windows', 'powershell_cmdlet'): 97,
    ('windows', 'registry_check'): 97,
    ('windows', 'event_log_analysis'): 80,
    ('windows', 'service_enumeration'): 97,
    ('windows', ''): 97,
    # Linux security scanner (local, authenticated by nature)
    ('linux', 'system_command'): 97,
    ('linux', 'config_file_check'): 97,
    ('linux', 'log_analysis'): 80,
    ('linux', 'service_enumeration'): 97,
    ('linux', ''): 97,
}


class QualityOfDetection:
    """Assigns and manages Quality of Detection scores."""

    _instance: Optional['QualityOfDetection'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.qod_map = SCANNER_QOD_MAP.copy()

    def assign_qod(self, scanner_name: str, detection_method: str = '',
                   authenticated: bool = False) -> float:
        """
        Auto-assign QoD based on scanner name and detection method.
        
        Args:
            scanner_name: Name of the scanner (e.g., 'vulnerability', 'network')
            detection_method: Specific detection method used
            authenticated: Whether this was an authenticated check
            
        Returns:
            QoD score (0-100)
        """
        if authenticated:
            return 97.0

        # Try exact match first
        key = (scanner_name, detection_method)
        if key in self.qod_map:
            return float(self.qod_map[key])

        # Try scanner-only match
        key = (scanner_name, '')
        if key in self.qod_map:
            return float(self.qod_map[key])

        # Default
        logger.debug(f"No QoD mapping for {scanner_name}/{detection_method}, using default 30")
        return 30.0

    def get_qod_label(self, qod_score: float) -> str:
        """Get human-readable label for a QoD score."""
        # Find closest matching level
        closest = min(QOD_LEVELS.keys(), key=lambda x: abs(x - qod_score))
        return QOD_LEVELS.get(closest, 'Unknown')

    def filter_by_qod(self, findings: List[Dict], min_qod: float = 50) -> List[Dict]:
        """Filter findings by minimum QoD threshold."""
        return [
            f for f in findings
            if (f.get('quality_of_detection') or 0) >= min_qod
        ]

    def get_qod_distribution(self, findings: List[Dict]) -> Dict:
        """Get distribution of QoD scores across findings."""
        distribution = {}
        for f in findings:
            qod = f.get('quality_of_detection', 0)
            label = self.get_qod_label(qod)
            bucket = f"{int(qod)}% - {label}"
            distribution[bucket] = distribution.get(bucket, 0) + 1
        return distribution

    def add_custom_mapping(self, scanner_name: str, detection_method: str, qod: float):
        """Add a custom scanner/method QoD mapping."""
        self.qod_map[(scanner_name, detection_method)] = qod

    @staticmethod
    def get_all_levels() -> Dict[int, str]:
        """Get all defined QoD levels."""
        return QOD_LEVELS.copy()


# Singleton accessor
_qod_scorer: Optional[QualityOfDetection] = None


def get_qod_scorer() -> QualityOfDetection:
    """Get the QoD scorer singleton."""
    global _qod_scorer
    if _qod_scorer is None:
        _qod_scorer = QualityOfDetection()
    return _qod_scorer


if __name__ == '__main__':
    qod = get_qod_scorer()
    print("Quality of Detection Scorer initialized")

    print("\nQoD Levels:")
    for score, label in sorted(QOD_LEVELS.items(), reverse=True):
        print(f"  {score:>3}% = {label}")

    print("\nScanner QoD Assignments:")
    test_cases = [
        ('vulnerability', 'active_check', False),
        ('network', 'port_scan', False),
        ('web', '', False),
        ('ssl', 'protocol_test', False),
        ('credential', 'package_audit', True),
        ('compliance', '', False),
        ('openvas', 'active_check', False),
        ('unknown', 'unknown', False),
    ]

    for scanner, method, auth in test_cases:
        score = qod.assign_qod(scanner, method, auth)
        label = qod.get_qod_label(score)
        print(f"  {scanner}/{method or 'default'} (auth={auth}): {score}% ({label})")
