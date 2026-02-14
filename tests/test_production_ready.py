#!/usr/bin/env python3
"""
Purple Team GRC Platform v7.0 - Production Readiness Test Suite

Comprehensive test suite validating all core modules for production deployment.
Covers imports, singletons, configuration, evidence management, vulnerability
intelligence, threat intel, compliance mapping, TUI, tool discovery, platform
detection, quality of detection, scanners, and logger.

Usage:
    python -m pytest tests/test_production_ready.py -v
    python tests/test_production_ready.py
"""

import logging
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap - mirrors bin/purple-launcher so every lib/scanner import works
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(PROJECT_ROOT / 'scanners'))
sys.path.insert(0, str(PROJECT_ROOT / 'utilities'))
os.environ.setdefault('PURPLE_TEAM_HOME', str(PROJECT_ROOT))


# ===================================================================
# 1. TestImports - verify every lib/ and scanners/ module can import
# ===================================================================
class TestImports(unittest.TestCase):
    """Verify that every expected module can be imported successfully."""

    def test_import_paths(self):
        from paths import paths, get_paths
        self.assertIsNotNone(paths)
        self.assertIsNotNone(get_paths)

    def test_import_config(self):
        from config import config, get_config
        self.assertIsNotNone(config)
        self.assertIsNotNone(get_config)

    def test_import_evidence(self):
        from evidence import get_evidence_manager
        self.assertIsNotNone(get_evidence_manager)

    def test_import_compliance(self):
        from compliance import get_compliance_mapper
        self.assertIsNotNone(get_compliance_mapper)

    def test_import_tui(self):
        from tui import tui
        self.assertIsNotNone(tui)

    def test_import_tool_discovery(self):
        from tool_discovery import ToolDiscovery
        self.assertIsNotNone(ToolDiscovery)

    def test_import_network(self):
        import network
        self.assertIsNotNone(network)

    def test_import_platform_detect(self):
        from platform_detect import get_platform_info
        self.assertIsNotNone(get_platform_info)

    def test_import_qod(self):
        from qod import get_qod_scorer
        self.assertIsNotNone(get_qod_scorer)

    def test_import_logger(self):
        from logger import get_logger
        self.assertIsNotNone(get_logger)

    def test_import_vuln_database(self):
        from vuln_database import get_vuln_database
        self.assertIsNotNone(get_vuln_database)

    def test_import_threat_intel(self):
        from threat_intel import get_threat_intel
        self.assertIsNotNone(get_threat_intel)

    def test_import_base_scanner(self):
        from base import BaseScanner
        self.assertIsNotNone(BaseScanner)

    def test_import_network_scanner(self):
        from network_scanner import NetworkScanner
        self.assertIsNotNone(NetworkScanner)

    def test_import_vulnerability_scanner(self):
        from vulnerability_scanner import VulnerabilityScanner
        self.assertIsNotNone(VulnerabilityScanner)

    def test_import_web_scanner(self):
        from web_scanner import WebScanner
        self.assertIsNotNone(WebScanner)

    def test_import_ssl_scanner(self):
        from ssl_scanner import SSLScanner
        self.assertIsNotNone(SSLScanner)

    def test_import_compliance_scanner(self):
        from compliance_scanner import ComplianceScanner
        self.assertIsNotNone(ComplianceScanner)


# ===================================================================
# 2. TestPaths - portable path resolver
# ===================================================================
class TestPaths(unittest.TestCase):
    """Validate the PortablePaths singleton and its path properties."""

    def test_singleton(self):
        from paths import get_paths
        self.assertIs(get_paths(), get_paths())

    def test_home_is_path(self):
        from paths import paths
        self.assertIsInstance(paths.home, Path)

    def test_data_directory(self):
        from paths import paths
        self.assertIsNotNone(paths.data)
        self.assertIsInstance(paths.data, Path)

    def test_session_dir(self):
        from paths import paths
        session_path = paths.session_dir('test123')
        self.assertIsInstance(session_path, Path)
        self.assertTrue(session_path.exists())
        # Cleanup
        shutil.rmtree(session_path, ignore_errors=True)

    def test_find_tool_nuclei(self):
        from paths import paths
        result = paths.find_tool('nuclei')
        # Should return a Path or None -- must not raise
        self.assertTrue(result is None or isinstance(result, Path))

    def test_results_dir(self):
        from paths import paths
        self.assertIsInstance(paths.results, Path)


# ===================================================================
# 3. TestConfig - configuration manager
# ===================================================================
class TestConfig(unittest.TestCase):
    """Validate configuration loading, defaults, and access."""

    def test_singleton(self):
        from config import get_config
        self.assertIs(get_config(), get_config())

    def test_get_default(self):
        from config import config
        self.assertEqual(config.get('nonexistent', 'default_val'), 'default_val')

    def test_get_frameworks(self):
        from config import config
        frameworks = config.get_frameworks()
        self.assertIsInstance(frameworks, list)
        self.assertIn('NIST-800-53', frameworks)

    def test_get_retention_days(self):
        from config import config
        days = config.get_retention_days()
        self.assertIsInstance(days, int)
        self.assertGreaterEqual(days, 0)

    def test_to_dict(self):
        from config import config
        d = config.to_dict()
        self.assertIsInstance(d, dict)


# ===================================================================
# 4. TestEvidenceManager - evidence CRUD with temp DB
# ===================================================================
class TestEvidenceManager(unittest.TestCase):
    """Evidence manager CRUD operations using an isolated temp database."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from evidence import get_evidence_manager
        self.em = get_evidence_manager()
        self._orig_db = self.em.db_path
        self.em.db_path = Path(self.tmpdir) / 'test_evidence.db'
        self.em._ensure_db()
        self.em._migrate_schema()

    def tearDown(self):
        self.em.db_path = self._orig_db
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_start_session(self):
        session_id = self.em.start_session('test', ['10.0.0.0/24'])
        self.assertIsInstance(session_id, str)
        self.assertTrue(len(session_id) > 0)

    def test_add_evidence(self):
        session_id = self.em.start_session('test', ['10.0.0.0/24'])
        evidence_id = self.em.add_evidence(
            session_id=session_id,
            evidence_type='scan_result',
            title='Port Scan Evidence',
            description='Discovered open ports',
            source_tool='nmap',
        )
        self.assertIsInstance(evidence_id, str)
        self.assertTrue(len(evidence_id) > 0)

    def test_add_finding(self):
        session_id = self.em.start_session('test', ['10.0.0.0/24'])
        finding_id = self.em.add_finding(
            session_id=session_id,
            severity='HIGH',
            title='Open SSH Port',
            description='Port 22 is open',
            affected_asset='10.0.0.1',
            cvss_score=7.5,
        )
        self.assertIsInstance(finding_id, str)
        self.assertTrue(len(finding_id) > 0)

    def test_map_to_control(self):
        session_id = self.em.start_session('test', ['10.0.0.0/24'])
        evidence_id = self.em.add_evidence(
            session_id=session_id,
            evidence_type='scan_result',
            title='Control Evidence',
        )
        # Should not raise
        self.em.map_to_control(
            evidence_id, 'NIST-800-53', 'RA-5',
            control_name='Vulnerability Scanning',
            control_family='Risk Assessment',
        )

    def test_get_findings_for_session(self):
        session_id = self.em.start_session('test', ['10.0.0.0/24'])
        self.em.add_finding(
            session_id=session_id,
            severity='MEDIUM',
            title='Test Finding',
        )
        findings = self.em.get_findings_for_session(session_id)
        self.assertIsInstance(findings, list)

    def test_end_session(self):
        session_id = self.em.start_session('test', ['10.0.0.0/24'])
        # Should not raise
        self.em.end_session(session_id, summary={'status': 'ok'})

    def test_full_workflow(self):
        """End-to-end: start -> evidence -> finding -> map -> get -> end."""
        session_id = self.em.start_session('workflow_test', ['192.168.1.0/24'])
        self.assertTrue(len(session_id) > 0)

        evidence_id = self.em.add_evidence(
            session_id=session_id,
            evidence_type='scan_result',
            title='Full Workflow Evidence',
            description='Comprehensive scan output',
            source_tool='nuclei',
        )
        self.assertTrue(len(evidence_id) > 0)

        finding_id = self.em.add_finding(
            session_id=session_id,
            severity='CRITICAL',
            title='SQL Injection',
            description='SQL injection detected in login form',
            affected_asset='webapp.internal',
            cvss_score=9.8,
            cve_ids=['CVE-2023-99999'],
            remediation='Use parameterized queries',
            evidence_id=evidence_id,
        )
        self.assertTrue(len(finding_id) > 0)

        self.em.map_to_control(
            evidence_id, 'NIST-800-53', 'RA-5',
            control_name='Vulnerability Monitoring and Scanning',
            control_family='Risk Assessment',
        )

        findings = self.em.get_findings_for_session(session_id)
        self.assertIsInstance(findings, list)
        self.assertGreaterEqual(len(findings), 1)

        self.em.end_session(session_id, summary={'findings': 1})


# ===================================================================
# 5. TestEvidenceEnrichment - finding enrichment fields
# ===================================================================
class TestEvidenceEnrichment(unittest.TestCase):
    """Validate finding enrichment update and persistence."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from evidence import get_evidence_manager
        self.em = get_evidence_manager()
        self._orig_db = self.em.db_path
        self.em.db_path = Path(self.tmpdir) / 'test_enrichment.db'
        self.em._ensure_db()
        self.em._migrate_schema()

    def tearDown(self):
        self.em.db_path = self._orig_db
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_update_finding_enrichment(self):
        session_id = self.em.start_session('enrich_test', ['10.0.0.0/24'])
        finding_id = self.em.add_finding(
            session_id=session_id,
            severity='HIGH',
            title='Enrichment Test',
        )
        # Should not raise
        self.em.update_finding_enrichment(
            finding_id,
            kev_status='true',
            epss_score=0.85,
            epss_percentile=0.95,
            effective_priority=8.5,
            quality_of_detection=95.0,
            detection_source='active_check',
            false_positive=0,
            fp_reason=None,
            scanner_name='vulnerability',
        )

    def test_enrichment_roundtrip(self):
        session_id = self.em.start_session('roundtrip', ['10.0.0.0/24'])
        finding_id = self.em.add_finding(
            session_id=session_id,
            severity='CRITICAL',
            title='Roundtrip Enrichment',
        )
        self.em.update_finding_enrichment(
            finding_id,
            kev_status='true',
            epss_score=0.92,
            effective_priority=9.1,
            quality_of_detection=98.0,
            scanner_name='ssl',
        )
        findings = self.em.get_findings_for_session(session_id)
        self.assertGreaterEqual(len(findings), 1)
        enriched = findings[0]
        self.assertEqual(enriched['kev_status'], 'true')
        self.assertAlmostEqual(enriched['epss_score'], 0.92, places=2)
        self.assertAlmostEqual(enriched['effective_priority'], 9.1, places=1)
        self.assertAlmostEqual(enriched['quality_of_detection'], 98.0, places=1)
        self.assertEqual(enriched['scanner_name'], 'ssl')


# ===================================================================
# 6. TestVulnDatabase - vulnerability intelligence lookups
# ===================================================================
class TestVulnDatabase(unittest.TestCase):
    """Validate embedded vuln intelligence: OWASP, CWE, CAPEC, ATT&CK."""

    @classmethod
    def setUpClass(cls):
        from vuln_database import get_vuln_database
        cls.vdb = get_vuln_database()

    def test_get_owasp_top_10(self):
        owasp = self.vdb.get_owasp_top_10()
        self.assertIsInstance(owasp, dict)
        self.assertEqual(len(owasp), 10)

    def test_get_cwe_top_25(self):
        cwe_list = self.vdb.get_cwe_top_25()
        self.assertIsInstance(cwe_list, list)
        self.assertEqual(len(cwe_list), 25)

    def test_lookup_cwe_79(self):
        result = self.vdb.lookup_cwe('CWE-79')
        self.assertIsInstance(result, dict)
        self.assertTrue(result['in_top_25'])

    def test_search_injection(self):
        results = self.vdb.search('injection')
        self.assertIsInstance(results, dict)
        self.assertIn('cwes', results)

    def test_get_capec_patterns(self):
        capec = self.vdb.get_capec_patterns()
        self.assertIsInstance(capec, dict)
        self.assertGreater(len(capec), 0)

    def test_get_attack_techniques(self):
        attack = self.vdb.get_attack_techniques()
        self.assertIsInstance(attack, dict)
        self.assertGreater(len(attack), 0)

    def test_get_statistics(self):
        stats = self.vdb.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('cached_cves', stats)


# ===================================================================
# 7. TestThreatIntel - CISA KEV / EPSS integration
# ===================================================================
class TestThreatIntel(unittest.TestCase):
    """Validate threat intel singleton, priority formula, and cache stats."""

    def test_singleton(self):
        from threat_intel import get_threat_intel
        self.assertIs(get_threat_intel(), get_threat_intel())

    def test_calculate_effective_priority(self):
        from threat_intel import ThreatIntelManager
        # Formula: cvss * 0.4 + epss * 10 * 0.3 + kev_bonus * 0.3
        # kev_bonus = 10 if True else 0
        # 9.0*0.4 + 0.95*10*0.3 + 10*0.3 = 3.6 + 2.85 + 3.0 = 9.45
        result = ThreatIntelManager.calculate_effective_priority(9.0, 0.95, True)
        self.assertAlmostEqual(result, 9.45, places=2)

        # 7.0*0.4 + 0.50*10*0.3 + 0*0.3 = 2.8 + 1.5 + 0 = 4.3
        result2 = ThreatIntelManager.calculate_effective_priority(7.0, 0.50, False)
        self.assertAlmostEqual(result2, 4.3, places=2)

    def test_cache_stats(self):
        from threat_intel import get_threat_intel
        ti = get_threat_intel()
        kev_stats = ti.get_kev_stats()
        epss_stats = ti.get_epss_stats()
        self.assertIsInstance(kev_stats, dict)
        self.assertIsInstance(epss_stats, dict)


# ===================================================================
# 8. TestCompliance - compliance framework mapper
# ===================================================================
class TestCompliance(unittest.TestCase):
    """Validate compliance mapper frameworks, controls, and mappings."""

    @classmethod
    def setUpClass(cls):
        from compliance import get_compliance_mapper
        cls.mapper = get_compliance_mapper()

    def test_get_supported_frameworks(self):
        frameworks = self.mapper.get_supported_frameworks()
        self.assertIsInstance(frameworks, list)
        self.assertIn('NIST-800-53', frameworks)
        self.assertIn('HIPAA', frameworks)
        self.assertIn('PCI-DSS-v4', frameworks)

    def test_get_controls_for_finding(self):
        controls = self.mapper.get_controls_for_finding('open_port')
        self.assertIsInstance(controls, dict)
        # Should have mappings across multiple frameworks
        self.assertGreater(len(controls), 0)
        # Check for at least one framework key
        has_framework = any(
            fw in controls
            for fw in ['NIST-800-53', 'PCI-DSS-v4', 'HIPAA']
        )
        self.assertTrue(has_framework)

    def test_get_control(self):
        from compliance import Control
        control = self.mapper.get_control('NIST-800-53', 'AC-2')
        self.assertIsNotNone(control)
        self.assertIsInstance(control, Control)

    def test_unknown_finding_type(self):
        controls = self.mapper.get_controls_for_finding('completely_unknown_type_xyz')
        self.assertIsInstance(controls, dict)
        self.assertEqual(len(controls), 0)


# ===================================================================
# 9. TestTUI - terminal user interface
# ===================================================================
class TestTUI(unittest.TestCase):
    """Validate TUI singleton, terminal metrics, and encoding detection."""

    def test_singleton(self):
        from tui import tui as tui1
        from tui import tui as tui2
        self.assertIs(tui1, tui2)

    def test_term_width(self):
        from tui import tui
        self.assertIsInstance(tui.term_width, int)
        self.assertGreaterEqual(tui.term_width, 40)

    def test_can_encode_unicode(self):
        from tui import _can_encode_unicode
        result = _can_encode_unicode()
        self.assertIsInstance(result, bool)

    def test_safe_input_non_interactive(self):
        from tui import safe_input, set_non_interactive
        # Force non-interactive mode so safe_input returns default
        set_non_interactive(True)
        try:
            result = safe_input('prompt> ', 'fallback_value')
            self.assertEqual(result, 'fallback_value')
        finally:
            # Restore based on actual stdin state
            set_non_interactive(not sys.stdin.isatty())


# ===================================================================
# 10. TestToolDiscovery - security tool detection
# ===================================================================
class TestToolDiscovery(unittest.TestCase):
    """Validate tool discovery, TOOLS dict, and Windows path handling."""

    def test_singleton_like(self):
        from tool_discovery import ToolDiscovery, TOOLS
        td1 = ToolDiscovery()
        td2 = ToolDiscovery()
        # Both instances should reference the same TOOLS data structure
        self.assertEqual(set(td1.tools.keys()), set(td2.tools.keys()))

    def test_tools_dict(self):
        from tool_discovery import TOOLS
        self.assertIn('nmap', TOOLS)
        self.assertIn('nuclei', TOOLS)

    def test_windows_paths(self):
        if sys.platform == 'win32':
            from tool_discovery import ToolDiscovery
            td = ToolDiscovery()
            win_paths = td._get_windows_tool_paths('nmap')
            for p in win_paths:
                self.assertTrue(str(p).endswith('.exe'))


# ===================================================================
# 11. TestNetworkModule - network utilities import
# ===================================================================
class TestNetworkModule(unittest.TestCase):
    """Validate network module imports and expected contents."""

    def test_import(self):
        import network
        self.assertIsNotNone(network)

    def test_dataclasses(self):
        import network
        self.assertTrue(hasattr(network, 'NetworkInterface'))
        self.assertTrue(hasattr(network, 'DiscoveredHost'))
        self.assertTrue(hasattr(network, 'NetworkDiscovery'))


# ===================================================================
# 12. TestPlatformDetect - cross-platform detection
# ===================================================================
class TestPlatformDetect(unittest.TestCase):
    """Validate platform detection on Windows."""

    @classmethod
    def setUpClass(cls):
        from platform_detect import get_platform_info
        cls.pi = get_platform_info()

    def test_is_windows(self):
        # We are running on Windows per the environment spec
        self.assertTrue(self.pi.is_windows)

    def test_os_name(self):
        self.assertEqual(self.pi.os_name, 'Windows')

    def test_get_summary(self):
        summary = self.pi.get_summary()
        self.assertIsInstance(summary, dict)
        self.assertGreater(len(summary), 0)


# ===================================================================
# 13. TestQoD - quality of detection scoring
# ===================================================================
class TestQoD(unittest.TestCase):
    """Validate QoD scoring, labels, and level lookup."""

    @classmethod
    def setUpClass(cls):
        from qod import get_qod_scorer, QOD_LEVELS
        cls.qod = get_qod_scorer()
        cls.levels = QOD_LEVELS

    def test_assign_qod_vulnerability(self):
        score = self.qod.assign_qod('vulnerability', 'active_check')
        self.assertEqual(score, 95.0)

    def test_assign_qod_network(self):
        score = self.qod.assign_qod('network', 'port_scan')
        self.assertEqual(score, 70.0)

    def test_assign_qod_default(self):
        score = self.qod.assign_qod('unknown_scanner', '')
        self.assertEqual(score, 30.0)

    def test_get_qod_label(self):
        label = self.qod.get_qod_label(97)
        self.assertIsInstance(label, str)
        self.assertIn('Authenticated', label)

    def test_get_all_levels(self):
        levels = self.qod.get_all_levels()
        self.assertIsInstance(levels, dict)
        self.assertIn(100, levels)
        self.assertIn(98, levels)
        self.assertIn(97, levels)


# ===================================================================
# 14. TestBaseScanner - abstract base and concrete subclass
# ===================================================================
class TestBaseScanner(unittest.TestCase):
    """Validate BaseScanner abstract enforcement and severity counting."""

    def test_abstract_instantiation(self):
        from base import BaseScanner
        with self.assertRaises(TypeError):
            BaseScanner()

    def test_concrete_subclass(self):
        from base import BaseScanner

        class MinimalScanner(BaseScanner):
            SCANNER_NAME = 'minimal_test'
            SCANNER_DESCRIPTION = 'Minimal test scanner'

            def scan(self, targets, **kwargs):
                return {'status': 'ok'}

        scanner = MinimalScanner()
        self.assertIsNotNone(scanner)
        self.assertEqual(scanner.SCANNER_NAME, 'minimal_test')

    def test_count_by_severity(self):
        from base import BaseScanner

        class CountScanner(BaseScanner):
            SCANNER_NAME = 'count_test'
            SCANNER_DESCRIPTION = 'Count test scanner'

            def scan(self, targets, **kwargs):
                return {}

        scanner = CountScanner()
        counts = scanner._count_by_severity()
        self.assertIsInstance(counts, dict)
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            self.assertIn(sev, counts)
            self.assertEqual(counts[sev], 0)


# ===================================================================
# 15. TestScannerImports - scanner module attributes
# ===================================================================
class TestScannerImports(unittest.TestCase):
    """Validate that each scanner class exposes SCANNER_NAME and SCANNER_DESCRIPTION."""

    def test_network_scanner_attrs(self):
        from network_scanner import NetworkScanner
        self.assertTrue(hasattr(NetworkScanner, 'SCANNER_NAME'))
        self.assertTrue(hasattr(NetworkScanner, 'SCANNER_DESCRIPTION'))

    def test_vulnerability_scanner_attrs(self):
        from vulnerability_scanner import VulnerabilityScanner
        self.assertTrue(hasattr(VulnerabilityScanner, 'SCANNER_NAME'))
        self.assertTrue(hasattr(VulnerabilityScanner, 'SCANNER_DESCRIPTION'))

    def test_web_scanner_attrs(self):
        from web_scanner import WebScanner
        self.assertTrue(hasattr(WebScanner, 'SCANNER_NAME'))
        self.assertTrue(hasattr(WebScanner, 'SCANNER_DESCRIPTION'))

    def test_ssl_scanner_attrs(self):
        from ssl_scanner import SSLScanner
        self.assertTrue(hasattr(SSLScanner, 'SCANNER_NAME'))
        self.assertTrue(hasattr(SSLScanner, 'SCANNER_DESCRIPTION'))

    def test_compliance_scanner_attrs(self):
        from compliance_scanner import ComplianceScanner
        self.assertTrue(hasattr(ComplianceScanner, 'SCANNER_NAME'))
        self.assertTrue(hasattr(ComplianceScanner, 'SCANNER_DESCRIPTION'))


# ===================================================================
# 16. TestConfigLoadSave - config set/get/reload roundtrip
# ===================================================================
class TestConfigLoadSave(unittest.TestCase):
    """Validate config set/get roundtrip and reload."""

    def test_set_get_roundtrip(self):
        from config import config
        config.set('test_key', 'test_value')
        self.assertEqual(config.get('test_key'), 'test_value')

    def test_to_dict_contains_key(self):
        from config import config
        config.set('test_key_dict', 'hello_world')
        d = config.to_dict()
        self.assertIn('test_key_dict', d)
        self.assertEqual(d['test_key_dict'], 'hello_world')

    def test_reload(self):
        from config import config
        # reload() should not raise
        config.reload()


# ===================================================================
# 17. TestLogger - logging system
# ===================================================================
class TestLogger(unittest.TestCase):
    """Validate logger creation and naming."""

    def test_get_logger(self):
        from logger import get_logger
        lgr = get_logger('test')
        self.assertIsInstance(lgr, logging.Logger)

    def test_logger_name(self):
        from logger import get_logger
        lgr = get_logger('test')
        self.assertIn('test', lgr.name)


# ===================================================================
# Entry point
# ===================================================================
if __name__ == '__main__':
    unittest.main(verbosity=2)
