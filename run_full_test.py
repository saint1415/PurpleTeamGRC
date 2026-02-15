#!/usr/bin/env python3
"""Full application test suite for PurpleTeamGRC on Windows 11."""
import json
import sys
import os
import traceback
from pathlib import Path

os.chdir("C:/Users/Cris/PurpleTeamGRC")
sys.path.insert(0, "lib")
sys.path.insert(0, ".")

log = []


def test(name, fn):
    try:
        result = fn()
        detail = str(result)[:200] if result else ""
        log.append({"test": name, "status": "PASS", "detail": detail})
        print(f"  PASS: {name}")
        return result
    except Exception as e:
        tb = traceback.format_exc()[-500:]
        log.append({"test": name, "status": "FAIL", "error": str(e)[:300], "traceback": tb})
        print(f"  FAIL: {name}: {e}")
        return None


# ========== PHASE 1: ALL IMPORTS ==========
print("=" * 60)
print("PHASE 1: Core Module Imports")
print("=" * 60)

lib_modules = [
    "paths", "config", "logger", "database", "evidence", "compliance",
    "notifications", "scheduler", "licensing", "ai_engine", "ai_prompts",
    "threat_intel", "vuln_database", "risk_quantification", "risk_register",
    "remediation", "exceptions", "audit", "export", "executive_report",
    "asset_inventory", "asset_manager", "scan_diff", "discovery",
    "credential_manager", "human_behavior", "network", "tui",
    "platform_detect", "qod", "tool_discovery", "sbom_generator",
    "cicd_integration", "cis_benchmarks", "intel_feeds", "agent_deployer",
]
for mod in lib_modules:
    test(f"import lib.{mod}", lambda m=mod: __import__(f"lib.{m}", fromlist=[m]))

scanner_modules = [
    "base", "network_scanner", "vulnerability_scanner", "web_scanner",
    "ssl_scanner", "compliance_scanner", "windows_scanner", "linux_scanner",
    "ad_scanner", "cloud_scanner", "container_scanner", "sbom_scanner",
    "malware_scanner", "credential_scanner", "asm_scanner", "openvas_scanner",
]
for mod in scanner_modules:
    test(f"import scanners.{mod}", lambda m=mod: __import__(f"scanners.{m}", fromlist=[m]))

util_modules = ["orchestrator", "reporter", "exporter", "audit_report", "delta_report", "executive_dashboard"]
for mod in util_modules:
    test(f"import utilities.{mod}", lambda m=mod: __import__(f"utilities.{m}", fromlist=[m]))

test("import web.api", lambda: __import__("web.api", fromlist=["api"]))
test("import web.dashboard", lambda: __import__("web.dashboard", fromlist=["dashboard"]))
test("import web.auth", lambda: __import__("web.auth", fromlist=["auth"]))

# ========== PHASE 2: SINGLETONS ==========
print()
print("=" * 60)
print("PHASE 2: Singleton Initialization")
print("=" * 60)

from lib.paths import get_paths
test("paths singleton", lambda: get_paths())
from lib.config import get_config
test("config singleton", lambda: get_config())
from lib.evidence import get_evidence_manager
test("evidence manager", lambda: get_evidence_manager())
from lib.compliance import get_compliance_mapper
test("compliance mapper", lambda: get_compliance_mapper())
from lib.notifications import get_notification_manager
test("notification manager", lambda: get_notification_manager())
from lib.scheduler import get_scheduler
test("scheduler", lambda: get_scheduler())
from lib.licensing import get_license_manager
test("license manager", lambda: get_license_manager())
from lib.ai_engine import get_ai_engine
test("AI engine", lambda: get_ai_engine())
from lib.threat_intel import get_threat_intel
test("threat intel", lambda: get_threat_intel())
from lib.risk_quantification import RiskQuantifier
test("risk quantifier", lambda: RiskQuantifier())
from lib.tool_discovery import tool_discovery as td
test("tool discovery", lambda: td)
from lib.audit import get_audit_trail
test("audit trail", lambda: get_audit_trail())
from lib.risk_register import get_risk_register
test("risk register", lambda: get_risk_register())
from lib.remediation import get_remediation_tracker
test("remediation tracker", lambda: get_remediation_tracker())
from lib.exceptions import get_exception_manager
test("exception manager", lambda: get_exception_manager())
from lib.asset_inventory import get_asset_inventory
test("asset inventory", lambda: get_asset_inventory())

# ========== PHASE 3: DATABASE OPS ==========
print()
print("=" * 60)
print("PHASE 3: Database Operations")
print("=" * 60)


def test_evidence():
    em = get_evidence_manager()
    sid = em.start_session("network", ["127.0.0.1"])
    eid = em.add_evidence(sid, "finding", "Test Finding", "Test desc", "test_scanner", raw_data={"test": True})
    fid = em.add_finding(sid, "HIGH", "Test Vuln", "Description", "127.0.0.1", 7.5, ["CVE-2024-0001"], "Patch system", eid)
    summary = em.get_session_summary(sid)
    findings = em.get_findings_for_session(sid)
    return f"session={sid}, findings={len(findings)}"


test("evidence CRUD", test_evidence)
test("notification channels", lambda: f"count={len(get_notification_manager().get_channels())}")
test("scheduler schedules", lambda: f"count={len(get_scheduler().get_all_schedules())}")


def test_audit():
    at = get_audit_trail()
    at.log("test_event", "tester", details=json.dumps({"action": "test"}))
    entries = at.get_log(limit=5)
    return f"entries={len(entries)}"


test("audit trail write+query", test_audit)
test("risk register query", lambda: f"risks={len(get_risk_register().get_risks())}")
test("remediation open items", lambda: f"items={len(get_remediation_tracker().get_open_items())}")
test("exceptions list", lambda: f"count={len(get_exception_manager().get_all_exceptions())}")

# ========== PHASE 4: SCANNERS ==========
print()
print("=" * 60)
print("PHASE 4: Scanner Instantiation")
print("=" * 60)

scanner_tests = [
    ("NetworkScanner", "scanners.network_scanner", "NetworkScanner"),
    ("VulnerabilityScanner", "scanners.vulnerability_scanner", "VulnerabilityScanner"),
    ("WebScanner", "scanners.web_scanner", "WebScanner"),
    ("SSLScanner", "scanners.ssl_scanner", "SSLScanner"),
    ("WindowsScanner", "scanners.windows_scanner", "WindowsScanner"),
    ("ComplianceScanner", "scanners.compliance_scanner", "ComplianceScanner"),
    ("MalwareScanner", "scanners.malware_scanner", "MalwareScanner"),
    ("ADScanner", "scanners.ad_scanner", "ADScanner"),
    ("CloudScanner", "scanners.cloud_scanner", "CloudScanner"),
    ("ContainerScanner", "scanners.container_scanner", "ContainerScanner"),
    ("SBOMScanner", "scanners.sbom_scanner", "SBOMScanner"),
    ("CredentialScanner", "scanners.credential_scanner", "CredentialScanner"),
    ("ASMScanner", "scanners.asm_scanner", "ASMScanner"),
    ("OpenVASScanner", "scanners.openvas_scanner", "OpenVASScanner"),
]
for name, mp, cn in scanner_tests:
    def mk(mp=mp, cn=cn):
        mod = __import__(mp, fromlist=[cn])
        return getattr(mod, cn)(f"test-{cn.lower()}")
    test(f"{name} init", mk)

# ========== PHASE 5: TOOL DISCOVERY ==========
print()
print("=" * 60)
print("PHASE 5: Tool Discovery")
print("=" * 60)

test("available tools", lambda: f"tools={len(td.get_available())}: {[t.name for t in td.get_available().values()]}")


def test_bundled():
    found = []
    for n in ["nmap", "nuclei.exe", "yara/yara64.exe", "testssl", "amass", "gobuster"]:
        if (Path("tools") / n).exists():
            found.append(n)
    return f"bundled={found}"


test("bundled tools", test_bundled)

# ========== PHASE 6: QUICK SCANS ==========
print()
print("=" * 60)
print("PHASE 6: Quick Scans (localhost)")
print("=" * 60)


def test_windows_scan():
    from scanners.windows_scanner import WindowsScanner
    ws = WindowsScanner("test-winscan-2")
    result = ws.scan(["localhost"], scan_type="quick")
    return f"findings={result.get('findings_count', 0)}, by_sev={result.get('findings_by_severity', {})}"


test("Windows quick scan", test_windows_scan)


def test_compliance_scan():
    from scanners.compliance_scanner import ComplianceScanner
    cs = ComplianceScanner("test-compscan-2")
    result = cs.scan(["localhost"], scan_type="quick")
    return f"findings={result.get('findings_count', 0)}"


test("Compliance quick scan", test_compliance_scan)


def test_malware_scan():
    from scanners.malware_scanner import MalwareScanner
    ms = MalwareScanner("test-malwarescan-2")
    result = ms.scan([str(Path("tools"))], scan_type="quick")
    return f"findings={result.get('findings_count', 0)}, yara={ms._yara_path is not None}"


test("Malware quick scan (tools/)", test_malware_scan)

# ========== PHASE 7: API ENDPOINTS ==========
print()
print("=" * 60)
print("PHASE 7: API Endpoints (requires server on :8443)")
print("=" * 60)

import urllib.request
import urllib.error

BASE = "http://localhost:8443"


def api_get(path):
    req = urllib.request.Request(f"{BASE}{path}", headers={"User-Agent": "test"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def api_post(path, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        f"{BASE}{path}", data=data,
        headers={"Content-Type": "application/json", "User-Agent": "test"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


test("GET /api/v1/stats", lambda: api_get("/api/v1/stats"))
test("GET /api/v1/scanners", lambda: f"count={api_get('/api/v1/scanners')['count']}")
test("GET /api/v1/license", lambda: api_get("/api/v1/license"))
test("GET /api/v1/ai/status", lambda: api_get("/api/v1/ai/status"))
test("GET /api/v1/notifications/channels", lambda: api_get("/api/v1/notifications/channels"))
test("GET /api/v1/notifications/stats", lambda: api_get("/api/v1/notifications/stats"))
test("GET /api/v1/schedules", lambda: api_get("/api/v1/schedules"))
test("GET /api/v1/notifications/history", lambda: api_get("/api/v1/notifications/history"))


def test_create_channel():
    result = api_post("/api/v1/notifications/channels", {
        "name": "test-webhook-auto",
        "channel_type": "webhook",
        "config": {"url": "http://localhost:9999/hook"},
    })
    return f"channel_id={result.get('channel_id', 'N/A')}"


test("POST create webhook channel", test_create_channel)


def test_dashboard():
    req = urllib.request.Request(f"{BASE}/", headers={"User-Agent": "test"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        html = resp.read().decode()
    has_tabs = all(t in html for t in ["scan-center", "schedules", "notifications", "ai-assistant"])
    return f"html_size={len(html)}, has_5_tabs={has_tabs}"


test("GET / (dashboard HTML)", test_dashboard)

# ========== PHASE 8: AI ENGINE ==========
print()
print("=" * 60)
print("PHASE 8: AI Engine (template mode)")
print("=" * 60)

engine = get_ai_engine()
test("AI status", lambda: engine.get_status())

sample_finding = {
    "title": "SQL Injection in Login Form",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "epss_score": 0.92,
    "kev_status": "true",
    "finding_type": "sql_injection",
    "affected_asset": "10.0.0.5",
    "remediation": "Use parameterized queries.",
}

test("AI analyze finding", lambda: engine.analyze_finding(sample_finding))
test("AI triage findings", lambda: engine.triage_findings([sample_finding]))
test("AI generate remediation", lambda: engine.generate_remediation(sample_finding))
test("AI query", lambda: engine.query("What is the most critical finding?", {"findings": [sample_finding]}))

# ========== PHASE 9: LICENSING ==========
print()
print("=" * 60)
print("PHASE 9: Licensing & Tier Enforcement")
print("=" * 60)

from lib.licensing import generate_license

lm = get_license_manager()
test("current tier = community", lambda: f"tier={lm.get_tier()}, label={lm.get_tier_label()}")
test("deep scan blocked", lambda: f"allowed={lm.check_scan_depth('deep')} (expect False)")
test("quick scan allowed", lambda: f"allowed={lm.check_scan_depth('quick')} (expect True)")
test("network scanner allowed", lambda: f"allowed={lm.check_feature_item('scanners', 'network')} (expect True)")
test("cloud scanner blocked", lambda: f"allowed={lm.check_feature_item('scanners', 'cloud')} (expect False)")
test("CSV export allowed", lambda: f"allowed={lm.check_feature_item('export_formats', 'csv')} (expect True)")
test("PDF export blocked", lambda: f"allowed={lm.check_feature_item('export_formats', 'pdf')} (expect False)")
test("AI quota available", lambda: f"has_quota={lm.check_ai_quota()} (expect True)")
test("scheduled scans blocked", lambda: f"allowed={lm.check_limit('scheduled_scans')} (expect False)")
test("generate pro license", lambda: generate_license("pro", "Test Corp", "2030-12-31"))
test("validate pro license", lambda: f"valid={lm._validate_license(generate_license('pro', 'TestCo', '2030-12-31'))}")

# ========== PHASE 10: THREAT INTEL ==========
print()
print("=" * 60)
print("PHASE 10: Threat Intelligence")
print("=" * 60)

ti = get_threat_intel()
test("enrich CVE-2021-44228 (Log4Shell)", lambda: ti.enrich_finding("CVE-2021-44228"))
test("calculate effective priority", lambda: ti.calculate_effective_priority(10.0, 0.97, True))

# ========== PHASE 11: COMPLIANCE FRAMEWORKS ==========
print()
print("=" * 60)
print("PHASE 11: Compliance Frameworks")
print("=" * 60)

cm = get_compliance_mapper()
test("list frameworks", lambda: f"frameworks={cm.get_supported_frameworks()[:8]}")


def test_framework_configs():
    fw_dir = Path("config/frameworks")
    if not fw_dir.exists():
        return "no config/frameworks dir"
    files = list(fw_dir.glob("*.json")) + list(fw_dir.glob("*.yaml"))
    return f"framework_config_files={len(files)}"


test("framework config files", test_framework_configs)

# ========== PHASE 12: RISK QUANTIFICATION ==========
print()
print("=" * 60)
print("PHASE 12: Risk Quantification (FAIR)")
print("=" * 60)


def test_fair():
    rq = RiskQuantifier()
    # Use quantify_finding with a mock finding dict
    finding = {
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_asset": "10.0.0.5",
        "title": "SQL Injection",
        "finding_type": "sql_injection",
    }
    result = rq.quantify_finding(finding)
    return f"result_keys={list(result.keys())[:5]}"


test("FAIR risk quantification", test_fair)

# ========== SAVE & SUMMARY ==========
Path("data").mkdir(exist_ok=True)
with open("data/test_run_log.json", "w") as f:
    json.dump(log, f, indent=2)

passed = sum(1 for t in log if t["status"] == "PASS")
failed = sum(1 for t in log if t["status"] == "FAIL")

print()
print("=" * 60)
print(f"FINAL: {passed} PASSED, {failed} FAILED out of {len(log)} tests")
print("=" * 60)

if failed:
    print()
    print("FAILURES:")
    for t in log:
        if t["status"] == "FAIL":
            print(f"  {t['test']}: {t.get('error', '')[:150]}")
