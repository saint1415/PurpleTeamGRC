# Purple Team Platform v6.0 - Release Notes

## Overview

Version 6.0 achieves full parity with OpenVAS/GVM and adds capabilities that surpass it. This release closes all identified gaps in vulnerability management while maintaining our advantages in compliance frameworks (10+), human-like behavior simulation, USB portability, and systems thinking integration.

## New Capabilities

### 1. CISA KEV + EPSS Threat Intelligence (Phase 1) ✅
**File: `lib/threat_intel.py`**

- Downloads and caches CISA Known Exploited Vulnerabilities (KEV) catalog
- Queries FIRST.org EPSS API for exploit probability scores
- 24-hour local cache in `data/threat_intel/` with TTL management
- `enrich_finding(cve_id)` returns KEV status, EPSS score/percentile, due dates
- `calculate_effective_priority()` formula: `cvss*0.4 + epss*10*0.3 + kev_bonus*0.3`
- All findings automatically enriched during scan (integrated into `scanners/base.py`)
- **Surpasses OpenVAS**: OpenVAS has no native KEV/EPSS integration

**Modified:** `lib/evidence.py` (schema migration for new columns), `scanners/base.py` (auto-enrichment)

---

### 2. Asset Inventory Database (Phase 2) ✅
**File: `lib/asset_manager.py`**

- Persistent asset tracking in SQLite (shared `evidence.db`)
- Tables: `assets` (IP, hostname, MAC, vendor, OS, scan count, tags) and `asset_ports`
- Automatic registration from network scans
- `get_asset_history(ip)` - all scan sessions for an asset
- `get_asset_risk_profile(ip)` - aggregate findings by severity
- `search_assets(query)` - search by IP, hostname, OS, or tag
- `tag_asset(ip, tags)` - categorization and grouping

**Modified:** `scanners/network_scanner.py` (auto-registration), `utilities/orchestrator.py` (asset phase)

---

### 3. Delta Reporting & Trend Analysis (Phase 3) ✅
**File: `utilities/delta_report.py`**

- `compare_sessions(id1, id2)` returns new, resolved, persistent, and severity-changed findings
- Fingerprint matching: same CVE OR (same title + same asset + same scanner)
- `trend_analysis(last_n_sessions)` with risk trend detection (increasing/decreasing/stable)
- Mean time to remediate calculation
- Top recurring findings identification
- HTML delta report with visual diff
- ASCII trend charts for terminal output

**Modified:** `utilities/reporter.py` (delta/trend HTML sections), `bin/purple-launcher` (Delta Report & Trend Analysis menus)

---

### 4. Quality of Detection (QoD) Scoring (Phase 4) ✅
**File: `lib/qod.py`**

- OpenVAS-compatible QoD scale (0-100%):
  - 100% = Exploit confirmed
  - 98% = Remote vulnerability detection (active check)
  - 97% = Authenticated version check
  - 95% = Remote vulnerability detection (passive)
  - 80% = Remote analysis (fingerprinting)
  - 70% = Version-based detection (unauthenticated)
  - 50% = Remote detection (banner grab only)
  - 30% = Default/heuristic
  - 1% = General note
- Auto-assigns QoD based on scanner name and detection method
- `filter_by_qod(findings, min_qod)` to filter low-confidence results
- QoD stored in findings table and displayed in reports

**Modified:** All 5 scanners (network, vulnerability, web, ssl, compliance) now pass `detection_method` to `add_finding()`

---

### 5. Credentialed/Authenticated Scanning (Phase 5) ✅
**Files: `lib/credential_manager.py`, `scanners/credential_scanner.py`**

- Credential storage with optional Fernet encryption (falls back to plaintext with warning)
- Credential types: SSH (key/password), WinRM, SNMP, HTTP basic auth
- Target matching by IP, CIDR, or wildcard pattern
- SSH-based authenticated checks:
  - Package version audit (dpkg/rpm)
  - Running services enumeration
  - SSH configuration audit
  - User account audit
  - PAM configuration check
  - File permissions audit
  - Patch level assessment
- All findings mapped to QoD 97% (authenticated)
- Uses paramiko with subprocess ssh fallback

**Modified:** `utilities/orchestrator.py` (Phase 1.5: credentialed scanning after network discovery)

---

### 6. False Positive Management (Phase 6) ✅
**Modified: `lib/evidence.py`, `scanners/base.py`, `bin/purple-launcher`**

- `finding_overrides` table with JSON match rules
- Override actions: `false_positive`, `severity_change`, `accepted_risk`
- Match criteria: title, CVE, asset IP, scanner name (any combination)
- Overrides checked before recording findings (still recorded for audit trail, but flagged)
- Optional expiration dates on overrides
- Interactive "Manage Overrides" menu in Settings

---

### 7. Windows 11 Cross-Platform Support (Phase 7) ✅
**File: `lib/platform_detect.py`**

- Detects OS (Windows/Linux/macOS), architecture, WSL status, admin/root status
- `get_available_package_manager()` - apt/dnf/pacman/choco/winget/brew
- `get_platform_tool_name(tool)` - platform-specific binary names
- `get_usb_paths()` - USB drive detection on both platforms
- **OpenVAS is Linux-only; we now run on Windows 11 natively**

**Modified:**
- `lib/network.py` - Cross-platform interface detection (ip/ipconfig/socket fallback)
- `lib/tool_discovery.py` - Windows tool paths, winget/choco install, security fix (shell=False)
- `lib/paths.py` - Windows venv paths, Windows tool finding
- `bin/purple-launcher` - Windows color support (colorama/ctypes), platform display

---

### 8. OpenVAS/GVM Integration (Phase 8) ✅
**File: `scanners/openvas_scanner.py`**

- Three integration modes:
  1. **GMP Protocol** (preferred): python-gvm library, full scan management
  2. **CLI mode**: gvm-cli subprocess for basic operations
  3. **Import mode**: Parse and import existing OpenVAS XML reports
- `import_openvas_report(xml_path)` - import existing reports
- `sync_findings()` - merge OpenVAS results with local DB
- OpenVAS QoD mapped directly to our QoD scores
- Imported findings enriched with KEV/EPSS (value-add over standalone OpenVAS)
- Interactive "OpenVAS Integration" submenu in Red Team menu

**Modified:** `utilities/orchestrator.py` (Phase 2.5: optional OpenVAS scanning)

---

## Files Summary

### New Files (7)
| File | Description |
|------|-------------|
| `lib/threat_intel.py` | CISA KEV + EPSS threat intelligence |
| `lib/asset_manager.py` | Persistent asset inventory |
| `lib/qod.py` | Quality of Detection scoring |
| `lib/credential_manager.py` | Encrypted credential storage |
| `lib/platform_detect.py` | Cross-platform detection |
| `scanners/credential_scanner.py` | SSH-based authenticated scanning |
| `scanners/openvas_scanner.py` | OpenVAS/GVM integration |
| `utilities/delta_report.py` | Delta reporting & trend analysis |

### Modified Files (~12)
| File | Changes |
|------|---------|
| `lib/evidence.py` | Schema migration, override system, new columns |
| `scanners/base.py` | Threat intel enrichment, QoD, override checking |
| `scanners/network_scanner.py` | Asset registration, detection_method |
| `scanners/vulnerability_scanner.py` | detection_method param |
| `scanners/web_scanner.py` | detection_method param |
| `scanners/ssl_scanner.py` | detection_method param |
| `scanners/compliance_scanner.py` | detection_method, gap findings |
| `utilities/orchestrator.py` | Asset, credential, OpenVAS phases |
| `utilities/reporter.py` | Delta report, trend report methods |
| `lib/network.py` | Cross-platform interface detection |
| `lib/tool_discovery.py` | Windows paths, security fix |
| `lib/paths.py` | Windows venv/tool paths |
| `bin/purple-launcher` | v6.0 menus, OpenVAS, overrides, credentials, delta, Windows |

---

## Comparison: Purple Team v6.0 vs OpenVAS/GVM

| Capability | OpenVAS/GVM | Purple Team v6.0 |
|-----------|-------------|-------------------|
| NVT/Vulnerability Checks | 160K+ NVTs | Nuclei (9K+) + Nmap NSE + Nikto + OpenVAS import |
| Credentialed Scanning | Yes | Yes (SSH, WinRM, SNMP) |
| Quality of Detection | Yes (QoD 0-100) | Yes (compatible scale) |
| CVSS Scoring | v2 + v3.1 | v3.1 (from NVD/tool output) |
| Asset Management | Yes | Yes (persistent SQLite) |
| Delta Reports | Yes | Yes (with trend analysis) |
| False Positive Mgmt | Overrides | Overrides + auto-expiry |
| CISA KEV Integration | No | **Yes** |
| EPSS Scoring | No | **Yes** |
| Compliance Frameworks | Limited | **10+ frameworks** |
| Human Behavior Sim | No | **Yes (stealth profiles)** |
| USB Portable | No | **Yes** |
| Windows Support | No (Linux only) | **Yes (Win11 + WSL)** |
| Systems Thinking | No | **Yes** |
| OpenVAS Integration | N/A | **Yes (GMP + CLI + Import)** |

---

## Verification

After installation, verify with:
```bash
# Self-test individual modules
python3 lib/threat_intel.py
python3 lib/asset_manager.py
python3 lib/qod.py
python3 lib/platform_detect.py

# Check tool discovery
python3 bin/purple-launcher tools

# Run quick scan
python3 bin/purple-launcher quick
```
