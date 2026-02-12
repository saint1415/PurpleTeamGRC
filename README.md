# Purple Team GRC Platform v7.0

**Enterprise-Grade Security Assessment, Risk Quantification, and Compliance Platform**

A complete, portable security assessment platform that replaces $110K+/yr in commercial tooling (Tenable, Qualys, RiskLens, Drata) with a single open-source solution. Runs from a USB drive, fixed installation, or CI/CD pipeline.

---

## What's New in v7.0

| Feature | Description |
|---------|-------------|
| **FAIR Risk Quantification** | Monte Carlo simulation translating findings into dollar-quantified risk (ALE) |
| **AI-Powered Analysis** | Multi-backend AI (template/Ollama/OpenAI) with data sanitization |
| **Container Security** | Docker/Podman image and runtime security assessment |
| **Cloud Security** | AWS, Azure, GCP misconfiguration detection (12 checks) |
| **Attack Surface Management** | Certificate transparency, DNS enumeration, Shodan/Censys |
| **SBOM Generation** | CycloneDX 1.4 and SPDX 2.3 from 10 package formats |
| **Executive Dashboard** | Terminal and HTML risk dashboards |
| **CI/CD Integration** | GitHub Actions, GitLab CI, Jenkins pipelines with SARIF export |
| **Deployment Modes** | Auto-detects portable (USB), installed (full), CI/CD (headless) |
| **Windows Support** | Cross-platform: Linux, macOS, Windows 11 |

See [docs/CHANGELOG-v7.md](docs/CHANGELOG-v7.md) for full release notes.

---

## Quick Start

### Linux / macOS

```bash
# 1. Clone or copy the platform
git clone https://github.com/saint1415/PurpleTeamGRC.git
cd PurpleTeamGRC

# 2. Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Populate vulnerability intelligence (optional, recommended)
python3 bin/update-intel.py --quick     # ~2 min: KEV + EPSS + 14-day NVD
# OR with NVD API key (free from https://nvd.nist.gov/developers/request-an-api-key):
NVD_API_KEY=your-key python3 bin/update-intel.py   # ~2 hrs: full 7-source DB (800K+ entries)

# 4. Launch
python3 bin/purple-launcher
```

### Windows

```cmd
REM 1. Clone or copy the platform
git clone https://github.com/saint1415/PurpleTeamGRC.git
cd PurpleTeamGRC

REM 2. Run setup (creates venv, installs deps)
bin\setup-windows.bat

REM 3. Populate vulnerability intelligence (optional, recommended)
python3 bin\update-intel.py --quick

REM 4. Launch
bin\purple-launcher.bat
```

### USB Portable Mode

Plug in the USB drive and run the launcher directly -- no installation required. The platform auto-detects USB deployment and adjusts features accordingly (cloud scanning disabled, AI defaults to template backend).

```bash
# Linux/macOS
python3 /media/USB_DRIVE/purple-final/bin/purple-launcher

# Windows
E:\purple-final\bin\purple-launcher.bat
```

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python3 bin/purple-launcher quick --output sarif
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for detailed setup instructions.

---

## Architecture

```
purple-final/
  bin/                    # Launchers (Linux, Windows, PowerShell)
    purple-launcher       # Main Python TUI launcher (cross-platform)
    purple-launcher.bat   # Windows batch launcher
    purple-launcher.ps1   # PowerShell launcher
    update-intel.py       # 7-source vulnerability intelligence downloader
    setup-windows.bat     # Windows environment setup
  lib/                    # Core libraries
    ai_analyzer.py        # AI analysis (template/ollama/openai)
    asset_manager.py      # Asset inventory with business context
    cicd_integration.py   # CI/CD pipeline generation + SARIF
    config.py             # Configuration management
    credential_manager.py # Encrypted credential storage
    evidence.py           # SQLite evidence database
    network.py            # Network discovery
    paths.py              # Portable path resolution
    platform_detect.py    # OS + deployment mode detection
    qod.py                # Quality of Detection scoring
    risk_quantification.py# FAIR Monte Carlo risk engine
    sbom_generator.py     # CycloneDX + SPDX generation
    threat_intel.py       # CISA KEV + EPSS enrichment
    tool_discovery.py     # Security tool detection
    vuln_database.py      # 7-source vulnerability intelligence (NVD/EPSS/SSVC/exploits)
    tui.py                # Terminal UI components
  scanners/               # Security scanners
    asm_scanner.py        # Attack surface management
    cloud_scanner.py      # AWS/Azure/GCP security
    compliance_scanner.py # Multi-framework compliance
    container_scanner.py  # Docker/Podman security
    credential_scanner.py # SSH authenticated scanning
    network_scanner.py    # Network discovery + port scan
    openvas_scanner.py    # OpenVAS/GVM integration
    ssl_scanner.py        # SSL/TLS assessment
    vulnerability_scanner.py # Vulnerability assessment
    web_scanner.py        # Web application scanning
  utilities/              # Reporting and orchestration
    delta_report.py       # Trend analysis + delta reports
    executive_dashboard.py# Terminal + HTML dashboards
    exporter.py           # SARIF, Jira, ServiceNow, Slack, Teams
    orchestrator.py       # Full assessment orchestration
    reporter.py           # HTML/JSON/CSV report generation
  config/active/          # Active configuration
    config.yaml           # Platform configuration (v7.0)
  data/                   # Runtime data
    threat_intel/         # KEV + EPSS cache (tracked in git for offline use)
    vuln_db/              # Full intel DB (generated by update-intel.py, ~732MB)
    evidence/             # SQLite evidence database (gitignored)
    reports/              # Generated reports (gitignored)
    logs/                 # Scan logs (gitignored)
  docs/                   # Documentation
```

---

## Deployment Modes

The platform automatically detects its deployment context and adjusts features:

| Mode | Detection | Cloud | AI | TUI | SARIF |
|------|-----------|-------|----|-----|-------|
| **Portable** | USB mount detected | Disabled | Template only | Full | Yes |
| **Installed** | Default (fixed system) | All providers | All backends | Full | Yes |
| **CI/CD** | CI env vars (GITHUB_ACTIONS, GITLAB_CI, etc.) | All providers | All backends | Headless | Yes |

See [docs/DEPLOYMENT-MODES.md](docs/DEPLOYMENT-MODES.md) for details.

---

## Features

### Vulnerability Assessment
- Network discovery and port scanning (nmap integration)
- Vulnerability scanning (Nuclei, Nmap NSE scripts)
- Web application scanning (Nikto integration)
- SSL/TLS certificate and cipher assessment
- OpenVAS/GVM integration for enterprise scanning

### Risk Quantification (v7.0)
- FAIR taxonomy: Risk = Loss Event Frequency x Loss Magnitude
- Monte Carlo simulation (10,000 iterations) for ALE ranges
- Maps EPSS scores, KEV status, and CVSS to FAIR factors
- Industry benchmarks (IBM/Ponemon 2025) for 8 verticals
- Data quality score (0-100%) shown with every estimate
- Always ranges (10th/50th/90th percentile), never point estimates

### AI-Powered Analysis (v7.0)
- Three backends: Template (default, no LLM needed), Ollama (local), OpenAI-compatible
- Executive summary generation, finding explanation, remediation guidance
- Attack chain narrative from correlated findings
- Data sanitization strips IPs/hostnames before external LLM calls
- All output tagged "AI-Generated - Verify Before Acting"

### Compliance (10+ Frameworks)
NIST 800-53, HIPAA, PCI-DSS v4, ISO 27001:2022, SOC 1/2 Type II, CMMC, FedRAMP, GDPR, SOX

### Container Security (v7.0)
- Docker and Podman detection and inspection
- Privileged mode, host network, sensitive mount checks
- Root user, exposed port, missing healthcheck detection
- Trivy integration for image vulnerability scanning
- Read-only operations only (no exec/attach)

### Cloud Security (v7.0)
- **AWS:** S3 public, IAM no-MFA, SG 0.0.0.0/0, CloudTrail, old keys, unencrypted EBS
- **Azure:** NSG rules, storage public access, SQL public access
- **GCP:** Firewall 0.0.0.0/0, GCS public, Cloud SQL public IP
- SDK or CLI fallback, read-only API calls only
- Disabled in portable mode (no cloud creds on USB)

### Attack Surface Management (v7.0)
- Certificate transparency via crt.sh (passive, no detection risk)
- DNS enumeration of common subdomains
- Active enumeration (amass/subfinder) with explicit opt-in
- Shodan/Censys integration (optional API keys)

### CI/CD Integration (v7.0)
- Generate GitHub Actions, GitLab CI, Jenkins pipeline configs
- SARIF v2.1.0 export (GitHub Security tab compatible)
- Security gate: pass/fail based on configurable thresholds
- Pre-commit hook generation

### Reporting and Export
- HTML, JSON, CSV reports
- SARIF for GitHub/GitLab security dashboards
- Jira ticket creation via REST API
- ServiceNow incident creation
- Slack and Microsoft Teams webhook notifications
- Delta reports for trend analysis across sessions

---

## Vulnerability Intelligence Database

The platform aggregates 7 intelligence sources into a local SQLite database for offline use:

| Source | Entries | What It Provides |
|--------|---------|-----------------|
| **NVD (NIST)** | 318,225 CVEs | CVSS scores, CWE mappings, references, affected products |
| **EPSS (FIRST.org)** | 314,949 scores | Exploit probability predictions for every CVE |
| **CISA Vulnrichment** | 130,904 decisions | SSVC triage: Act / Attend / Track per CVE |
| **Exploit-DB** | 30,215 mappings | CVE-to-public-exploit cross-references |
| **Nuclei Templates** | 3,782 templates | CVE-to-detection-template mappings |
| **Metasploit** | 3,482 modules | CVE-to-Metasploit-module mappings |
| **CISA KEV** | 1,513 entries | Known actively exploited vulnerabilities |
| **Total** | **803,070+** | |

Populate the database with a single command:

```bash
# Quick mode (~2 min): KEV + full EPSS + 14-day NVD
python3 bin/update-intel.py --quick

# Full mode (~2 hrs with API key): all 7 sources, 2-year NVD coverage
NVD_API_KEY=your-key python3 bin/update-intel.py

# Check current database status
python3 bin/update-intel.py --status
```

Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key (10x faster downloads).

---

## Competitive Comparison

### Intelligence Database

| Metric | Tenable ($30K+) | Qualys ($20K+) | Rapid7 ($25K+) | OpenVAS (Free) | **Purple v7.0 (Free)** |
|--------|:-:|:-:|:-:|:-:|:-:|
| Vuln signatures | 312K plugins | 80K+ QIDs | 180K+ checks | 160-200K NVTs | **318K CVEs** |
| EPSS scores | Partial | Partial | No | Enterprise only | **315K (full dataset)** |
| SSVC triage | No | No | No | No | **131K decisions** |
| Exploit cross-refs | Internal | 25+ feeds | Metasploit | No | **37K (3 sources)** |
| CISA KEV | Yes | Yes | Partial | No | **Yes** |
| Total intel entries | ~312K | ~200K+ | ~180K+ | ~200K | **803K+** |

### Feature Comparison

| Feature | Tenable | Qualys | Rapid7 | RiskLens ($50K) | Drata ($10K) | **Purple v7.0** |
|---------|:-:|:-:|:-:|:-:|:-:|:-:|
| Network scanning | Yes | Yes | Yes | No | No | **Yes** |
| Web app scanning | Paid | Yes | Yes | No | No | **Yes** |
| FAIR Risk ($$$) | No | No | No | Core | No | **Yes** |
| AI Analysis | Add-on | Add-on | No | No | Add-on | **Yes** |
| Container Security | Paid | Paid | Yes | No | No | **Yes** |
| SBOM Generation | No | SCA | No | No | No | **Yes** |
| Cloud Security | Paid | Paid | Paid | No | Partial | **Yes** |
| CI/CD + SARIF | Limited | Limited | Limited | No | Yes | **Yes** |
| Attack Surface Mgmt | Paid | Paid | Paid | No | No | **Yes** |
| 10+ Compliance | Partial | Partial | Partial | No | Yes | **Yes** |
| USB Portable | No | No | No | No | No | **Yes** |
| Airgapped Operation | No | No | No | No | No | **Yes** |
| Open Source | No | No | No | No | No | **Yes** |

### Cost to Replicate

To match Purple v7.0's capability set with commercial products:

| Capability | Product Needed | Annual Cost |
|-----------|---------------|-------------|
| Scanning + vuln mgmt | Tenable.io | $6,000+ |
| Cloud security | Cloud add-on | $10,000+ |
| Container security | Container add-on | $5,000+ |
| FAIR risk quantification | RiskLens/SAFE | $50,000+ |
| Compliance automation | Drata | $10,000+ |
| Attack surface mgmt | ASM add-on | $10,000+ |
| **Total** | **3-4 products** | **$91,000+/yr** |
| **Purple Team v7.0** | **One tool** | **$0** |

---

## Configuration

The main configuration file is `config/active/config.yaml`. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete reference.

Key settings:

```yaml
# AI backend (template is default, works offline)
ai:
  provider: 'template'        # template | ollama | openai
  sanitize_external: true     # Strip IPs/hostnames for external LLMs

# Risk quantification
risk:
  industry: 'technology'      # Maps to IBM/Ponemon benchmarks
  monte_carlo_iterations: 10000

# Compliance frameworks to assess
compliance:
  frameworks:
    - 'NIST-800-53'
    - 'HIPAA'
    - 'PCI-DSS-v4'
    - 'ISO27001-2022'

# CI/CD security gate thresholds
cicd:
  security_gate:
    max_critical: 0
    max_high: 5
```

---

## Platform Requirements

### All Platforms
- Python 3.10+ (3.11+ recommended)
- 4GB RAM minimum
- 1GB disk space (100MB base + up to 800MB for full vulnerability intelligence DB)

### Linux (Primary)
- Any modern distribution (Kali, Ubuntu, Debian, RHEL, etc.)
- Recommended: nmap, nikto, nuclei, testssl.sh for full scanning

### Windows 11
- Python from python.org or Microsoft Store
- Recommended: nmap for Windows
- See [docs/WINDOWS-GUIDE.md](docs/WINDOWS-GUIDE.md)

### macOS
- Python via Homebrew or python.org
- Recommended: nmap via Homebrew

### External Tools (Optional)
| Tool | Purpose | Required? |
|------|---------|-----------|
| nmap | Network scanning | Recommended |
| nikto | Web scanning | Optional |
| nuclei | Vulnerability scanning | Optional |
| testssl.sh | SSL assessment | Optional (Linux/macOS) |
| trivy | Container/SBOM vuln check | Optional |
| amass | Active DNS enumeration | Optional |
| docker/podman | Container scanning | Optional |
| aws/az/gcloud | Cloud scanning | Optional |

All scanners gracefully degrade when tools are unavailable.

---

## Security

- All scanning requires explicit authorization
- Cloud credentials never stored in portable (USB) mode
- LLM data sanitization strips infrastructure details before external API calls
- Container scanner uses read-only operations only
- Credential storage uses Fernet symmetric encryption
- Evidence database contains sensitive data -- protect accordingly

---

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | 5-minute cross-platform setup guide |
| [FEATURES-v7.md](docs/FEATURES-v7.md) | Detailed v7.0 feature documentation |
| [DEPLOYMENT-MODES.md](docs/DEPLOYMENT-MODES.md) | Portable / Installed / CI-CD modes |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete config.yaml reference |
| [WINDOWS-GUIDE.md](docs/WINDOWS-GUIDE.md) | Windows 11 setup and usage |
| [CLI-REFERENCE.md](docs/CLI-REFERENCE.md) | Command-line interface reference |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [CHANGELOG-v7.md](docs/CHANGELOG-v7.md) | v7.0 release notes |
| [CHANGELOG-v6.md](docs/CHANGELOG-v6.md) | v6.0 release notes |
| [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) | Systems thinking architecture |
| [AUDITOR_GUIDE.md](AUDITOR_GUIDE.md) | Audit evidence and compliance |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Professional security assessment use. Only scan networks with explicit written authorization.

---

**Purple Team GRC Platform v7.0**
*Enterprise-Grade Security Assessment and Compliance*
