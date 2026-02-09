# Purple Team Platform v7.0 - Release Notes

**Release Date:** February 2026
**Previous Version:** v6.0

---

## Overview

Version 7.0 transforms the Purple Team Platform from a vulnerability management tool into a complete security intelligence platform. Eight new modules add FAIR risk quantification, AI-powered analysis, container and cloud security, SBOM generation, attack surface management, executive dashboards, and CI/CD pipeline integration with SARIF output.

All v7.0 features respect the platform's three deployment modes (portable, installed, CI/CD). Cloud scanning and external AI are automatically disabled in portable mode. Container scanning requires explicit user confirmation before accessing the Docker socket.

---

## New Capabilities

### 1. FAIR Risk Quantification

**File:** `lib/risk_quantification.py`

Translates security findings into dollar-quantified risk using the FAIR (Factor Analysis of Information Risk) taxonomy. Replaces commercial tools like RiskLens ($50K+/year).

- FAIR decomposition: Risk = Loss Event Frequency (LEF) x Loss Magnitude (LM)
- Maps platform data to FAIR inputs:
  - EPSS score -> Probability of Action (PA)
  - KEV status -> Contact Frequency boost
  - CVSS score -> Resistance Strength (inverted)
  - Asset context -> Loss Magnitude
- Monte Carlo simulation (10,000 iterations default) producing ALE percentiles (10th, 50th, 90th)
- Industry benchmarks from IBM/Ponemon Cost of a Data Breach 2025 for 9 sectors: healthcare ($10.93M), financial ($5.9M), technology ($4.97M), government ($2.58M), education ($3.65M), retail ($3.28M), manufacturing ($4.73M), energy ($4.78M), default ($4.45M)
- Data quality scoring (0-100%) indicating how much real vs default data was used
- Confidence warnings when data quality is below 50%
- Revenue cap: single loss capped at 10% of annual revenue
- Results persisted in SQLite `risk_quantification` table
- `quantify_finding()` - single finding quantification
- `quantify_asset()` - aggregate risk per asset
- `quantify_organization()` - total organizational risk
- `get_top_risks()` - top N findings by ALE
- Accessible from Compliance & Reports menu (option `r`) and CLI (`purple-launcher risk`)

---

### 2. AI-Powered Analysis Engine

**File:** `lib/ai_analyzer.py`

Multi-backend AI analysis with three providers: template (default), Ollama (local LLM), and OpenAI-compatible APIs.

- **Template backend** (always available): Pure Python rule-based analysis with knowledge base of 14 finding types and remediation steps. No LLM or network connection required.
- **Ollama backend**: Local LLM via Ollama API at `http://localhost:11434`. Sends full unsanitized data (stays local).
- **OpenAI backend**: OpenAI-compatible API with Bearer auth. Data sanitized by default (IPs masked, hostnames replaced, org names removed). CVE IDs and CVSS scores preserved (public data).
- All LLM output tagged with disclaimer: "AI-Generated - Verify Before Acting"
- Portable deployment mode forces template backend (no external API calls from USB)
- Analysis methods:
  - `generate_executive_summary()` - C-level summary from session results
  - `explain_finding()` - plain English finding explanation with business impact
  - `suggest_remediation()` - actionable remediation steps with timelines
  - `generate_attack_narrative()` - realistic attack chain from grouped findings
  - `prioritize_findings()` - weighted priority ranking with reasoning
- LLM calls fall back to template on any error
- API key retrieved from credential manager if not explicitly provided
- Accessible from Compliance & Reports menu (option `a`)

---

### 3. SBOM Generation

**File:** `lib/sbom_generator.py`

Software Bill of Materials generation in CycloneDX 1.4 and SPDX 2.3 formats.

- Parses 10 package manifest formats:
  - Python: `requirements.txt`, `Pipfile.lock`
  - Node.js: `package.json`, `package-lock.json` (v1/v2/v3)
  - Go: `go.mod`
  - Rust: `Cargo.toml`, `Cargo.lock`
  - Java: `pom.xml` (Maven, with namespace handling)
  - Ruby: `Gemfile.lock`
  - PHP: `composer.lock`
- Lock file preference: uses lock files over manifests when both exist (with warning)
- Recursive directory scanning, skips `node_modules`, `.git`, `venv`, etc.
- De-duplication by name+version+type
- Package URL (purl) generation per ecosystem
- Honest coverage indicator: explicitly states what was and was NOT analyzed (system packages, C/C++ libraries, static binaries, vendored source not covered)
- Vulnerability checking via trivy or grype (if installed)
- Export methods:
  - `export_cyclonedx()` - CycloneDX 1.4 JSON with serial number and tool metadata
  - `export_spdx()` - SPDX 2.3 JSON with package-manager external references

---

### 4. CI/CD Integration

**File:** `lib/cicd_integration.py`

Pipeline configuration generation, SARIF reporting, and security gate evaluation.

- Pipeline generators:
  - `generate_github_actions()` - complete GitHub Actions workflow with SARIF upload to GitHub Security tab
  - `generate_gitlab_ci()` - complete `.gitlab-ci.yml` with SAST artifact reporting
  - `generate_jenkins_pipeline()` - declarative Jenkinsfile with archive artifacts
- **SARIF export** (v2.1.0): findings exported with rules, fingerprints, severity mapping (CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note), CVE tags, and security-severity properties
- **Security gate evaluation**: configurable thresholds per severity level
  - Default policy: fail on any CRITICAL, or more than 5 HIGH
  - Custom policy support: `{'critical': 0, 'high': 5, 'medium': 20}`
  - Returns pass/fail, reason, exit code, and severity summary
- **Pre-commit hook generator**: shell script that runs quick scan and evaluates security gate before each commit
- `save_pipeline_config()` - writes config to the correct path for each provider
- Accessible from Settings > CI/CD Integration (option `c`)

---

### 5. Container Security Scanner

**File:** `scanners/container_scanner.py`

Docker and Podman container security assessment. Extends `BaseScanner`.

- Safety measures:
  - Requires explicit `user_confirmed=True` before accessing Docker socket
  - Read-only inspection only (no exec, attach, pull, or modification operations)
  - Sensitive environment variable values are never logged (only names)
- Auto-detects container runtime (Docker or Podman)
- Container security checks:
  - Privileged mode (CRITICAL)
  - Host network mode (HIGH)
  - Sensitive host path mounts: `/etc/shadow`, `/var/run/docker.sock`, `/root`, `/home` and Windows equivalents (HIGH)
  - Running as root (MEDIUM)
  - Secrets in environment variables (MEDIUM)
  - Missing health checks (LOW)
  - Exposed ports (INFO)
- Image security checks:
  - Image age over 180 days (MEDIUM)
  - Excessive layers over 40 (INFO)
- Trivy integration for image vulnerability scanning (standard/deep scan types)
- Cross-platform: Windows and Linux sensitive path lists
- All findings mapped to compliance controls

---

### 6. Cloud Security Scanner

**File:** `scanners/cloud_scanner.py`

AWS, Azure, and GCP security configuration assessment. Extends `BaseScanner`.

- Safety measures:
  - Disabled in portable deployment mode (no cloud creds on USB)
  - All API calls are read-only (no modifications)
  - Warning: "Cloud credentials should use read-only IAM roles"
- Provider detection via SDK (boto3, azure-identity, google-cloud) or CLI (aws, az, gcloud) with graceful degradation
- **AWS checks (6):**
  - S3 buckets with public access/ACL grants (CRITICAL)
  - IAM users without MFA (HIGH)
  - Security groups allowing 0.0.0.0/0 or ::/0 ingress (HIGH)
  - CloudTrail disabled or missing (HIGH)
  - Access keys older than 90 days (MEDIUM)
  - Unencrypted EBS volumes (MEDIUM)
- **Azure checks (3):**
  - NSG rules allowing any-source inbound (HIGH)
  - Storage accounts with public blob access (CRITICAL)
  - SQL servers with public network access (HIGH)
- **GCP checks (3):**
  - Firewall rules allowing 0.0.0.0/0 ingress (HIGH)
  - GCS buckets with allUsers/allAuthenticatedUsers IAM bindings (CRITICAL)
  - Cloud SQL instances with public IP (HIGH/MEDIUM)

---

### 7. Attack Surface Management Scanner

**File:** `scanners/asm_scanner.py`

External attack surface discovery and monitoring. Extends `BaseScanner`.

- Passive-first design: CT logs and DNS lookups are default. Active enumeration requires explicit `active=True`.
- Passive checks (always run):
  - Certificate Transparency (CT) log queries via crt.sh API with rate limiting (2s between requests)
  - Expired certificate detection (MEDIUM)
  - Wildcard certificate detection (INFO)
  - DNS subdomain enumeration (13 common prefixes)
  - HTTPS availability check on discovered subdomains (MEDIUM if no port 443)
  - DNS zone transfer (AXFR) detection via dig or host (HIGH)
- Active checks (opt-in only):
  - amass passive enumeration
  - subfinder enumeration
  - Extended DNS brute-force (60+ subdomain prefixes) as fallback
- Shodan integration:
  - API key from credential manager
  - Unexpected externally exposed services (HIGH)
  - Internal services exposed externally (HIGH): SSH, MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch
- Large attack surface warning at 50+ subdomains (INFO)

---

### 8. Executive Dashboard

**File:** `utilities/executive_dashboard.py`

Terminal-based and HTML-export security dashboard.

- **Terminal dashboard**: ANSI-colored with box-drawing characters. Displays:
  - Risk score gauge (0-100) with color coding (green < 40, yellow 40-70, red > 70)
  - Trend indicator (improving/worsening/stable) based on last 5 sessions
  - Severity breakdown cards (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Total findings and tracked asset count
  - Compliance meters per framework with percentage bars
  - Top 5 critical/high findings with CVSS scores
- **HTML dashboard export**: professional CSS-styled static HTML with:
  - Gradient header
  - Risk score gauge with animation
  - Severity card grid
  - Key metrics row (findings, assets, open ports)
  - Compliance meter bars
  - Top findings table with severity badges
- Risk score formula: CRITICAL * 10 + HIGH * 7 + MEDIUM * 4 + LOW * 1 (capped at 100)
- Trend detection: compares newer half vs older half of recent sessions
- Compliance rates: percentage of controls with supporting evidence per framework
- Accessible from main menu (option `d`) and CLI (`purple-launcher dashboard`)

---

## Deployment Modes

**File:** `lib/platform_detect.py` (updated from v6.0)

Three deployment modes with auto-detection:

| Mode | Detection | Features Enabled | Features Disabled |
|------|-----------|------------------|-------------------|
| Portable | USB/removable media mount path | Template AI, SBOM, risk quant, container scan | Cloud scanning, external AI |
| Installed | Fixed system path | All features | None |
| CI/CD | CI environment variables | Headless scanning, SARIF, security gates | Interactive menus |

CI/CD detection checks: `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `CIRCLECI`, `TRAVIS`, `BITBUCKET_PIPELINE`, `TF_BUILD`, `CODEBUILD_BUILD_ID`, `BUILDKITE`.

---

## Configuration (v7.0 Additions)

**File:** `config/active/config.yaml`

New configuration sections in v7.0:

| Section | Key Settings |
|---------|--------------|
| `ai` | provider (template/ollama/openai), model, api_url, sanitize_external |
| `risk` | industry, benchmark_year, monte_carlo_iterations, custom_benchmarks |
| `container` | enabled, runtime (auto/docker/podman), trivy_enabled |
| `cloud` | enabled, aws/azure/gcp sub-sections with read_only flag |
| `asm` | active_enumeration, ct_logs, dns_brute |
| `sbom` | enabled, formats (cyclonedx, spdx) |
| `cicd` | security_gate thresholds (fail_on_critical, max_high, max_medium) |
| `reporting.formats` | sarif added to export format list |
| `notifications` | slack (webhook_url), teams (webhook_url) |
| `integrations` | jira (url, project_key), servicenow (instance_url), shodan, censys |

---

## Modified Files

| File | Changes |
|------|---------|
| `bin/purple-launcher` | v7.0 menus, CLI commands (risk, dashboard), AI/SBOM/CI-CD handlers |
| `config/active/config.yaml` | New v7.0 sections for AI, risk, container, cloud, ASM, SBOM, CI/CD |
| `lib/platform_detect.py` | Deployment mode property (portable/installed/cicd), is_portable/is_cicd |

---

## New Files Summary

| File | Lines | Description |
|------|-------|-------------|
| `lib/risk_quantification.py` | ~887 | FAIR risk quantification with Monte Carlo |
| `lib/ai_analyzer.py` | ~1143 | AI-powered analysis (template/ollama/openai) |
| `lib/sbom_generator.py` | ~945 | SBOM generation (CycloneDX, SPDX) |
| `lib/cicd_integration.py` | ~566 | CI/CD pipeline configs, SARIF, security gates |
| `scanners/container_scanner.py` | ~708 | Container security (Docker/Podman) |
| `scanners/cloud_scanner.py` | ~1024 | Cloud security (AWS/Azure/GCP) |
| `scanners/asm_scanner.py` | ~733 | Attack surface management |
| `utilities/executive_dashboard.py` | ~534 | Executive dashboard (terminal + HTML) |

---

## Migration Notes from v6.0

### Configuration

v7.0 adds new sections to `config/active/config.yaml`. Existing v6.0 configurations are fully compatible. New sections default to safe values:

- AI defaults to `template` provider (no external calls)
- Cloud scanning auto-disables in portable mode
- Container scanning requires explicit confirmation
- ASM defaults to passive-only (no active enumeration)
- CI/CD security gate defaults: fail on any critical, max 5 high

### Database

v7.0 adds the `risk_quantification` table to the existing `evidence.db`. The table is created automatically on first use. No manual migration required.

### Dependencies

v7.0 has no new required dependencies. All new modules use Python standard library. Optional dependencies for enhanced functionality:

| Package | Purpose | Required? |
|---------|---------|-----------|
| `boto3` | AWS cloud scanning via SDK | No (CLI fallback) |
| `azure-identity` | Azure cloud scanning via SDK | No (CLI fallback) |
| `google-cloud-*` | GCP cloud scanning via SDK | No (CLI fallback) |
| `trivy` | Container/SBOM vulnerability scanning | No (feature skipped) |
| `grype` | SBOM vulnerability scanning | No (feature skipped) |
| `amass` | Active subdomain enumeration | No (DNS fallback) |
| `subfinder` | Active subdomain enumeration | No (DNS fallback) |
| Ollama | Local LLM for AI analysis | No (template fallback) |

---

## Competitive Comparison

| Capability | Tenable.io | Qualys | RiskLens | Drata | Purple Team v7.0 |
|-----------|------------|--------|----------|-------|-------------------|
| Vulnerability Scanning | Yes | Yes | No | No | Yes (Nuclei + Nmap + Nikto + OpenVAS) |
| FAIR Risk Quantification | No | No | Yes ($50K+/yr) | No | **Yes (open-source)** |
| AI-Powered Analysis | Limited | Limited | No | No | **Yes (3 backends)** |
| Container Security | Yes (add-on) | Yes (add-on) | No | No | **Yes (Docker + Podman + Trivy)** |
| Cloud Security (CSPM) | Yes (add-on) | Yes (add-on) | No | Yes | **Yes (AWS + Azure + GCP)** |
| Attack Surface Management | Yes (add-on) | Yes (add-on) | No | No | **Yes (CT logs + DNS + Shodan)** |
| SBOM Generation | No | No | No | No | **Yes (CycloneDX + SPDX)** |
| CI/CD Integration | Limited | Limited | No | Yes | **Yes (GitHub/GitLab/Jenkins + SARIF)** |
| Executive Dashboard | Yes | Yes | Yes | Yes | **Yes (terminal + HTML)** |
| USB Portable Mode | No | No | No | No | **Yes** |
| Windows Support | Agent | Agent | Cloud | Cloud | **Yes (native + WSL)** |
| Compliance Frameworks | ~5 | ~5 | 0 | ~10 | **10+ frameworks** |
| Evidence Chain of Custody | No | No | No | Yes | **Yes (SHA-256 hashed)** |
| Human Behavior Simulation | No | No | No | No | **Yes (stealth profiles)** |
| Open Source | No | No | No | No | **Yes** |
| Annual Cost | $20K-100K+ | $15K-80K+ | $50K-150K+ | $10K-50K+ | **$0** |

---

## Verification

After installation, verify v7.0 features:

```bash
# Self-test individual modules
python3 lib/risk_quantification.py
python3 lib/ai_analyzer.py
python3 lib/sbom_generator.py
python3 lib/cicd_integration.py
python3 scanners/container_scanner.py
python3 scanners/cloud_scanner.py
python3 scanners/asm_scanner.py
python3 utilities/executive_dashboard.py

# Check tool discovery
python3 bin/purple-launcher tools

# Run quick scan
python3 bin/purple-launcher quick

# Show dashboard
python3 bin/purple-launcher dashboard

# Run risk quantification
python3 bin/purple-launcher risk
```

---

Purple Team Platform v7.0
February 2026
