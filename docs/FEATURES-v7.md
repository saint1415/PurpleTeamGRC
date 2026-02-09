# Purple Team Platform v7.0 - Feature Guide

Detailed guide to all v7.0 features with setup instructions, usage examples, and expected output.

---

## Table of Contents

1. [FAIR Risk Quantification](#1-fair-risk-quantification)
2. [AI-Powered Analysis](#2-ai-powered-analysis)
3. [SBOM Generation](#3-sbom-generation)
4. [CI/CD Integration](#4-cicd-integration)
5. [Container Security](#5-container-security)
6. [Cloud Security](#6-cloud-security)
7. [Attack Surface Management](#7-attack-surface-management)
8. [Executive Dashboard](#8-executive-dashboard)

---

## 1. FAIR Risk Quantification

**v7.0 New** | File: `lib/risk_quantification.py`

### Overview

Translates security findings into dollar-quantified risk using the Factor Analysis of Information Risk (FAIR) taxonomy. This enables presenting risk in financial terms that executives and board members understand, replacing commercial tools like RiskLens ($50K+/year).

The FAIR decomposition:

```
Risk = Loss Event Frequency (LEF) x Loss Magnitude (LM)
LEF  = Threat Event Frequency (TEF) x Vulnerability
TEF  = Contact Frequency (CF) x Probability of Action (PA)
```

Platform data is mapped to FAIR inputs:
- EPSS score -> Probability of Action
- KEV status -> Contact Frequency boost (12-52 events/year vs 1-4)
- CVSS score -> Resistance Strength (inverted: high CVSS = low resistance)
- Asset context (value, criticality, records) -> Loss Magnitude

### Setup

1. Set your organization's business context via the interactive menu or programmatically:

```python
from lib.risk_quantification import get_risk_quantifier

rq = get_risk_quantifier()
rq.set_business_context(
    industry='healthcare',        # Sets breach cost benchmarks
    revenue=50_000_000,           # Annual revenue (caps loss at 10%)
    record_count=100_000,         # PII / sensitive records held
    asset_values={                # Per-asset dollar values
        '10.0.0.5': 500_000,
        '10.0.0.10': 1_000_000,
    },
    business_criticality={        # Per-asset criticality
        '10.0.0.5': 'critical',
        '10.0.0.10': 'high',
    }
)
```

2. Update `config/active/config.yaml`:

```yaml
risk:
  industry: healthcare
  monte_carlo_iterations: 10000
```

### Usage

**Interactive menu:** Compliance & Reports > Risk Quantification (option `r`)

**CLI:** `python3 bin/purple-launcher risk`

**Programmatic:**

```python
rq = get_risk_quantifier()
rq.set_business_context(industry='technology', revenue=50_000_000)

# Quantify a single finding
result = rq.quantify_finding({
    'severity': 'CRITICAL',
    'cvss_score': 9.8,
    'epss_score': 0.85,
    'kev_status': 'true',
    'title': 'Remote Code Execution',
    'affected_asset': '10.0.0.1',
})

# Quantify entire organization
org_risk = rq.quantify_organization()

# Get top risks
top = rq.get_top_risks(n=10)
```

### Example Output

```
FAIR Risk Quantification

Finding: Remote Code Execution (CVE-2024-1234)
  ALE 10th percentile: $142,500
  ALE 50th percentile: $485,000
  ALE 90th percentile: $1,230,000
  Single Loss (median): $750,000
  Annual Frequency: 0.65
  Data Quality: 85%

  FAIR Parameters:
    CVSS:     9.8
    EPSS/PA:  0.85
    KEV:      True
    Industry: healthcare
    TEF:      (7.14, 25.5, 54.12)
    Vuln:     (0.83, 0.98, 1.0)
    LM:       ($585K, $1.95M, $4.88M)
```

### Data Quality Score

Each quantification includes a data quality score (0-100%) indicating confidence:

| Component | Points | How to Improve |
|-----------|--------|----------------|
| Real EPSS score present | +20 | Run threat intel enrichment |
| KEV status checked | +15 | Run threat intel enrichment |
| Asset value configured | +25 | Set via `set_business_context()` |
| Record count known | +15 | Set via `set_business_context()` |
| Industry benchmarks set | +10 | Set `risk.industry` in config |
| Business criticality set | +15 | Set via `set_business_context()` |

Scores below 50% show a confidence warning: "ESTIMATE ONLY - configure asset context for accuracy".

---

## 2. AI-Powered Analysis

**v7.0 New** | File: `lib/ai_analyzer.py`

### Overview

Multi-backend AI engine that generates executive summaries, explains findings in plain English, suggests remediation, creates attack narratives, and prioritizes findings. Three backends ensure the feature works everywhere: from air-gapped USB deployments to cloud-connected workstations.

### Backends

| Backend | Network | Data Privacy | Quality | Setup |
|---------|---------|-------------|---------|-------|
| Template | None | Full (offline) | Good | None (always available) |
| Ollama | Localhost only | Full (stays local) | Very Good | Install Ollama + model |
| OpenAI | Internet | Sanitized | Excellent | API key required |

### Setup

**Template** (default, no setup needed):

The template backend uses a knowledge base of 14 vulnerability types with pre-written explanations and remediation steps. Works offline, instantly, on any platform.

**Ollama:**

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3

# Update config
# ai:
#   provider: ollama
#   model: llama3
```

**OpenAI-compatible API:**

```yaml
# config/active/config.yaml
ai:
  provider: openai
  model: gpt-4
  api_url: https://api.openai.com/v1
  sanitize_external: true
```

Store the API key via Settings > Manage Credentials, or the credential manager will attempt to retrieve it automatically.

### Data Sanitization

When `sanitize_external: true` (default for OpenAI), outbound data is sanitized:

| Data Type | Treatment | Example |
|-----------|-----------|---------|
| IP addresses | Last octet zeroed | `192.168.1.100` -> `192.168.1.0` |
| Hostnames (FQDN) | Replaced with placeholders | `web.corp.acme.com` -> `[HOST-1]` |
| Organization names | Replaced | `organization: ACME Corp` -> `[ORG]` |
| CVE IDs | Preserved (public data) | `CVE-2024-1234` -> `CVE-2024-1234` |
| CVSS scores | Preserved (public data) | `9.8` -> `9.8` |

### Usage

**Interactive menu:** Compliance & Reports > AI Analysis (option `a`)

**Programmatic:**

```python
from lib.ai_analyzer import AIAnalyzer

ai = AIAnalyzer(provider='template')

# Executive summary
summary = ai.generate_executive_summary(session_results)

# Explain a finding
explanation = ai.explain_finding(finding_dict)

# Suggest remediation
remediation = ai.suggest_remediation(finding_dict)

# Attack narrative from multiple findings
narrative = ai.generate_attack_narrative(findings_list)

# Prioritize findings
prioritized = ai.prioritize_findings(findings_list)
```

### Example Output (Template Backend)

```
EXECUTIVE SUMMARY - Security Assessment SESSION-20260209-143022
Date: 2026-02-09 14:45
============================================================

Overall Risk Posture: CRITICAL
  Immediate action required. Critical vulnerabilities were identified.

Assessment Statistics:
  Hosts Scanned:    12
  Total Findings:   23
  Critical:         1
  High:             4
  Medium:           8
  Low:              6
  Informational:    4

Compliance Rate: 72.5% (ADEQUATE)

Priority Actions:
  - Address 1 CRITICAL finding(s) within 24 hours
  - Remediate 4 HIGH finding(s) within 7 days
  - Plan remediation for 8 MEDIUM finding(s) within 30 days

Recommendation: Engage incident response for critical findings and
schedule emergency patching cycle.
```

All LLM-generated output (Ollama/OpenAI) includes the disclaimer: `--- AI-Generated - Verify Before Acting ---`

---

## 3. SBOM Generation

**v7.0 New** | File: `lib/sbom_generator.py`

### Overview

Generates Software Bill of Materials from package manifest files. Supports 10 package formats across 7 ecosystems. Exports in CycloneDX 1.4 and SPDX 2.3 JSON formats. Includes honest coverage indicators that explicitly state what was NOT analyzed.

### Supported Formats

| Ecosystem | Manifest File | Lock File (preferred) |
|-----------|--------------|----------------------|
| Python | `requirements.txt` | `Pipfile.lock` |
| Node.js | `package.json` | `package-lock.json` |
| Go | `go.mod` | - |
| Rust | `Cargo.toml` | `Cargo.lock` |
| Java | `pom.xml` | - |
| Ruby | - | `Gemfile.lock` |
| PHP | - | `composer.lock` |

When both a manifest and its lock file exist in the same directory, the lock file is used (more precise versions).

### Setup

No setup required. Optional: install trivy or grype for vulnerability checking against the SBOM.

```bash
# Optional vulnerability scanners
sudo apt install trivy
# or
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s
```

### Usage

```python
from lib.sbom_generator import get_sbom_generator

sg = get_sbom_generator()

# Scan a project directory
result = sg.scan_directory('/path/to/project', recursive=True)

print(f"Components found: {result['total_components']}")
print(f"Coverage: {sg.get_coverage_indicator(result)}")

# Export CycloneDX
sg.export_cyclonedx(result['components'], 'sbom_cyclonedx.json')

# Export SPDX
sg.export_spdx(result['components'], 'sbom_spdx.json')

# Check for vulnerabilities (requires trivy or grype)
vulns = sg.check_vulnerabilities(result['components'])
```

### Example Output

```
SBOM Generator initialized
Scanning: /home/user/webapp

Components found: 147
Package files found: 3
  /home/user/webapp/requirements.txt (42 components)
  /home/user/webapp/package-lock.json (98 components)
  /home/user/webapp/go.mod (7 components)

Coverage: Analyzed: Python (pip), Node.js (npm), Go (modules).
          NOT analyzed: system packages, C/C++ libraries, static
          binaries, vendored / copied source.

Warnings:
  - Skipping /home/user/webapp/package.json in favor of lock file package-lock.json
  - Using requirements.txt without lock file - versions may be imprecise

CycloneDX exported: data/reports/sbom_cyclonedx.json
SPDX exported: data/reports/sbom_spdx.json
```

---

## 4. CI/CD Integration

**v7.0 New** | File: `lib/cicd_integration.py`

### Overview

Generates pipeline configurations for GitHub Actions, GitLab CI, and Jenkins. Exports findings in SARIF v2.1.0 format for integration with GitHub Security tab. Evaluates configurable security gates to pass or fail builds.

### Setup

**Interactive:** Settings > CI/CD Integration (option `c`)

### GitHub Actions

Generated workflow (`.github/workflows/security-scan.yml`):

```yaml
name: Purple Team Security Scan
on: [push, pull_request]
permissions:
  security-events: write
  contents: read
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          python3 -m pip install --upgrade pip
          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
      - name: Run Security Scan (quick)
        run: python3 bin/purple-launcher quick
      - name: Export SARIF results
        if: always()
        run: # ... exports findings to SARIF
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: data/reports/results.sarif
      - name: Evaluate Security Gate (fail on critical)
        run: # ... evaluates gate, exits with code 0 or 1
```

### GitLab CI

Generated config (`.gitlab-ci.yml`) with SAST artifact reporting and security gate.

### Jenkins

Generated Jenkinsfile with declarative pipeline stages: Setup, Security Scan, Export Results, Security Gate.

### SARIF Export

SARIF (Static Analysis Results Interchange Format) v2.1.0 output is compatible with:
- GitHub Security tab (Code Scanning)
- GitLab SAST reporting
- Azure DevOps
- Any SARIF-compatible viewer

Severity mapping: CRITICAL/HIGH -> `error`, MEDIUM -> `warning`, LOW/INFO -> `note`.

### Security Gate

Default policy:
- Fail on any CRITICAL finding
- Fail if more than 5 HIGH findings
- No limit on MEDIUM/LOW/INFO

Custom policy example:

```python
gate = ci.evaluate_security_gate(findings, {
    'critical': 0,    # Zero tolerance for critical
    'high': 3,        # Max 3 high findings
    'medium': 10,     # Max 10 medium findings
    'low': -1,        # No limit (-1)
})
# Returns: {'passed': True/False, 'reason': '...', 'exit_code': 0/1, 'summary': {...}}
```

### Pre-commit Hook

Generate a git pre-commit hook:

```python
hook = ci.generate_pre_commit_hook()
# Install:
# cp hook .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

The hook runs a quick scan before each commit and blocks commits with critical findings.

---

## 5. Container Security

**v7.0 New** | File: `scanners/container_scanner.py`

### Overview

Docker and Podman container security assessment. Inspects running containers and local images for misconfigurations, then optionally runs Trivy for image vulnerability scanning. All operations are read-only. Requires explicit user confirmation before accessing the Docker socket.

### Setup

Install Docker or Podman:

```bash
# Docker
sudo apt install docker.io
sudo usermod -aG docker $USER

# Podman (rootless alternative)
sudo apt install podman

# Optional: Trivy for image vulnerability scanning
sudo apt install trivy
```

### Safety Measures

1. **Explicit confirmation required**: `user_confirmed=True` must be passed to proceed
2. **Read-only operations only**: inspect, ps, images, history (no exec, attach, pull, or modifications)
3. **Secret value protection**: environment variable values are never logged, only names
4. **Socket path warning**: users are informed which socket will be accessed

### Checks Performed

| Check | Severity | What it Detects |
|-------|----------|----------------|
| Privileged mode | CRITICAL | `--privileged` flag grants full host access |
| Host network | HIGH | `--network=host` exposes all host interfaces |
| Sensitive mounts | HIGH | Bind mounts to `/etc/shadow`, `/var/run/docker.sock`, etc. |
| Running as root | MEDIUM | Container user is root or unset |
| Secret in env vars | MEDIUM | Env vars named password, secret, key, token, etc. |
| Image age | MEDIUM | Images older than 180 days |
| Missing health check | LOW | No HEALTHCHECK defined |
| Exposed ports | INFO | Ports published to host |
| Excessive layers | INFO | Images with 40+ layers |
| Trivy vulnerabilities | Varies | CVE-based image vulnerabilities |

### Usage

```python
from scanners.container_scanner import ContainerScanner

scanner = ContainerScanner()
results = scanner.scan(
    scan_type='standard',
    user_confirmed=True    # Required acknowledgment
)
```

### Example Output

```
Container Scanner initialized
  Docker: True
  Podman: False
  Trivy:  True
  Runtime: docker
  Version: 24.0.7

Phase 3: Enumerating running containers
  Found 3 running containers
Phase 4: Enumerating local images
  Found 8 local images
Phase 5: Trivy image vulnerability scanning
  Scanning nginx:latest... 12 vulnerabilities
  Scanning postgres:15... 4 vulnerabilities

Summary:
  Containers scanned: 3
  Images scanned: 8
  Total findings: 24
    CRITICAL: 2  HIGH: 5  MEDIUM: 8  LOW: 4  INFO: 5
```

---

## 6. Cloud Security

**v7.0 New** | File: `scanners/cloud_scanner.py`

### Overview

Security configuration assessment for AWS, Azure, and GCP. Detects misconfigurations such as public storage buckets, missing MFA, open security groups, and disabled logging. All API calls are read-only.

### Setup

Install cloud SDK or CLI for each provider you want to scan:

**AWS:**
```bash
pip install boto3
# or
sudo apt install awscli
aws configure
```

**Azure:**
```bash
pip install azure-identity azure-mgmt-resource
# or
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
```

**GCP:**
```bash
pip install google-cloud-resource-manager
# or install gcloud CLI
gcloud auth application-default login
```

### IAM Requirements

The scanner warns: "Cloud credentials should use read-only IAM roles."

Recommended policies:

| Provider | Recommended Role |
|----------|-----------------|
| AWS | `SecurityAudit` managed policy |
| Azure | `Reader` + `Security Reader` roles |
| GCP | `roles/viewer` + `roles/iam.securityReviewer` |

### Checks by Provider

**AWS (6 checks):**

| Check | Severity | Description |
|-------|----------|-------------|
| S3 public buckets | CRITICAL | Public ACL grants on S3 buckets |
| S3 Block Public Access | MEDIUM | Block Public Access not fully enabled |
| IAM without MFA | HIGH | Users with no MFA device configured |
| Security groups 0.0.0.0/0 | HIGH | Ingress from any source |
| CloudTrail disabled | HIGH | Logging not active |
| Old access keys | MEDIUM | Active keys older than 90 days |
| Unencrypted EBS | MEDIUM | Volumes without encryption at rest |

**Azure (3 checks):**

| Check | Severity | Description |
|-------|----------|-------------|
| Storage public access | CRITICAL | allowBlobPublicAccess enabled |
| NSG any-source rules | HIGH | Inbound allow from * or 0.0.0.0/0 |
| SQL public access | HIGH | Public network access enabled |

**GCP (3 checks):**

| Check | Severity | Description |
|-------|----------|-------------|
| GCS public buckets | CRITICAL | allUsers/allAuthenticatedUsers bindings |
| Firewall 0.0.0.0/0 | HIGH | Ingress from 0.0.0.0/0 |
| Cloud SQL public IP | HIGH/MEDIUM | Public IP with open authorized networks |

### Portable Mode

Cloud scanning is automatically disabled in portable mode. The scanner returns:

```
Cloud scanning is disabled in portable mode.
Cloud credentials should not be stored on USB media.
```

### Usage

```python
from scanners.cloud_scanner import CloudScanner

scanner = CloudScanner()
print(f"AWS: {scanner.aws_available}")
print(f"Azure: {scanner.azure_available}")
print(f"GCP: {scanner.gcp_available}")

results = scanner.scan(targets=['aws', 'azure'])
```

---

## 7. Attack Surface Management

**v7.0 New** | File: `scanners/asm_scanner.py`

### Overview

External attack surface discovery and monitoring. Discovers subdomains, certificates, and external exposure through passive techniques by default. Active enumeration requires explicit opt-in to avoid triggering security alerts on target infrastructure.

### Passive vs Active

| Mode | Techniques | Risk | Default |
|------|-----------|------|---------|
| Passive | CT log queries, DNS lookups, HTTPS probes | None (public data only) | Yes |
| Active | amass, subfinder, DNS brute-force | May trigger IDS/WAF alerts | No (opt-in) |

### Setup

No setup required for passive scanning. For enhanced active scanning:

```bash
# Optional tools
sudo apt install amass
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Optional: Shodan API key
# Store via Settings > Manage Credentials
```

### Passive Checks

1. **Certificate Transparency (CT) logs**: Queries crt.sh API for all certificates issued for the domain. Rate limited to 2 seconds between requests.
   - Expired certificates (MEDIUM)
   - Wildcard certificates (INFO)
   - Subdomain discovery from certificate SANs

2. **DNS enumeration**: Resolves 13 common subdomain prefixes (www, mail, smtp, ftp, vpn, remote, admin, dev, staging, api, app, portal, test).
   - HTTPS availability check on each subdomain (MEDIUM if no port 443)

3. **DNS zone transfer**: Attempts AXFR via dig or host command.
   - Successful zone transfer (HIGH)

4. **Shodan lookup** (if API key configured): Queries Shodan for external exposure.
   - Unexpected services exposed externally (HIGH)

### Active Checks (opt-in)

When `active=True`:

1. **amass** passive enumeration (if installed)
2. **subfinder** enumeration (if installed)
3. Extended DNS brute-force (60+ subdomain prefixes) as fallback

### Usage

```python
from scanners.asm_scanner import ASMScanner

scanner = ASMScanner()

# Passive scan (safe, default)
results = scanner.scan(
    targets=['example.com'],
    scan_type='standard',
    active=False
)

# Active scan (opt-in, may trigger alerts)
results = scanner.scan(
    targets=['example.com'],
    scan_type='deep',
    active=True
)
```

### Example Output

```
ASM Scanner initialized
  amass: True
  subfinder: True
  dig: True

Starting ASM scan (type=standard, active=False)
Checking Certificate Transparency for example.com
  CT log results: 45 certificates, 45 unique
Enumerating DNS for example.com
  DNS enumeration: 8 hosts resolved
  Zone transfer test: not vulnerable

Summary:
  Total domains: 1
  Total subdomains: 12
  Total certificates: 45
  Findings: 3
    MEDIUM: 2 (expired certs, no HTTPS)
    INFO: 1 (wildcard cert)
```

---

## 8. Executive Dashboard

**v7.0 New** | File: `utilities/executive_dashboard.py`

### Overview

Security posture dashboard with both terminal (ANSI) and HTML export views. Displays risk score, finding severity breakdown, compliance meters, trend indicators, and top risks.

### Setup

No setup required. Data is read from the evidence database.

### Usage

**Interactive menu:** Main Menu > Dashboard (option `d`)

**CLI:** `python3 bin/purple-launcher dashboard`

**Programmatic:**

```python
from utilities.executive_dashboard import ExecutiveDashboard

dashboard = ExecutiveDashboard()

# Terminal display
dashboard.display_terminal_dashboard()

# HTML export
output_path = dashboard.export_html_dashboard()
print(f"Dashboard saved: {output_path}")

# Specific session
dashboard.display_terminal_dashboard(session_id='SESSION-20260209-143022')
```

### Risk Score Calculation

```
Score = CRITICAL * 10 + HIGH * 7 + MEDIUM * 4 + LOW * 1
Capped at 100
```

| Score Range | Color | Interpretation |
|-------------|-------|---------------|
| 0-39 | Green | Low risk |
| 40-69 | Yellow | Moderate risk |
| 70-100 | Red | High/critical risk |

### Trend Detection

Compares the last N sessions (default 5):
- Splits sessions into newer half and older half
- Compares average finding counts
- **Improving**: newer average < older average * 0.9
- **Worsening**: newer average > older average * 1.1
- **Stable**: within 10% of each other

### HTML Dashboard

The HTML export produces a self-contained static HTML file with:
- Professional CSS styling (no external dependencies)
- Responsive layout (works on desktop and mobile)
- Gradient header with session info
- Interactive-looking gauges and meters (pure CSS)
- Severity card grid
- Compliance meter bars
- Top findings table

Output location: `data/reports/dashboard_YYYYMMDD_HHMMSS.html`

### Example HTML Output

The HTML dashboard includes:
- Risk score gauge with color-coded fill
- Trend badge (improving/worsening/stable)
- Five severity cards with counts
- Three key metrics (total findings, tracked assets, open ports)
- Compliance status bars per framework
- Top critical/high findings table with severity badges
- Footer with generation timestamp

---

Purple Team Platform v7.0
February 2026
