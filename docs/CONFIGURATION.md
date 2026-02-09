# Purple Team Platform v7.0 - Configuration Reference

Complete reference for `config/active/config.yaml`.

---

## File Location

```
<platform-root>/config/active/config.yaml
```

The configuration file is loaded by `lib/config.py` at startup. Changes take effect on next launch.

---

## Platform

```yaml
version: '7.0.0'

platform:
  name: Purple Team Platform
  mode: auto          # auto-detect: portable, installed, cicd
  auto_detect_networks: true   # Auto-discover RFC1918 ranges on active interfaces
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `version` | string | `7.0.0` | Platform version identifier |
| `platform.mode` | string | `auto` | Deployment mode. `auto` uses detection logic. |
| `platform.auto_detect_networks` | bool | `true` | Enable automatic network range discovery |

---

## Scanning

```yaml
scanning:
  stealth_level: 3             # 1-5 (higher = stealthier, slower)
  delay_min_seconds: 30        # Minimum random delay between scan phases
  delay_max_seconds: 300       # Maximum random delay between scan phases
  concurrent_scans: 1          # Number of parallel scan threads
  timeout_minutes: 120         # Maximum scan duration before timeout
  excluded_hosts: []           # List of IPs or CIDRs to never scan
  excluded_ports: []           # List of ports to skip
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `stealth_level` | int | `3` | 1=aggressive, 5=maximum stealth. Controls timing profiles. |
| `delay_min_seconds` | int | `30` | Minimum inter-phase delay for human-like behavior |
| `delay_max_seconds` | int | `300` | Maximum inter-phase delay |
| `concurrent_scans` | int | `1` | Parallel scan threads. Increase for large networks. |
| `timeout_minutes` | int | `120` | Hard timeout for entire scan session |
| `excluded_hosts` | list | `[]` | IPs/CIDRs excluded from all scans |
| `excluded_ports` | list | `[]` | Ports excluded from port scanning |

---

## Scheduling

```yaml
scheduling:
  enabled: false
  window_start: '18:00'       # Start of scan window (24h format)
  window_end: '20:00'         # End of scan window
  randomize_start: true       # Randomize start time within window
  frequency: monthly           # monthly, weekly, daily
  day_of_month: 1             # Day for monthly scans (1-28)
  run_until_complete: true    # Continue past window end if scan in progress
```

---

## Retention

```yaml
retention:
  days: 365                   # Evidence and results retention period
  compress_after_days: 30     # Compress results older than this
  archive_format: tar.gz      # Compression format
  auto_cleanup: true          # Automatically remove expired data
```

---

## Evidence Collection

```yaml
evidence:
  collect_screenshots: false   # Capture screenshots during scanning
  hash_algorithm: sha256       # Hash for evidence integrity (sha256, sha512)
  include_raw_output: true     # Store raw tool output in evidence
  timestamp_format: '%Y-%m-%d %H:%M:%S UTC'
```

---

## Compliance

```yaml
compliance:
  frameworks:
    - NIST-800-53
    - HIPAA
    - SOC1-Type2
    - SOC2-Type2
    - PCI-DSS-v4
    - ISO27001-2022
    - CMMC
    - FedRAMP
    - GDPR
    - SOX
  auto_map_findings: true       # Auto-map findings to compliance controls
  generate_attestations: true   # Create attestation records
  include_remediation: true     # Include remediation guidance in reports
```

Available frameworks: `NIST-800-53`, `HIPAA`, `SOC1-Type2`, `SOC2-Type2`, `PCI-DSS-v4`, `ISO27001-2022`, `CMMC`, `FedRAMP`, `GDPR`, `SOX`.

---

## Reporting

```yaml
reporting:
  formats:
    - json
    - html
    - csv
    - pdf
    - sarif                    # v7.0: SARIF 2.1.0 for CI/CD integration
  executive_summary: true
  technical_details: true
  include_evidence_refs: true
```

---

## Export

```yaml
export:
  oscal: true                  # OSCAL JSON for federal/NIST compliance
  scap: false                  # SCAP format
  csv_grc: true                # CSV for GRC platform import
  json_api: true               # API-compatible JSON
  sarif: true                  # v7.0: SARIF export enabled
```

---

## Network

```yaml
network:
  auto_detect: true            # Auto-discover networks from active interfaces
  scan_ranges: []              # Manual network ranges (e.g., ['192.168.1.0/24'])
  exclude_ranges:
    - 127.0.0.0/8              # Loopback always excluded
  dns_resolution: true         # Resolve hostnames during scanning
```

---

## Tools

```yaml
tools:
  nmap:
    enabled: true
    extra_args: ''             # Additional nmap arguments
  nikto:
    enabled: true
    extra_args: ''             # Additional nikto arguments
  nuclei:
    enabled: true
    extra_args: ''
    templates: default         # Template set: default, all, or path
  testssl:
    enabled: true
    extra_args: ''
```

---

## v7.0: AI Analysis

```yaml
ai:
  provider: template           # template, ollama, openai
  model: ''                    # Model name (e.g., llama3, gpt-4)
  api_url: ''                  # API endpoint URL
  sanitize_external: true      # Strip IPs/hostnames before sending to external LLMs
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ai.provider` | string | `template` | AI backend. `template` = offline rule-based (always works). `ollama` = local LLM. `openai` = OpenAI-compatible API. |
| `ai.model` | string | `''` | Model name. Ollama: `llama3`, `mistral`, etc. OpenAI: `gpt-4`, `gpt-3.5-turbo`, etc. Ignored for template. |
| `ai.api_url` | string | `''` | API base URL. Ollama default: `http://localhost:11434`. OpenAI default: `https://api.openai.com/v1`. |
| `ai.sanitize_external` | bool | `true` | Sanitize data before sending to OpenAI. Masks IPs (last octet zeroed), replaces hostnames with `[HOST-N]`, replaces org names with `[ORG]`. CVE IDs and CVSS scores preserved. |

**Provider comparison:**

| Feature | Template | Ollama | OpenAI |
|---------|----------|--------|--------|
| Network required | No | No (localhost) | Yes |
| Data leaves system | No | No | Yes (sanitized if enabled) |
| Quality | Good (rule-based) | Very good | Excellent |
| Speed | Instant | 5-30 seconds | 2-10 seconds |
| Portable mode | Yes | Forced | Forced to template |
| Cost | Free | Free | Per-token billing |

---

## v7.0: Risk Quantification (FAIR)

```yaml
risk:
  industry: default            # Industry for breach cost benchmarks
  benchmark_year: 2025         # Benchmark data year
  monte_carlo_iterations: 10000  # Simulation iterations per finding
  custom_benchmarks: {}        # Custom benchmark overrides
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `risk.industry` | string | `default` | Industry for loss magnitude estimation. Options: `healthcare`, `financial`, `technology`, `government`, `education`, `retail`, `manufacturing`, `energy`, `default`. |
| `risk.benchmark_year` | int | `2025` | Year of industry benchmark data (IBM/Ponemon) |
| `risk.monte_carlo_iterations` | int | `10000` | Number of Monte Carlo simulation iterations. Higher = more precise, slower. |
| `risk.custom_benchmarks` | dict | `{}` | Custom industry benchmarks: `{avg_breach_cost: 5000000, cost_per_record: 170}` |

**Industry benchmarks (2025):**

| Industry | Avg Breach Cost | Cost Per Record |
|----------|----------------|-----------------|
| healthcare | $10,930,000 | $164 |
| financial | $5,900,000 | $181 |
| technology | $4,970,000 | $175 |
| government | $2,580,000 | $153 |
| education | $3,650,000 | $155 |
| retail | $3,280,000 | $142 |
| manufacturing | $4,730,000 | $165 |
| energy | $4,780,000 | $170 |
| default | $4,450,000 | $158 |

---

## v7.0: Container Security

```yaml
container:
  enabled: true
  runtime: auto                # auto, docker, podman
  trivy_enabled: true          # Use trivy for image vulnerability scanning
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `container.enabled` | bool | `true` | Enable container security scanning |
| `container.runtime` | string | `auto` | Container runtime. `auto` detects Docker then Podman. |
| `container.trivy_enabled` | bool | `true` | Use trivy for image vulnerability scanning if installed |

---

## v7.0: Cloud Security

```yaml
cloud:
  enabled: true                # Disabled automatically in portable mode
  aws:
    enabled: true
    read_only: true            # Only read-only API calls
  azure:
    enabled: true
    read_only: true
  gcp:
    enabled: true
    read_only: true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cloud.enabled` | bool | `true` | Master switch for cloud scanning. Auto-disabled in portable mode. |
| `cloud.aws.enabled` | bool | `true` | Enable AWS security checks |
| `cloud.aws.read_only` | bool | `true` | Enforce read-only API calls only |
| `cloud.azure.enabled` | bool | `true` | Enable Azure security checks |
| `cloud.gcp.enabled` | bool | `true` | Enable GCP security checks |

---

## v7.0: Attack Surface Management

```yaml
asm:
  active_enumeration: false    # Passive-first, active requires opt-in
  ct_logs: true                # Query Certificate Transparency logs (crt.sh)
  dns_brute: false             # DNS brute-force enumeration
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `asm.active_enumeration` | bool | `false` | Enable active subdomain enumeration (amass, subfinder). May trigger security alerts on target infrastructure. |
| `asm.ct_logs` | bool | `true` | Query CT logs for certificate discovery |
| `asm.dns_brute` | bool | `false` | Extended DNS brute-force with 60+ subdomain prefixes |

---

## v7.0: SBOM Generation

```yaml
sbom:
  enabled: true
  formats:
    - cyclonedx                # CycloneDX 1.4 JSON
    - spdx                     # SPDX 2.3 JSON
```

---

## v7.0: CI/CD Integration

```yaml
cicd:
  security_gate:
    fail_on_critical: true     # Fail build on any CRITICAL finding
    max_high: 5                # Maximum HIGH findings before build fails
    max_medium: 20             # Maximum MEDIUM findings (-1 = no limit)
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cicd.security_gate.fail_on_critical` | bool | `true` | Fail pipeline on any CRITICAL finding |
| `cicd.security_gate.max_high` | int | `5` | Maximum allowed HIGH findings |
| `cicd.security_gate.max_medium` | int | `20` | Maximum allowed MEDIUM findings. Set to -1 for no limit. |

---

## Notifications

```yaml
notifications:
  enabled: false
  email:
    enabled: false
    smtp_server: ''
    smtp_port: 587
    use_tls: true
    recipients: []
  slack:
    enabled: false
    webhook_url: ''            # Slack incoming webhook URL
  teams:
    enabled: false
    webhook_url: ''            # Microsoft Teams incoming webhook URL
  on_critical: true            # Notify on CRITICAL findings
  on_complete: true            # Notify on scan completion
```

---

## Integrations

```yaml
integrations:
  thehive:
    enabled: false
    url: ''                    # TheHive instance URL
    api_key: ''
  wazuh:
    enabled: false
    url: ''                    # Wazuh manager URL
    api_key: ''
  siem:
    enabled: false
    type: ''                   # SIEM type (splunk, elastic, etc.)
    endpoint: ''
  jira:
    enabled: false
    url: ''                    # Jira instance URL (e.g., https://yourorg.atlassian.net)
    project_key: ''            # Jira project key for ticket creation
    email: ''                  # Jira account email
  servicenow:
    enabled: false
    instance_url: ''           # ServiceNow instance URL
  shodan:
    enabled: false             # Shodan API integration for ASM
  censys:
    enabled: false             # Censys API integration
```

---

## Example: Healthcare Organization

```yaml
version: '7.0.0'

platform:
  mode: auto
  auto_detect_networks: true

scanning:
  stealth_level: 4
  concurrent_scans: 1
  excluded_hosts:
    - 10.0.0.1                 # Core switch
    - 10.0.1.0/24              # Medical devices subnet

compliance:
  frameworks:
    - HIPAA
    - NIST-800-53
    - SOC2-Type2

ai:
  provider: template

risk:
  industry: healthcare

container:
  enabled: true

cloud:
  enabled: true
  aws:
    enabled: true
```

## Example: CI/CD Pipeline

```yaml
version: '7.0.0'

platform:
  mode: auto

scanning:
  stealth_level: 1
  timeout_minutes: 30

reporting:
  formats:
    - sarif
    - json

cicd:
  security_gate:
    fail_on_critical: true
    max_high: 0
    max_medium: 10
```

---

Purple Team Platform v7.0
February 2026
