# Purple Team Platform v7.0 - CLI Reference

Complete reference for command-line usage of `bin/purple-launcher`.

---

## Usage

```
python3 bin/purple-launcher [command]
```

On Windows:

```
python bin\purple-launcher [command]
```

When invoked without a command, the platform starts in interactive menu mode.

---

## Commands

### (no command) - Interactive Mode

```bash
python3 bin/purple-launcher
```

Launches the full interactive terminal menu with access to all platform features including Red Team, Blue Team, Purple Team operations, compliance reporting, settings, and the executive dashboard.

### quick - Quick Security Scan

```bash
python3 bin/purple-launcher quick
```

Runs a fast security posture check. Duration: 15-30 minutes.

Phases: network discovery, service enumeration, vulnerability scanning, SSL/TLS checks, compliance mapping.

### standard - Standard Assessment

```bash
python3 bin/purple-launcher standard
```

Runs a comprehensive security assessment. Duration: 1-2 hours.

Includes all quick scan phases plus: web application scanning, credentialed scanning (if credentials configured), container scanning (if Docker/Podman available), cloud scanning (if installed mode with credentials), and FAIR risk quantification.

Prompts for confirmation before starting.

### deep - Deep Assessment

```bash
python3 bin/purple-launcher deep
```

Runs a full security audit with detailed evidence collection. Duration: 2-4 hours.

Includes all standard assessment phases plus: extended vulnerability checks, full compliance mapping across all configured frameworks, evidence chain documentation.

Prompts for confirmation before starting. Default confirmation is "No" (requires explicit opt-in).

### tools - Tool Inventory

```bash
python3 bin/purple-launcher tools
```

Displays the status of all security tools the platform can use. Shows which tools are installed, their versions, and which are missing.

Detected tools include: nmap, nikto, nuclei, testssl.sh, trivy, Docker, Podman, and others.

### dashboard - Executive Dashboard

```bash
python3 bin/purple-launcher dashboard
```

Displays the executive security dashboard in the terminal. Shows:

- Risk score (0-100) calculated as: CRITICAL*10 + HIGH*7 + MEDIUM*4 + LOW*1, capped at 100
- Findings count by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Compliance rates per configured framework
- Top critical and high findings
- Security trend indicator (improving, stable, worsening)

After display, offers to export as an HTML file.

### risk - FAIR Risk Quantification

```bash
python3 bin/purple-launcher risk
```

Runs the FAIR (Factor Analysis of Information Risk) risk quantification engine. Prompts for industry context (healthcare, financial, technology, government, education, retail, manufacturing, energy, or default).

Outputs:
- Total Annualized Loss Expectancy (ALE) at 10th, 50th, and 90th percentiles
- Data quality score
- Top 5 risks ranked by ALE
- Option to generate an HTML risk report

### delta - Delta Report

```bash
python3 bin/purple-launcher delta
```

Compares two scan sessions side-by-side. Lists recent sessions and prompts for baseline (older) and compare (newer) session IDs.

Outputs:
- New findings (present in newer session only)
- Resolved findings (present in older session only)
- Persistent findings (present in both)
- Severity changes

Offers to generate an HTML delta report.

### help - Show Help

```bash
python3 bin/purple-launcher help
```

Displays help text with quick start instructions, key concepts, v7.0 feature list, file locations, and documentation references.

Also available with flags:

```bash
python3 bin/purple-launcher --help
python3 bin/purple-launcher -h
```

---

## Interactive Menu Structure

When running in interactive mode, the menus are organized as follows:

```
Main Menu
  1. Red Team - Attack Simulation
       1. Network Reconnaissance
       2. Vulnerability Scanning
       3. Web Application Testing
       4. Password Auditing
       5. Exploit Validation
       6. ATT&CK Simulation
       7. Phishing Simulation
       8. Social Engineering
       9. OpenVAS Integration
            1. Run OpenVAS Scan
            2. Import OpenVAS Report
            3. Sync Findings
            4. Configure Connection
  2. Blue Team - Detection & Defense
       1. Security Hardening Audit
       2. Malware Detection
       3. Log Analysis
       4. File Integrity Check
       5. Network Traffic Analysis
       6. Detection Rule Testing
       7. Incident Response Drill
       8. Threat Hunting
  3. Purple Team - Integrated Assessment
       1. Detection Gap Analysis
       2. Control Effectiveness
       3. Attack Path Mapping
       4. Coverage Assessment
       5. Full Purple Assessment
       6. Continuous Validation
  4. Quick Scan
  5. Standard Assessment
  6. Deep Assessment
  7. Compliance & Reports
       1. Generate Audit Report
       2. NIST 800-53 Report
       3. HIPAA Report
       4. PCI-DSS Report
       5. SOC 2 Report
       6. ISO 27001 Report
       7. Export for GRC Platform
       8. View Past Reports
       9. Delta Report
       t. Trend Analysis
       r. Risk Quantification (v7.0)
       a. AI Analysis (v7.0)
  8. Schedule Scans
  9. Tool Status
  d. Dashboard (v7.0)
  s. Settings
       1. Scan Timing
       2. Behavior Profile
            1. Stealth
            2. Normal (Recommended)
            3. Fast
            4. Aggressive
       3. Compliance Frameworks
       4. Network Targets
       5. Notifications
       6. View Full Config
       7. Reset to Defaults
       8. Manage Overrides
       9. Manage Credentials
       c. CI/CD Integration (v7.0)
            1. Generate GitHub Actions
            2. Generate GitLab CI
            3. Generate Jenkins Pipeline
            4. Export SARIF
  h. Help
  q. Quit
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, or CI/CD security gate passed |
| 1 | CI/CD security gate failed (critical findings exceeded threshold) |

In CI/CD mode (detected via environment variables), the exit code reflects the security gate evaluation. In interactive mode, the exit code is always 0 on normal exit.

The security gate thresholds are configured in `config/active/config.yaml`:

```yaml
cicd:
  security_gate:
    fail_on_critical: true    # Exit 1 on any CRITICAL finding
    max_high: 5               # Exit 1 if HIGH findings exceed this
    max_medium: 20            # Exit 1 if MEDIUM findings exceed this (-1 = no limit)
```

---

## Environment Variables

| Variable | Effect |
|----------|--------|
| `PURPLE_TEAM_HOME` | Set automatically by the launcher to the platform root directory. Used by all modules to resolve paths. |
| `CI` | If set, forces CI/CD deployment mode (headless, SARIF output, exit codes). |
| `GITHUB_ACTIONS` | Triggers CI/CD mode (set automatically by GitHub Actions). |
| `GITLAB_CI` | Triggers CI/CD mode (set automatically by GitLab CI). |
| `JENKINS_URL` | Triggers CI/CD mode (set automatically by Jenkins). |
| `CIRCLECI` | Triggers CI/CD mode (set automatically by CircleCI). |
| `TRAVIS` | Triggers CI/CD mode (set automatically by Travis CI). |
| `BITBUCKET_PIPELINE` | Triggers CI/CD mode (set automatically by Bitbucket Pipelines). |
| `TF_BUILD` | Triggers CI/CD mode (set automatically by Azure DevOps). |
| `CODEBUILD_BUILD_ID` | Triggers CI/CD mode (set automatically by AWS CodeBuild). |
| `BUILDKITE` | Triggers CI/CD mode (set automatically by Buildkite). |

---

## Behavior Profiles

The platform supports four behavior profiles that control scan timing and stealth:

| Profile | Description | Use Case |
|---------|-------------|----------|
| `stealth` | Very slow, maximum evasion, large random delays | Testing detection capabilities |
| `normal` | Balanced speed and stealth (default) | Standard authorized assessments |
| `fast` | Quick execution, minimal delays | Lab environments |
| `aggressive` | Minimal delays, speed priority | Isolated test networks |

Set via the interactive menu (Settings > Behavior Profile) or via the `stealth_level` config key (1=aggressive, 2=fast, 3=normal, 4-5=stealth).

---

## File Locations

| Path | Content |
|------|---------|
| `bin/purple-launcher` | Main launcher script |
| `config/active/config.yaml` | Active configuration |
| `data/results/` | Raw scan results |
| `data/reports/` | Generated reports (HTML, JSON, CSV, PDF, SARIF) |
| `data/evidence/evidence.db` | SQLite evidence database |
| `data/logs/` | Platform log files |
| `lib/` | Core library modules |
| `scanners/` | Scanner modules |
| `utilities/` | Orchestrator, reporter, dashboard |

---

## Examples

```bash
# Interactive mode
python3 bin/purple-launcher

# Quick scan from USB drive on Linux
cd /run/media/$USER/PURPLETEAMG/purple-final/
python3 bin/purple-launcher quick

# Show tools on Windows
python bin\purple-launcher tools

# Run in CI/CD mode
export CI=true
python3 bin/purple-launcher quick

# Executive dashboard
python3 bin/purple-launcher dashboard

# FAIR risk quantification
python3 bin/purple-launcher risk

# Compare two scan sessions
python3 bin/purple-launcher delta
```

---

Purple Team Platform v7.0
February 2026
