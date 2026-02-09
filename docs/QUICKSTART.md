# Purple Team Platform v7.0 - Quick Start Guide

Get scanning in 5 minutes on any platform.

---

## Prerequisites

### Linux (Kali, Ubuntu, Debian)

```bash
# Required
python3 --version   # 3.10 or later required
pip3 --version      # pip for Python package management

# Recommended security tools (platform will prompt to install missing ones)
sudo apt install nmap nikto
```

### macOS

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Required
brew install python@3.11

# Recommended
brew install nmap nikto
```

### Windows 11

```
1. Install Python 3.11+ from https://python.org
   - Check "Add Python to PATH" during install
2. Install Nmap from https://nmap.org/download.html
   - Check "Register Nmap Path" during install
3. Open PowerShell or Command Prompt
```

---

## Step 1: Get the Platform

### Option A: USB Drive (Portable Mode)

Plug in the USB drive containing the platform. The platform auto-detects portable mode and adjusts features accordingly (cloud scanning and external AI are disabled).

```bash
# Linux
cd /run/media/$USER/PURPLETEAMG/purple-final/

# macOS
cd /Volumes/PURPLETEAMG/purple-final/

# Windows
cd E:\purple-final\
```

### Option B: Git Clone (Installed Mode)

```bash
git clone https://github.com/saint1415/PurpleTeamGRC.git
cd PurpleTeamGRC
```

---

## Step 2: Launch the Platform

```bash
# Interactive menu (recommended for first use)
python3 bin/purple-launcher

# Or run a quick scan directly
python3 bin/purple-launcher quick
```

On first launch the platform will:

1. Display the banner with platform detection (OS, architecture, deployment mode)
2. Discover available security tools (nmap, nikto, nuclei, testssl.sh, etc.)
3. Report which tools are available and which are missing
4. Offer to install missing tools (if on a supported package manager)

---

## Step 3: Run Your First Scan

### From the Interactive Menu

```
PURPLE TEAM PLATFORM v7.0
Systems Thinking Security Assessment | Linux x86_64

Main Menu:
  1. Red Team - Attack Simulation
  2. Blue Team - Detection & Defense
  3. Purple Team - Integrated Assessment
  ---
  4. Quick Scan           <-- Start here
  5. Standard Assessment
  6. Deep Assessment
  ---
  7. Compliance & Reports
  d. Dashboard
  s. Settings
  q. Quit
```

Select option `4` for a Quick Scan. The platform will:

1. Auto-detect network ranges (RFC1918 private ranges on active interfaces)
2. Run network discovery (host detection, port scanning)
3. Run vulnerability checks (CVE detection, service enumeration)
4. Run SSL/TLS analysis (certificate validation, cipher checks)
5. Run compliance mapping (findings mapped to 10+ frameworks)
6. Generate findings with threat intelligence enrichment (KEV + EPSS)
7. Store results in the evidence database

### From the Command Line

```bash
# Quick scan (15-30 minutes)
python3 bin/purple-launcher quick

# Standard assessment (1-2 hours)
python3 bin/purple-launcher standard

# Deep assessment (2-4 hours)
python3 bin/purple-launcher deep
```

---

## Step 4: View Results

### Executive Dashboard

```bash
python3 bin/purple-launcher dashboard
```

Displays a terminal dashboard with:
- Risk score gauge (0-100)
- Findings by severity
- Compliance status per framework
- Top critical/high findings
- Security trend indicator

### Generated Reports

Reports are saved in `data/reports/`:

```
data/reports/
  report_YYYYMMDD_HHMMSS.html   # HTML report with charts
  report_YYYYMMDD_HHMMSS.json   # Machine-readable JSON
  report_YYYYMMDD_HHMMSS.csv    # Spreadsheet-compatible CSV
```

### Evidence Database

All findings, evidence, and compliance mappings are stored in:

```
data/evidence/evidence.db        # SQLite database
```

---

## Step 5: Explore v7.0 Features

### Risk Quantification (FAIR)

```bash
python3 bin/purple-launcher risk
```

Translates findings into dollar amounts using the FAIR model. Set your industry for benchmarks:
- healthcare, financial, technology, government, education, retail, manufacturing, energy

### AI Analysis

From the Compliance & Reports menu, select `a` for AI Analysis. Choose a backend:
- Template (default): works offline, no LLM needed
- Ollama: local LLM, requires Ollama running
- OpenAI: external API with data sanitization

### Container Security

Requires Docker or Podman installed. Container scanning is available through the orchestrator during standard and deep assessments.

### Cloud Security

Requires AWS CLI, Azure CLI, or gcloud CLI configured. Cloud scanning auto-detects available providers. Disabled in portable mode.

---

## Common CLI Commands

| Command | Description | Duration |
|---------|-------------|----------|
| `purple-launcher` | Interactive menu | - |
| `purple-launcher quick` | Quick security scan | 15-30 min |
| `purple-launcher standard` | Standard assessment | 1-2 hours |
| `purple-launcher deep` | Deep audit with evidence | 2-4 hours |
| `purple-launcher tools` | Show tool inventory | Instant |
| `purple-launcher dashboard` | Executive dashboard | Instant |
| `purple-launcher risk` | FAIR risk quantification | 1-5 min |
| `purple-launcher delta` | Compare scan sessions | Instant |
| `purple-launcher help` | Show CLI help | Instant |

---

## Expected Output

### Quick Scan Output

```
PURPLE TEAM PLATFORM v7.0
Systems Thinking Security Assessment | Linux x86_64

[*] Checking Prerequisites
    nmap .............. OK (7.95)
    nikto ............. OK (2.5.0)
    nuclei ............ OK (3.2.1)
    testssl.sh ........ OK (3.2)
[+] All required tools are available

Quick Security Scan
[*] Running quick security posture check...
[*] Behavior profile: normal
[*] Auto-detected network: 192.168.1.0/24

[*] Phase 1: Network Discovery
    Discovered 12 hosts
[*] Phase 2: Service Enumeration
    Found 47 open ports
[*] Phase 3: Vulnerability Scanning
    Checked 12 hosts
[*] Phase 4: Compliance Mapping
    Mapped to 10 frameworks

[+] Scan complete! Session: SESSION-20260209-143022
[*] Total findings: 23
    CRITICAL: 1  HIGH: 4  MEDIUM: 8  LOW: 6  INFO: 4
```

### Dashboard Output

```
+--------------------------------------------------------+
| SECURITY DASHBOARD - Session: SESSION-20260209         |
+--------------------------------------------------------+
| RISK SCORE: [===============.....] 73/100              |
| Trend: WORSENING                                       |
+--------------------------------------------------------+
| CRITICAL: 1  HIGH: 4  MEDIUM: 8  LOW: 6               |
| Total findings: 23   Assets: 12                        |
+--------------------------------------------------------+
| COMPLIANCE                                             |
|   NIST-800-53    [========..] 80.0%                   |
|   HIPAA          [=======...] 72.5%                   |
|   PCI-DSS-v4     [======....] 65.0%                   |
+--------------------------------------------------------+
| TOP RISKS                                              |
|   1. [CRIT] SQL Injection in login     10.0.0.5       |
|   2. [HIGH] Weak TLS configuration     10.0.0.2       |
+--------------------------------------------------------+
```

---

## Next Steps

1. **Configure for your environment**: Edit `config/active/config.yaml` with your industry, network ranges, and compliance frameworks.
2. **Set up credentials**: From Settings > Manage Credentials, add SSH keys or passwords for authenticated scanning.
3. **Schedule assessments**: Configure automated monthly scans from the Settings menu.
4. **Generate reports**: From Compliance & Reports, generate framework-specific audit reports.
5. **Integrate CI/CD**: From Settings > CI/CD Integration, generate pipeline configs for GitHub Actions, GitLab CI, or Jenkins.

---

## Getting Help

```bash
# Built-in help
python3 bin/purple-launcher help

# Documentation
docs/CHANGELOG-v7.md        # v7.0 release notes
docs/FEATURES-v7.md         # Feature deep-dive
docs/CONFIGURATION.md       # Config reference
docs/TROUBLESHOOTING.md     # Problem solving
docs/CLI-REFERENCE.md       # Command reference
AUDITOR_GUIDE.md            # Guide for auditors
```

---

Purple Team Platform v7.0
February 2026
