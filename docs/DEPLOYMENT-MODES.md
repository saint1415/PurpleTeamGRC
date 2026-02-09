# Purple Team Platform v7.0 - Deployment Modes

The platform automatically detects its deployment context and adjusts available features. Three modes are supported: portable, installed, and CI/CD.

---

## Mode Detection Logic

Detection is handled by `lib/platform_detect.py` in the `deployment_mode` property. The checks run in this order:

### 1. CI/CD Mode (checked first)

The platform checks for any of these environment variables:

```
CI, GITHUB_ACTIONS, GITLAB_CI, JENKINS_URL, CIRCLECI, TRAVIS,
BITBUCKET_PIPELINE, TF_BUILD, CODEBUILD_BUILD_ID, BUILDKITE
```

If any variable is set (regardless of value), the platform enters CI/CD mode.

### 2. Portable Mode (checked second)

The platform resolves the absolute path of `lib/platform_detect.py` and checks if it contains any of these USB mount path indicators:

| OS | Indicators |
|----|------------|
| Linux | `/run/media/`, `/media/`, `/mnt/usb` |
| macOS | `/volumes/` |
| Windows | Drive letter with `GetDriveTypeW() == 2` (DRIVE_REMOVABLE) |

### 3. Installed Mode (default)

If neither CI/CD nor portable conditions are met, the platform assumes a fixed system installation with full feature access.

---

## Portable Mode (USB)

**Use case:** Walk-in security consultant deployment, air-gapped environments, field assessments.

### What is enabled

- Full vulnerability scanning (nmap, nikto, nuclei, testssl.sh)
- Network discovery and asset management
- Compliance mapping (10+ frameworks)
- Evidence collection and audit trail
- Credentialed scanning (SSH, SNMP)
- Delta reports and trend analysis
- Threat intelligence enrichment (KEV + EPSS, cached locally)
- FAIR risk quantification
- AI analysis (template backend only)
- SBOM generation
- Container scanning (if Docker/Podman present on host)
- Executive dashboard (terminal and HTML)
- All report formats (HTML, JSON, CSV, PDF)

### What is disabled

| Feature | Reason |
|---------|--------|
| Cloud scanning (AWS/Azure/GCP) | Cloud credentials should not be stored on USB media |
| External AI (Ollama, OpenAI) | Network dependency; data privacy risk from portable media |
| Active ASM enumeration | Requires network; may be inappropriate in field settings |

### How cloud scanning is disabled

In `scanners/cloud_scanner.py`, the `scan()` method checks:

```python
if get_platform_info is not None:
    pi = get_platform_info()
    if pi.is_portable:
        return {'error': 'Cloud scanning is disabled in portable mode.'}
```

### How AI is restricted

In `lib/ai_analyzer.py`, the `__init__()` method checks:

```python
if platform_info.is_portable and provider != 'template':
    logger.warning("Portable deployment mode detected. Forcing provider to 'template'")
    provider = 'template'
```

---

## Installed Mode (Full Features)

**Use case:** Permanent installation on a security workstation, Kali Purple system, or dedicated assessment server.

### What is enabled

All platform features without restriction:

- All scanning modules (network, vulnerability, web, SSL, compliance, container, cloud, ASM)
- All AI backends (template, Ollama, OpenAI)
- Cloud security scanning (AWS, Azure, GCP)
- Active ASM enumeration
- Full CI/CD integration
- All notification channels (email, Slack, Teams)
- All integrations (TheHive, Wazuh, Jira, ServiceNow)

### Setup for cloud scanning

Install the cloud provider SDK or CLI:

```bash
# AWS
pip install boto3
# or
sudo apt install awscli

# Azure
pip install azure-identity azure-mgmt-resource azure-mgmt-network azure-mgmt-storage
# or
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# GCP
pip install google-cloud-resource-manager google-cloud-compute google-cloud-storage
# or
# Install gcloud CLI from https://cloud.google.com/sdk/docs/install
```

Configure credentials:

```bash
# AWS
aws configure

# Azure
az login

# GCP
gcloud auth application-default login
```

### Setup for AI backends

**Ollama (local LLM):**

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull llama3

# Update config.yaml
# ai:
#   provider: ollama
#   model: llama3
```

**OpenAI-compatible API:**

Store the API key via the credential manager (Settings > Manage Credentials) or update `config.yaml`:

```yaml
ai:
  provider: openai
  model: gpt-4
  api_url: https://api.openai.com/v1
  sanitize_external: true
```

---

## CI/CD Mode

**Use case:** Automated security scanning in continuous integration pipelines.

### What is enabled

- Headless scanning (no interactive menus)
- SARIF output for GitHub Security tab and GitLab SAST
- Security gate evaluation with configurable thresholds
- All scanning modules (depending on available tools in the CI environment)
- Exit codes: 0 = gate passed, 1 = gate failed

### What is different

| Behavior | Interactive Mode | CI/CD Mode |
|----------|-----------------|------------|
| User prompts | Shown | Skipped (uses defaults) |
| Output format | Colored terminal | Plain text + SARIF |
| Exit code | Always 0 | Based on security gate |
| Progress display | Progress bars | Log lines |

### Pipeline integration

Generate pipeline configs from the platform:

```bash
# Interactive
python3 bin/purple-launcher
# Settings > CI/CD Integration

# Or generate directly
python3 -c "
from lib.cicd_integration import get_cicd_integrator
ci = get_cicd_integrator()
print(ci.generate_github_actions())
"
```

See `docs/FEATURES-v7.md` for complete pipeline examples.

---

## Overriding the Detected Mode

### Force portable mode

Set the `PURPLE_TEAM_MODE` environment variable (note: this is a convention; the actual detection is path-based):

The simplest override is to run from a path containing `/media/` or `/run/media/`.

### Force CI/CD mode

Set any CI environment variable:

```bash
export CI=true
python3 bin/purple-launcher quick
```

### Force installed mode

Ensure no CI variables are set and run from a non-removable path:

```bash
unset CI GITHUB_ACTIONS GITLAB_CI JENKINS_URL
cp -r /media/usb/purple-final/ /opt/purple-team/
cd /opt/purple-team/
python3 bin/purple-launcher
```

---

## Checking Current Mode

```bash
python3 lib/platform_detect.py
```

Output:

```
Platform Detection initialized

  os: Linux
  architecture: x86_64
  version: 6.17.10+kali-amd64
  wsl: False
  admin: False
  package_manager: apt
  usb_paths: ['/run/media/crissantos/PURPLETEAMG']
  deployment_mode: portable

Deployment mode: portable
  is_portable:  True
  is_installed: False
  is_cicd:      False
```

---

Purple Team Platform v7.0
February 2026
