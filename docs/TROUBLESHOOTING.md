# Purple Team Platform v7.0 - Troubleshooting Guide

Common issues and solutions for the Purple Team Platform.

---

## Tool Detection Issues

### Problem: "nmap not found" even though it is installed

**Cause:** The tool is installed but not in PATH.

**Solution:**

```bash
# Linux/macOS: verify nmap location
which nmap
# or
find / -name nmap -type f 2>/dev/null

# Add to PATH if found in a non-standard location
export PATH="$PATH:/usr/local/bin"

# Windows: add Nmap install directory to PATH
$env:PATH += ";C:\Program Files (x86)\Nmap"
```

The platform searches these paths automatically on Windows: `C:\Program Files\Nmap`, `C:\Program Files (x86)\Nmap`, `C:\Program Files\Wireshark`, `C:\Program Files\Greenbone`, and `%LOCALAPPDATA%\Programs`.

### Problem: Tool status shows "missing" after a fresh install

**Cause:** Tool discovery cache has not refreshed.

**Solution:**

```bash
# Force a fresh discovery by running tool status
python3 bin/purple-launcher tools
```

The `tool_discovery.discover_all()` method re-scans all known tool paths each time it runs.

### Problem: nikto not available on Windows

**Cause:** Nikto requires a Perl runtime which is not bundled with Windows.

**Solution:** Use WSL (Windows Subsystem for Linux) for nikto support, or rely on nuclei for web vulnerability scanning. The platform functions without nikto; it is listed as optional.

---

## Network and Scanning Issues

### Problem: "No networks detected" on startup

**Cause:** The platform could not find RFC1918 private ranges on any active network interface.

**Solution:**

```bash
# Linux: check interfaces manually
ip addr show

# macOS
ifconfig

# Windows
ipconfig /all
```

If your interfaces are up but the platform still cannot detect them, configure targets manually in `config/active/config.yaml`:

```yaml
network:
  auto_detect: false
  scan_ranges:
    - '192.168.1.0/24'
    - '10.0.0.0/24'
```

### Problem: Scan finds no hosts on the network

**Cause:** Multiple possibilities -- firewall blocking, wrong interface, host firewalls dropping pings.

**Solution:**

1. Run the platform as root/administrator (required for SYN scans and ICMP):
   ```bash
   sudo python3 bin/purple-launcher quick
   ```
2. Check that your firewall allows outbound scan traffic.
3. Try scanning a known-up host directly to verify connectivity.
4. On Windows, ensure Windows Defender Firewall is not blocking nmap (see WINDOWS-GUIDE.md).

Without root/admin, the platform falls back to TCP connect scans which are slower but do not require elevated privileges.

### Problem: Scan takes much longer than expected

**Cause:** High stealth level introduces large random delays between scan phases.

**Solution:** Check the `stealth_level` in config:

```yaml
scanning:
  stealth_level: 1    # 1=aggressive (fastest), 5=maximum stealth (slowest)
  delay_min_seconds: 5
  delay_max_seconds: 30
```

The default stealth level of 3 adds delays between 30 and 300 seconds between phases to simulate human-paced scanning. Lower the stealth level for faster assessments in lab or authorized environments.

### Problem: "Permission denied" during scanning

**Cause:** Nmap SYN scans and OS detection require root/administrator privileges.

**Solution:**

```bash
# Linux/macOS
sudo python3 bin/purple-launcher quick

# Windows: right-click terminal, "Run as administrator"
python bin\purple-launcher quick
```

---

## Database and Evidence Issues

### Problem: "database is locked" error

**Cause:** Another instance of the platform is accessing the SQLite database, or a previous process did not shut down cleanly.

**Solution:**

1. Ensure no other `purple-launcher` processes are running:
   ```bash
   ps aux | grep purple-launcher
   # Kill any stale processes
   ```
2. If the problem persists, the lock file may be stale. Restart the platform.
3. The evidence database is located at `data/evidence/evidence.db`. In extreme cases, you can copy it as a backup and delete the journal file (`evidence.db-journal`) to clear the lock.

### Problem: Evidence database is missing or empty

**Cause:** First run, or the `data/evidence/` directory was deleted.

**Solution:** The platform creates the database automatically on first use via `EvidenceManager._ensure_db()`. Run any scan and the database will be created:

```bash
python3 bin/purple-launcher quick
```

The database file is stored at: `<platform-root>/data/evidence/evidence.db`

### Problem: "No sessions found" in delta report or trend analysis

**Cause:** No completed scan sessions exist in the evidence database.

**Solution:** Run at least one scan to generate session data. For delta reports, you need at least two completed sessions. For trend analysis, at least two sessions are required (five or more are recommended for meaningful trends).

---

## AI Backend Issues

### Problem: AI analysis returns only template responses

**Cause:** The platform defaults to the template (rule-based) backend, or portable mode forces template mode.

**Solution:**

1. If running from USB (portable mode), the platform forces the template backend. This is by design -- external AI backends are disabled in portable mode for data privacy.
2. For installed mode, configure the AI provider in `config/active/config.yaml`:
   ```yaml
   ai:
     provider: ollama    # or: openai
     model: llama3       # or: gpt-4
   ```

### Problem: Ollama connection refused

**Cause:** The Ollama service is not running, or it is listening on a different address.

**Solution:**

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if not running
ollama serve

# Pull a model if none are available
ollama pull llama3
```

The default Ollama API URL is `http://localhost:11434`. If your Ollama instance is on a different host or port, update `config/active/config.yaml`:

```yaml
ai:
  provider: ollama
  model: llama3
  api_url: 'http://192.168.1.100:11434'
```

### Problem: OpenAI API returns authentication errors

**Cause:** API key not configured or expired.

**Solution:** Store the API key using the credential manager:

1. Launch the platform: `python3 bin/purple-launcher`
2. Go to Settings > Manage Credentials
3. Add the API key

Or verify your key works directly:

```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer YOUR_API_KEY"
```

When `ai.sanitize_external` is `true` (default), the platform strips IP addresses, hostnames, and organization names before sending data to external APIs.

---

## Platform Detection Issues

### Problem: Platform shows "installed" mode when running from USB

**Cause:** The USB drive mount path does not match the expected patterns, or the drive reports as a fixed disk.

**Solution:** The platform detects portable mode by checking if its path contains any of these indicators:

| OS | Path Indicators |
|----|-----------------|
| Linux | `/run/media/`, `/media/`, `/mnt/usb` |
| macOS | `/volumes/` |
| Windows | `GetDriveTypeW() == 2` (DRIVE_REMOVABLE) |

Some USB SSDs and large USB drives report as fixed disks (drive type 3 instead of 2 on Windows). In this case, the platform runs in installed mode which enables all features.

Verify detection:

```bash
python3 lib/platform_detect.py
```

### Problem: CI/CD mode not detected

**Cause:** None of the expected CI environment variables are set.

**Solution:** The platform checks for these variables: `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `CIRCLECI`, `TRAVIS`, `BITBUCKET_PIPELINE`, `TF_BUILD`, `CODEBUILD_BUILD_ID`, `BUILDKITE`.

Set any one of them:

```bash
export CI=true
python3 bin/purple-launcher quick
```

---

## Report Generation Issues

### Problem: HTML reports have broken formatting

**Cause:** Report was opened in a browser that blocks local file access to CSS resources.

**Solution:** The platform embeds all CSS inline in HTML reports. If the report still looks wrong, open it in a different browser. Chrome, Firefox, and Edge all support the embedded CSS and SVG used in reports.

### Problem: Reports directory is empty after a scan

**Cause:** Reports are generated on demand, not automatically after every scan.

**Solution:** Generate reports explicitly:

1. From the interactive menu: Compliance & Reports > Generate Audit Report
2. From the command line: the orchestrator stores findings in the evidence database. Use the compliance menu to generate formatted output.

Reports are saved to `data/reports/` by default.

### Problem: SARIF export produces empty results

**Cause:** No open findings exist in the evidence database.

**Solution:** Run a scan first, then export:

1. Settings > CI/CD Integration > Export SARIF
2. Or programmatically:
   ```python
   from lib.cicd_integration import get_cicd_integrator
   ci = get_cicd_integrator()
   ci.export_sarif(findings)
   ```

---

## Container and Cloud Issues

### Problem: "Docker not found" for container scanning

**Cause:** Docker or Podman is not installed, or the Docker socket is not accessible.

**Solution:**

```bash
# Verify Docker is running
docker info

# Linux: ensure your user is in the docker group
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect

# Windows: start Docker Desktop and ensure your user is in docker-users
```

The container scanner auto-detects Docker first, then falls back to Podman.

### Problem: Cloud scanning returns "disabled in portable mode"

**Cause:** The platform is running from a USB drive. Cloud scanning is disabled in portable mode because storing cloud credentials on removable media is a security risk.

**Solution:** Copy the platform to a fixed installation path and run from there:

```bash
cp -r /media/usb/purple-final/ /opt/purple-team/
cd /opt/purple-team/
python3 bin/purple-launcher
```

Cloud scanning also requires the relevant SDK or CLI to be installed and configured (AWS CLI, Azure CLI, or gcloud).

### Problem: Cloud scan finds no resources

**Cause:** Credentials not configured, or the authenticated account lacks read permissions.

**Solution:**

```bash
# AWS: verify credentials
aws sts get-caller-identity

# Azure: verify login
az account show

# GCP: verify authentication
gcloud auth list
```

The platform uses read-only API calls only (`cloud.aws.read_only: true` by default). Ensure the authenticated identity has at least read access to the resources being scanned.

---

## Terminal Display Issues

### Problem: Box-drawing characters display as garbled text

**Cause:** Terminal does not support UTF-8 encoding.

**Solution:**

```bash
# Linux/macOS: set UTF-8 locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Windows PowerShell: set code page to UTF-8
chcp 65001
```

Use Windows Terminal (recommended) instead of legacy Command Prompt for best results.

### Problem: Colors not displaying in terminal

**Cause:** Terminal does not support ANSI escape codes, or the `TERM` environment variable is not set.

**Solution:**

```bash
# Linux: set TERM if not set
export TERM=xterm-256color

# Windows: install colorama
pip install colorama

# Or use Windows Terminal which supports ANSI natively
```

The platform uses ANSI color codes via `lib/tui.py`. On Windows, it attempts to enable ANSI support via `colorama` first, then falls back to `SetConsoleMode` with virtual terminal processing.

---

## Getting Help

```bash
# Built-in help
python3 bin/purple-launcher help

# Platform detection diagnostics
python3 lib/platform_detect.py

# Tool inventory
python3 bin/purple-launcher tools
```

If issues persist, check the log files in `data/logs/` for detailed error messages.

---

Purple Team Platform v7.0
February 2026
