# Purple Team GRC Platform v7.0 - Installation Guide

## Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **pip** (Python package manager)
- **Git** (optional, for cloning)

### Optional Security Tools

These tools enhance scanning capabilities but are not required. The platform gracefully degrades when tools are unavailable.

| Tool | Purpose | Install |
|------|---------|---------|
| nmap | Network scanning | `apt install nmap` / `brew install nmap` / [nmap.org](https://nmap.org/download) |
| nikto | Web scanning | `apt install nikto` |
| nuclei | Vuln scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| testssl.sh | SSL assessment | `apt install testssl.sh` (Linux/macOS only) |
| trivy | Container vulns | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| amass | DNS enumeration | `apt install amass` |
| docker | Container scanning | [docker.com](https://docker.com) |

---

## Linux Installation

### From GitHub

```bash
git clone https://github.com/saint1415/PurpleTeamGRC.git
cd PurpleTeamGRC

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Launch
python3 bin/purple-launcher
```

### From USB Drive

```bash
# Navigate to USB mount
cd /run/media/$USER/PURPLETEAMG/purple-final

# Option A: Run directly (no venv needed if deps installed system-wide)
python3 bin/purple-launcher

# Option B: Create local venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 bin/purple-launcher
```

### Install Security Tools (Debian/Ubuntu/Kali)

```bash
sudo apt update
sudo apt install -y nmap nikto testssl.sh amass
```

---

## Windows 11 Installation

### Step 1: Install Python

Download Python 3.11+ from [python.org](https://www.python.org/downloads/).

During installation:
- Check "Add Python to PATH"
- Check "Install pip"

Verify:
```cmd
python --version
pip --version
```

### Step 2: Get the Platform

```cmd
git clone https://github.com/saint1415/PurpleTeamGRC.git
cd PurpleTeamGRC
```

Or copy from USB drive to a local folder.

### Step 3: Setup

```cmd
bin\setup-windows.bat
```

This creates a virtual environment and installs dependencies.

### Step 4: Launch

```cmd
bin\purple-launcher.bat
```

Or with PowerShell:
```powershell
.\bin\purple-launcher.ps1
```

### Install nmap for Windows (Optional)

Download from [nmap.org/download](https://nmap.org/download). Install to `C:\Program Files\Nmap`. The platform auto-detects it.

---

## macOS Installation

```bash
# Install Python (if not present)
brew install python@3.11

# Clone
git clone https://github.com/saint1415/PurpleTeamGRC.git
cd PurpleTeamGRC

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install tools
brew install nmap

# Launch
python3 bin/purple-launcher
```

---

## USB Portable Deployment

The platform is designed to run directly from a USB drive with zero installation.

### Prepare USB Drive

1. Format USB drive (FAT32 for cross-platform, or exFAT for files >4GB)
2. Copy the `purple-final/` directory to the drive
3. (Optional) Create a venv on the drive:

```bash
cd /path/to/usb/purple-final
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Run from USB

The platform auto-detects USB deployment (portable mode):
- Cloud scanning is disabled (no credentials on removable media)
- AI defaults to template backend (no external API calls)
- All other features work normally

```bash
# Linux
python3 /media/USB/purple-final/bin/purple-launcher

# macOS
python3 /Volumes/USB/purple-final/bin/purple-launcher

# Windows
E:\purple-final\bin\purple-launcher.bat
```

---

## CI/CD Pipeline Installation

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Purple Team
        run: |
          pip install -r requirements.txt
      - name: Run Security Scan
        run: |
          python3 bin/purple-launcher quick
```

The platform auto-detects CI environment variables and runs in headless mode.

### Generate Pipeline Configs

```bash
python3 -c "
from lib.cicd_integration import get_cicd_integrator
ci = get_cicd_integrator()
ci.save_pipeline_config('github', '.')
"
```

---

## Configuration

After installation, edit `config/active/config.yaml`:

```yaml
# Set your industry for risk benchmarks
risk:
  industry: 'healthcare'  # healthcare, financial, technology, government, etc.

# Set compliance frameworks
compliance:
  frameworks:
    - 'HIPAA'
    - 'SOC2-Type2'
    - 'NIST-800-53'

# Network targets (or use auto-detection)
network:
  auto_detect: true
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete reference.

---

## Verification

After installation, verify everything works:

```bash
# Check platform detection
python3 lib/platform_detect.py

# Check tool availability
python3 bin/purple-launcher tools

# Run a quick scan
python3 bin/purple-launcher quick
```

---

## Troubleshooting

### "Module not found" errors

Ensure you're in the virtual environment:
```bash
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
```

### Python not found (Windows)

Ensure Python is in your PATH. Reinstall from python.org with "Add to PATH" checked.

### Permission denied (Linux)

Some scanners need root for raw sockets:
```bash
sudo python3 bin/purple-launcher
```

### nmap not found

Install nmap for your platform (see Prerequisites above). The platform works without it but network scanning will be limited.

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more solutions.
