# Purple Team GRC Platform v3.0 - Installation Quick Reference

**For comprehensive deployment instructions, see:** `Purple_Team_Deployment_Guide_v3.html`

This document provides quick installation commands only. For detailed walkthrough with troubleshooting, use the HTML guide.

---

## Prerequisites

### Required

1. **Kali Purple 2024.4+** (NOT standard Kali Linux)
   - Download: https://www.kali.org/get-kali/
   - Select: "Kali Purple" variant
   - Install following official Kali documentation

2. **Hardware Requirements**
   - RAM: 16GB minimum (32GB recommended)
   - Storage: 50GB+ free space
   - Network: Gigabit Ethernet (WiFi supported)

3. **Internet Connection** (for initial setup)
   - Required for package updates
   - Required for security tool downloads

### Verification

```bash
# Verify Kali Purple
grep "Kali" /etc/os-release
dpkg -l | grep "kali-linux-purple"

# Check Python version (3.10+ required)
python3 --version

# Check disk space (50GB+ recommended)
df -h /
```

---

## Quick Installation

### Step 1: Transfer Package

```bash
# Option A: USB Drive
cp -r /media/usb/purple-team-package ~/

# Option B: Git Clone (if available)
cd ~
git clone <repository-url> purple-team-package

# Option C: Network Copy
scp -r user@host:/path/to/purple-team-package ~/
```

### Step 2: Run Master Setup

```bash
# Navigate to package
cd ~/purple-team-package

# Make executable
chmod +x master_setup.sh

# Run installation (10-20 minutes)
sudo ./master_setup.sh
```

**What happens during setup:**
1. Pre-flight checks (OS, network, disk, Python)
2. System package updates
3. Security tool installation
4. Directory structure creation (dual installation)
5. Python environment setup (system + user)
6. Configuration file creation
7. Script installation
8. Launcher installation
9. Sync manager setup
10. Optional systemd services

### Step 3: Configure for Client

```bash
# Edit per-user configuration
vim ~/.purple-team/config.yaml

# Required changes:
# - client.name: "Your Client Name"
# - client.industry: healthcare|finance|retail|technology|government
# - network.ranges: Add client-specific ranges
# - network.exclusions: Add critical systems to exclude
```

### Step 4: Launch Platform

```bash
# Terminal menu (recommended)
purple-team-launcher

# Or desktop GUI
purple-team-gui
```

---

## Installation Locations

### System-Wide Installation
```
/opt/purple-team/
├── config/              # Configuration templates
├── scanners/            # Scanner Python scripts
├── utils/               # Utility scripts
├── results/             # Shared results (if any)
├── logs/                # System logs
├── tools/               # Downloaded tools (testssl.sh, etc.)
└── venv/                # System Python virtual environment
```

### Per-User Installation
```
~/.purple-team/
├── config.yaml          # YOUR client-specific configuration
├── results/             # YOUR scan results
├── logs/                # YOUR scan logs
├── evidence/            # YOUR audit evidence
├── reports/             # YOUR generated reports
├── venv/                # YOUR Python virtual environment
└── README.txt           # User guide
```

### System Logs (Centralized)
```
/var/log/purple-team/
└── <username>/          # Your logs synced here for audit trail
```

---

## Quick Commands

### Launch Platform
```bash
purple-team-launcher     # Terminal menu interface
purple-team-gui          # Desktop GUI interface
```

### Sync Installations
```bash
purple-team-sync         # Sync /opt with ~/.purple-team
purple-team-sync --check # Check sync status only
```

### Manual Script Execution
```bash
# Activate environment
source ~/.purple-team/venv/bin/activate

# Run scanner
cd ~/.purple-team/scanners
python3 network_scanner.py

# Deactivate when done
deactivate
```

### Pre-Flight Validation
```bash
# Run comprehensive validation
/opt/purple-team/utils/pre-flight-checker.py

# Check network detection
/opt/purple-team/utils/network-detector.py
```

### Update Management
```bash
# Check for updates
/opt/purple-team/utils/update-manager.py

# Updates checked automatically on every launcher start
```

---

## Systemd Services (Optional)

### Enable Auto-Start Services

```bash
# Enable scheduler (for automated scans)
sudo systemctl enable purple-team-scheduler.service
sudo systemctl start purple-team-scheduler.service

# Enable dashboard (for web interface)
sudo systemctl enable purple-team-dashboard.service
sudo systemctl start purple-team-dashboard.service

# Check status
sudo systemctl status purple-team-scheduler.service
sudo systemctl status purple-team-dashboard.service
```

### Service Management

```bash
# Start services
sudo systemctl start purple-team-scheduler.service
sudo systemctl start purple-team-dashboard.service

# Stop services
sudo systemctl stop purple-team-scheduler.service
sudo systemctl stop purple-team-dashboard.service

# Restart services
sudo systemctl restart purple-team-scheduler.service
sudo systemctl restart purple-team-dashboard.service

# View logs
sudo journalctl -u purple-team-scheduler.service -f
sudo journalctl -u purple-team-dashboard.service -f
```

---

## Configuration Templates

### Quick Start: Use Industry Template

```bash
# Copy template to your config
cd ~/.purple-team

# Healthcare
cp /opt/purple-team/config/config-healthcare.yaml config.yaml

# Finance
cp /opt/purple-team/config/config-finance.yaml config.yaml

# Retail
cp /opt/purple-team/config/config-retail.yaml config.yaml

# Government
cp /opt/purple-team/config/config-government.yaml config.yaml

# Then customize as needed
vim config.yaml
```

### Minimal Configuration

```yaml
client:
  name: "ACME Corporation"
  industry: "technology"

network:
  auto_detect: true
  exclusions:
    - "10.0.0.1"  # Add critical systems

compliance:
  frameworks:
    - "SOC2"
    - "NIST"

scanning:
  stealth_level: 3
  max_rate: 100
```

---

## Network Auto-Detection

### How It Works

1. Platform detects all active network interfaces
2. Identifies wired (eth0, ens*) and wireless (wlan0, wlp*) interfaces
3. Auto-detects RFC1918 private IP ranges:
   - 10.0.0.0/8
   - 172.16.0.0/12
   - 192.168.0.0/16
4. Presents detected ranges for confirmation
5. Scans approved ranges

### Manual Configuration

If auto-detection doesn't work:

```bash
# Edit config
vim ~/.purple-team/config.yaml

# Disable auto-detect
network:
  auto_detect: false
  ranges:
    - "10.50.0.0/16"      # Your specific range
    - "192.168.1.0/24"    # Your specific range
  exclusions:
    - "10.50.0.1"         # Gateway
    - "10.50.0.10"        # DC
```

---

## Verification

### Verify Installation

```bash
# Check system installation
ls -la /opt/purple-team/
ls -la /opt/purple-team/scanners/
ls -la /opt/purple-team/utils/

# Check user installation
ls -la ~/.purple-team/
cat ~/.purple-team/README.txt

# Check launchers installed
which purple-team-launcher
which purple-team-gui
which purple-team-sync

# Check Python environment
source ~/.purple-team/venv/bin/activate
python3 --version
pip list | grep -i purple
deactivate
```

### Run Test Scan (Safe)

```bash
# Launch platform
purple-team-launcher

# From menu:
# 1. Run Pre-Flight Check
# 2. Verify all green checks
# 3. Select "Network Discovery"
# 4. Use auto-detect
# 5. Review detected ranges
# 6. Approve to scan

# Or manual test:
source ~/.purple-team/venv/bin/activate
cd ~/.purple-team/scanners
python3 network_scanner.py --help
```

---

## Troubleshooting

### Installation Issues

**"Must be run as root":**
```bash
sudo ./master_setup.sh
```

**"Python version too old":**
```bash
# Update Python
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev

# Re-run setup
sudo ./master_setup.sh
```

**"No internet connectivity":**
```bash
# Check network
ping 8.8.8.8

# Check DNS
nslookup google.com

# If behind proxy, configure:
export http_proxy="http://proxy:port"
export https_proxy="http://proxy:port"
```

**"Package installation failed":**
```bash
# Update package lists
sudo apt update

# Fix broken dependencies
sudo apt --fix-broken install

# Re-run setup
sudo ./master_setup.sh
```

### Runtime Issues

**"Module not found":**
```bash
# Ensure venv activated
source ~/.purple-team/venv/bin/activate

# Or use launcher (handles automatically)
purple-team-launcher
```

**"Permission denied":**
```bash
# Fix permissions
sudo chown -R $(whoami):$(whoami) ~/.purple-team/

# Or use sudo for system operations
sudo purple-team-sync
```

**"Network auto-detection failed":**
```bash
# Manual network detection
ip addr show
ip route show

# Edit config manually
vim ~/.purple-team/config.yaml
# Set auto_detect: false
# Add ranges manually
```

**"Scan results missing":**
```bash
# Check output directory
ls -la ~/.purple-team/results/

# Check logs
tail -f ~/.purple-team/logs/network_scanner.log

# Check permissions
ls -la ~/.purple-team/
```

### Getting Help

1. **Check Logs:**
   ```bash
   # User logs
   tail -f ~/.purple-team/logs/*.log
   
   # System logs
   tail -f /var/log/purple-team/*.log
   
   # Installation log
   tail -f /var/log/purple-team/setup.log
   ```

2. **Run Diagnostics:**
   ```bash
   # Pre-flight check
   /opt/purple-team/utils/pre-flight-checker.py
   
   # Network detection test
   /opt/purple-team/utils/network-detector.py
   
   # Sync check
   purple-team-sync --check
   ```

3. **Review Documentation:**
   ```bash
   # User guide
   cat ~/.purple-team/README.txt
   
   # Deployment guide
   firefox /opt/purple-team/docs/Purple_Team_Deployment_Guide_v3.html
   ```

---

## Uninstallation

### Remove Platform (if needed)

```bash
# Stop services
sudo systemctl stop purple-team-scheduler.service
sudo systemctl stop purple-team-dashboard.service
sudo systemctl disable purple-team-scheduler.service
sudo systemctl disable purple-team-dashboard.service

# Remove system installation
sudo rm -rf /opt/purple-team

# Remove user installation
rm -rf ~/.purple-team

# Remove launchers
sudo rm /usr/local/bin/purple-team-launcher
sudo rm /usr/local/bin/purple-team-gui
sudo rm /usr/local/bin/purple-team-sync

# Remove desktop entry
sudo rm /usr/share/applications/purple-team-grc.desktop

# Remove systemd services
sudo rm /etc/systemd/system/purple-team-*.service
sudo systemctl daemon-reload

# Remove logs
sudo rm -rf /var/log/purple-team
```

---

## Next Steps After Installation

1. **Configure:** Edit `~/.purple-team/config.yaml` with client details
2. **Validate:** Run pre-flight check to verify installation
3. **Test:** Launch platform and run network discovery
4. **Review:** Check logs and results directories
5. **Document:** Record client-specific settings
6. **Deploy:** Begin security assessment

---

## Additional Resources

### Documentation
- **Comprehensive Guide:** `Purple_Team_Deployment_Guide_v3.html`
- **Operations Guide:** `02_Operations_Playbook.md`
- **Quick Reference:** `03_Quick_Reference_Guide.md`
- **README:** `README.md`

### Support Files
- **Configuration Templates:** `/opt/purple-team/config/config-*.yaml`
- **Example Configs:** See industry-specific templates
- **Utility Scripts:** `/opt/purple-team/utils/`
- **Scanner Scripts:** `/opt/purple-team/scanners/`

### Commands Reference
- `purple-team-launcher` - Main terminal interface
- `purple-team-gui` - Desktop GUI interface
- `purple-team-sync` - Sync system and user installations
- `/opt/purple-team/utils/pre-flight-checker.py` - System validation
- `/opt/purple-team/utils/network-detector.py` - Network discovery test
- `/opt/purple-team/utils/update-manager.py` - Update management

---

**Installation Complete!**

For detailed deployment guide with screenshots and troubleshooting:  
**See:** `Purple_Team_Deployment_Guide_v3.html`

For daily operations and workflow:  
**See:** `02_Operations_Playbook.md`

For quick command reference:  
**See:** `03_Quick_Reference_Guide.md`

---

**Purple Team GRC Platform v3.0**  
*Production-Ready Security Assessment & Compliance Platform*  
*© 2026 - Professional Security Consulting Use*
