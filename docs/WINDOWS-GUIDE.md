# Purple Team Platform v7.0 - Windows Guide

Running the Purple Team Platform on Windows 11.

---

## Prerequisites

### 1. Python 3.11+

Download from https://python.org/downloads/

During installation:
- Check "Add Python to PATH" (important)
- Check "Install for all users" (recommended)
- Check "Disable path length limit" when prompted at the end

Verify:

```powershell
python --version
# Python 3.11.x or later

pip --version
# pip 24.x
```

If `python` is not recognized, add it to PATH manually:

```powershell
# Find Python installation
where python

# Add to PATH (adjust version number as needed)
$env:PATH += ";C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311\Scripts"
```

### 2. Nmap

Download from https://nmap.org/download.html

- Run the installer
- Check "Register Nmap Path" during installation
- Default install location: `C:\Program Files (x86)\Nmap`

Verify:

```powershell
nmap --version
```

### 3. Optional: Nikto

Nikto requires Perl on Windows. The simplest approach is to use it through WSL (see below).

### 4. Optional: Docker Desktop

For container scanning, install Docker Desktop from https://docker.com/products/docker-desktop/

---

## USB Drive Setup

### Connecting the USB Drive

1. Insert the USB drive containing the platform
2. Note the drive letter assigned (e.g., `E:\`)
3. Open PowerShell or Command Prompt

```powershell
# Navigate to the platform
cd E:\purple-final\

# Or if the drive letter is different
cd F:\purple-final\
```

### Running from USB

```powershell
# Launch the interactive menu
python bin\purple-launcher

# Run a quick scan
python bin\purple-launcher quick

# Check available tools
python bin\purple-launcher tools
```

The platform will auto-detect portable mode when running from a USB drive. It uses `GetDriveTypeW()` to detect removable media on Windows.

---

## Running the Platform

### Terminal Color Support

The platform uses ANSI color codes for its terminal interface. Windows 10 version 1511+ and Windows 11 support ANSI natively. The launcher automatically enables ANSI support via:

1. `colorama` library (if installed): `pip install colorama`
2. Windows Console API fallback: `SetConsoleMode` with virtual terminal processing

If colors do not display correctly:
- Use Windows Terminal (recommended) instead of legacy Command Prompt
- Or install colorama: `pip install colorama`

### PowerShell

```powershell
python bin\purple-launcher
```

### Command Prompt

```cmd
python bin\purple-launcher
```

### Windows Terminal (recommended)

Windows Terminal provides the best experience with full ANSI color support, Unicode box-drawing characters, and proper terminal sizing.

---

## Tool Installation on Windows

### Using the Platform Installer

The platform can detect and suggest installation for missing tools:

```powershell
python bin\purple-launcher tools
```

It detects available package managers:
1. `winget` (Windows Package Manager, built into Windows 11)
2. `choco` (Chocolatey, if installed)

### Manual Installation

| Tool | Installation | Verify |
|------|-------------|--------|
| nmap | https://nmap.org/download.html | `nmap --version` |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `nuclei --version` |
| trivy | `winget install aquasecurity.trivy` | `trivy --version` |
| Docker | https://docker.com/products/docker-desktop/ | `docker --version` |

### Tool Path Detection

The platform searches these Windows-specific paths:

```
C:\Program Files\Nmap
C:\Program Files\Wireshark
C:\Program Files\Greenbone
C:\Program Files (x86)\Nmap
%LOCALAPPDATA%\Programs
```

Tool binary names are adjusted for Windows:
- `nmap` becomes `nmap.exe`
- `python3` becomes `python.exe`
- `nikto` becomes `nikto.pl`

---

## Platform Detection on Windows

The platform detects:

| Property | Detection Method |
|----------|-----------------|
| OS | `platform.system()` returns `'Windows'` |
| Architecture | `platform.machine()` (e.g., `AMD64`) |
| Admin status | `ctypes.windll.shell32.IsUserAnAdmin()` |
| WSL | N/A (WSL detected on Linux side) |
| USB drives | `GetDriveTypeW()` for removable media (type 2) |
| Package manager | Checks for `winget`, then `choco` |

Verify detection:

```powershell
python lib\platform_detect.py
```

Expected output:

```
Platform Detection initialized

  os: Windows
  architecture: AMD64
  version: 10.0.22631
  wsl: False
  admin: False
  package_manager: winget
  usb_paths: ['E:\']
  deployment_mode: installed
```

---

## Network Scanning on Windows

### Running with Administrator Privileges

Some scan features (SYN scanning, OS detection) require administrator privileges:

1. Right-click PowerShell or Windows Terminal
2. Select "Run as administrator"
3. Navigate to the platform directory
4. Run the scan

```powershell
# As administrator for full scan capabilities
python bin\purple-launcher standard
```

Without administrator privileges, the platform falls back to TCP connect scans (slower but still functional).

### Windows Firewall

Windows Defender Firewall may block scan traffic. For authorized assessments:

```powershell
# Temporarily disable for scanning (requires admin)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Re-enable after scanning
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

Alternatively, add nmap as an allowed application in Windows Firewall settings.

### Network Interface Detection

The platform uses cross-platform network detection:
1. `ip addr` (WSL/Linux)
2. `ipconfig` (Windows native)
3. `socket` module (fallback)

---

## WSL (Windows Subsystem for Linux)

For the best experience on Windows, consider running the platform inside WSL:

### Install WSL

```powershell
# From PowerShell (admin)
wsl --install -d kali-linux
```

### Run in WSL

```bash
# Inside WSL
cd /mnt/e/purple-final/   # Access USB drive
# or
cd /mnt/c/Users/username/PurpleTeamGRC/

python3 bin/purple-launcher
```

The platform detects WSL by checking `/proc/version` for "Microsoft" or "WSL" strings. It reports the OS as "WSL (Linux on Windows)".

Benefits of WSL:
- Full Linux tool compatibility (nmap, nikto, nuclei, testssl.sh)
- Native package management via `apt`
- Better ANSI terminal support
- Access to Windows drives via `/mnt/`

---

## Troubleshooting

### "python" is not recognized

**Cause:** Python not added to PATH during installation.

**Fix:**
```powershell
# Try python3 instead
python3 bin\purple-launcher

# Or use the full path
C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\python.exe bin\purple-launcher
```

### "nmap" is not recognized

**Cause:** Nmap not in PATH.

**Fix:**
```powershell
# Add Nmap to PATH for current session
$env:PATH += ";C:\Program Files (x86)\Nmap"
nmap --version
```

### Colors not displaying correctly

**Cause:** Legacy Command Prompt does not support ANSI.

**Fix:** Use Windows Terminal instead, or install colorama:
```powershell
pip install colorama
```

### Permission denied errors

**Cause:** Scanning requires elevated privileges for some operations.

**Fix:** Run PowerShell as Administrator.

### UnicodeEncodeError in terminal output

**Cause:** Console code page does not support Unicode.

**Fix:**
```powershell
# Set UTF-8 code page
chcp 65001
python bin\purple-launcher
```

### Scan results show fewer hosts than expected

**Cause:** Windows Firewall blocking outbound scan traffic.

**Fix:** Add nmap to firewall exceptions or temporarily disable the firewall for the assessment (see Network Scanning section above).

### Docker socket access denied

**Cause:** Docker Desktop not running, or user not in docker-users group.

**Fix:**
1. Start Docker Desktop
2. Ensure your user is in the `docker-users` group (Settings > General)
3. Restart your terminal

### USB drive not detected as portable mode

**Cause:** Windows drive type detection failed.

**Fix:** The platform uses `GetDriveTypeW()` to detect removable drives. Some USB drives report as fixed disks (especially USB SSDs). The platform will run in installed mode, which enables all features.

---

## Known Limitations on Windows

| Limitation | Details | Workaround |
|------------|---------|------------|
| Nikto not available | Requires Perl runtime | Use WSL, or skip (web scanning still works via nuclei) |
| testssl.sh limited | Requires bash | Use WSL, or platform falls back to Python SSL checks |
| Raw socket scanning | Requires admin privileges | Run as administrator |
| File permissions | Windows ACLs differ from POSIX | Evidence integrity uses SHA-256 hashes instead |
| SSH credentialed scanning | Paramiko works; ssh CLI may differ | Use paramiko backend (default) |
| Path lengths | Windows 260-char limit | Enable long paths in Python installer |

---

Purple Team Platform v7.0
February 2026
