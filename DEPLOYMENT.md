# Purple Team GRC -- Deployment Guide

## Quick Start (Windows)

```
git clone --recurse-submodules https://github.com/YOUR_ORG/PurpleTeamGRC.git
cd PurpleTeamGRC
git lfs pull
python -m pip install -r requirements.txt
python bin/purple-launcher
```

The launcher presents an interactive menu. To run a Windows security scan directly:

```
python bin/purple-launcher winscan
```

Optional dependencies (for PDF export, YARA, etc.) install automatically with requirements.txt.

## Quick Start (Linux)

```
git clone --recurse-submodules https://github.com/YOUR_ORG/PurpleTeamGRC.git
cd PurpleTeamGRC
git lfs pull
```

Ensure Python 3.9+ is installed (`python3 --version`). Then:

```
pip install -r requirements.txt
python3 bin/purple-launcher
```

Run a Linux security scan:

```
python3 bin/purple-launcher linscan
```

Some Linux scanner checks require root for full results (e.g., firewall rules, kernel params, service enumeration). Use `sudo` when needed:

```
sudo python3 bin/purple-launcher linscan
```

## Offline / Air-Gapped Deployment

Copy the entire repo to USB or removable media. No internet connection is required.

- All CVE data (332K+ CVEs) is included in `data/vuln_db/vuln_intel.db`
- All portable tools are bundled in the `tools/` directory
- Python and pip are the only external prerequisites

On the target machine, copy the repo and run the launcher as described above.

## Data Updates

Incremental NVD update (fetches only recent changes):

```
python bin/update-intel.py --incremental
```

Full NVD database rebuild:

```
python bin/update-intel.py --full
```

Bundle/update portable tools:

```
python bin/bundle-tools.py --all
```

GitHub Actions runs incremental updates automatically every 4 hours.

## Docker Deployment (PostgreSQL)

```
docker-compose up -d
```

This starts PostgreSQL, the API server, and a scheduler worker.

To migrate an existing SQLite database to PostgreSQL:

```
python bin/migrate-db.py
```

## Linux-Specific Setup Notes

Install recommended system packages:

```
# Debian/Ubuntu
sudo apt install nmap yara

# RHEL/CentOS/Fedora
sudo yum install nmap yara
```

- `testssl.sh` works natively on Linux (no Git Bash wrapper needed)
- YARA can also use the bundled binary in `tools/` if not installed system-wide
- For agent deployment to remote hosts, ensure SSH access is configured

Linux scanner checks cover: firewall (iptables/nftables/ufw), SSH configuration,
user accounts, running services, pending patches, kernel parameters, file
permissions, and AI-powered detection.

## API & Dashboard

Start the server:

```
python bin/start-server.py --port 8443
```

- Dashboard: https://localhost:8443
- API endpoints: https://localhost:8443/api/v1/

## Environment Variables

```
cp .env.example .env
```

Key variables:

| Variable      | Purpose                                      |
|---------------|----------------------------------------------|
| NVD_API_KEY   | NVD API access (free, speeds up data pulls)  |

Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

For GitHub Actions automated updates, add `NVD_API_KEY` as a repository secret
under Settings > Secrets and variables > Actions.
