#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Portable Tool Bundler

Downloads portable security tools for air-gapped deployment.
Run on a connected machine, then copy the tools/ directory to the target.

Usage:
    python bin/bundle-tools.py --all           # Download everything
    python bin/bundle-tools.py --nmap          # Just nmap portable
    python bin/bundle-tools.py --sysinternals  # Microsoft Sysinternals suite
    python bin/bundle-tools.py --yara          # YARA malware scanner
    python bin/bundle-tools.py --testssl       # testssl.sh
    python bin/bundle-tools.py --wordlists     # Password/directory wordlists
    python bin/bundle-tools.py --status        # Show what's installed
"""

import sys
import os
import io
import json
import hashlib
import zipfile
import argparse
import urllib.request
import urllib.error
import ssl
from pathlib import Path

# Resolve project root
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
TOOLS_DIR = PROJECT_ROOT / 'tools'


def banner():
    print()
    print("  ============================================================")
    print("   Purple Team Platform v7.0 - Portable Tool Bundler")
    print("  ============================================================")
    print()


def download_file(url, dest_path, description="", expected_sha256=None):
    """Download a file from URL with progress display."""
    print(f"  Downloading: {description or url}")
    print(f"  URL: {url}")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={
            'User-Agent': 'PurpleTeamPlatform/7.0'
        })

        with urllib.request.urlopen(req, timeout=120, context=ctx) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            data = bytearray()
            chunk_size = 65536
            downloaded = 0

            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                data.extend(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    pct = downloaded * 100 // total_size
                    mb = downloaded / (1024 * 1024)
                    print(f"\r  Progress: {pct}% ({mb:.1f} MB)", end='', flush=True)

            print()

        # Verify SHA256 if provided
        if expected_sha256:
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected_sha256:
                print(f"  WARNING: SHA256 mismatch!")
                print(f"    Expected: {expected_sha256}")
                print(f"    Got:      {actual}")
                return None

        # Write to disk
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(data)
        print(f"  Saved: {dest_path} ({len(data) / (1024*1024):.1f} MB)")
        return bytes(data)

    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  FAILED: {e}")
        return None
    except Exception as e:
        print(f"  FAILED: {e}")
        return None


def download_and_extract_zip(url, extract_dir, description=""):
    """Download a ZIP file and extract it."""
    print(f"  Downloading: {description or url}")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={
            'User-Agent': 'PurpleTeamPlatform/7.0'
        })

        with urllib.request.urlopen(req, timeout=300, context=ctx) as response:
            data = response.read()

        print(f"  Downloaded: {len(data) / (1024*1024):.1f} MB")

        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(str(extract_dir))
            file_count = len(zf.namelist())

        print(f"  Extracted: {file_count} files to {extract_dir}")
        return True

    except Exception as e:
        print(f"  FAILED: {e}")
        return False


# ============================================================
# Tool definitions
# ============================================================

SYSINTERNALS_TOOLS = {
    'sigcheck': {
        'url': 'https://live.sysinternals.com/sigcheck.exe',
        'description': 'File signature verification (detects unsigned/tampered binaries)',
    },
    'sigcheck64': {
        'url': 'https://live.sysinternals.com/sigcheck64.exe',
        'description': 'File signature verification (64-bit)',
    },
    'autoruns': {
        'url': 'https://live.sysinternals.com/autoruns.exe',
        'description': 'Autostart entry viewer (persistence detection)',
    },
    'autoruns64': {
        'url': 'https://live.sysinternals.com/autoruns64.exe',
        'description': 'Autostart entry viewer (64-bit)',
    },
    'autorunsc': {
        'url': 'https://live.sysinternals.com/autorunsc.exe',
        'description': 'Autostart command-line tool',
    },
    'autorunsc64': {
        'url': 'https://live.sysinternals.com/autorunsc64.exe',
        'description': 'Autostart command-line tool (64-bit)',
    },
    'tcpview': {
        'url': 'https://live.sysinternals.com/tcpview.exe',
        'description': 'TCP/UDP connection viewer',
    },
    'tcpvcon': {
        'url': 'https://live.sysinternals.com/tcpvcon.exe',
        'description': 'TCP connection viewer (command-line)',
    },
    'accesschk': {
        'url': 'https://live.sysinternals.com/accesschk.exe',
        'description': 'Permission and access auditing',
    },
    'accesschk64': {
        'url': 'https://live.sysinternals.com/accesschk64.exe',
        'description': 'Permission and access auditing (64-bit)',
    },
    'handle': {
        'url': 'https://live.sysinternals.com/handle.exe',
        'description': 'Open handle listing (process analysis)',
    },
    'handle64': {
        'url': 'https://live.sysinternals.com/handle64.exe',
        'description': 'Open handle listing (64-bit)',
    },
    'strings': {
        'url': 'https://live.sysinternals.com/strings.exe',
        'description': 'Binary string extraction',
    },
    'strings64': {
        'url': 'https://live.sysinternals.com/strings64.exe',
        'description': 'Binary string extraction (64-bit)',
    },
    'listdlls': {
        'url': 'https://live.sysinternals.com/listdlls.exe',
        'description': 'Loaded DLL listing (DLL hijacking detection)',
    },
    'listdlls64': {
        'url': 'https://live.sysinternals.com/listdlls64.exe',
        'description': 'Loaded DLL listing (64-bit)',
    },
    'pslist': {
        'url': 'https://live.sysinternals.com/pslist.exe',
        'description': 'Process listing (detailed)',
    },
    'pslist64': {
        'url': 'https://live.sysinternals.com/pslist64.exe',
        'description': 'Process listing (64-bit)',
    },
}


def bundle_sysinternals():
    """Download Sysinternals tools from live.sysinternals.com."""
    print("\n[Sysinternals] Downloading Microsoft Sysinternals tools...")
    dest_dir = TOOLS_DIR / 'sysinternals'
    dest_dir.mkdir(parents=True, exist_ok=True)

    success = 0
    for name, info in SYSINTERNALS_TOOLS.items():
        dest = dest_dir / f"{name}.exe"
        if dest.exists():
            print(f"  {name}: already present ({dest.stat().st_size / 1024:.0f} KB)")
            success += 1
            continue

        result = download_file(info['url'], dest, info['description'])
        if result:
            success += 1

    print(f"  Sysinternals: {success}/{len(SYSINTERNALS_TOOLS)} tools ready")
    return success > 0


def bundle_nmap():
    """Download nmap portable ZIP."""
    print("\n[Nmap] Downloading nmap portable...")
    dest_dir = TOOLS_DIR / 'nmap'

    # Check if already present
    nmap_exe = dest_dir / 'nmap.exe'
    if nmap_exe.exists():
        print(f"  nmap: already present at {nmap_exe}")
        return True

    # nmap portable ZIP - use the latest stable
    # Note: actual URL may vary by version; user should verify
    url = 'https://nmap.org/dist/nmap-7.92-win32.zip'
    print(f"  Source: {url}")
    print("  Note: If this version is unavailable, check https://nmap.org/download.html")

    success = download_and_extract_zip(url, dest_dir, 'Nmap portable scanner')

    if success:
        # Move files from nested directory if needed
        for subdir in dest_dir.iterdir():
            if subdir.is_dir() and subdir.name.startswith('nmap-'):
                for item in subdir.iterdir():
                    target = dest_dir / item.name
                    if not target.exists():
                        item.rename(target)
                # Clean up empty subdirectory
                try:
                    subdir.rmdir()
                except OSError:
                    pass
                break

    return success


def bundle_yara():
    """Download YARA portable binary."""
    print("\n[YARA] Downloading YARA malware scanner...")
    dest_dir = TOOLS_DIR / 'yara'
    dest_dir.mkdir(parents=True, exist_ok=True)

    yara_exe = dest_dir / 'yara64.exe'
    if yara_exe.exists():
        print(f"  yara: already present at {yara_exe}")
        return True

    # YARA releases on GitHub
    url = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
    print("  Source: github.com/VirusTotal/yara/releases")
    print("  Note: If URL fails, check https://github.com/VirusTotal/yara/releases for latest")

    success = download_and_extract_zip(url, dest_dir, 'YARA malware scanner')
    return success


def bundle_testssl():
    """Download testssl.sh."""
    print("\n[testssl.sh] Downloading testssl.sh...")
    dest_dir = TOOLS_DIR / 'testssl'
    dest_dir.mkdir(parents=True, exist_ok=True)

    testssl_sh = dest_dir / 'testssl.sh'
    if testssl_sh.exists():
        print(f"  testssl.sh: already present at {testssl_sh}")
        return True

    url = 'https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2/main.zip'
    print("  Source: github.com/drwetter/testssl.sh")
    print("  Note: Requires Git Bash or WSL to run on Windows")

    success = download_and_extract_zip(url, dest_dir, 'testssl.sh SSL/TLS tester')
    return success


def bundle_wordlists():
    """Create embedded wordlists for password/directory testing."""
    print("\n[Wordlists] Creating security wordlists...")
    dest_dir = TOOLS_DIR / 'wordlists'
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Common passwords list (top 1000)
    passwords_file = dest_dir / 'common-passwords.txt'
    if not passwords_file.exists():
        # Top common passwords (shortened sample - real deployment would have full list)
        common_passwords = [
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "michael", "shadow", "123123", "654321", "superman",
            "qazwsx", "michael", "football", "password1", "password123",
            "batman", "login", "admin", "princess", "welcome",
            "solo", "qwerty123", "starwars", "passw0rd", "hello",
            "charlie", "donald", "loveme", "master1", "jordan",
            "access", "flower", "hottie", "jesus", "lovely",
            "7777777", "000000", "password2", "123456789", "nicole",
            "summer", "1q2w3e4r", "jessica", "ranger", "hunter",
            "maggie", "pepper", "ginger", "abcdef", "joshua",
            "tigger", "1q2w3e", "q1w2e3r4", "qwert", "zxcvbn",
            "computer", "soccer", "buster", "secret", "cookie",
            "thunder", "matrix", "sparky", "jordan23", "thomas",
            "hammer", "killer", "george", "harley", "robert",
            "andrew", "charlie1", "andrea", "joshua1", "asshole",
            "fuckyou", "winner", "jasmine", "justin", "samsung",
            "corvette", "mercedes", "diamond", "midnight", "richard",
            "yankees", "silver", "golfing", "jackson", "bigdog",
            "P@ssw0rd", "P@ssword1", "Passw0rd!", "Admin123",
            "Welcome1", "Changeme1", "Password!", "Test1234",
            "Winter2024", "Summer2024", "Spring2024", "Company1",
        ]
        passwords_file.write_text('\n'.join(common_passwords), encoding='utf-8')
        print(f"  Created: {passwords_file} ({len(common_passwords)} entries)")
    else:
        print(f"  common-passwords.txt: already present")

    # Common web directories
    dirs_file = dest_dir / 'common-dirs.txt'
    if not dirs_file.exists():
        common_dirs = [
            "admin", "login", "wp-admin", "wp-login.php", "administrator",
            "api", "v1", "v2", "graphql", "swagger", "docs",
            "backup", "backups", "db", "database", "sql",
            ".git", ".svn", ".env", ".htaccess", ".htpasswd",
            "config", "configuration", "settings", "setup", "install",
            "upload", "uploads", "files", "media", "images",
            "test", "testing", "debug", "dev", "staging",
            "phpmyadmin", "phpinfo.php", "info.php", "server-status",
            "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
            "console", "shell", "cmd", "terminal", "manage",
            "dashboard", "portal", "cpanel", "webmail", "mail",
            "xmlrpc.php", "wp-content", "wp-includes", "readme.html",
            ".well-known", "favicon.ico", "humans.txt",
            "cgi-bin", "bin", "scripts", "includes", "assets",
            "static", "public", "private", "internal", "secret",
            "tmp", "temp", "cache", "log", "logs",
            "status", "health", "metrics", "monitoring", "trace",
            "actuator", "env", "heapdump", "threaddump", "mappings",
        ]
        dirs_file.write_text('\n'.join(common_dirs), encoding='utf-8')
        print(f"  Created: {dirs_file} ({len(common_dirs)} entries)")
    else:
        print(f"  common-dirs.txt: already present")

    # Default usernames
    users_file = dest_dir / 'common-users.txt'
    if not users_file.exists():
        common_users = [
            "admin", "administrator", "root", "user", "test",
            "guest", "info", "mysql", "postgres", "oracle",
            "ftp", "anonymous", "www-data", "nginx", "apache",
            "operator", "manager", "adm", "sysadmin", "webmaster",
            "support", "backup", "service", "deploy", "jenkins",
            "git", "svn", "tomcat", "jboss", "wildfly",
            "sa", "dba", "dbadmin", "sysop", "nobody",
        ]
        users_file.write_text('\n'.join(common_users), encoding='utf-8')
        print(f"  Created: {users_file} ({len(common_users)} entries)")
    else:
        print(f"  common-users.txt: already present")

    return True


def show_status():
    """Show what tools are currently bundled."""
    print("\n  Tool Bundle Status:")
    print(f"  Tools directory: {TOOLS_DIR}")
    print()

    if not TOOLS_DIR.exists():
        print("  No tools directory found.")
        return

    total_size = 0
    for item in sorted(TOOLS_DIR.rglob('*')):
        if item.is_file():
            total_size += item.stat().st_size

    # Check each tool category
    categories = {
        'Nmap': TOOLS_DIR / 'nmap' / 'nmap.exe',
        'Nuclei': TOOLS_DIR / 'nuclei.exe',
        'Gobuster': TOOLS_DIR / 'gobuster',
        'Amass': TOOLS_DIR / 'amass',
        'YARA': TOOLS_DIR / 'yara',
        'testssl.sh': TOOLS_DIR / 'testssl',
        'Sysinternals': TOOLS_DIR / 'sysinternals',
        'Wordlists': TOOLS_DIR / 'wordlists',
    }

    for name, path in categories.items():
        if path.exists():
            if path.is_file():
                size = path.stat().st_size / (1024 * 1024)
                print(f"  {name:20s} PRESENT  ({size:.1f} MB)")
            else:
                files = list(path.rglob('*'))
                file_count = sum(1 for f in files if f.is_file())
                dir_size = sum(f.stat().st_size for f in files if f.is_file()) / (1024 * 1024)
                print(f"  {name:20s} PRESENT  ({file_count} files, {dir_size:.1f} MB)")
        else:
            print(f"  {name:20s} MISSING")

    print(f"\n  Total size: {total_size / (1024 * 1024):.1f} MB")


def main():
    parser = argparse.ArgumentParser(
        description='Download portable security tools for air-gapped deployment')
    parser.add_argument('--all', action='store_true',
                       help='Download all available tools')
    parser.add_argument('--nmap', action='store_true',
                       help='Download nmap portable')
    parser.add_argument('--sysinternals', action='store_true',
                       help='Download Microsoft Sysinternals tools')
    parser.add_argument('--yara', action='store_true',
                       help='Download YARA malware scanner')
    parser.add_argument('--testssl', action='store_true',
                       help='Download testssl.sh')
    parser.add_argument('--wordlists', action='store_true',
                       help='Create security wordlists')
    parser.add_argument('--status', action='store_true',
                       help='Show what tools are currently bundled')

    args = parser.parse_args()

    banner()

    if args.status:
        show_status()
        return

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    specific = any([args.nmap, args.sysinternals, args.yara, args.testssl, args.wordlists])

    if args.all or args.nmap or not specific:
        bundle_nmap()

    if args.all or args.sysinternals:
        bundle_sysinternals()

    if args.all or args.yara:
        bundle_yara()

    if args.all or args.testssl:
        bundle_testssl()

    if args.all or args.wordlists:
        bundle_wordlists()

    if args.all and not specific:
        # Also get sysinternals when --all
        bundle_sysinternals()

    print()
    show_status()
    print()
    print("  Done! Copy the tools/ directory for air-gapped deployment.")
    print()


if __name__ == '__main__':
    main()
