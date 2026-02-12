#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Universal Intelligence Downloader

Standalone script to refresh all threat intelligence data from 7+ sources.
Run this on a connected machine, then copy the USB to an airgapped system.

Sources:
  1. CISA KEV       - Known Exploited Vulnerabilities catalog
  2. NVD CVEs       - NIST National Vulnerability Database (2+ years with API key)
  3. EPSS Full CSV  - Exploit Prediction Scoring System (complete dataset)
  4. Exploit-DB     - Public exploit index with CVE mappings
  5. Metasploit     - CVE-to-module mapping
  6. Nuclei         - ProjectDiscovery template CVE index
  7. Vulnrichment   - CISA SSVC triage decisions

Usage:
    python3 bin/update-intel.py                    # Update all sources
    python3 bin/update-intel.py --status           # Show cache status
    python3 bin/update-intel.py --kev-only         # Just CISA KEV
    python3 bin/update-intel.py --nvd-only         # Just NVD
    python3 bin/update-intel.py --epss-only        # Just EPSS full CSV
    python3 bin/update-intel.py --exploits-only    # Exploit-DB + Metasploit + Nuclei
    python3 bin/update-intel.py --vulnrichment-only  # CISA Vulnrichment
    python3 bin/update-intel.py --api-key KEY      # Set NVD API key
    python3 bin/update-intel.py --quick            # Only KEV + EPSS + recent NVD (fast)
"""

import sys
import os
import time
import argparse
import json
import csv
import gzip
import tarfile
import io
import ssl
import urllib.request
import urllib.parse
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Rate delay for NVD API
def _nvd_rate_delay():
    return 0.7 if os.environ.get('NVD_API_KEY') else 6.0

# Resolve project root
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(PROJECT_ROOT / 'scanners'))

# HTTPS context and user-agent
_SSL_CTX = ssl.create_default_context()
_USER_AGENT = 'PurpleTeamPlatform/7.0'


# ============================================================
# Helpers
# ============================================================

def _http_get(url, headers=None, timeout=60):
    """Perform an HTTPS GET request and return the response bytes."""
    hdrs = {'User-Agent': _USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return resp.read()


def _http_get_json(url, headers=None, timeout=60):
    """Perform an HTTPS GET request and return parsed JSON."""
    data = _http_get(url, headers=headers, timeout=timeout)
    return json.loads(data.decode('utf-8'))


def _get_github_token():
    """Try to get a GitHub auth token for higher API rate limits."""
    # Check environment variable first
    token = os.environ.get('GITHUB_TOKEN', '')
    if token:
        return token

    # Try gh CLI
    try:
        gh_path = os.path.expanduser('~/.local/bin/gh')
        if not os.path.isfile(gh_path):
            gh_path = 'gh'
        result = subprocess.run(
            [gh_path, 'auth', 'token'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    return ''


def _github_headers():
    """Return HTTP headers for GitHub API requests, with auth if available."""
    headers = {'Accept': 'application/json'}
    token = _get_github_token()
    if token:
        headers['Authorization'] = 'token ' + token
    return headers


def _fmt_count(n):
    """Format a number with comma separators."""
    return '{:,}'.format(n)


# ============================================================
# Banner
# ============================================================

def banner():
    print()
    print("  ============================================================")
    print("   Purple Team Platform v7.0 - Universal Intel Downloader")
    print("  ============================================================")
    print()


# ============================================================
# 1. CISA KEV
# ============================================================

def update_kev():
    """Update CISA KEV catalog."""
    from threat_intel import get_threat_intel
    ti = get_threat_intel()
    print("[1/7] Refreshing CISA KEV catalog...")
    try:
        if ti.update_kev_catalog():
            stats = ti.get_kev_stats()
            print("  KEV: {} entries".format(stats.get('total_entries', '?')))
            return True
        else:
            print("  KEV: FAILED (no network?)")
            return False
    except Exception as e:
        print("  KEV: FAILED ({})".format(e))
        return False


# ============================================================
# 2. NVD CVEs (multi-window with API key)
# ============================================================

def update_nvd():
    """Update NVD CVE cache with multi-window date-range downloads."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    has_key = bool(os.environ.get('NVD_API_KEY'))
    if has_key:
        print("  NVD API key: ACTIVE (50 req/30s)")
        # Go back 2 years in 90-day windows
        windows = 8  # 8 x 90 days = 720 days ~ 2 years
    else:
        print("  NVD API key: none (5 req/30s - set NVD_API_KEY for 10x speed)")
        # Without key, just do 14 days (too slow otherwise)
        windows = 1

    print("[2/7] Downloading NVD CVEs ({} windows, {} coverage)...".format(
        windows, '~2 years' if windows > 1 else '14 days'))

    total = 0
    for i in range(windows):
        if has_key:
            end_dt = datetime.now(timezone.utc) - timedelta(days=i * 90)
            start_dt = end_dt - timedelta(days=90)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=14)

        # Use lastModStartDate/lastModEndDate to catch modified older CVEs too
        params = {
            'lastModStartDate': start_dt.strftime('%Y-%m-%dT00:00:00.000+00:00'),
            'lastModEndDate': end_dt.strftime('%Y-%m-%dT23:59:59.999+00:00'),
            'resultsPerPage': '2000',
        }

        window_cached = 0
        window_total = 0
        start_index = 0

        while True:
            params['startIndex'] = str(start_index)
            try:
                response = vdb._nvd_api_request(params, timeout=60)
            except Exception:
                response = None

            if not response:
                break

            window_total = response.get('totalResults', 0)
            vulnerabilities = response.get('vulnerabilities', [])

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                parsed = vdb._parse_nvd_cve(item)
                vdb._cache_cve(parsed)
                window_cached += 1

            start_index += len(vulnerabilities)

            if start_index >= window_total:
                break

            time.sleep(_nvd_rate_delay())

        total += window_cached
        print("  Window {}/{}: {} to {}... {} CVEs".format(
            i + 1, windows, start_dt.strftime('%Y-%m-%d'),
            end_dt.strftime('%Y-%m-%d'), _fmt_count(window_cached)))

        if i < windows - 1:
            time.sleep(_nvd_rate_delay())

    print("  NVD date-range total: {} CVEs cached".format(_fmt_count(total)))

    # Keyword searches for common enterprise products
    print("  Running keyword searches for major products...")
    keywords = [
        'Microsoft Exchange', 'Log4j', 'VMware', 'Cisco IOS',
        'WordPress', 'OpenSSL', 'Linux kernel', 'Active Directory',
        'Apache HTTP', 'nginx', 'Fortinet', 'Palo Alto',
        'Citrix', 'SolarWinds', 'Ivanti', 'Atlassian',
        'Docker', 'Kubernetes', 'Jenkins', 'GitLab',
        'Zoom', 'Chrome', 'Firefox', 'Windows SMB',
        'Oracle Java', 'Adobe Reader', 'Grafana', 'Redis',
        'PostgreSQL', 'MySQL', 'MongoDB', 'Elasticsearch',
    ]
    kw_total = 0
    for kw in keywords:
        try:
            result = vdb.update_nvd_by_keyword(kw, max_results=200)
            count = result.get('cached', 0)
            kw_total += count
            if count > 0:
                print("    {}: {} CVEs".format(kw, count))
            time.sleep(_nvd_rate_delay())
        except Exception:
            pass
    print("  Keyword searches: {} CVEs from {} terms".format(
        _fmt_count(kw_total), len(keywords)))

    # Cache famous CVEs individually
    famous_cves = [
        'CVE-2021-44228', 'CVE-2021-45046',   # Log4Shell
        'CVE-2017-0144',                        # EternalBlue
        'CVE-2014-0160',                        # Heartbleed
        'CVE-2021-26855', 'CVE-2021-34473',    # ProxyLogon/ProxyShell
        'CVE-2024-3400',                        # Palo Alto PAN-OS
        'CVE-2023-4966',                        # Citrix Bleed
        'CVE-2023-22515',                       # Confluence
        'CVE-2023-34362',                       # MOVEit
        'CVE-2024-21887',                       # Ivanti
        'CVE-2023-46805',                       # Ivanti
        'CVE-2024-1709',                        # ConnectWise ScreenConnect
        'CVE-2023-27997',                       # FortiGate
        'CVE-2024-47575',                       # FortiManager
        'CVE-2023-20198',                       # Cisco IOS XE
        'CVE-2023-42793',                       # JetBrains TeamCity
        'CVE-2024-0012',                        # Palo Alto PAN-OS
        'CVE-2025-0282',                        # Ivanti Connect Secure 2025
        'CVE-2024-55591',                       # FortiOS 2025
    ]
    cached = 0
    for cve_id in famous_cves:
        try:
            result = vdb.lookup_cve(cve_id)
            if result and result.get('cve_id'):
                cached += 1
        except Exception:
            pass
    print("  Famous CVEs: {}/{} cached".format(cached, len(famous_cves)))

    stats = vdb.get_statistics()
    print("  NVD total: {} CVEs in cache".format(
        _fmt_count(stats.get('cached_cves', 0))))
    return True


def update_nvd_quick():
    """Quick NVD update: just last 14 days, no keyword searches."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()
    print("[2/7] Quick NVD update (last 14 days)...")
    try:
        recent = vdb.update_nvd_recent(days=14)
        print("  NVD recent: {} CVEs cached from {} total".format(
            recent.get('cached', 0), recent.get('total_results', 0)))
    except Exception as e:
        print("  NVD recent: FAILED ({})".format(e))
    return True


# ============================================================
# 3. EPSS Full CSV
# ============================================================

def update_epss_full():
    """Download the complete EPSS dataset as a gzipped CSV."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  EPSS: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    print("[3/7] Downloading complete EPSS dataset...")
    url = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'

    try:
        raw_data = _http_get(url, timeout=120)
    except Exception as e:
        print("  EPSS: FAILED to download ({})".format(e))
        return False

    try:
        decompressed = gzip.decompress(raw_data)
    except Exception as e:
        print("  EPSS: FAILED to decompress ({})".format(e))
        return False

    text_stream = io.StringIO(decompressed.decode('utf-8'))

    # First line is a comment with model version/date (starts with #)
    model_version = ''
    score_date = ''
    first_line = text_stream.readline()
    if first_line.startswith('#'):
        # e.g. "#model_version:v2025.01.01,score_date:2025-02-09T00:00:00+0000"
        model_version = first_line.strip()
        # Try to extract date
        date_match = re.search(r'score_date:(\S+)', first_line)
        if date_match:
            score_date = date_match.group(1)
        ver_match = re.search(r'model_version:(\S+?)(?:,|$)', first_line)
        if ver_match:
            model_version = ver_match.group(1)

    reader = csv.DictReader(text_stream)
    total_scores = 0
    batch = []
    batch_size = 10000

    for row in reader:
        cve_id = row.get('cve', '').strip()
        if not cve_id:
            continue
        try:
            epss_val = float(row.get('epss', 0))
            pct_val = float(row.get('percentile', 0))
        except (ValueError, TypeError):
            continue

        batch.append({
            'cve_id': cve_id,
            'epss': epss_val,
            'percentile': pct_val,
            'model_version': model_version,
            'score_date': score_date,
        })
        total_scores += 1

        if len(batch) >= batch_size:
            vdb.bulk_import_epss(batch)
            batch = []

    # Final batch
    if batch:
        vdb.bulk_import_epss(batch)

    print("  EPSS: {} scores downloaded".format(_fmt_count(total_scores)))
    return True


# ============================================================
# 4. Exploit-DB CSV Index
# ============================================================

def update_exploit_db():
    """Download the Exploit-DB CSV index and extract CVE mappings."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  Exploit-DB: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    print("[4/7] Downloading Exploit-DB index...")
    url = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'

    try:
        raw_data = _http_get(url, timeout=120)
    except Exception as e:
        print("  Exploit-DB: FAILED to download ({})".format(e))
        return False

    text_stream = io.StringIO(raw_data.decode('utf-8'))
    reader = csv.DictReader(text_stream)

    refs = []
    total_exploits = 0
    cve_mapping_count = 0

    for row in reader:
        total_exploits += 1
        edb_id = row.get('id', '').strip()
        description = row.get('description', '').strip()
        codes = row.get('codes', '').strip()

        if not edb_id or not codes:
            continue

        # Extract CVE IDs from the codes column (semicolon-separated)
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', codes, re.IGNORECASE)
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            refs.append({
                'cve_id': cve_id,
                'source': 'exploit-db',
                'ref_id': 'EDB-{}'.format(edb_id),
                'title': description,
                'url': 'https://www.exploit-db.com/exploits/{}'.format(edb_id),
            })
            cve_mapping_count += 1

    if refs:
        # Bulk import in batches to avoid memory issues
        batch_size = 10000
        for i in range(0, len(refs), batch_size):
            vdb.bulk_import_exploit_refs(refs[i:i + batch_size])

    print("  Exploit-DB: {} CVE-to-exploit mappings from {} exploits".format(
        _fmt_count(cve_mapping_count), _fmt_count(total_exploits)))
    return True


# ============================================================
# 5. Metasploit CVE Map
# ============================================================

def update_metasploit():
    """Download the pre-extracted Metasploit CVE mapping."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  Metasploit: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    print("[5/7] Downloading Metasploit CVE mapping...")
    url = 'https://raw.githubusercontent.com/dogasantos/msfcve/main/metasploit_cves.json'

    try:
        data = _http_get_json(url, timeout=60)
    except Exception as e:
        print("  Metasploit: FAILED to download ({})".format(e))
        return False

    refs = []

    # The JSON format is: {"metadata": {...}, "cves": {"CVE-xxx": {"modules": [...]}, ...}}
    # Each module entry is a dict with keys: module_path, name, github_url, etc.
    cve_data = data
    if isinstance(data, dict) and 'cves' in data:
        cve_data = data['cves']

    if isinstance(cve_data, dict):
        for cve_id, cve_entry in cve_data.items():
            cve_id = cve_id.upper().strip()
            if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
                continue

            # Extract module list from the CVE entry
            if isinstance(cve_entry, dict):
                modules = cve_entry.get('modules', [])
            elif isinstance(cve_entry, list):
                modules = cve_entry
            else:
                continue

            if isinstance(modules, list):
                for mod in modules:
                    if isinstance(mod, dict):
                        mod_path = mod.get('module_path', '')
                        mod_name = mod.get('name', '')
                        mod_url = mod.get('github_url', '')
                        if not mod_path:
                            continue
                        if not mod_name:
                            mod_name = mod_path.rsplit('/', 1)[-1] if '/' in mod_path else mod_path
                        refs.append({
                            'cve_id': cve_id,
                            'source': 'metasploit',
                            'ref_id': mod_path,
                            'title': mod_name,
                            'url': mod_url,
                        })
                    elif isinstance(mod, str):
                        mod_name = mod.rsplit('/', 1)[-1] if '/' in mod else mod
                        refs.append({
                            'cve_id': cve_id,
                            'source': 'metasploit',
                            'ref_id': mod,
                            'title': mod_name,
                            'url': '',
                        })

    if refs:
        batch_size = 10000
        for i in range(0, len(refs), batch_size):
            vdb.bulk_import_exploit_refs(refs[i:i + batch_size])

    print("  Metasploit: {} CVE-to-module mappings".format(_fmt_count(len(refs))))
    return True


# ============================================================
# 6. Nuclei Template CVE Index
# ============================================================

def update_nuclei():
    """Download nuclei template CVE listing from GitHub."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  Nuclei: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    print("[6/7] Downloading Nuclei template CVE index...")
    url = 'https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1'

    try:
        gh_hdrs = _github_headers()
        data = _http_get_json(url, headers=gh_hdrs, timeout=120)
    except Exception as e:
        print("  Nuclei: FAILED to download tree ({})".format(e))
        return False

    tree = data.get('tree', [])
    if not tree:
        print("  Nuclei: FAILED (empty tree response)")
        return False

    # Filter for paths matching http/cves/YYYY/CVE-*.yaml
    cve_pattern = re.compile(r'http/cves/\d{4}/(CVE-\d{4}-\d{4,})\.yaml$', re.IGNORECASE)
    refs = []

    for entry in tree:
        path = entry.get('path', '')
        match = cve_pattern.search(path)
        if match:
            cve_id = match.group(1).upper()
            filename = path.rsplit('/', 1)[-1]
            refs.append({
                'cve_id': cve_id,
                'source': 'nuclei',
                'ref_id': filename,
                'title': cve_id,
                'url': 'https://github.com/projectdiscovery/nuclei-templates/blob/main/{}'.format(path),
            })

    if refs:
        batch_size = 10000
        for i in range(0, len(refs), batch_size):
            vdb.bulk_import_exploit_refs(refs[i:i + batch_size])

    print("  Nuclei: {} CVE detection templates".format(_fmt_count(len(refs))))
    return True


# ============================================================
# 7. CISA Vulnrichment (SSVC)
# ============================================================

def update_vulnrichment():
    """Download CISA Vulnrichment SSVC data from GitHub tarball."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  Vulnrichment: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    print("[7/7] Downloading CISA Vulnrichment SSVC data...")
    print("  (This is a ~100MB download, please be patient)")

    url = 'https://api.github.com/repos/cisagov/vulnrichment/tarball/develop'

    try:
        gh_hdrs = _github_headers()
        # Don't set Accept: application/json for tarball download
        gh_hdrs['Accept'] = 'application/vnd.github+json'
        raw_data = _http_get(url, headers=gh_hdrs, timeout=600)
    except Exception as e:
        print("  Vulnrichment: FAILED to download tarball ({})".format(e))
        return False

    print("  Downloaded {:.1f} MB, extracting...".format(len(raw_data) / 1048576))

    entries = []
    files_processed = 0
    cve_json_pattern = re.compile(r'/\d{4}/\d+xxx/(CVE-\d{4}-\d{4,})\.json$')

    try:
        tar_stream = io.BytesIO(raw_data)
        with tarfile.open(fileobj=tar_stream, mode='r:gz') as tar:
            for member in tar:
                if not member.isfile():
                    continue

                match = cve_json_pattern.search(member.name)
                if not match:
                    continue

                cve_id = match.group(1).upper()
                files_processed += 1

                try:
                    f = tar.extractfile(member)
                    if not f:
                        continue
                    cve_data = json.loads(f.read().decode('utf-8'))
                    f.close()
                except Exception:
                    continue

                # Parse CVE JSON 5.0 format for SSVC data
                # Look in containers.adp array for CISA provider
                try:
                    containers = cve_data.get('containers', {})
                    if not isinstance(containers, dict):
                        continue
                    adp_list = containers.get('adp', [])
                    if not isinstance(adp_list, list):
                        adp_list = [adp_list] if adp_list else []

                    for adp in adp_list:
                        if not isinstance(adp, dict):
                            continue
                        provider_org = adp.get('providerMetadata', {}).get('shortName', '')
                        if provider_org.upper() != 'CISA-ADP':
                            continue

                        # Look for SSVC in metrics
                        exploitation = ''
                        automatable = ''
                        technical_impact = ''

                        # Check x_ssvc at top level of adp
                        x_ssvc = adp.get('x_ssvc', {})
                        if isinstance(x_ssvc, dict) and x_ssvc:
                            exploitation = x_ssvc.get('exploitation', '')
                            automatable = x_ssvc.get('automatable', '')
                            technical_impact = x_ssvc.get('technicalImpact', '')

                        # Also check metrics array for SSVC content
                        metrics = adp.get('metrics', [])
                        if isinstance(metrics, list):
                            for metric in metrics:
                                if not isinstance(metric, dict):
                                    continue
                                other = metric.get('other', {})
                                if not isinstance(other, dict):
                                    continue
                                if other.get('type') == 'ssvc':
                                    content = other.get('content', {})
                                    if not isinstance(content, dict):
                                        continue
                                    # options can be a list of dicts or a dict
                                    raw_opts = content.get('options', {})
                                    if isinstance(raw_opts, list):
                                        opts = {}
                                        for o in raw_opts:
                                            if isinstance(o, dict):
                                                opts.update(o)
                                    elif isinstance(raw_opts, dict):
                                        opts = raw_opts
                                    else:
                                        opts = {}
                                    # Direct keys
                                    if not exploitation:
                                        exploitation = (content.get('exploitation', '') or
                                                       opts.get('Exploitation', ''))
                                    if not automatable:
                                        automatable = (content.get('automatable', '') or
                                                      opts.get('Automatable', ''))
                                    if not technical_impact:
                                        technical_impact = (content.get('technicalImpact', '') or
                                                           content.get('technical_impact', '') or
                                                           opts.get('Technical Impact', ''))

                        if exploitation or automatable or technical_impact:
                            entries.append({
                                'cve_id': cve_id,
                                'exploitation': exploitation.lower() if exploitation else '',
                                'automatable': automatable.lower() if automatable else '',
                                'technical_impact': technical_impact.lower() if technical_impact else '',
                                'provider': 'CISA-ADP',
                            })
                            break  # Only need one CISA ADP entry per CVE
                except Exception:
                    continue  # Skip malformed CVE files

                if files_processed % 10000 == 0:
                    print("  Processed {} CVE files...".format(_fmt_count(files_processed)))

    except Exception as e:
        print("  Vulnrichment: FAILED to extract tarball ({})".format(e))
        return False

    if entries:
        batch_size = 10000
        for i in range(0, len(entries), batch_size):
            vdb.bulk_import_vulnrichment(entries[i:i + batch_size])

    print("  Vulnrichment: {} SSVC triage decisions (from {} CVE files)".format(
        _fmt_count(len(entries)), _fmt_count(files_processed)))
    return True


# ============================================================
# Status Display
# ============================================================

def show_status():
    """Show current cache status for all sources."""
    import sqlite3
    from threat_intel import get_threat_intel

    ti = get_threat_intel()
    stale = ti.is_cache_stale()
    kev_stats = ti.get_kev_stats()

    print("  CISA KEV:")
    if kev_stats.get('status') == 'loaded':
        print("    Entries: {}".format(kev_stats.get('total_entries', '?')))
        print("    Version: {}".format(kev_stats.get('catalog_version', '?')))
        print("    Age: {:.1f} hours".format(kev_stats.get('cache_age_hours', 0)))
        print("    Stale: {}".format(stale.get('kev_stale', True)))
    else:
        print("    Status: NOT LOADED")

    try:
        from vuln_database import get_vuln_database
        vdb = get_vuln_database()
        stats = vdb.get_statistics()

        print()
        print("  NVD (vuln_intel.db):")
        print("    CVEs cached: {}".format(_fmt_count(stats.get('cached_cves', 0))))
        db_size = vdb.db_path.stat().st_size if vdb.db_path.exists() else 0
        print("    DB size: {:.1f} MB".format(db_size / 1048576))
        if stats.get('last_nvd_update'):
            print("    Last update: {}".format(stats['last_nvd_update']))

        # EPSS scores from bulk table
        try:
            conn = sqlite3.connect(str(vdb.db_path))
            epss_count = conn.execute('SELECT COUNT(*) FROM epss_scores').fetchone()[0]
            conn.close()
            print()
            print("  EPSS (bulk scores):")
            print("    Scores cached: {}".format(_fmt_count(epss_count)))
        except (sqlite3.Error, Exception):
            print()
            print("  EPSS: no bulk scores")

        # Exploit references
        try:
            conn = sqlite3.connect(str(vdb.db_path))
            edb_count = conn.execute(
                "SELECT COUNT(*) FROM exploit_refs WHERE source='exploit-db'"
            ).fetchone()[0]
            msf_count = conn.execute(
                "SELECT COUNT(*) FROM exploit_refs WHERE source='metasploit'"
            ).fetchone()[0]
            nuclei_count = conn.execute(
                "SELECT COUNT(*) FROM exploit_refs WHERE source='nuclei'"
            ).fetchone()[0]
            total_refs = conn.execute(
                "SELECT COUNT(*) FROM exploit_refs"
            ).fetchone()[0]
            unique_cves_with_exploits = conn.execute(
                "SELECT COUNT(DISTINCT cve_id) FROM exploit_refs"
            ).fetchone()[0]
            conn.close()

            print()
            print("  Exploit References:")
            print("    Exploit-DB: {} mappings".format(_fmt_count(edb_count)))
            print("    Metasploit: {} mappings".format(_fmt_count(msf_count)))
            print("    Nuclei: {} templates".format(_fmt_count(nuclei_count)))
            print("    Total: {} refs covering {} unique CVEs".format(
                _fmt_count(total_refs), _fmt_count(unique_cves_with_exploits)))
        except (sqlite3.Error, Exception):
            print()
            print("  Exploit References: no data")

        # Vulnrichment
        try:
            conn = sqlite3.connect(str(vdb.db_path))
            vr_count = conn.execute('SELECT COUNT(*) FROM vulnrichment').fetchone()[0]
            conn.close()
            print()
            print("  CISA Vulnrichment (SSVC):")
            print("    Triage decisions: {}".format(_fmt_count(vr_count)))
        except (sqlite3.Error, Exception):
            print()
            print("  Vulnrichment: no data")

    except ImportError:
        print()
        print("  NVD: module not available")

    # EPSS via threat_intel (legacy)
    epss_stats = ti.get_epss_stats()
    if epss_stats.get('cached_scores', 0) > 0:
        print()
        print("  EPSS (legacy cache):")
        print("    Cached scores: {}".format(epss_stats.get('cached_scores', 0)))


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Purple Team Platform v7.0 - Universal Intelligence Downloader')
    parser.add_argument('--kev-only', action='store_true',
                       help='Only update CISA KEV catalog')
    parser.add_argument('--nvd-only', action='store_true',
                       help='Only update NVD CVE cache')
    parser.add_argument('--epss-only', action='store_true',
                       help='Only update EPSS full CSV scores')
    parser.add_argument('--exploits-only', action='store_true',
                       help='Only update Exploit-DB + Metasploit + Nuclei')
    parser.add_argument('--vulnrichment-only', action='store_true',
                       help='Only update CISA Vulnrichment SSVC data')
    parser.add_argument('--status', action='store_true',
                       help='Show current cache status')
    parser.add_argument('--api-key', type=str,
                       help='NVD API key (or set NVD_API_KEY env var)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick mode: KEV + EPSS + recent NVD only')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Minimal output')

    args = parser.parse_args()

    # Set API key from arg if provided (takes precedence over env var)
    if args.api_key:
        os.environ['NVD_API_KEY'] = args.api_key

    if not args.quiet:
        banner()

    if args.status:
        show_status()
        return

    specific = (args.kev_only or args.nvd_only or args.epss_only or
                args.exploits_only or args.vulnrichment_only)

    start = time.time()

    if args.quick:
        # Quick mode: KEV + EPSS + recent NVD
        update_kev()
        update_epss_full()
        update_nvd_quick()
    elif specific:
        if args.kev_only:
            update_kev()
        if args.nvd_only:
            update_nvd()
        if args.epss_only:
            update_epss_full()
        if args.exploits_only:
            update_exploit_db()
            update_metasploit()
            update_nuclei()
        if args.vulnrichment_only:
            update_vulnrichment()
    else:
        # Full update: all 7 sources
        update_kev()
        update_nvd()
        update_epss_full()
        update_exploit_db()
        update_metasploit()
        update_nuclei()
        update_vulnrichment()

    elapsed = time.time() - start

    if not args.quiet:
        print()
        print("  Done in {:.0f}s ({:.1f} min)".format(elapsed, elapsed / 60))
        print()
        show_status()
        print()


if __name__ == '__main__':
    main()
