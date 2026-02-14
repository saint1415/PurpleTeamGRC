#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Intel Data Updater

Standalone script to refresh all threat intelligence data.
Run this on a connected machine, then copy the USB to an airgapped system.

Usage:
    python3 bin/update-intel.py                   # Incremental update (default)
    python3 bin/update-intel.py --full             # Full NVD bulk download (250K+ CVEs)
    python3 bin/update-intel.py --incremental      # Only new/modified since last run
    python3 bin/update-intel.py --year 2024        # Download a specific year
    python3 bin/update-intel.py --kev-only         # Just CISA KEV catalog
    python3 bin/update-intel.py --nvd-only         # Just NVD CVE cache (incremental)
    python3 bin/update-intel.py --epss-only        # Just EPSS scores
    python3 bin/update-intel.py --status           # Show cache status
"""

import sys
import os
import time
import argparse
from pathlib import Path

def _nvd_rate_delay():
    return 0.7 if os.environ.get('NVD_API_KEY') else 6.0

# Resolve project root
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(PROJECT_ROOT / 'scanners'))

# Minimal banner
def banner():
    print()
    print("  ============================================================")
    print("   Purple Team Platform v7.0 - Intel Data Updater")
    print("  ============================================================")
    print()


def update_kev():
    """Update CISA KEV catalog."""
    from threat_intel import get_threat_intel
    ti = get_threat_intel()
    print("[1/4] Refreshing CISA KEV catalog...")
    if ti.update_kev_catalog():
        stats = ti.get_kev_stats()
        print("  KEV: {} entries".format(stats.get('total_entries', '?')))
        return True
    else:
        print("  KEV: FAILED (no network?)")
        return False


def update_nvd_full():
    """Full NVD bulk download - all 250K+ CVEs by year."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    has_api_key = bool(os.environ.get('NVD_API_KEY'))
    if has_api_key:
        print("  NVD API key: ACTIVE (50 req/30s)")
        print("  Estimated time: ~30-60 minutes")
    else:
        print("  NVD API key: none (5 req/30s - set NVD_API_KEY for 10x speed)")
        print("  Estimated time: ~2-4 hours")

    print()
    print("[FULL] Downloading ALL CVEs from NVD (1999-present)...")
    print("  This downloads ~250K+ CVEs. Progress shown per year.")
    print()

    download_start = time.time()

    def progress_callback(year, page, total_so_far):
        elapsed = time.time() - download_start
        rate = total_so_far / elapsed if elapsed > 0 else 0
        print("  Year {}: page {} | Total: {:,} CVEs | {:.0f} CVEs/min".format(
            year, page, total_so_far, rate * 60))

    try:
        result = vdb.update_nvd_full(start_year=1999, callback=progress_callback)
        print()
        print("  Full download complete:")
        print("    New CVEs cached: {:,}".format(result.get('new_cached', 0)))
        print("    Already existed: {:,}".format(result.get('already_existed', 0)))
        print("    Total in DB:     {:,}".format(result.get('total_in_db', 0)))
        print("    Years processed: {}".format(result.get('years_processed', 0)))
        print("    Elapsed:         {:.0f}s".format(result.get('elapsed_seconds', 0)))
    except Exception as e:
        print("  NVD full download: FAILED ({})".format(e))
        return False

    stats = vdb.get_statistics()
    print("  NVD total: {:,} CVEs in cache ({:.1f} MB)".format(
        stats.get('cached_cves', 0), stats.get('db_size_mb', 0)))
    return True


def update_nvd_incremental():
    """Incremental NVD update - only new/modified CVEs since last run."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    has_api_key = bool(os.environ.get('NVD_API_KEY'))
    if has_api_key:
        print("  NVD API key: ACTIVE (50 req/30s)")
    else:
        print("  NVD API key: none (5 req/30s - set NVD_API_KEY for 10x speed)")

    print("[INCREMENTAL] Fetching CVEs modified since last update...")

    try:
        result = vdb.update_nvd_incremental()
        print("  Incremental update: {} modified CVEs fetched from {} total".format(
            result.get('cached', 0), result.get('total_results', 0)))
        print("  Period: since {}".format(result.get('since', 'unknown')))
    except Exception as e:
        print("  NVD incremental: FAILED ({})".format(e))
        return False

    stats = vdb.get_statistics()
    print("  NVD total: {:,} CVEs in cache ({:.1f} MB)".format(
        stats.get('cached_cves', 0), stats.get('db_size_mb', 0)))
    return True


def update_nvd_year(year):
    """Download all CVEs for a specific year."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    has_api_key = bool(os.environ.get('NVD_API_KEY'))
    if has_api_key:
        print("  NVD API key: ACTIVE (50 req/30s)")
    else:
        print("  NVD API key: none (5 req/30s - set NVD_API_KEY for 10x speed)")

    print("[YEAR] Downloading all CVEs for year {}...".format(year))

    try:
        result = vdb.update_nvd_year(year)
        print("  Year {}: {}/{} CVEs cached".format(
            year, result.get('cached', 0), result.get('total_results', 0)))
    except Exception as e:
        print("  NVD year {}: FAILED ({})".format(year, e))
        return False

    stats = vdb.get_statistics()
    print("  NVD total: {:,} CVEs in cache ({:.1f} MB)".format(
        stats.get('cached_cves', 0), stats.get('db_size_mb', 0)))
    return True


def update_nvd():
    """Update NVD CVE cache (recent + high-profile) - legacy behavior."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    has_api_key = bool(os.environ.get('NVD_API_KEY'))
    if has_api_key:
        print("  NVD API key: ACTIVE (50 req/30s)")
    else:
        print("  NVD API key: none (5 req/30s - set NVD_API_KEY for 10x speed)")

    # With API key: pull 90 days (NVD max ~90 days per query). Without: 14 days.
    days = 90 if has_api_key else 14
    print("[2/4] Downloading NVD CVEs (last {} days)...".format(days))
    try:
        recent = vdb.update_nvd_recent(days=days)
        print("  NVD recent: {} CVEs cached from {} total".format(
            recent.get('cached', 0), recent.get('total', 0)))
    except Exception as e:
        print("  NVD recent: FAILED ({})".format(e))

    print("[3/4] Caching high-profile CVEs + keyword searches...")
    famous_cves = [
        'CVE-2021-44228', 'CVE-2021-45046',  # Log4Shell
        'CVE-2017-0144',  # EternalBlue
        'CVE-2014-0160',  # Heartbleed
        'CVE-2021-26855', 'CVE-2021-34473',  # ProxyLogon/ProxyShell
        'CVE-2024-3400',  # Palo Alto PAN-OS
        'CVE-2023-4966',  # Citrix Bleed
        'CVE-2023-22515',  # Confluence
        'CVE-2023-34362',  # MOVEit
        'CVE-2024-21887',  # Ivanti
        'CVE-2023-46805',  # Ivanti
        'CVE-2024-1709',  # ConnectWise ScreenConnect
        'CVE-2023-27997',  # FortiGate
        'CVE-2024-47575',  # FortiManager
        'CVE-2023-20198',  # Cisco IOS XE
        'CVE-2023-42793',  # JetBrains TeamCity
        'CVE-2024-0012',  # Palo Alto PAN-OS
        'CVE-2025-0282',  # Ivanti Connect Secure 2025
        'CVE-2024-55591',  # FortiOS 2025
    ]
    cached = 0
    for cve_id in famous_cves:
        try:
            result = vdb.lookup_cve(cve_id)
            if result and result.get('found'):
                cached += 1
        except Exception:
            pass
    print("  Famous CVEs: {}/{} cached".format(cached, len(famous_cves)))

    # Keyword searches for common enterprise products
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
    print("  Keyword searches: {} CVEs from {} terms".format(kw_total, len(keywords)))

    stats = vdb.get_statistics()
    print("  NVD total: {} CVEs in cache".format(stats.get('cached_cves', '?')))
    return True


def update_epss():
    """Pre-fetch EPSS scores for all cached CVEs."""
    try:
        from vuln_database import get_vuln_database
        from threat_intel import get_threat_intel
    except ImportError:
        print("  EPSS: SKIPPED (modules not found)")
        return False

    ti = get_threat_intel()
    vdb = get_vuln_database()

    print("[4/4] Pre-fetching EPSS scores for cached CVEs...")

    # Get all CVE IDs from vuln_intel.db
    import sqlite3
    db_path = vdb.db_path
    if not db_path.exists():
        print("  EPSS: No vuln_intel.db found")
        return False

    conn = sqlite3.connect(str(db_path))
    cursor = conn.execute("SELECT cve_id FROM nvd_cves")
    all_cves = [row[0] for row in cursor.fetchall()]
    conn.close()

    if not all_cves:
        print("  EPSS: No CVEs to query")
        return False

    # Batch query EPSS (API limit 100 per request)
    total_fetched = 0
    batch_size = 100
    for i in range(0, len(all_cves), batch_size):
        batch = all_cves[i:i + batch_size]
        try:
            results = ti.query_epss(batch)
            total_fetched += len(results)
            # Rate limit
            if i + batch_size < len(all_cves):
                time.sleep(1)
        except Exception as e:
            print("  EPSS batch {}: FAILED ({})".format(i // batch_size, e))

    print("  EPSS: {} scores cached for {} CVEs".format(total_fetched, len(all_cves)))
    return True


def show_status():
    """Show current cache status."""
    from threat_intel import get_threat_intel

    ti = get_threat_intel()
    stale = ti.is_cache_stale()
    kev_stats = ti.get_kev_stats()
    epss_stats = ti.get_epss_stats()

    print("  CISA KEV:")
    if kev_stats.get('status') == 'loaded':
        print("    Entries: {}".format(kev_stats.get('total_entries', '?')))
        print("    Version: {}".format(kev_stats.get('catalog_version', '?')))
        print("    Age: {:.1f} hours".format(kev_stats.get('cache_age_hours', 0)))
        print("    Stale: {}".format(stale.get('kev_stale', True)))
    else:
        print("    Status: NOT LOADED")

    print()
    print("  EPSS:")
    print("    Cached scores: {}".format(epss_stats.get('cached_scores', 0)))
    print("    Stale: {}".format(stale.get('epss_stale', True)))

    try:
        from vuln_database import get_vuln_database
        vdb = get_vuln_database()
        stats = vdb.get_statistics()
        print()
        print("  NVD (vuln_intel.db):")
        print("    CVEs cached: {:,}".format(stats.get('cached_cves', 0)))
        db_size = vdb.db_path.stat().st_size if vdb.db_path.exists() else 0
        print("    DB size: {:.1f} MB".format(db_size / 1048576))
    except ImportError:
        print()
        print("  NVD: module not available")


def main():
    parser = argparse.ArgumentParser(
        description='Update Purple Team threat intelligence data')
    parser.add_argument('--full', action='store_true',
                       help='Full NVD bulk download (all 250K+ CVEs, 1999-present)')
    parser.add_argument('--incremental', action='store_true',
                       help='Incremental update (only CVEs modified since last run)')
    parser.add_argument('--year', type=int, metavar='YYYY',
                       help='Download all CVEs for a specific year')
    parser.add_argument('--kev-only', action='store_true',
                       help='Only update CISA KEV catalog')
    parser.add_argument('--nvd-only', action='store_true',
                       help='Only update NVD CVE cache')
    parser.add_argument('--epss-only', action='store_true',
                       help='Only update EPSS scores')
    parser.add_argument('--status', action='store_true',
                       help='Show current cache status')
    parser.add_argument('--api-key', type=str,
                       help='NVD API key (or set NVD_API_KEY env var)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Minimal output')

    args = parser.parse_args()

    # Set API key from arg if provided
    if args.api_key:
        os.environ['NVD_API_KEY'] = args.api_key

    if not args.quiet:
        banner()

    if args.status:
        show_status()
        return

    start = time.time()

    # Handle new bulk download modes
    if args.full:
        update_kev()
        update_nvd_full()
        update_epss()
    elif args.year:
        update_nvd_year(args.year)
    elif args.incremental:
        update_kev()
        update_nvd_incremental()
        update_epss()
    else:
        # Default behavior: incremental if we have existing data, else legacy
        specific = args.kev_only or args.nvd_only or args.epss_only

        if args.kev_only or not specific:
            update_kev()

        if args.nvd_only:
            # --nvd-only now defaults to incremental
            update_nvd_incremental()
        elif not specific:
            update_nvd()

        if args.epss_only or not specific:
            update_epss()

    elapsed = time.time() - start

    if not args.quiet:
        print()
        print("  Done in {:.0f}s".format(elapsed))
        print()
        show_status()
        print()


if __name__ == '__main__':
    main()
