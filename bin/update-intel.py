#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Intel Data Updater

Standalone script to refresh all threat intelligence data.
Run this on a connected machine, then copy the USB to an airgapped system.

Usage:
    python3 bin/update-intel.py              # Update all sources
    python3 bin/update-intel.py --kev-only   # Just CISA KEV catalog
    python3 bin/update-intel.py --nvd-only   # Just NVD CVE cache
    python3 bin/update-intel.py --epss-only  # Just EPSS scores
    python3 bin/update-intel.py --status     # Show cache status
"""

import sys
import os
import time
import argparse
from pathlib import Path

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


def update_nvd():
    """Update NVD CVE cache (recent + high-profile)."""
    try:
        from vuln_database import get_vuln_database
    except ImportError:
        print("  NVD: SKIPPED (vuln_database module not found)")
        return False

    vdb = get_vuln_database()

    print("[2/4] Downloading recent NVD CVEs (14 days)...")
    try:
        recent = vdb.update_nvd_recent(days=14)
        print("  NVD recent: {} CVEs cached from {} total".format(
            recent.get('cached', 0), recent.get('total', 0)))
    except Exception as e:
        print("  NVD recent: FAILED ({})".format(e))

    print("[3/4] Caching high-profile CVEs...")
    famous_cves = [
        'CVE-2021-44228', 'CVE-2021-45046',  # Log4Shell
        'CVE-2017-0144',  # EternalBlue
        'CVE-2014-0160',  # Heartbleed
        'CVE-2021-26855', 'CVE-2021-34473',  # ProxyLogon/ProxyShell
        'CVE-2023-44228',  # Recent critical
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

    stats = vdb.get_statistics()
    print("  NVD total: {} CVEs in cache".format(stats.get('nvd_cves_cached', '?')))
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
        print("    CVEs cached: {}".format(stats.get('cached_cves', 0)))
        db_size = vdb.db_path.stat().st_size if vdb.db_path.exists() else 0
        print("    DB size: {:.1f} MB".format(db_size / 1048576))
    except ImportError:
        print()
        print("  NVD: module not available")


def main():
    parser = argparse.ArgumentParser(
        description='Update Purple Team threat intelligence data')
    parser.add_argument('--kev-only', action='store_true',
                       help='Only update CISA KEV catalog')
    parser.add_argument('--nvd-only', action='store_true',
                       help='Only update NVD CVE cache')
    parser.add_argument('--epss-only', action='store_true',
                       help='Only update EPSS scores')
    parser.add_argument('--status', action='store_true',
                       help='Show current cache status')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Minimal output')

    args = parser.parse_args()

    if not args.quiet:
        banner()

    if args.status:
        show_status()
        return

    specific = args.kev_only or args.nvd_only or args.epss_only

    start = time.time()

    if args.kev_only or not specific:
        update_kev()

    if args.nvd_only or not specific:
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
