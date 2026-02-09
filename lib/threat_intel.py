#!/usr/bin/env python3
"""
Purple Team Platform v6.0 - Threat Intelligence Manager
Integrates CISA KEV catalog and EPSS scores for finding enrichment.
Surpasses OpenVAS: they lack CISA KEV and EPSS integration entirely.
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('threat_intel')

# URLs for threat intelligence feeds
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Cache TTL: 24 hours
CACHE_TTL_SECONDS = 86400


class ThreatIntelManager:
    """Manages CISA KEV and EPSS threat intelligence data."""

    _instance: Optional['ThreatIntelManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.cache_dir = paths.data / 'threat_intel'
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.kev_cache_path = self.cache_dir / 'cisa_kev.json'
        self.epss_cache_path = self.cache_dir / 'epss_cache.json'

        self._kev_data: Optional[Dict] = None
        self._epss_cache: Dict[str, Dict] = {}

        self._load_caches()

    def _load_caches(self):
        """Load cached data from disk. Always loads even if stale (for airgapped use)."""
        # Load KEV cache - always load, refresh later if needed
        if self.kev_cache_path.exists():
            try:
                with open(self.kev_cache_path, 'r') as f:
                    cached = json.load(f)
                self._kev_data = cached
                age_hours = (time.time() - cached.get('_cached_at', 0)) / 3600
                entry_count = len(cached.get('vulnerabilities', []))
                if age_hours > CACHE_TTL_SECONDS / 3600:
                    logger.debug(f"Loaded KEV cache (stale, {age_hours:.0f}h old): {entry_count} entries")
                else:
                    logger.debug(f"Loaded KEV cache: {entry_count} entries")
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Error loading KEV cache: {e}")

        # Load EPSS cache - always load, refresh later if needed
        if self.epss_cache_path.exists():
            try:
                with open(self.epss_cache_path, 'r') as f:
                    cached = json.load(f)
                self._epss_cache = cached.get('scores', {})
                age_hours = (time.time() - cached.get('_cached_at', 0)) / 3600
                if age_hours > CACHE_TTL_SECONDS / 3600:
                    logger.debug(f"Loaded EPSS cache (stale, {age_hours:.0f}h old): {len(self._epss_cache)} entries")
                else:
                    logger.debug(f"Loaded EPSS cache: {len(self._epss_cache)} entries")
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Error loading EPSS cache: {e}")

    def is_cache_stale(self) -> Dict[str, bool]:
        """Check if caches are stale (past TTL). Stale caches still work but should be refreshed."""
        now = time.time()
        kev_age = now - (self._kev_data.get('_cached_at', 0) if self._kev_data else 0)
        epss_stale = True
        if self.epss_cache_path.exists():
            try:
                with open(self.epss_cache_path, 'r') as f:
                    cached = json.load(f)
                epss_age = now - cached.get('_cached_at', 0)
                epss_stale = epss_age > CACHE_TTL_SECONDS
            except (json.JSONDecodeError, OSError):
                pass
        return {
            'kev_stale': kev_age > CACHE_TTL_SECONDS,
            'epss_stale': epss_stale,
            'kev_loaded': self._kev_data is not None,
            'epss_loaded': len(self._epss_cache) > 0,
        }

    def refresh_if_stale(self) -> Dict[str, bool]:
        """Attempt to refresh stale caches. Returns what was refreshed. Safe to call offline."""
        status = self.is_cache_stale()
        refreshed = {'kev': False, 'epss': False}
        if status['kev_stale']:
            refreshed['kev'] = self.update_kev_catalog()
        return refreshed

    def _save_kev_cache(self):
        """Save KEV data to disk cache."""
        if self._kev_data:
            try:
                self._kev_data['_cached_at'] = time.time()
                with open(self.kev_cache_path, 'w') as f:
                    json.dump(self._kev_data, f)
            except OSError as e:
                logger.warning(f"Error saving KEV cache: {e}")

    def _save_epss_cache(self):
        """Save EPSS scores to disk cache."""
        try:
            cache_data = {
                '_cached_at': time.time(),
                'scores': self._epss_cache
            }
            with open(self.epss_cache_path, 'w') as f:
                json.dump(cache_data, f)
        except OSError as e:
            logger.warning(f"Error saving EPSS cache: {e}")

    def update_kev_catalog(self) -> bool:
        """Download and cache the CISA KEV catalog."""
        try:
            import urllib.request
            import ssl

            logger.info("Downloading CISA KEV catalog...")

            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                CISA_KEV_URL,
                headers={'User-Agent': 'PurpleTeamPlatform/6.0'}
            )

            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))

            self._kev_data = data
            self._save_kev_cache()

            vuln_count = len(data.get('vulnerabilities', []))
            logger.info(f"KEV catalog updated: {vuln_count} known exploited vulnerabilities")
            return True

        except Exception as e:
            logger.warning(f"Failed to update KEV catalog: {e}")
            return False

    def query_epss(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Query EPSS API for exploit probability scores."""
        if not cve_ids:
            return {}

        # Check cache first
        uncached = [cve for cve in cve_ids if cve not in self._epss_cache]

        if uncached:
            try:
                import urllib.request
                import ssl
                import urllib.parse

                # EPSS API accepts comma-separated CVE IDs
                cve_param = ','.join(uncached[:100])  # API limit
                url = f"{EPSS_API_URL}?cve={urllib.parse.quote(cve_param)}"

                ctx = ssl.create_default_context()
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'PurpleTeamPlatform/6.0'}
                )

                with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
                    data = json.loads(response.read().decode('utf-8'))

                for entry in data.get('data', []):
                    cve_id = entry.get('cve', '')
                    self._epss_cache[cve_id] = {
                        'epss': float(entry.get('epss', 0)),
                        'percentile': float(entry.get('percentile', 0)),
                        'date': entry.get('date', ''),
                    }

                self._save_epss_cache()
                logger.debug(f"EPSS data fetched for {len(uncached)} CVEs")

            except Exception as e:
                logger.warning(f"Failed to query EPSS API: {e}")

        # Return results for requested CVEs
        results = {}
        for cve_id in cve_ids:
            if cve_id in self._epss_cache:
                results[cve_id] = self._epss_cache[cve_id]
        return results

    def is_in_kev(self, cve_id: str) -> Optional[Dict]:
        """Check if a CVE is in the CISA KEV catalog."""
        if not self._kev_data:
            # Try to load from disk first (might have been added after init)
            self._load_caches()
        if not self._kev_data:
            # Only hit network as last resort
            self.update_kev_catalog()

        if not self._kev_data:
            return None

        for vuln in self._kev_data.get('vulnerabilities', []):
            if vuln.get('cveID', '').upper() == cve_id.upper():
                return {
                    'in_kev': True,
                    'vendor': vuln.get('vendorProject', ''),
                    'product': vuln.get('product', ''),
                    'name': vuln.get('vulnerabilityName', ''),
                    'date_added': vuln.get('dateAdded', ''),
                    'due_date': vuln.get('dueDate', ''),
                    'required_action': vuln.get('requiredAction', ''),
                    'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                    'notes': vuln.get('notes', ''),
                }
        return {'in_kev': False}

    def enrich_finding(self, cve_id: str) -> Dict:
        """
        Enrich a finding with threat intelligence data.

        Returns:
            Dict with KEV status, EPSS score, EPSS percentile, due date if KEV
        """
        enrichment = {
            'cve_id': cve_id,
            'kev_status': False,
            'kev_due_date': None,
            'kev_ransomware': None,
            'kev_required_action': None,
            'epss_score': 0.0,
            'epss_percentile': 0.0,
        }

        # KEV lookup
        kev_result = self.is_in_kev(cve_id)
        if kev_result and kev_result.get('in_kev'):
            enrichment['kev_status'] = True
            enrichment['kev_due_date'] = kev_result.get('due_date')
            enrichment['kev_ransomware'] = kev_result.get('known_ransomware')
            enrichment['kev_required_action'] = kev_result.get('required_action')

        # EPSS lookup
        epss_results = self.query_epss([cve_id])
        if cve_id in epss_results:
            enrichment['epss_score'] = epss_results[cve_id].get('epss', 0.0)
            enrichment['epss_percentile'] = epss_results[cve_id].get('percentile', 0.0)

        return enrichment

    def enrich_findings_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Batch enrich multiple CVEs at once (more efficient)."""
        results = {}

        if not cve_ids:
            return results

        # Batch EPSS query
        epss_results = self.query_epss(cve_ids)

        # Individual KEV lookups (KEV is local cache, fast)
        for cve_id in cve_ids:
            enrichment = {
                'cve_id': cve_id,
                'kev_status': False,
                'kev_due_date': None,
                'kev_ransomware': None,
                'kev_required_action': None,
                'epss_score': 0.0,
                'epss_percentile': 0.0,
            }

            kev_result = self.is_in_kev(cve_id)
            if kev_result and kev_result.get('in_kev'):
                enrichment['kev_status'] = True
                enrichment['kev_due_date'] = kev_result.get('due_date')
                enrichment['kev_ransomware'] = kev_result.get('known_ransomware')
                enrichment['kev_required_action'] = kev_result.get('required_action')

            if cve_id in epss_results:
                enrichment['epss_score'] = epss_results[cve_id].get('epss', 0.0)
                enrichment['epss_percentile'] = epss_results[cve_id].get('percentile', 0.0)

            results[cve_id] = enrichment

        return results

    @staticmethod
    def calculate_effective_priority(cvss: float, epss_score: float,
                                      kev: bool) -> float:
        """
        Calculate effective priority score (0-10) using weighted formula.

        Formula: base_cvss * 0.4 + epss_score * 10 * 0.3 + kev_bonus * 0.3
        KEV bonus = 10 if in KEV, 0 otherwise
        """
        kev_bonus = 10.0 if kev else 0.0
        priority = (cvss * 0.4) + (epss_score * 10.0 * 0.3) + (kev_bonus * 0.3)
        return round(min(priority, 10.0), 2)

    def get_kev_stats(self) -> Dict:
        """Get KEV catalog statistics."""
        if not self._kev_data:
            self._load_caches()
        if not self._kev_data:
            self.update_kev_catalog()

        if not self._kev_data:
            return {'status': 'unavailable'}

        vulns = self._kev_data.get('vulnerabilities', [])
        return {
            'status': 'loaded',
            'total_entries': len(vulns),
            'catalog_version': self._kev_data.get('catalogVersion', 'unknown'),
            'last_updated': self._kev_data.get('dateReleased', 'unknown'),
            'cache_age_hours': round(
                (time.time() - self._kev_data.get('_cached_at', 0)) / 3600, 1
            ),
        }

    def get_epss_stats(self) -> Dict:
        """Get EPSS cache statistics."""
        return {
            'cached_scores': len(self._epss_cache),
            'cache_file': str(self.epss_cache_path),
        }


# Singleton accessor
_threat_intel: Optional[ThreatIntelManager] = None


def get_threat_intel() -> ThreatIntelManager:
    """Get the threat intelligence manager singleton."""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelManager()
    return _threat_intel


if __name__ == '__main__':
    # Self-test
    ti = get_threat_intel()
    print("Threat Intelligence Manager initialized")
    print(f"Cache dir: {ti.cache_dir}")

    # Test KEV
    print("\nKEV Statistics:")
    stats = ti.get_kev_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # Test enrichment with a known KEV CVE
    print("\nTesting enrichment for CVE-2021-44228 (Log4Shell):")
    result = ti.enrich_finding('CVE-2021-44228')
    for k, v in result.items():
        print(f"  {k}: {v}")

    # Test priority calculation
    print("\nPriority calculation examples:")
    print(f"  CVSS 9.0, EPSS 0.95, KEV=True:  {ThreatIntelManager.calculate_effective_priority(9.0, 0.95, True)}")
    print(f"  CVSS 7.0, EPSS 0.50, KEV=False: {ThreatIntelManager.calculate_effective_priority(7.0, 0.50, False)}")
    print(f"  CVSS 4.0, EPSS 0.10, KEV=False: {ThreatIntelManager.calculate_effective_priority(4.0, 0.10, False)}")
    print(f"  CVSS 5.0, EPSS 0.30, KEV=True:  {ThreatIntelManager.calculate_effective_priority(5.0, 0.30, True)}")
