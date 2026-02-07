#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - FAIR Risk Quantification
Translates security findings into dollar-quantified risk using FAIR taxonomy.
Surpasses RiskLens ($50K+/yr) with open-source implementation.

FAIR Taxonomy:
  Risk = Loss Event Frequency (LEF) x Loss Magnitude (LM)
  LEF  = Threat Event Frequency (TEF) x Vulnerability
  TEF  = Contact Frequency (CF) x Probability of Action (PA)

Data sources mapped from platform:
  EPSS score       -> Probability of Action (PA)
  KEV status       -> Contact Frequency boost
  CVSS score       -> Resistance Strength (inverted)
  Asset context    -> Loss Magnitude
"""

import json
import math
import random
import sqlite3
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('risk_quantification')


# ---------------------------------------------------------------------------
# Industry benchmarks (IBM / Ponemon Cost of a Data Breach 2025)
# ---------------------------------------------------------------------------
INDUSTRY_BENCHMARKS = {
    'healthcare':    {'avg_breach_cost': 10_930_000, 'cost_per_record': 164, 'benchmark_year': 2025},
    'financial':     {'avg_breach_cost':  5_900_000, 'cost_per_record': 181, 'benchmark_year': 2025},
    'technology':    {'avg_breach_cost':  4_970_000, 'cost_per_record': 175, 'benchmark_year': 2025},
    'government':    {'avg_breach_cost':  2_580_000, 'cost_per_record': 153, 'benchmark_year': 2025},
    'education':     {'avg_breach_cost':  3_650_000, 'cost_per_record': 155, 'benchmark_year': 2025},
    'retail':        {'avg_breach_cost':  3_280_000, 'cost_per_record': 142, 'benchmark_year': 2025},
    'manufacturing': {'avg_breach_cost':  4_730_000, 'cost_per_record': 165, 'benchmark_year': 2025},
    'energy':        {'avg_breach_cost':  4_780_000, 'cost_per_record': 170, 'benchmark_year': 2025},
    'default':       {'avg_breach_cost':  4_450_000, 'cost_per_record': 158, 'benchmark_year': 2025},
}

# Severity-to-CVSS fallback when no explicit CVSS score is provided
SEVERITY_CVSS_DEFAULTS = {
    'CRITICAL': 9.5,
    'HIGH':     7.5,
    'MEDIUM':   5.0,
    'LOW':      2.5,
    'INFO':     0.5,
}

# Contact-frequency ranges (events per year) by exposure type
CF_RANGES = {
    'kev':             (12.0,  30.0,  52.0),   # Known-exploited: weekly to continuous
    'external_facing': ( 4.0,   8.0,  12.0),   # Internet-exposed services
    'internal_only':   ( 1.0,   2.0,   4.0),   # Internal network only
    'default':         ( 2.0,   4.0,   8.0),   # Unknown exposure
}


class RiskQuantifier:
    """
    FAIR-based risk quantification engine.

    Singleton -- use ``get_risk_quantifier()`` to obtain the shared instance.
    All dollar figures are expressed in USD and represent Annualized Loss
    Expectancy (ALE) ranges computed via Monte Carlo simulation.
    """

    _instance: Optional['RiskQuantifier'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_path: Path = paths.evidence_db
        self._ensure_tables()

        # Organization-wide business context (set via set_business_context)
        self._industry: str = 'default'
        self._revenue: float = 0.0
        self._record_count: int = 0
        self._asset_values: Dict[str, float] = {}
        self._business_criticality: Dict[str, str] = {}  # asset_id -> 'critical'|'high'|'medium'|'low'

        logger.info("RiskQuantifier initialized")

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    def _ensure_tables(self):
        """Create the risk_quantification table in the shared evidence DB."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS risk_quantification (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    finding_id TEXT,
                    asset_id TEXT,
                    timestamp TEXT NOT NULL,
                    ale_10th REAL,
                    ale_50th REAL,
                    ale_90th REAL,
                    single_loss REAL,
                    annual_frequency REAL,
                    data_quality_score REAL,
                    industry TEXT,
                    parameters TEXT,
                    UNIQUE(finding_id)
                );

                CREATE INDEX IF NOT EXISTS idx_rq_session
                    ON risk_quantification(session_id);
                CREATE INDEX IF NOT EXISTS idx_rq_finding
                    ON risk_quantification(finding_id);
                CREATE INDEX IF NOT EXISTS idx_rq_asset
                    ON risk_quantification(asset_id);
                CREATE INDEX IF NOT EXISTS idx_rq_ale
                    ON risk_quantification(ale_90th);
            ''')

    # ------------------------------------------------------------------
    # Business context
    # ------------------------------------------------------------------

    def set_business_context(self, industry: str = 'default',
                             revenue: float = 0.0,
                             record_count: int = 0,
                             asset_values: Optional[Dict[str, float]] = None,
                             business_criticality: Optional[Dict[str, str]] = None):
        """
        Set organization-wide context used for loss magnitude estimation.

        Args:
            industry:    Key from INDUSTRY_BENCHMARKS (e.g. 'healthcare').
            revenue:     Annual revenue in USD (used to cap loss estimates).
            record_count: Total PII / sensitive records held.
            asset_values: Mapping of asset IP or ID to dollar value.
            business_criticality: Mapping of asset IP or ID to criticality
                                  ('critical', 'high', 'medium', 'low').
        """
        self._industry = industry if industry in INDUSTRY_BENCHMARKS else 'default'
        self._revenue = max(revenue, 0.0)
        self._record_count = max(record_count, 0)
        self._asset_values = asset_values or {}
        self._business_criticality = business_criticality or {}
        logger.info(
            f"Business context set: industry={self._industry}, "
            f"revenue=${self._revenue:,.0f}, records={self._record_count:,}"
        )

    # ------------------------------------------------------------------
    # Data quality
    # ------------------------------------------------------------------

    def get_data_quality_score(self, finding_dict: Dict,
                               asset_dict: Optional[Dict] = None) -> float:
        """
        Compute a data-quality score (0-100) indicating how much real
        versus default data was available for quantification.

        Scoring components:
            Has real EPSS score:      +20
            Has KEV status check:     +15
            Has asset value set:      +25
            Has record count:         +15
            Has industry benchmarks:  +10
            Has business criticality: +15
        """
        score = 0.0

        # EPSS score present and non-zero
        epss = finding_dict.get('epss_score')
        if epss is not None and float(epss) > 0:
            score += 20.0

        # KEV status explicitly set
        kev = finding_dict.get('kev_status')
        if kev is not None and str(kev).lower() in ('true', 'false', '1', '0'):
            score += 15.0

        # Asset value configured
        asset_ip = finding_dict.get('affected_asset', '')
        asset_id = asset_dict.get('asset_id', '') if asset_dict else ''
        if (asset_ip in self._asset_values or asset_id in self._asset_values or
                (asset_dict and asset_dict.get('value'))):
            score += 25.0

        # Record count known
        record_count = 0
        if asset_dict and asset_dict.get('record_count'):
            record_count = int(asset_dict['record_count'])
        elif self._record_count > 0:
            record_count = self._record_count
        if record_count > 0:
            score += 15.0

        # Industry benchmark configured (not 'default')
        if self._industry != 'default':
            score += 10.0

        # Business criticality set for this asset
        if (asset_ip in self._business_criticality or
                asset_id in self._business_criticality):
            score += 15.0

        return min(score, 100.0)

    # ------------------------------------------------------------------
    # FAIR parameter estimation helpers
    # ------------------------------------------------------------------

    def _estimate_contact_frequency(self, finding: Dict,
                                     asset: Optional[Dict] = None
                                     ) -> Tuple[float, float, float]:
        """
        Estimate Contact Frequency (CF) as a triangular distribution
        triple (low, mode, high) in events-per-year.

        Rules:
            KEV = true            -> 12-52 events/year
            External-facing asset -> 4-12  events/year
            Internal-only asset   -> 1-4   events/year
        """
        kev_status = str(finding.get('kev_status', '')).lower()

        if kev_status in ('true', '1', 'yes'):
            return CF_RANGES['kev']

        # Check if asset is external-facing (by tag, metadata, or port)
        if asset:
            tags = asset.get('tags', '[]')
            if isinstance(tags, str):
                tags = tags.lower()
            else:
                tags = str(tags).lower()

            metadata = asset.get('metadata', '{}')
            if isinstance(metadata, str):
                metadata = metadata.lower()
            else:
                metadata = str(metadata).lower()

            if ('external' in tags or 'dmz' in tags or 'internet' in tags or
                    'external' in metadata or 'public' in metadata):
                return CF_RANGES['external_facing']

            # Heuristic: common internet-facing ports
            ports = asset.get('ports', [])
            external_ports = {80, 443, 8080, 8443, 25, 587, 993, 995}
            if isinstance(ports, list):
                for p in ports:
                    port_num = p.get('port', 0) if isinstance(p, dict) else 0
                    if port_num in external_ports:
                        return CF_RANGES['external_facing']

            return CF_RANGES['internal_only']

        return CF_RANGES['default']

    def _estimate_loss_magnitude(self, finding: Dict,
                                  asset: Optional[Dict] = None
                                  ) -> Tuple[float, float, float]:
        """
        Estimate single-loss magnitude (SLE) as a triangular distribution
        triple (low, mode, high) in USD.

        Uses asset value, record count, and industry benchmarks.
        """
        benchmark = INDUSTRY_BENCHMARKS.get(self._industry,
                                            INDUSTRY_BENCHMARKS['default'])
        cost_per_record = benchmark['cost_per_record']
        avg_breach_cost = benchmark['avg_breach_cost']

        # Determine record count for this asset
        record_count = 0
        if asset and asset.get('record_count'):
            record_count = int(asset['record_count'])
        elif self._record_count > 0:
            record_count = self._record_count

        # Determine asset value
        asset_ip = finding.get('affected_asset', '')
        asset_id = asset.get('asset_id', '') if asset else ''
        asset_value = (
            self._asset_values.get(asset_ip) or
            self._asset_values.get(asset_id) or
            (asset.get('value') if asset else None) or
            0.0
        )

        # Severity multiplier
        severity = finding.get('severity', 'MEDIUM').upper()
        severity_multiplier = {
            'CRITICAL': 1.0,
            'HIGH':     0.6,
            'MEDIUM':   0.3,
            'LOW':      0.1,
            'INFO':     0.01,
        }.get(severity, 0.3)

        # Determine business criticality multiplier
        criticality = (
            self._business_criticality.get(asset_ip) or
            self._business_criticality.get(asset_id) or
            'medium'
        ).lower()
        criticality_multiplier = {
            'critical': 1.5,
            'high':     1.2,
            'medium':   1.0,
            'low':      0.5,
        }.get(criticality, 1.0)

        # Base loss calculation
        if record_count > 0:
            # Record-based estimation
            base_loss = record_count * cost_per_record * severity_multiplier
        elif asset_value > 0:
            # Asset-value-based estimation
            base_loss = asset_value * severity_multiplier
        else:
            # Fall back to industry average, scaled by severity
            base_loss = avg_breach_cost * severity_multiplier

        base_loss *= criticality_multiplier

        # Revenue cap: single loss should not exceed 10% of annual revenue
        if self._revenue > 0:
            base_loss = min(base_loss, self._revenue * 0.10)

        # Build triangular distribution parameters
        low  = base_loss * 0.3
        mode = base_loss
        high = base_loss * 2.5

        # Floor values to avoid degenerate zero distributions
        low  = max(low,  500.0)
        mode = max(mode, 1_000.0)
        high = max(high, 2_500.0)

        return (low, mode, high)

    # ------------------------------------------------------------------
    # Monte Carlo simulation
    # ------------------------------------------------------------------

    def _monte_carlo(self, tef_params: Tuple[float, float, float],
                     vuln_params: Tuple[float, float, float],
                     lm_params: Tuple[float, float, float],
                     iterations: int = 10_000) -> Dict[str, Any]:
        """
        Run Monte Carlo simulation over the FAIR model.

        FAIR decomposition per iteration:
            TEF  = triangular(tef_low, tef_mode, tef_high)
            Vuln = triangular(vuln_low, vuln_mode, vuln_high)   [0-1]
            LEF  = TEF * Vuln
            LM   = triangular(lm_low, lm_mode, lm_high)
            ALE  = LEF * LM

        Returns dict with:
            ale_10th, ale_50th, ale_90th  -- percentile ALE values
            single_loss_50th              -- median single loss
            frequency_50th                -- median annual loss-event frequency
            raw_ales                      -- full list (for further analysis)
        """
        ales: List[float] = []
        single_losses: List[float] = []
        frequencies: List[float] = []

        tef_lo, tef_md, tef_hi = tef_params
        vul_lo, vul_md, vul_hi = vuln_params
        lm_lo, lm_md, lm_hi   = lm_params

        # Clamp vulnerability params to [0, 1]
        vul_lo = max(0.0, min(vul_lo, 1.0))
        vul_md = max(vul_lo, min(vul_md, 1.0))
        vul_hi = max(vul_md, min(vul_hi, 1.0))

        # Ensure triangular constraints: low <= mode <= high
        tef_md = max(tef_lo, min(tef_md, tef_hi))
        lm_md  = max(lm_lo, min(lm_md, lm_hi))

        for _ in range(iterations):
            tef  = random.triangular(tef_lo, tef_hi, tef_md)
            vuln = random.triangular(vul_lo, vul_hi, vul_md)
            lef  = tef * vuln
            lm   = random.triangular(lm_lo, lm_hi, lm_md)
            ale  = lef * lm

            ales.append(ale)
            single_losses.append(lm)
            frequencies.append(lef)

        ales.sort()
        single_losses.sort()
        frequencies.sort()

        def percentile(data: List[float], pct: float) -> float:
            idx = int(len(data) * pct / 100.0)
            idx = max(0, min(idx, len(data) - 1))
            return data[idx]

        return {
            'ale_10th':         round(percentile(ales, 10), 2),
            'ale_50th':         round(percentile(ales, 50), 2),
            'ale_90th':         round(percentile(ales, 90), 2),
            'single_loss_50th': round(percentile(single_losses, 50), 2),
            'frequency_50th':   round(percentile(frequencies, 50), 4),
            'raw_ales':         ales,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _store_result(self, session_id: Optional[str], finding_id: str,
                      asset_id: Optional[str], result: Dict):
        """Store a quantification result in the database."""
        now = datetime.utcnow().isoformat()
        params_json = json.dumps({
            k: v for k, v in result.items() if k != 'raw_ales'
        })

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO risk_quantification
                    (session_id, finding_id, asset_id, timestamp,
                     ale_10th, ale_50th, ale_90th, single_loss,
                     annual_frequency, data_quality_score, industry, parameters)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id, finding_id, asset_id, now,
                result.get('ale_10th', 0),
                result.get('ale_50th', 0),
                result.get('ale_90th', 0),
                result.get('single_loss', 0),
                result.get('frequency', 0),
                result.get('data_quality_score', 0),
                self._industry,
                params_json,
            ))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def quantify_finding(self, finding_dict: Dict,
                         asset_dict: Optional[Dict] = None) -> Dict:
        """
        Quantify a single finding in dollar terms using the FAIR model.

        Args:
            finding_dict: Finding data with keys like severity, cvss_score,
                          epss_score, kev_status, affected_asset, cve_ids, etc.
            asset_dict:   Optional asset data from AssetManager.

        Returns:
            Dict with ale_10th, ale_50th, ale_90th, single_loss, frequency,
            data_quality_score, confidence_warning, and full parameters.
        """
        # --- 1. Data quality assessment ---
        dq_score = self.get_data_quality_score(finding_dict, asset_dict)

        # --- 2. CVSS / Resistance Strength ---
        cvss = finding_dict.get('cvss_score')
        if cvss is None or float(cvss) <= 0:
            severity = finding_dict.get('severity', 'MEDIUM').upper()
            cvss = SEVERITY_CVSS_DEFAULTS.get(severity, 5.0)
        cvss = float(cvss)

        # Resistance Strength = 1 - CVSS/10  (lower CVSS -> higher resistance)
        rs = 1.0 - (cvss / 10.0)
        rs = max(0.01, min(rs, 0.99))

        # Vulnerability = 1 - RS (probability exploit succeeds given attempt)
        vuln_mode = 1.0 - rs
        vuln_low  = max(0.0, vuln_mode - 0.15)
        vuln_high = min(1.0, vuln_mode + 0.10)

        # --- 3. EPSS -> Probability of Action (PA) ---
        epss = finding_dict.get('epss_score')
        if epss is not None and float(epss) > 0:
            pa = float(epss)
        else:
            # Default PA based on severity
            pa = {
                'CRITICAL': 0.60,
                'HIGH':     0.35,
                'MEDIUM':   0.15,
                'LOW':      0.05,
                'INFO':     0.01,
            }.get(finding_dict.get('severity', 'MEDIUM').upper(), 0.15)

        # --- 4. Contact Frequency (CF) ---
        cf_low, cf_mode, cf_high = self._estimate_contact_frequency(
            finding_dict, asset_dict
        )

        # --- 5. TEF = CF * PA (as distribution) ---
        tef_low  = cf_low  * max(pa - 0.10, 0.01)
        tef_mode = cf_mode * pa
        tef_high = cf_high * min(pa + 0.10, 1.0)

        # --- 6. Loss Magnitude ---
        lm_low, lm_mode, lm_high = self._estimate_loss_magnitude(
            finding_dict, asset_dict
        )

        # --- 7. Monte Carlo ---
        mc_result = self._monte_carlo(
            tef_params=(tef_low, tef_mode, tef_high),
            vuln_params=(vuln_low, vuln_mode, vuln_high),
            lm_params=(lm_low, lm_mode, lm_high),
            iterations=10_000,
        )

        # --- 8. Build result ---
        result = {
            'ale_10th':           mc_result['ale_10th'],
            'ale_50th':           mc_result['ale_50th'],
            'ale_90th':           mc_result['ale_90th'],
            'single_loss':        mc_result['single_loss_50th'],
            'frequency':          mc_result['frequency_50th'],
            'data_quality_score': dq_score,
            'confidence_warning': None,
            'parameters': {
                'cvss':      cvss,
                'epss':      pa,
                'kev':       str(finding_dict.get('kev_status', '')).lower() in ('true', '1', 'yes'),
                'industry':  self._industry,
                'tef':       (round(tef_low, 4), round(tef_mode, 4), round(tef_high, 4)),
                'vuln':      (round(vuln_low, 4), round(vuln_mode, 4), round(vuln_high, 4)),
                'lm':        (round(lm_low, 2), round(lm_mode, 2), round(lm_high, 2)),
            },
        }

        # Add confidence warning when data quality is low
        if dq_score < 50:
            result['confidence_warning'] = (
                "ESTIMATE ONLY - configure asset context for accuracy "
                f"(data quality: {dq_score:.0f}%)"
            )

        # --- 9. Persist ---
        finding_id = finding_dict.get('finding_id', finding_dict.get('title', 'unknown'))
        asset_ip = finding_dict.get('affected_asset', '')
        session_id = finding_dict.get('session_id')
        try:
            self._store_result(session_id, finding_id, asset_ip, result)
        except Exception as e:
            logger.warning(f"Failed to store risk result: {e}")

        return result

    def quantify_asset(self, ip_or_asset_id: str,
                       session_id: Optional[str] = None) -> Dict:
        """
        Aggregate risk for a single asset across all its open findings.

        Queries the evidence DB for findings affecting this asset, runs
        quantification on each, and returns aggregated ALE ranges.
        """
        findings = self._get_findings_for_asset(ip_or_asset_id, session_id)

        if not findings:
            return {
                'asset': ip_or_asset_id,
                'finding_count': 0,
                'ale_10th': 0.0,
                'ale_50th': 0.0,
                'ale_90th': 0.0,
                'findings': [],
            }

        results = []
        total_10 = 0.0
        total_50 = 0.0
        total_90 = 0.0

        for f in findings:
            r = self.quantify_finding(f)
            total_10 += r['ale_10th']
            total_50 += r['ale_50th']
            total_90 += r['ale_90th']
            results.append({
                'finding_id': f.get('finding_id', ''),
                'title':      f.get('title', ''),
                'severity':   f.get('severity', ''),
                'ale_50th':   r['ale_50th'],
            })

        results.sort(key=lambda x: x['ale_50th'], reverse=True)

        return {
            'asset':         ip_or_asset_id,
            'finding_count': len(findings),
            'ale_10th':      round(total_10, 2),
            'ale_50th':      round(total_50, 2),
            'ale_90th':      round(total_90, 2),
            'findings':      results,
        }

    def quantify_organization(self, session_id: Optional[str] = None) -> Dict:
        """
        Compute total organizational risk from all open findings.

        Returns aggregated ALE ranges plus per-asset breakdown.
        """
        findings = self._get_all_open_findings(session_id)

        if not findings:
            return {
                'finding_count': 0,
                'asset_count':   0,
                'ale_10th':      0.0,
                'ale_50th':      0.0,
                'ale_90th':      0.0,
                'industry':      self._industry,
                'assets':        {},
            }

        # Group by asset
        asset_findings: Dict[str, List[Dict]] = {}
        for f in findings:
            asset = f.get('affected_asset', 'unknown')
            asset_findings.setdefault(asset, []).append(f)

        total_10 = 0.0
        total_50 = 0.0
        total_90 = 0.0
        asset_summaries: Dict[str, Dict] = {}

        for asset_ip, asset_flist in asset_findings.items():
            asset_10 = 0.0
            asset_50 = 0.0
            asset_90 = 0.0

            for f in asset_flist:
                r = self.quantify_finding(f)
                asset_10 += r['ale_10th']
                asset_50 += r['ale_50th']
                asset_90 += r['ale_90th']

            total_10 += asset_10
            total_50 += asset_50
            total_90 += asset_90

            asset_summaries[asset_ip] = {
                'finding_count': len(asset_flist),
                'ale_10th':      round(asset_10, 2),
                'ale_50th':      round(asset_50, 2),
                'ale_90th':      round(asset_90, 2),
            }

        return {
            'finding_count': len(findings),
            'asset_count':   len(asset_summaries),
            'ale_10th':      round(total_10, 2),
            'ale_50th':      round(total_50, 2),
            'ale_90th':      round(total_90, 2),
            'industry':      self._industry,
            'assets':        asset_summaries,
        }

    def get_top_risks(self, n: int = 10,
                      session_id: Optional[str] = None) -> List[Dict]:
        """
        Return the top N findings by ALE (90th percentile), either from
        cached DB results or by re-quantifying all open findings.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            if session_id:
                rows = conn.execute('''
                    SELECT rq.*, f.title, f.severity, f.affected_asset
                    FROM risk_quantification rq
                    LEFT JOIN findings f ON rq.finding_id = f.finding_id
                    WHERE rq.session_id = ?
                    ORDER BY rq.ale_90th DESC
                    LIMIT ?
                ''', (session_id, n)).fetchall()
            else:
                rows = conn.execute('''
                    SELECT rq.*, f.title, f.severity, f.affected_asset
                    FROM risk_quantification rq
                    LEFT JOIN findings f ON rq.finding_id = f.finding_id
                    ORDER BY rq.ale_90th DESC
                    LIMIT ?
                ''', (n,)).fetchall()

        results = []
        for row in rows:
            rd = dict(row)
            results.append({
                'finding_id':        rd.get('finding_id', ''),
                'title':             rd.get('title', ''),
                'severity':          rd.get('severity', ''),
                'affected_asset':    rd.get('affected_asset', ''),
                'ale_10th':          rd.get('ale_10th', 0),
                'ale_50th':          rd.get('ale_50th', 0),
                'ale_90th':          rd.get('ale_90th', 0),
                'data_quality_score': rd.get('data_quality_score', 0),
            })

        return results

    # ------------------------------------------------------------------
    # Internal helpers - DB queries
    # ------------------------------------------------------------------

    def _get_findings_for_asset(self, ip_or_id: str,
                                 session_id: Optional[str] = None
                                 ) -> List[Dict]:
        """Retrieve open findings from the evidence DB for a given asset."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            if session_id:
                rows = conn.execute('''
                    SELECT * FROM findings
                    WHERE affected_asset = ? AND session_id = ?
                      AND status = 'open'
                      AND (false_positive IS NULL OR false_positive = 0)
                    ORDER BY cvss_score DESC
                ''', (ip_or_id, session_id)).fetchall()
            else:
                rows = conn.execute('''
                    SELECT * FROM findings
                    WHERE affected_asset = ? AND status = 'open'
                      AND (false_positive IS NULL OR false_positive = 0)
                    ORDER BY cvss_score DESC
                ''', (ip_or_id,)).fetchall()

        return [dict(r) for r in rows]

    def _get_all_open_findings(self, session_id: Optional[str] = None
                                ) -> List[Dict]:
        """Retrieve all open findings from the evidence DB."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            if session_id:
                rows = conn.execute('''
                    SELECT * FROM findings
                    WHERE session_id = ? AND status = 'open'
                      AND (false_positive IS NULL OR false_positive = 0)
                    ORDER BY cvss_score DESC
                ''', (session_id,)).fetchall()
            else:
                rows = conn.execute('''
                    SELECT * FROM findings
                    WHERE status = 'open'
                      AND (false_positive IS NULL OR false_positive = 0)
                    ORDER BY cvss_score DESC
                ''', ()).fetchall()

        return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# Singleton accessor
# --------------------------------------------------------------------------

_risk_quantifier: Optional[RiskQuantifier] = None


def get_risk_quantifier() -> RiskQuantifier:
    """Get the risk quantifier singleton."""
    global _risk_quantifier
    if _risk_quantifier is None:
        _risk_quantifier = RiskQuantifier()
    return _risk_quantifier


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

if __name__ == '__main__':
    rq = get_risk_quantifier()
    print("Risk Quantifier initialized")
    print(f"Database: {rq.db_path}")

    # Set business context
    rq.set_business_context(industry='technology', revenue=50_000_000, record_count=100_000)

    # Test with sample finding
    sample_finding = {
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'epss_score': 0.85,
        'kev_status': 'true',
        'title': 'Remote Code Execution',
        'affected_asset': '10.0.0.1',
        'cve_ids': ['CVE-2024-1234'],
    }

    result = rq.quantify_finding(sample_finding)
    print(f"\nFinding Risk Quantification:")
    print(f"  ALE 10th: ${result['ale_10th']:,.0f}")
    print(f"  ALE 50th: ${result['ale_50th']:,.0f}")
    print(f"  ALE 90th: ${result['ale_90th']:,.0f}")
    print(f"  Single Loss (median): ${result['single_loss']:,.0f}")
    print(f"  Annual Frequency: {result['frequency']:.2f}")
    print(f"  Data Quality: {result['data_quality_score']:.0f}%")
    if result.get('confidence_warning'):
        print(f"  WARNING: {result['confidence_warning']}")

    print(f"\n  FAIR Parameters:")
    params = result['parameters']
    print(f"    CVSS:     {params['cvss']}")
    print(f"    EPSS/PA:  {params['epss']}")
    print(f"    KEV:      {params['kev']}")
    print(f"    Industry: {params['industry']}")
    print(f"    TEF:      {params['tef']}")
    print(f"    Vuln:     {params['vuln']}")
    print(f"    LM:       {params['lm']}")

    # Test a lower-severity finding
    low_finding = {
        'severity': 'LOW',
        'cvss_score': 3.1,
        'epss_score': 0.02,
        'kev_status': 'false',
        'title': 'Information Disclosure',
        'affected_asset': '10.0.0.2',
    }

    result2 = rq.quantify_finding(low_finding)
    print(f"\nLow-severity Finding:")
    print(f"  ALE 10th: ${result2['ale_10th']:,.0f}")
    print(f"  ALE 50th: ${result2['ale_50th']:,.0f}")
    print(f"  ALE 90th: ${result2['ale_90th']:,.0f}")
    print(f"  Data Quality: {result2['data_quality_score']:.0f}%")
    if result2.get('confidence_warning'):
        print(f"  WARNING: {result2['confidence_warning']}")

    # Test data quality scoring
    print(f"\nData Quality Scores:")
    full_context_finding = {
        'severity': 'HIGH',
        'cvss_score': 7.5,
        'epss_score': 0.45,
        'kev_status': 'true',
        'affected_asset': '10.0.0.1',
    }
    rq._asset_values['10.0.0.1'] = 500_000
    rq._business_criticality['10.0.0.1'] = 'critical'
    dq = rq.get_data_quality_score(full_context_finding)
    print(f"  Full context: {dq:.0f}%")

    minimal_finding = {
        'severity': 'MEDIUM',
        'title': 'Some Finding',
    }
    dq2 = rq.get_data_quality_score(minimal_finding)
    print(f"  Minimal context: {dq2:.0f}%")

    print("\nAll industry benchmarks:")
    for ind, data in INDUSTRY_BENCHMARKS.items():
        print(f"  {ind}: ${data['avg_breach_cost']:,} avg ({data['benchmark_year']})")

    print("\nSelf-test PASSED")
