#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Multi-Source Intelligence Feed Manager

Ingests threat intelligence from multiple authoritative sources beyond NVD:
- ExploitDB       - Public exploits and PoCs mapped to CVEs
- Google OSV       - Open Source Vulnerability database (PyPI, npm, Go, etc.)
- GitHub Advisories - Security advisories across GitHub ecosystems
- CISA Alerts      - ICS-CERT advisories and Known Exploited Vulnerabilities
- MITRE ATT&CK     - Enterprise tactics, techniques, and mitigations
- abuse.ch         - URLhaus malicious URLs and ThreatFox IOCs

All data stored in data/intel_feeds.db (separate from vuln_intel.db).
Python stdlib only - no external dependencies.
"""

import csv
import io
import json
import os
import re
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('intel_feeds')

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns"  # GET /v1/vulns/{id}
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CISA_ALERTS_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Rate-limit defaults (seconds between requests)
RATE_LIMIT_DEFAULT = 1.0
RATE_LIMIT_GITHUB = 1.5   # 60 req/min unauthenticated
RATE_LIMIT_OSV = 0.5
RATE_LIMIT_NVD = 6.0

# OSV ecosystems to query
OSV_ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "NuGet", "RubyGems", "crates.io"]

# Page size for GitHub Advisories API
GITHUB_PAGE_SIZE = 100


def _create_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """Create an SSL context that works in most environments."""
    if verify:
        try:
            ctx = ssl.create_default_context()
            return ctx
        except Exception:
            pass
    # Fallback: unverified context for hosts with cert issues
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: int = 60) -> bytes:
    """Perform an HTTP GET with proper headers and error handling."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "PurpleTeamGRC/7.0 IntelFeedManager")
    req.add_header("Accept", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = _create_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def _http_post(url: str, data: dict, headers: Optional[Dict[str, str]] = None,
               timeout: int = 60) -> bytes:
    """Perform an HTTP POST with JSON body."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("User-Agent", "PurpleTeamGRC/7.0 IntelFeedManager")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = _create_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


# ===================================================================
# IntelFeedManager
# ===================================================================
class IntelFeedManager:
    """
    Manages ingestion, storage, and querying of multi-source threat
    intelligence feeds.  All data lives in data/intel_feeds.db.
    """

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = paths.data / "intel_feeds.db"
        else:
            self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Database initialisation
    # ------------------------------------------------------------------
    def _init_db(self):
        """Create all tables if they do not already exist."""
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS exploitdb (
                id           INTEGER PRIMARY KEY,
                description  TEXT,
                date_published TEXT,
                platform     TEXT,
                type         TEXT,
                cve_id       TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_exploitdb_cve ON exploitdb(cve_id)
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS osv_vulns (
                id              TEXT PRIMARY KEY,
                summary         TEXT,
                details         TEXT,
                aliases         TEXT,
                ecosystem       TEXT,
                affected_package TEXT,
                severity        TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_osv_ecosystem ON osv_vulns(ecosystem)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_osv_aliases ON osv_vulns(aliases)
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS github_advisories (
                ghsa_id      TEXT PRIMARY KEY,
                cve_id       TEXT,
                summary      TEXT,
                severity     TEXT,
                published_at TEXT,
                updated_at   TEXT,
                ecosystem    TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_ghsa_cve ON github_advisories(cve_id)
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS cisa_alerts (
                id           TEXT PRIMARY KEY,
                title        TEXT,
                description  TEXT,
                published    TEXT,
                severity     TEXT,
                cve_ids      TEXT,
                source       TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_cisa_cve ON cisa_alerts(cve_ids)
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS mitre_attack (
                technique_id TEXT PRIMARY KEY,
                name         TEXT,
                tactic       TEXT,
                description  TEXT,
                platforms    TEXT,
                detection    TEXT,
                mitigations  TEXT
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_mitre_tactic ON mitre_attack(tactic)
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type  TEXT,
                indicator_value TEXT,
                threat_type     TEXT,
                source          TEXT,
                first_seen      TEXT,
                confidence      INTEGER
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_ti_type ON threat_indicators(indicator_type)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_ti_value ON threat_indicators(indicator_value)
        """)

        # Meta table to track last-update timestamps per feed
        c.execute("""
            CREATE TABLE IF NOT EXISTS feed_meta (
                feed_name    TEXT PRIMARY KEY,
                last_updated TEXT,
                record_count INTEGER
            )
        """)

        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        """Return a new connection to the database."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _update_meta(self, conn: sqlite3.Connection, feed_name: str,
                     record_count: int):
        """Update the feed_meta table with last-updated timestamp."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO feed_meta (feed_name, last_updated, record_count) "
            "VALUES (?, ?, ?)",
            (feed_name, now, record_count),
        )

    # ==================================================================
    # 1. ExploitDB
    # ==================================================================
    def update_exploitdb(self) -> Dict[str, Any]:
        """
        Download ExploitDB CSV and store exploits in the exploitdb table.
        Maps exploits to CVE IDs where the codes column contains a CVE reference.
        Returns summary dict with counts.
        """
        print("  [ExploitDB] Downloading CSV from GitLab...")
        try:
            raw = _http_get(EXPLOITDB_CSV_URL, timeout=120)
        except Exception as e:
            msg = f"  [ExploitDB] FAILED to download: {e}"
            print(msg)
            logger.error(msg)
            return {"status": "error", "error": str(e), "count": 0}

        text = raw.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))

        conn = self._conn()
        inserted = 0
        skipped = 0

        # ExploitDB CSV columns (as of 2024):
        #   id, file, description, date_published, author, platform, type, port, codes
        # 'codes' may contain CVE IDs like "CVE-2021-44228;CVE-2021-45046"
        for row in reader:
            try:
                eid = int(row.get("id", 0))
                if eid == 0:
                    skipped += 1
                    continue

                description = row.get("description", "").strip()
                date_pub = row.get("date_published", "").strip()
                platform = row.get("platform", "").strip()
                etype = row.get("type", "").strip()
                codes = row.get("codes", "")

                # Extract CVE IDs from codes field
                cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", codes, re.IGNORECASE)
                cve_str = ";".join(cve_ids) if cve_ids else ""

                conn.execute(
                    "INSERT OR REPLACE INTO exploitdb "
                    "(id, description, date_published, platform, type, cve_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (eid, description, date_pub, platform, etype, cve_str),
                )
                inserted += 1

            except Exception as exc:
                skipped += 1
                if skipped <= 5:
                    logger.warning(f"ExploitDB row parse error: {exc}")

        self._update_meta(conn, "exploitdb", inserted)
        conn.commit()
        conn.close()

        print(f"  [ExploitDB] Done: {inserted:,} exploits stored, {skipped} skipped")
        return {"status": "ok", "count": inserted, "skipped": skipped}

    # ==================================================================
    # 2. Google OSV
    # ==================================================================
    def update_osv(self) -> Dict[str, Any]:
        """
        Query Google OSV API for recent vulnerabilities across key ecosystems.
        Uses POST /v1/query with ecosystem filter, then fetches details.
        Returns summary dict.
        """
        print("  [OSV] Querying ecosystems: {}".format(", ".join(OSV_ECOSYSTEMS)))
        conn = self._conn()
        total_inserted = 0
        errors = []

        for ecosystem in OSV_ECOSYSTEMS:
            print(f"    Ecosystem: {ecosystem} ...", end=" ", flush=True)
            try:
                count = self._osv_fetch_ecosystem(conn, ecosystem)
                total_inserted += count
                print(f"{count} vulns")
            except Exception as e:
                errors.append(f"{ecosystem}: {e}")
                print(f"FAILED ({e})")
                logger.error(f"OSV {ecosystem} error: {e}")
            time.sleep(RATE_LIMIT_OSV)

        self._update_meta(conn, "osv", total_inserted)
        conn.commit()
        conn.close()

        print(f"  [OSV] Done: {total_inserted:,} total vulnerabilities stored")
        result = {"status": "ok", "count": total_inserted}
        if errors:
            result["errors"] = errors
        return result

    def _osv_fetch_ecosystem(self, conn: sqlite3.Connection,
                             ecosystem: str) -> int:
        """Fetch OSV vulns for a single ecosystem via GCS bulk export.
        OSV publishes all.zip per ecosystem at:
        https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
        """
        inserted = 0
        import zipfile
        import io

        url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=120, context=ctx)
            zip_data = resp.read()
        except Exception as e:
            raise RuntimeError(f"Download failed: {e}")

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for name in zf.namelist():
                if not name.endswith('.json'):
                    continue
                try:
                    raw = zf.read(name)
                    v = json.loads(raw)
                    vid = v.get("id", "")
                    if not vid:
                        continue

                    summary = v.get("summary", "")
                    details = v.get("details", "")

                    aliases = v.get("aliases", [])
                    aliases_str = ",".join(aliases) if aliases else ""

                    affected = v.get("affected", [])
                    pkg_name = ""
                    if affected:
                        pkg_info = affected[0].get("package", {})
                        pkg_name = pkg_info.get("name", "")

                    severity_str = ""
                    sev_list = v.get("severity", [])
                    if sev_list:
                        for s in sev_list:
                            if s.get("type") == "CVSS_V3":
                                severity_str = s.get("score", "")
                                break
                        if not severity_str:
                            severity_str = sev_list[0].get("score", "")
                    if not severity_str:
                        db_spec = v.get("database_specific", {})
                        severity_str = db_spec.get("severity", "")

                    conn.execute(
                        "INSERT OR REPLACE INTO osv_vulns "
                        "(id, summary, details, aliases, ecosystem, affected_package, severity) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (vid, summary, details[:4000], aliases_str,
                         ecosystem, pkg_name, severity_str),
                    )
                    inserted += 1
                except Exception:
                    continue
            time.sleep(RATE_LIMIT_OSV)

        return inserted

    # ==================================================================
    # 3. GitHub Advisories
    # ==================================================================
    def update_github_advisories(self) -> Dict[str, Any]:
        """
        Fetch security advisories from the GitHub Advisory Database REST API.
        Handles pagination via Link header. Requires no auth for public advisories
        but is rate-limited to 60 req/hour without a token.
        Set GITHUB_TOKEN env var for 5000 req/hour.
        Returns summary dict.
        """
        print("  [GitHub Advisories] Fetching from API...")
        conn = self._conn()
        inserted = 0
        page = 1
        max_pages = 30  # Safety cap: 30 pages x 100 = 3000 advisories

        headers = {}
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        if gh_token:
            headers["Authorization"] = f"Bearer {gh_token}"
            print("    GitHub token: ACTIVE (5000 req/hr)")
        else:
            print("    GitHub token: none (60 req/hr - set GITHUB_TOKEN for higher rate)")

        while page <= max_pages:
            url = (
                f"{GITHUB_ADVISORIES_URL}"
                f"?type=reviewed&per_page={GITHUB_PAGE_SIZE}&page={page}"
            )
            print(f"    Page {page} ...", end=" ", flush=True)

            try:
                raw = _http_get(url, headers=headers, timeout=30)
                advisories = json.loads(raw)
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    print("RATE LIMITED - stopping")
                    logger.warning("GitHub API rate limit hit")
                    break
                elif e.code == 422:
                    print("PAGINATION LIMIT - stopping")
                    break
                else:
                    print(f"HTTP {e.code} - stopping")
                    break
            except Exception as e:
                print(f"FAILED ({e})")
                break

            if not advisories or not isinstance(advisories, list):
                print("no more results")
                break

            for adv in advisories:
                ghsa_id = adv.get("ghsa_id", "")
                if not ghsa_id:
                    continue

                cve_id = adv.get("cve_id", "") or ""
                summary = adv.get("summary", "")
                severity = adv.get("severity", "")
                published_at = adv.get("published_at", "")
                updated_at = adv.get("updated_at", "")

                # Ecosystem: from vulnerabilities[0].package.ecosystem
                ecosystem = ""
                vulns = adv.get("vulnerabilities", [])
                if vulns and isinstance(vulns, list):
                    pkg = vulns[0].get("package", {})
                    ecosystem = pkg.get("ecosystem", "")

                conn.execute(
                    "INSERT OR REPLACE INTO github_advisories "
                    "(ghsa_id, cve_id, summary, severity, published_at, updated_at, ecosystem) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ghsa_id, cve_id, summary, severity, published_at,
                     updated_at, ecosystem),
                )
                inserted += 1

            count_this_page = len(advisories)
            print(f"{count_this_page} advisories")

            if count_this_page < GITHUB_PAGE_SIZE:
                break  # Last page

            page += 1
            time.sleep(RATE_LIMIT_GITHUB)

        self._update_meta(conn, "github_advisories", inserted)
        conn.commit()
        conn.close()

        print(f"  [GitHub Advisories] Done: {inserted:,} advisories stored")
        return {"status": "ok", "count": inserted}

    # ==================================================================
    # 4. CISA Alerts (KEV JSON + RSS advisories)
    # ==================================================================
    def update_cisa_alerts(self) -> Dict[str, Any]:
        """
        Fetch CISA Known Exploited Vulnerabilities JSON and CISA cybersecurity
        advisories RSS feed.  Stores combined data in cisa_alerts table.
        Returns summary dict.
        """
        print("  [CISA] Fetching KEV and advisories...")
        conn = self._conn()
        total = 0

        # --- Part 1: KEV JSON ---
        try:
            print("    KEV catalog ...", end=" ", flush=True)
            raw = _http_get(CISA_KEV_URL, timeout=60)
            kev = json.loads(raw)

            vulns = kev.get("vulnerabilities", [])
            kev_count = 0
            for v in vulns:
                cve_id = v.get("cveID", "")
                title = v.get("vulnerabilityName", "")
                desc = v.get("shortDescription", "")
                published = v.get("dateAdded", "")
                severity = v.get("knownRansomwareCampaignUse", "Unknown")
                due_date = v.get("dueDate", "")
                vendor = v.get("vendorProject", "")
                product = v.get("product", "")

                alert_id = f"KEV-{cve_id}" if cve_id else f"KEV-{kev_count}"

                conn.execute(
                    "INSERT OR REPLACE INTO cisa_alerts "
                    "(id, title, description, published, severity, cve_ids, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (alert_id,
                     f"{vendor} {product}: {title}",
                     desc,
                     published,
                     severity,
                     cve_id,
                     "CISA-KEV"),
                )
                kev_count += 1
            total += kev_count
            print(f"{kev_count:,} entries")
        except Exception as e:
            print(f"FAILED ({e})")
            logger.error(f"CISA KEV fetch error: {e}")

        time.sleep(RATE_LIMIT_DEFAULT)

        # --- Part 2: CISA Advisories RSS feed ---
        try:
            print("    Advisories RSS ...", end=" ", flush=True)
            raw = _http_get(CISA_ALERTS_RSS_URL, timeout=60,
                            headers={"Accept": "application/xml, text/xml, */*"})
            rss_text = raw.decode("utf-8", errors="replace")
            rss_count = self._parse_cisa_rss(conn, rss_text)
            total += rss_count
            print(f"{rss_count} advisories")
        except Exception as e:
            print(f"FAILED ({e})")
            logger.error(f"CISA RSS fetch error: {e}")

        self._update_meta(conn, "cisa_alerts", total)
        conn.commit()
        conn.close()

        print(f"  [CISA] Done: {total:,} total alerts stored")
        return {"status": "ok", "count": total}

    def _parse_cisa_rss(self, conn: sqlite3.Connection, xml_text: str) -> int:
        """
        Parse CISA RSS/Atom XML advisory feed using stdlib xml.etree.
        We do minimal XML parsing without pulling in lxml.
        """
        import xml.etree.ElementTree as ET

        count = 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.warning(f"CISA RSS XML parse error: {e}")
            return 0

        # RSS 2.0: root is <rss>, items under <channel><item>
        # Atom: root may be <feed>, entries under <entry>
        ns = {"atom": "http://www.w3.org/2005/Atom"}

        # Try RSS 2.0
        items = root.findall(".//item")
        if items:
            for item in items:
                title_el = item.find("title")
                desc_el = item.find("description")
                pub_el = item.find("pubDate")
                link_el = item.find("link")
                guid_el = item.find("guid")

                title = title_el.text if title_el is not None and title_el.text else ""
                desc = desc_el.text if desc_el is not None and desc_el.text else ""
                published = pub_el.text if pub_el is not None and pub_el.text else ""
                link = link_el.text if link_el is not None and link_el.text else ""
                guid = guid_el.text if guid_el is not None and guid_el.text else link

                alert_id = f"CISA-RSS-{guid}" if guid else f"CISA-RSS-{count}"

                # Extract CVE IDs from title + description
                cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {desc}",
                                     re.IGNORECASE)
                cve_str = ",".join(sorted(set(cve_ids)))

                conn.execute(
                    "INSERT OR REPLACE INTO cisa_alerts "
                    "(id, title, description, published, severity, cve_ids, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (alert_id, title, desc[:4000], published, "", cve_str,
                     "CISA-Advisory"),
                )
                count += 1
            return count

        # Try Atom format
        entries = root.findall("atom:entry", ns)
        if not entries:
            entries = root.findall("{http://www.w3.org/2005/Atom}entry")
        for entry in entries:
            title_el = entry.find("atom:title", ns)
            if title_el is None:
                title_el = entry.find("{http://www.w3.org/2005/Atom}title")
            summary_el = entry.find("atom:summary", ns)
            if summary_el is None:
                summary_el = entry.find("{http://www.w3.org/2005/Atom}summary")
            updated_el = entry.find("atom:updated", ns)
            if updated_el is None:
                updated_el = entry.find("{http://www.w3.org/2005/Atom}updated")
            id_el = entry.find("atom:id", ns)
            if id_el is None:
                id_el = entry.find("{http://www.w3.org/2005/Atom}id")

            title = title_el.text if title_el is not None and title_el.text else ""
            summary = summary_el.text if summary_el is not None and summary_el.text else ""
            updated = updated_el.text if updated_el is not None and updated_el.text else ""
            entry_id = id_el.text if id_el is not None and id_el.text else f"atom-{count}"

            alert_id = f"CISA-RSS-{entry_id}"
            cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {summary}",
                                 re.IGNORECASE)
            cve_str = ",".join(sorted(set(cve_ids)))

            conn.execute(
                "INSERT OR REPLACE INTO cisa_alerts "
                "(id, title, description, published, severity, cve_ids, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (alert_id, title, summary[:4000], updated, "", cve_str,
                 "CISA-Advisory"),
            )
            count += 1

        return count

    # ==================================================================
    # 5. MITRE ATT&CK Enterprise
    # ==================================================================
    def update_mitre_attack(self) -> Dict[str, Any]:
        """
        Download the MITRE ATT&CK Enterprise STIX 2.0 bundle and parse
        attack-patterns (techniques), their kill-chain phases (tactics),
        and related mitigations (course-of-action).
        Returns summary dict.
        """
        print("  [MITRE ATT&CK] Downloading Enterprise STIX bundle...")
        try:
            raw = _http_get(MITRE_ATTACK_URL, timeout=180)
        except Exception as e:
            msg = f"  [MITRE ATT&CK] FAILED to download: {e}"
            print(msg)
            logger.error(msg)
            return {"status": "error", "error": str(e), "count": 0}

        data = json.loads(raw)
        objects = data.get("objects", [])
        print(f"    STIX bundle: {len(objects):,} objects")

        # Index objects by ID for relationship resolution
        obj_by_id: Dict[str, dict] = {}
        relationships: List[dict] = []

        for obj in objects:
            oid = obj.get("id", "")
            otype = obj.get("type", "")
            if oid:
                obj_by_id[oid] = obj
            if otype == "relationship":
                relationships.append(obj)

        # Build mitigation map: technique_stix_id -> [mitigation_name, ...]
        mitigation_map: Dict[str, List[str]] = {}
        for rel in relationships:
            if rel.get("relationship_type") != "mitigates":
                continue
            # Exclude revoked/deprecated relationships
            if rel.get("revoked") or rel.get("x_mitre_deprecated"):
                continue
            source_id = rel.get("source_ref", "")
            target_id = rel.get("target_ref", "")
            source_obj = obj_by_id.get(source_id, {})
            if source_obj.get("type") == "course-of-action":
                mitigation_name = source_obj.get("name", "")
                if mitigation_name:
                    mitigation_map.setdefault(target_id, []).append(mitigation_name)

        # Parse attack-patterns (techniques)
        conn = self._conn()
        inserted = 0

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            # External references: get ATT&CK technique ID (e.g. T1059)
            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break
            if not technique_id:
                continue

            name = obj.get("name", "")
            description = obj.get("description", "")

            # Tactics from kill_chain_phases
            phases = obj.get("kill_chain_phases", [])
            tactics = []
            for phase in phases:
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))
            tactic_str = ",".join(tactics) if tactics else ""

            # Platforms
            platforms = obj.get("x_mitre_platforms", [])
            platform_str = ",".join(platforms) if platforms else ""

            # Detection
            detection = obj.get("x_mitre_detection", "")

            # Mitigations
            stix_id = obj.get("id", "")
            mitigations = mitigation_map.get(stix_id, [])
            mitigation_str = "; ".join(mitigations) if mitigations else ""

            conn.execute(
                "INSERT OR REPLACE INTO mitre_attack "
                "(technique_id, name, tactic, description, platforms, detection, mitigations) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (technique_id, name, tactic_str, description[:8000],
                 platform_str, detection[:4000], mitigation_str[:4000]),
            )
            inserted += 1

        self._update_meta(conn, "mitre_attack", inserted)
        conn.commit()
        conn.close()

        print(f"  [MITRE ATT&CK] Done: {inserted:,} techniques stored")
        return {"status": "ok", "count": inserted}

    # ==================================================================
    # 6. abuse.ch feeds (URLhaus + ThreatFox)
    # ==================================================================
    def update_abuse_ch(self) -> Dict[str, Any]:
        """
        Fetch threat indicators from abuse.ch:
          - URLhaus: recently reported malicious URLs
          - ThreatFox: recent IOCs (hashes, domains, IPs, URLs)
        Stores in threat_indicators table.
        Returns summary dict.
        """
        print("  [abuse.ch] Fetching threat feeds...")
        conn = self._conn()
        total = 0

        # --- URLhaus ---
        try:
            print("    URLhaus recent URLs ...", end=" ", flush=True)
            payload = urllib.parse.urlencode({"recent": ""}).encode("utf-8")
            req = urllib.request.Request(URLHAUS_API_URL, data=payload)
            req.add_header("User-Agent", "PurpleTeamGRC/7.0")
            ctx = _create_ssl_context(verify=False)  # abuse.ch certs vary
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                raw = resp.read()
            data = json.loads(raw)
            urls = data.get("urls", [])
            uh_count = 0
            for entry in urls:
                indicator = entry.get("url", "")
                if not indicator:
                    continue
                threat_type = entry.get("threat", "")
                tags = entry.get("tags") or []
                tag_str = ",".join(tags) if isinstance(tags, list) else str(tags)
                first_seen = entry.get("date_added", "")
                urlhaus_ref = entry.get("urlhaus_reference", "")

                conn.execute(
                    "INSERT INTO threat_indicators "
                    "(indicator_type, indicator_value, threat_type, source, first_seen, confidence) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    ("url", indicator, f"{threat_type} [{tag_str}]",
                     f"URLhaus {urlhaus_ref}", first_seen, 80),
                )
                uh_count += 1
            total += uh_count
            print(f"{uh_count:,} URLs")
        except Exception as e:
            print(f"FAILED ({e})")
            logger.error(f"URLhaus fetch error: {e}")

        time.sleep(RATE_LIMIT_DEFAULT)

        # --- ThreatFox ---
        try:
            print("    ThreatFox recent IOCs ...", end=" ", flush=True)
            raw = _http_post(THREATFOX_API_URL,
                             {"query": "get_iocs", "days": 7},
                             timeout=60)
            data = json.loads(raw)

            query_status = data.get("query_status", "")
            iocs = data.get("data", [])
            if query_status != "ok" or not isinstance(iocs, list):
                iocs = []

            tf_count = 0
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type", "")
                ioc_value = ioc.get("ioc", "")
                if not ioc_value:
                    continue

                threat_type = ioc.get("threat_type", "")
                malware = ioc.get("malware_printable", "")
                confidence = ioc.get("confidence_level", 50)
                first_seen = ioc.get("first_seen_utc", "")
                reference = ioc.get("reference", "")

                try:
                    conf_int = int(confidence)
                except (ValueError, TypeError):
                    conf_int = 50

                conn.execute(
                    "INSERT INTO threat_indicators "
                    "(indicator_type, indicator_value, threat_type, source, first_seen, confidence) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (ioc_type, ioc_value, f"{threat_type}: {malware}",
                     f"ThreatFox {reference}", first_seen, conf_int),
                )
                tf_count += 1
            total += tf_count
            print(f"{tf_count:,} IOCs")
        except Exception as e:
            print(f"FAILED ({e})")
            logger.error(f"ThreatFox fetch error: {e}")

        self._update_meta(conn, "abuse_ch", total)
        conn.commit()
        conn.close()

        print(f"  [abuse.ch] Done: {total:,} total indicators stored")
        return {"status": "ok", "count": total}

    # ==================================================================
    # 7. update_all  -- orchestrator
    # ==================================================================
    def update_all(self) -> Dict[str, Any]:
        """
        Run all feed updates sequentially. Failures in one feed do not
        block the others.  Returns a summary dict with per-feed results.
        """
        print()
        print("  ============================================================")
        print("   Intel Feed Manager - Updating All Sources")
        print("  ============================================================")
        print()

        results: Dict[str, Any] = {}
        overall_start = time.time()

        feeds = [
            ("exploitdb", self.update_exploitdb),
            ("osv", self.update_osv),
            ("github_advisories", self.update_github_advisories),
            ("cisa_alerts", self.update_cisa_alerts),
            ("mitre_attack", self.update_mitre_attack),
            ("abuse_ch", self.update_abuse_ch),
        ]

        for name, func in feeds:
            print()
            try:
                results[name] = func()
            except Exception as e:
                results[name] = {"status": "error", "error": str(e), "count": 0}
                print(f"  [{name}] UNEXPECTED ERROR: {e}")
                logger.error(f"Feed {name} failed: {e}")

        elapsed = time.time() - overall_start

        # Summary
        print()
        print("  ============================================================")
        print("   Feed Update Summary")
        print("  ============================================================")
        total_records = 0
        for name, res in results.items():
            count = res.get("count", 0)
            status = res.get("status", "?")
            total_records += count
            marker = "OK" if status == "ok" else "FAIL"
            print(f"    {name:25s}  {marker:4s}  {count:>8,} records")

        print(f"    {'':25s}  ----  {'-' * 8}")
        print(f"    {'TOTAL':25s}        {total_records:>8,} records")
        print(f"    Elapsed: {elapsed:.0f}s")
        print()

        results["_total"] = total_records
        results["_elapsed_seconds"] = elapsed

        # Persist DB size info
        if self.db_path.exists():
            db_mb = self.db_path.stat().st_size / (1024 * 1024)
            results["_db_size_mb"] = round(db_mb, 2)
            print(f"    Database: {self.db_path} ({db_mb:.2f} MB)")
            print()

        return results

    # ==================================================================
    # 8. get_stats
    # ==================================================================
    def get_stats(self) -> Dict[str, Any]:
        """Return record counts for every intel table and feed metadata."""
        conn = self._conn()
        stats: Dict[str, Any] = {}

        tables = [
            "exploitdb", "osv_vulns", "github_advisories",
            "cisa_alerts", "mitre_attack", "threat_indicators",
        ]
        for table in tables:
            try:
                row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                stats[table] = row[0] if row else 0
            except sqlite3.OperationalError:
                stats[table] = 0

        # Feed metadata
        try:
            rows = conn.execute(
                "SELECT feed_name, last_updated, record_count FROM feed_meta"
            ).fetchall()
            meta = {}
            for feed_name, last_updated, record_count in rows:
                meta[feed_name] = {
                    "last_updated": last_updated,
                    "record_count": record_count,
                }
            stats["_meta"] = meta
        except sqlite3.OperationalError:
            stats["_meta"] = {}

        # Database size
        if self.db_path.exists():
            stats["_db_size_mb"] = round(
                self.db_path.stat().st_size / (1024 * 1024), 2
            )

        conn.close()
        return stats

    # ==================================================================
    # 9. search_indicators
    # ==================================================================
    def search_indicators(self, query: str) -> List[Dict[str, Any]]:
        """
        Search across all intel tables for a query string.
        Returns a list of matching records with their source table.
        """
        if not query or len(query) < 2:
            return []

        conn = self._conn()
        conn.row_factory = sqlite3.Row
        results: List[Dict[str, Any]] = []
        like = f"%{query}%"

        # ExploitDB
        for row in conn.execute(
            "SELECT id, description, date_published, platform, type, cve_id "
            "FROM exploitdb WHERE description LIKE ? OR cve_id LIKE ? LIMIT 100",
            (like, like),
        ):
            results.append({
                "source": "exploitdb",
                "id": row["id"],
                "description": row["description"],
                "date": row["date_published"],
                "platform": row["platform"],
                "type": row["type"],
                "cve_id": row["cve_id"],
            })

        # OSV
        for row in conn.execute(
            "SELECT id, summary, aliases, ecosystem, affected_package, severity "
            "FROM osv_vulns WHERE summary LIKE ? OR aliases LIKE ? OR "
            "affected_package LIKE ? LIMIT 100",
            (like, like, like),
        ):
            results.append({
                "source": "osv",
                "id": row["id"],
                "summary": row["summary"],
                "aliases": row["aliases"],
                "ecosystem": row["ecosystem"],
                "package": row["affected_package"],
                "severity": row["severity"],
            })

        # GitHub Advisories
        for row in conn.execute(
            "SELECT ghsa_id, cve_id, summary, severity, published_at, ecosystem "
            "FROM github_advisories WHERE summary LIKE ? OR cve_id LIKE ? OR "
            "ghsa_id LIKE ? LIMIT 100",
            (like, like, like),
        ):
            results.append({
                "source": "github_advisory",
                "ghsa_id": row["ghsa_id"],
                "cve_id": row["cve_id"],
                "summary": row["summary"],
                "severity": row["severity"],
                "published": row["published_at"],
                "ecosystem": row["ecosystem"],
            })

        # CISA Alerts
        for row in conn.execute(
            "SELECT id, title, published, severity, cve_ids, source "
            "FROM cisa_alerts WHERE title LIKE ? OR cve_ids LIKE ? OR "
            "description LIKE ? LIMIT 100",
            (like, like, like),
        ):
            results.append({
                "source": "cisa_alert",
                "id": row["id"],
                "title": row["title"],
                "published": row["published"],
                "severity": row["severity"],
                "cve_ids": row["cve_ids"],
                "feed_source": row["source"],
            })

        # MITRE ATT&CK
        for row in conn.execute(
            "SELECT technique_id, name, tactic, platforms, detection, mitigations "
            "FROM mitre_attack WHERE name LIKE ? OR description LIKE ? OR "
            "technique_id LIKE ? OR tactic LIKE ? LIMIT 100",
            (like, like, like, like),
        ):
            results.append({
                "source": "mitre_attack",
                "technique_id": row["technique_id"],
                "name": row["name"],
                "tactic": row["tactic"],
                "platforms": row["platforms"],
                "detection": row["detection"][:500] if row["detection"] else "",
                "mitigations": row["mitigations"][:500] if row["mitigations"] else "",
            })

        # Threat Indicators
        for row in conn.execute(
            "SELECT indicator_type, indicator_value, threat_type, source, "
            "first_seen, confidence "
            "FROM threat_indicators WHERE indicator_value LIKE ? OR "
            "threat_type LIKE ? LIMIT 200",
            (like, like),
        ):
            results.append({
                "source": "threat_indicator",
                "indicator_type": row["indicator_type"],
                "indicator_value": row["indicator_value"],
                "threat_type": row["threat_type"],
                "feed_source": row["source"],
                "first_seen": row["first_seen"],
                "confidence": row["confidence"],
            })

        conn.close()
        return results

    # ==================================================================
    # 10. correlate_cve
    # ==================================================================
    def correlate_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Given a CVE ID (e.g. 'CVE-2021-44228'), find all related intelligence
        across every feed table.  Returns a dict keyed by source with matching
        records.
        """
        if not cve_id:
            return {}

        cve_upper = cve_id.upper().strip()
        conn = self._conn()
        conn.row_factory = sqlite3.Row
        result: Dict[str, Any] = {"cve_id": cve_upper}

        # ExploitDB: cve_id column may contain multiple CVEs separated by ;
        exploits = []
        for row in conn.execute(
            "SELECT id, description, date_published, platform, type, cve_id "
            "FROM exploitdb WHERE cve_id LIKE ?",
            (f"%{cve_upper}%",),
        ):
            exploits.append(dict(row))
        result["exploitdb"] = exploits

        # OSV: aliases column is CSV of CVE IDs
        osv_matches = []
        for row in conn.execute(
            "SELECT id, summary, aliases, ecosystem, affected_package, severity "
            "FROM osv_vulns WHERE aliases LIKE ?",
            (f"%{cve_upper}%",),
        ):
            osv_matches.append(dict(row))
        result["osv"] = osv_matches

        # GitHub Advisories
        ghsa_matches = []
        for row in conn.execute(
            "SELECT ghsa_id, cve_id, summary, severity, published_at, updated_at, ecosystem "
            "FROM github_advisories WHERE cve_id = ?",
            (cve_upper,),
        ):
            ghsa_matches.append(dict(row))
        result["github_advisories"] = ghsa_matches

        # CISA Alerts
        cisa_matches = []
        for row in conn.execute(
            "SELECT id, title, description, published, severity, cve_ids, source "
            "FROM cisa_alerts WHERE cve_ids LIKE ?",
            (f"%{cve_upper}%",),
        ):
            cisa_matches.append(dict(row))
        result["cisa_alerts"] = cisa_matches

        # MITRE ATT&CK: search in description for CVE reference
        attack_matches = []
        for row in conn.execute(
            "SELECT technique_id, name, tactic, description, platforms, "
            "detection, mitigations "
            "FROM mitre_attack WHERE description LIKE ?",
            (f"%{cve_upper}%",),
        ):
            attack_matches.append({
                "technique_id": row["technique_id"],
                "name": row["name"],
                "tactic": row["tactic"],
                "platforms": row["platforms"],
                "mitigations": row["mitigations"],
            })
        result["mitre_attack"] = attack_matches

        # Threat Indicators: search in threat_type or indicator_value
        ti_matches = []
        for row in conn.execute(
            "SELECT indicator_type, indicator_value, threat_type, source, "
            "first_seen, confidence "
            "FROM threat_indicators WHERE threat_type LIKE ? OR "
            "indicator_value LIKE ?",
            (f"%{cve_upper}%", f"%{cve_upper}%"),
        ):
            ti_matches.append(dict(row))
        result["threat_indicators"] = ti_matches

        # Summary counts
        result["_counts"] = {
            "exploitdb": len(exploits),
            "osv": len(osv_matches),
            "github_advisories": len(ghsa_matches),
            "cisa_alerts": len(cisa_matches),
            "mitre_attack": len(attack_matches),
            "threat_indicators": len(ti_matches),
            "total": (len(exploits) + len(osv_matches) + len(ghsa_matches) +
                      len(cisa_matches) + len(attack_matches) + len(ti_matches)),
        }

        conn.close()
        return result


# ===================================================================
# Module-level convenience function
# ===================================================================
_instance: Optional[IntelFeedManager] = None


def get_intel_feed_manager(db_path: Optional[Path] = None) -> IntelFeedManager:
    """Get or create the IntelFeedManager singleton."""
    global _instance
    if _instance is None:
        _instance = IntelFeedManager(db_path=db_path)
    return _instance


if __name__ == "__main__":
    # Self-test / standalone usage
    import argparse

    parser = argparse.ArgumentParser(description="Intel Feed Manager - standalone")
    parser.add_argument("--update", action="store_true", help="Update all feeds")
    parser.add_argument("--stats", action="store_true", help="Show stats")
    parser.add_argument("--search", type=str, help="Search query")
    parser.add_argument("--correlate", type=str, metavar="CVE_ID",
                        help="Correlate a CVE across all feeds")
    parser.add_argument("--feed", type=str,
                        choices=["exploitdb", "osv", "github", "cisa",
                                 "mitre", "abuse"],
                        help="Update a single feed")
    args = parser.parse_args()

    mgr = IntelFeedManager()

    if args.update:
        mgr.update_all()
    elif args.feed:
        feed_map = {
            "exploitdb": mgr.update_exploitdb,
            "osv": mgr.update_osv,
            "github": mgr.update_github_advisories,
            "cisa": mgr.update_cisa_alerts,
            "mitre": mgr.update_mitre_attack,
            "abuse": mgr.update_abuse_ch,
        }
        feed_map[args.feed]()
    elif args.stats:
        import pprint
        pprint.pprint(mgr.get_stats())
    elif args.search:
        results = mgr.search_indicators(args.search)
        print(f"Found {len(results)} results for '{args.search}':")
        for r in results[:20]:
            print(f"  [{r['source']}] {r}")
    elif args.correlate:
        result = mgr.correlate_cve(args.correlate)
        counts = result.get("_counts", {})
        print(f"Correlation for {args.correlate}: {counts.get('total', 0)} matches")
        for src, cnt in counts.items():
            if src != "total" and cnt > 0:
                print(f"  {src}: {cnt}")
    else:
        parser.print_help()
