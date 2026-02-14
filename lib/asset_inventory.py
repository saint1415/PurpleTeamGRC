#!/usr/bin/env python3
"""
Purple Team GRC Platform - Asset Inventory / CMDB Module
Comprehensive asset tracking with auto-discovery, CSV import/export,
scan coverage metrics, and finding linkage.
"""

import csv
import io
import json
import os
import platform
import socket
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('asset_inventory')


class AssetInventory:
    """Enterprise asset inventory / CMDB backed by SQLite."""

    _instance: Optional['AssetInventory'] = None

    VALID_OS_TYPES = ('windows', 'linux', 'network', 'cloud', 'macos', 'other')
    VALID_CRITICALITIES = ('critical', 'high', 'medium', 'low')
    VALID_ASSET_TYPES = (
        'server', 'workstation', 'network_device', 'cloud_resource', 'container',
    )
    VALID_STATUSES = ('active', 'inactive', 'decommissioned')

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_path = paths.data / 'asset_inventory.db'
        self._ensure_db()

    # ------------------------------------------------------------------
    # Database bootstrap
    # ------------------------------------------------------------------
    def _ensure_db(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS assets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id    TEXT UNIQUE NOT NULL,
                    hostname    TEXT,
                    ip_address  TEXT,
                    mac_address TEXT,
                    os_type     TEXT,
                    os_version  TEXT,
                    business_unit TEXT,
                    owner       TEXT,
                    criticality TEXT DEFAULT 'medium',
                    asset_type  TEXT DEFAULT 'server',
                    location    TEXT,
                    tags        TEXT DEFAULT '[]',
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    last_scanned TEXT,
                    status      TEXT DEFAULT 'active',
                    notes       TEXT,
                    metadata    TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS asset_findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id  TEXT NOT NULL,
                    asset_id    TEXT NOT NULL,
                    linked_at   TEXT NOT NULL,
                    UNIQUE(finding_id, asset_id),
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
                );

                CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
                CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
                CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
                CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
                CREATE INDEX IF NOT EXISTS idx_assets_bu ON assets(business_unit);
                CREATE INDEX IF NOT EXISTS idx_assets_os ON assets(os_type);
                CREATE INDEX IF NOT EXISTS idx_af_asset ON asset_findings(asset_id);
                CREATE INDEX IF NOT EXISTS idx_af_finding ON asset_findings(finding_id);
            ''')

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _generate_id(self) -> str:
        """Generate a UUID-based asset identifier."""
        return f"ASSET-{uuid.uuid4().hex[:12].upper()}"

    def _now(self) -> str:
        return datetime.utcnow().isoformat()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a Row to a plain dict, deserialising JSON fields."""
        d = dict(row)
        for jf in ('tags', 'metadata'):
            if jf in d and isinstance(d[jf], str):
                try:
                    d[jf] = json.loads(d[jf])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def add_asset(self, hostname: str, ip_address: str, **kwargs) -> str:
        """
        Add or upsert an asset.  If an asset with the same hostname AND
        ip_address already exists it is updated (last_seen refreshed) and
        its asset_id is returned.  Otherwise a new record is created.

        Returns:
            asset_id (str)
        """
        now = self._now()
        with self._conn() as conn:
            # Check for existing asset by hostname + ip
            existing = conn.execute(
                'SELECT asset_id FROM assets WHERE hostname = ? AND ip_address = ?',
                (hostname, ip_address),
            ).fetchone()

            if existing:
                asset_id = existing['asset_id']
                # Build update from kwargs
                updates = {'last_seen': now}
                updates.update(self._sanitize_kwargs(kwargs))
                set_clause = ', '.join(f"{k} = ?" for k in updates)
                values = list(updates.values()) + [asset_id]
                conn.execute(
                    f"UPDATE assets SET {set_clause} WHERE asset_id = ?", values
                )
                logger.info(f"Upserted asset {asset_id} ({hostname}/{ip_address})")
                return asset_id

            asset_id = self._generate_id()
            fields = {
                'asset_id': asset_id,
                'hostname': hostname,
                'ip_address': ip_address,
                'mac_address': kwargs.get('mac_address', ''),
                'os_type': kwargs.get('os_type', ''),
                'os_version': kwargs.get('os_version', ''),
                'business_unit': kwargs.get('business_unit', ''),
                'owner': kwargs.get('owner', ''),
                'criticality': kwargs.get('criticality', 'medium'),
                'asset_type': kwargs.get('asset_type', 'server'),
                'location': kwargs.get('location', ''),
                'tags': json.dumps(kwargs.get('tags', [])),
                'first_seen': now,
                'last_seen': now,
                'last_scanned': kwargs.get('last_scanned'),
                'status': kwargs.get('status', 'active'),
                'notes': kwargs.get('notes', ''),
                'metadata': json.dumps(kwargs.get('metadata', {})),
            }
            cols = ', '.join(fields.keys())
            placeholders = ', '.join('?' for _ in fields)
            conn.execute(
                f"INSERT INTO assets ({cols}) VALUES ({placeholders})",
                list(fields.values()),
            )
            logger.info(f"Created asset {asset_id} ({hostname}/{ip_address})")
            return asset_id

    def _sanitize_kwargs(self, kwargs: Dict) -> Dict:
        """Return only columns that belong in the assets table."""
        allowed = {
            'hostname', 'ip_address', 'mac_address', 'os_type', 'os_version',
            'business_unit', 'owner', 'criticality', 'asset_type', 'location',
            'tags', 'first_seen', 'last_seen', 'last_scanned', 'status',
            'notes', 'metadata',
        }
        sanitized = {}
        for k, v in kwargs.items():
            if k in allowed:
                if k in ('tags', 'metadata') and not isinstance(v, str):
                    v = json.dumps(v)
                sanitized[k] = v
        return sanitized

    def update_asset(self, asset_id: str, **kwargs):
        """Update arbitrary fields on an existing asset."""
        updates = self._sanitize_kwargs(kwargs)
        if not updates:
            return
        updates['last_seen'] = self._now()
        set_clause = ', '.join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [asset_id]
        with self._conn() as conn:
            conn.execute(f"UPDATE assets SET {set_clause} WHERE asset_id = ?", values)
        logger.info(f"Updated asset {asset_id}: {list(updates.keys())}")

    def get_asset(self, asset_id: str) -> Optional[Dict]:
        """Retrieve a single asset by ID."""
        with self._conn() as conn:
            row = conn.execute(
                'SELECT * FROM assets WHERE asset_id = ?', (asset_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def find_assets(
        self,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        business_unit: Optional[str] = None,
        os_type: Optional[str] = None,
        criticality: Optional[str] = None,
        status: str = 'active',
        asset_type: Optional[str] = None,
        owner: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict]:
        """Flexible asset search with optional filters."""
        clauses: List[str] = []
        params: list = []

        if hostname:
            clauses.append("hostname LIKE ?")
            params.append(f"%{hostname}%")
        if ip:
            clauses.append("ip_address LIKE ?")
            params.append(f"%{ip}%")
        if business_unit:
            clauses.append("business_unit = ?")
            params.append(business_unit)
        if os_type:
            clauses.append("os_type = ?")
            params.append(os_type)
        if criticality:
            clauses.append("criticality = ?")
            params.append(criticality)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if asset_type:
            clauses.append("asset_type = ?")
            params.append(asset_type)
        if owner:
            clauses.append("owner = ?")
            params.append(owner)

        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        sql = f"SELECT * FROM assets{where} ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------
    def auto_discover_local(self) -> Dict:
        """
        Detect local machine information (hostname, IP, OS, etc.) and
        register / update it in the inventory.  Returns the asset dict.
        """
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            ip_address = '127.0.0.1'

        system = platform.system().lower()
        if system == 'windows':
            os_type = 'windows'
        elif system == 'darwin':
            os_type = 'macos'
        elif system == 'linux':
            os_type = 'linux'
        else:
            os_type = 'other'

        os_version = platform.platform()
        mac_address = self._get_mac_address()

        asset_id = self.add_asset(
            hostname=hostname,
            ip_address=ip_address,
            mac_address=mac_address,
            os_type=os_type,
            os_version=os_version,
            asset_type='workstation',
            last_scanned=self._now(),
            metadata={
                'processor': platform.processor(),
                'architecture': platform.machine(),
                'python_version': platform.python_version(),
                'discovered_by': 'auto_discover_local',
            },
        )
        asset = self.get_asset(asset_id)
        logger.info(f"Auto-discovered local asset: {hostname} ({ip_address})")
        return asset or {}

    @staticmethod
    def _get_mac_address() -> str:
        """Best-effort MAC address retrieval using uuid module."""
        try:
            mac_int = uuid.getnode()
            mac_hex = f"{mac_int:012X}"
            return ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
        except Exception:
            return ''

    # ------------------------------------------------------------------
    # Grouping / aggregation
    # ------------------------------------------------------------------
    def get_asset_groups(self) -> Dict:
        """
        Return counts grouped by business_unit, os_type, and criticality.
        """
        groups: Dict[str, Dict[str, int]] = {
            'by_business_unit': {},
            'by_os_type': {},
            'by_criticality': {},
        }
        with self._conn() as conn:
            for row in conn.execute(
                "SELECT business_unit, COUNT(*) AS cnt FROM assets "
                "WHERE status = 'active' GROUP BY business_unit"
            ):
                groups['by_business_unit'][row['business_unit'] or 'unassigned'] = row['cnt']

            for row in conn.execute(
                "SELECT os_type, COUNT(*) AS cnt FROM assets "
                "WHERE status = 'active' GROUP BY os_type"
            ):
                groups['by_os_type'][row['os_type'] or 'unknown'] = row['cnt']

            for row in conn.execute(
                "SELECT criticality, COUNT(*) AS cnt FROM assets "
                "WHERE status = 'active' GROUP BY criticality"
            ):
                groups['by_criticality'][row['criticality'] or 'medium'] = row['cnt']

        return groups

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------
    def mark_inactive(self, asset_id: str):
        """Mark an asset as inactive."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE assets SET status = 'inactive', last_seen = ? WHERE asset_id = ?",
                (self._now(), asset_id),
            )
        logger.info(f"Marked asset {asset_id} as inactive")

    def decommission(self, asset_id: str):
        """Mark an asset as decommissioned."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE assets SET status = 'decommissioned', last_seen = ? WHERE asset_id = ?",
                (self._now(), asset_id),
            )
        logger.info(f"Decommissioned asset {asset_id}")

    # ------------------------------------------------------------------
    # Scan coverage
    # ------------------------------------------------------------------
    def get_scan_coverage(self) -> Dict:
        """
        Return the percentage of active assets scanned within the last
        7, 30, and 90 days.
        """
        now = datetime.utcnow()
        thresholds = {
            'last_7_days': (now - timedelta(days=7)).isoformat(),
            'last_30_days': (now - timedelta(days=30)).isoformat(),
            'last_90_days': (now - timedelta(days=90)).isoformat(),
        }

        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE status = 'active'"
            ).fetchone()[0]

            if total == 0:
                return {k: 0.0 for k in thresholds}

            coverage: Dict[str, float] = {}
            for label, cutoff in thresholds.items():
                scanned = conn.execute(
                    "SELECT COUNT(*) FROM assets "
                    "WHERE status = 'active' AND last_scanned >= ?",
                    (cutoff,),
                ).fetchone()[0]
                coverage[label] = round(scanned / total * 100, 2)

            coverage['total_active'] = total
            return coverage

    # ------------------------------------------------------------------
    # Finding linkage
    # ------------------------------------------------------------------
    def link_finding_to_asset(self, finding_id: str, asset_id: str):
        """Create an association between a finding and an asset."""
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO asset_findings (finding_id, asset_id, linked_at) "
                    "VALUES (?, ?, ?)",
                    (finding_id, asset_id, self._now()),
                )
            except sqlite3.IntegrityError:
                pass  # Already linked

    def get_findings_for_asset(self, asset_id: str) -> List[Dict]:
        """Return all finding IDs linked to the given asset."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT finding_id, linked_at FROM asset_findings "
                "WHERE asset_id = ? ORDER BY linked_at DESC",
                (asset_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # CSV import / export
    # ------------------------------------------------------------------
    def import_from_csv(self, filepath: str) -> int:
        """
        Import assets from a CSV file.  The CSV must have a header row
        with at least ``hostname`` and ``ip_address`` columns.  All other
        recognised asset columns are optional.

        Returns:
            Number of assets imported / updated.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"CSV file not found: {filepath}")

        count = 0
        with open(filepath, 'r', newline='', encoding='utf-8') as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                hostname = row.get('hostname', '').strip()
                ip_address = row.get('ip_address', '').strip()
                if not hostname or not ip_address:
                    continue

                kwargs: Dict[str, Any] = {}
                for key in (
                    'mac_address', 'os_type', 'os_version', 'business_unit',
                    'owner', 'criticality', 'asset_type', 'location', 'notes',
                ):
                    val = row.get(key, '').strip()
                    if val:
                        kwargs[key] = val

                # Handle tags as a JSON list or comma-separated string
                tags_raw = row.get('tags', '').strip()
                if tags_raw:
                    try:
                        kwargs['tags'] = json.loads(tags_raw)
                    except json.JSONDecodeError:
                        kwargs['tags'] = [t.strip() for t in tags_raw.split(',') if t.strip()]

                self.add_asset(hostname, ip_address, **kwargs)
                count += 1

        logger.info(f"Imported {count} assets from {filepath}")
        return count

    def export_to_csv(self, filepath: str) -> int:
        """
        Export all active assets to a CSV file.

        Returns:
            Number of rows written.
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        columns = [
            'asset_id', 'hostname', 'ip_address', 'mac_address', 'os_type',
            'os_version', 'business_unit', 'owner', 'criticality', 'asset_type',
            'location', 'tags', 'first_seen', 'last_seen', 'last_scanned',
            'status', 'notes',
        ]

        assets = self.find_assets(status=None, limit=100000)
        with open(filepath, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            for asset in assets:
                # Serialise complex fields back to string for CSV
                row = dict(asset)
                if isinstance(row.get('tags'), (list, dict)):
                    row['tags'] = json.dumps(row['tags'])
                writer.writerow(row)

        logger.info(f"Exported {len(assets)} assets to {filepath}")
        return len(assets)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_statistics(self) -> Dict:
        """
        Comprehensive statistics about the asset inventory.
        """
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE status = 'active'"
            ).fetchone()[0]
            inactive = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE status = 'inactive'"
            ).fetchone()[0]
            decommissioned = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE status = 'decommissioned'"
            ).fetchone()[0]

            # Criticality breakdown (active only)
            crit_rows = conn.execute(
                "SELECT criticality, COUNT(*) AS cnt FROM assets "
                "WHERE status = 'active' GROUP BY criticality"
            ).fetchall()
            by_criticality = {r['criticality']: r['cnt'] for r in crit_rows}

            # OS breakdown (active only)
            os_rows = conn.execute(
                "SELECT os_type, COUNT(*) AS cnt FROM assets "
                "WHERE status = 'active' GROUP BY os_type"
            ).fetchall()
            by_os = {r['os_type'] or 'unknown': r['cnt'] for r in os_rows}

            # Type breakdown (active only)
            type_rows = conn.execute(
                "SELECT asset_type, COUNT(*) AS cnt FROM assets "
                "WHERE status = 'active' GROUP BY asset_type"
            ).fetchall()
            by_type = {r['asset_type'] or 'unknown': r['cnt'] for r in type_rows}

            # Linked findings count
            finding_links = conn.execute(
                "SELECT COUNT(DISTINCT finding_id) FROM asset_findings"
            ).fetchone()[0]

            # Never scanned
            never_scanned = conn.execute(
                "SELECT COUNT(*) FROM assets "
                "WHERE status = 'active' AND last_scanned IS NULL"
            ).fetchone()[0]

        return {
            'total_assets': total,
            'active': active,
            'inactive': inactive,
            'decommissioned': decommissioned,
            'by_criticality': by_criticality,
            'by_os_type': by_os,
            'by_asset_type': by_type,
            'linked_findings': finding_links,
            'never_scanned': never_scanned,
            'scan_coverage': self.get_scan_coverage(),
        }


# ======================================================================
# Singleton accessor
# ======================================================================
_asset_inventory: Optional[AssetInventory] = None


def get_asset_inventory() -> AssetInventory:
    """Get the AssetInventory singleton."""
    global _asset_inventory
    if _asset_inventory is None:
        _asset_inventory = AssetInventory()
    return _asset_inventory


# ======================================================================
# Self-test
# ======================================================================
if __name__ == '__main__':
    inv = get_asset_inventory()
    print(f"Asset Inventory DB: {inv.db_path}")
    print(f"DB exists: {inv.db_path.exists()}")

    # Auto-discover local machine
    local = inv.auto_discover_local()
    print(f"Local asset: {local.get('hostname')} / {local.get('ip_address')}")

    # Add a sample asset
    aid = inv.add_asset(
        hostname='web-server-01',
        ip_address='10.0.1.50',
        os_type='linux',
        os_version='Ubuntu 22.04',
        criticality='high',
        asset_type='server',
        business_unit='Engineering',
        owner='devops-team',
        tags=['production', 'web'],
    )
    print(f"Added asset: {aid}")

    # Statistics
    stats = inv.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")

    # Groups
    groups = inv.get_asset_groups()
    print(f"Groups: {json.dumps(groups, indent=2)}")

    # Coverage
    coverage = inv.get_scan_coverage()
    print(f"Scan coverage: {coverage}")
