#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Asset Inventory Manager
SQLite-backed asset tracking with business context for FAIR risk quantification.
Tracks hosts, ports, services, scan history, risk profiles, and business impact.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('asset_manager')


class AssetManager:
    """Manages asset inventory using the shared evidence database."""

    _instance: Optional['AssetManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_path = paths.evidence_db
        self._ensure_tables()

    def _ensure_tables(self):
        """Create asset tracking tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT UNIQUE NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    os_fingerprint TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1,
                    tags TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS asset_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    service TEXT,
                    version TEXT,
                    state TEXT DEFAULT 'open',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
                    UNIQUE(asset_id, port, protocol)
                );

                CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
                CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
                CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac);
                CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);
                CREATE INDEX IF NOT EXISTS idx_asset_ports_asset ON asset_ports(asset_id);
                CREATE INDEX IF NOT EXISTS idx_asset_ports_port ON asset_ports(port);
            ''')

            # v7.0 migration: add business context columns
            biz_columns = [
                ('assets', 'asset_value', 'REAL'),
                ('assets', 'data_sensitivity', 'TEXT'),
                ('assets', 'record_count', 'INTEGER'),
                ('assets', 'business_criticality', 'TEXT'),
                ('assets', 'regulatory_frameworks', 'TEXT'),
                ('assets', 'industry', 'TEXT'),
                ('assets', 'revenue_impact', 'REAL'),
            ]
            for table, column, col_type in biz_columns:
                try:
                    conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {col_type}')
                except Exception:
                    pass

    def _generate_asset_id(self, ip: str) -> str:
        """Generate deterministic asset ID from IP."""
        return f"ASSET-{ip.replace('.', '-')}"

    def register_asset(self, ip: str, hostname: str = None,
                       mac: str = None, vendor: str = None,
                       os_fingerprint: str = None,
                       metadata: Dict = None) -> str:
        """Register or update an asset in the inventory."""
        asset_id = self._generate_asset_id(ip)
        now = datetime.utcnow().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Check if asset exists
            existing = conn.execute(
                'SELECT id, scan_count FROM assets WHERE asset_id = ?',
                (asset_id,)
            ).fetchone()

            if existing:
                # Update existing asset
                updates = ['last_seen = ?', 'scan_count = scan_count + 1']
                params = [now]

                if hostname:
                    updates.append('hostname = ?')
                    params.append(hostname)
                if mac:
                    updates.append('mac = ?')
                    params.append(mac)
                if vendor:
                    updates.append('vendor = ?')
                    params.append(vendor)
                if os_fingerprint:
                    updates.append('os_fingerprint = ?')
                    params.append(os_fingerprint)
                if metadata:
                    updates.append('metadata = ?')
                    params.append(json.dumps(metadata))

                params.append(asset_id)
                conn.execute(
                    f"UPDATE assets SET {', '.join(updates)} WHERE asset_id = ?",
                    params
                )
                logger.debug(f"Updated asset: {ip} ({asset_id})")
            else:
                # Insert new asset
                conn.execute('''
                    INSERT INTO assets
                    (asset_id, ip, hostname, mac, vendor, os_fingerprint,
                     first_seen, last_seen, scan_count, tags, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, '[]', ?)
                ''', (
                    asset_id, ip, hostname, mac, vendor, os_fingerprint,
                    now, now, json.dumps(metadata or {})
                ))
                logger.info(f"Registered new asset: {ip} ({asset_id})")

        return asset_id

    def update_ports(self, ip: str, ports: List[Dict]):
        """Update port information for an asset."""
        asset_id = self._generate_asset_id(ip)
        now = datetime.utcnow().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            for port_info in ports:
                port = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                state = port_info.get('state', 'open')

                if not port:
                    continue

                # Upsert port
                existing = conn.execute('''
                    SELECT id FROM asset_ports
                    WHERE asset_id = ? AND port = ? AND protocol = ?
                ''', (asset_id, port, protocol)).fetchone()

                if existing:
                    conn.execute('''
                        UPDATE asset_ports
                        SET service = ?, version = ?, state = ?, last_seen = ?
                        WHERE asset_id = ? AND port = ? AND protocol = ?
                    ''', (service, version, state, now,
                          asset_id, port, protocol))
                else:
                    conn.execute('''
                        INSERT INTO asset_ports
                        (asset_id, port, protocol, service, version, state, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (asset_id, port, protocol, service, version, state, now, now))

    def update_from_scan(self, session_id: str, scan_results: Dict):
        """Batch update assets from network scan results."""
        hosts = scan_results.get('hosts', [])
        registered = 0

        for host in hosts:
            ip = host.get('ip')
            if not ip:
                continue

            self.register_asset(
                ip=ip,
                hostname=host.get('hostname'),
                mac=host.get('mac'),
                vendor=host.get('vendor'),
                metadata={'last_session': session_id}
            )

            ports = host.get('ports', [])
            if ports:
                self.update_ports(ip, ports)

            registered += 1

        logger.info(f"Updated {registered} assets from scan session {session_id}")
        return registered

    def get_asset(self, ip: str) -> Optional[Dict]:
        """Get full asset details including ports."""
        asset_id = self._generate_asset_id(ip)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            asset = conn.execute(
                'SELECT * FROM assets WHERE asset_id = ?', (asset_id,)
            ).fetchone()

            if not asset:
                return None

            asset_dict = dict(asset)

            # Get ports
            ports = conn.execute('''
                SELECT * FROM asset_ports WHERE asset_id = ?
                ORDER BY port
            ''', (asset_id,)).fetchall()

            asset_dict['ports'] = [dict(p) for p in ports]
            return asset_dict

    def get_asset_history(self, ip: str) -> List[Dict]:
        """Get all scan sessions that included this asset."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Find findings for this asset
            cursor = conn.execute('''
                SELECT DISTINCT s.session_id, s.start_time, s.end_time,
                       s.scan_type, s.status,
                       COUNT(f.id) as finding_count
                FROM sessions s
                LEFT JOIN findings f ON f.session_id = s.session_id
                    AND f.affected_asset = ?
                GROUP BY s.session_id
                ORDER BY s.start_time DESC
            ''', (ip,))

            return [dict(row) for row in cursor.fetchall()]

    def get_asset_risk_profile(self, ip: str) -> Dict:
        """Get aggregate risk profile for an asset."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get findings by severity
            findings = conn.execute('''
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE affected_asset = ? AND status = 'open'
                    AND (false_positive IS NULL OR false_positive = 0)
                GROUP BY severity
            ''', (ip,)).fetchall()

            severity_counts = {row['severity']: row['count'] for row in findings}

            # Get KEV findings
            kev_count = conn.execute('''
                SELECT COUNT(*) FROM findings
                WHERE affected_asset = ? AND kev_status = 'true'
                    AND status = 'open'
            ''', (ip,)).fetchone()[0]

            # Get highest effective priority
            max_priority = conn.execute('''
                SELECT MAX(effective_priority) FROM findings
                WHERE affected_asset = ? AND status = 'open'
            ''', (ip,)).fetchone()[0]

            # Calculate risk score
            risk_score = (
                severity_counts.get('CRITICAL', 0) * 10 +
                severity_counts.get('HIGH', 0) * 7 +
                severity_counts.get('MEDIUM', 0) * 4 +
                severity_counts.get('LOW', 0) * 1
            )

            return {
                'ip': ip,
                'findings_by_severity': severity_counts,
                'total_open_findings': sum(severity_counts.values()),
                'kev_findings': kev_count,
                'max_effective_priority': max_priority or 0,
                'risk_score': risk_score,
                'risk_level': (
                    'CRITICAL' if risk_score >= 50 else
                    'HIGH' if risk_score >= 20 else
                    'MEDIUM' if risk_score >= 5 else
                    'LOW'
                ),
            }

    def set_asset_business_context(self, ip: str, asset_value: float = None,
                                     data_sensitivity: str = None,
                                     record_count: int = None,
                                     business_criticality: str = None,
                                     regulatory_frameworks: List[str] = None,
                                     industry: str = None,
                                     revenue_impact: float = None):
        """Set business context for FAIR risk quantification."""
        asset_id = self._generate_asset_id(ip)

        updates = []
        params = []
        field_map = {
            'asset_value': asset_value,
            'data_sensitivity': data_sensitivity,
            'record_count': record_count,
            'business_criticality': business_criticality,
            'regulatory_frameworks': json.dumps(regulatory_frameworks) if regulatory_frameworks else None,
            'industry': industry,
            'revenue_impact': revenue_impact,
        }
        for field, value in field_map.items():
            if value is not None:
                updates.append(f"{field} = ?")
                params.append(value)

        if not updates:
            return

        params.append(asset_id)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                f"UPDATE assets SET {', '.join(updates)} WHERE asset_id = ?",
                params
            )
        logger.info(f"Set business context for {ip}")

    def get_asset_business_context(self, ip: str) -> Optional[Dict]:
        """Get business context for an asset."""
        asset_id = self._generate_asset_id(ip)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute('''
                SELECT asset_value, data_sensitivity, record_count,
                       business_criticality, regulatory_frameworks,
                       industry, revenue_impact
                FROM assets WHERE asset_id = ?
            ''', (asset_id,)).fetchone()

            if not row:
                return None

            ctx = dict(row)
            # Parse JSON fields
            if ctx.get('regulatory_frameworks'):
                try:
                    ctx['regulatory_frameworks'] = json.loads(ctx['regulatory_frameworks'])
                except (json.JSONDecodeError, TypeError):
                    ctx['regulatory_frameworks'] = []
            return ctx

    def search_assets(self, query: str) -> List[Dict]:
        """Search assets by IP, hostname, OS, or tag."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            search = f"%{query}%"

            cursor = conn.execute('''
                SELECT * FROM assets
                WHERE ip LIKE ? OR hostname LIKE ? OR os_fingerprint LIKE ?
                    OR tags LIKE ? OR mac LIKE ?
                ORDER BY last_seen DESC
            ''', (search, search, search, search, search))

            return [dict(row) for row in cursor.fetchall()]

    def get_all_assets(self, limit: int = 500) -> List[Dict]:
        """Get all assets in inventory."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def tag_asset(self, ip: str, tags: List[str]):
        """Add categorization tags to an asset."""
        asset_id = self._generate_asset_id(ip)

        with sqlite3.connect(self.db_path) as conn:
            # Get existing tags
            row = conn.execute(
                'SELECT tags FROM assets WHERE asset_id = ?', (asset_id,)
            ).fetchone()

            if row:
                try:
                    existing = json.loads(row[0] or '[]')
                except json.JSONDecodeError:
                    existing = []

                # Merge tags
                merged = list(set(existing + tags))
                conn.execute(
                    'UPDATE assets SET tags = ? WHERE asset_id = ?',
                    (json.dumps(merged), asset_id)
                )

    def get_inventory_summary(self) -> Dict:
        """Get asset inventory summary."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute('SELECT COUNT(*) FROM assets').fetchone()[0]
            total_ports = conn.execute('SELECT COUNT(*) FROM asset_ports WHERE state = ?', ('open',)).fetchone()[0]

            # OS distribution
            os_dist = conn.execute('''
                SELECT os_fingerprint, COUNT(*) as count
                FROM assets WHERE os_fingerprint IS NOT NULL
                GROUP BY os_fingerprint ORDER BY count DESC LIMIT 10
            ''').fetchall()

            # Top services
            top_services = conn.execute('''
                SELECT service, COUNT(*) as count
                FROM asset_ports WHERE state = 'open'
                GROUP BY service ORDER BY count DESC LIMIT 10
            ''').fetchall()

            return {
                'total_assets': total,
                'total_open_ports': total_ports,
                'os_distribution': {row[0]: row[1] for row in os_dist},
                'top_services': {row[0]: row[1] for row in top_services},
            }


# Singleton accessor
_asset_manager: Optional[AssetManager] = None


def get_asset_manager() -> AssetManager:
    """Get the asset manager singleton."""
    global _asset_manager
    if _asset_manager is None:
        _asset_manager = AssetManager()
    return _asset_manager


if __name__ == '__main__':
    # Self-test
    am = get_asset_manager()
    print("Asset Manager initialized")
    print(f"Database: {am.db_path}")

    # Test registration
    asset_id = am.register_asset(
        ip='192.168.1.100',
        hostname='test-host',
        mac='AA:BB:CC:DD:EE:FF',
        vendor='Test Vendor'
    )
    print(f"Registered asset: {asset_id}")

    # Test port update
    am.update_ports('192.168.1.100', [
        {'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'state': 'open'},
        {'port': 80, 'protocol': 'tcp', 'service': 'http', 'state': 'open'},
    ])
    print("Updated ports")

    # Test retrieval
    asset = am.get_asset('192.168.1.100')
    if asset:
        print(f"Asset: {asset['ip']} ({asset['hostname']})")
        print(f"  Ports: {len(asset['ports'])}")
        print(f"  First seen: {asset['first_seen']}")
        print(f"  Scan count: {asset['scan_count']}")

    # Test tagging
    am.tag_asset('192.168.1.100', ['production', 'web-server'])
    print("Tagged asset")

    # Test business context (v7.0)
    am.set_asset_business_context(
        '192.168.1.100',
        asset_value=500000,
        data_sensitivity='high',
        record_count=50000,
        business_criticality='critical',
        industry='technology',
        revenue_impact=100000
    )
    print("Set business context")

    biz = am.get_asset_business_context('192.168.1.100')
    if biz:
        print(f"Business context: value=${biz.get('asset_value', 0):,.0f}, "
              f"sensitivity={biz.get('data_sensitivity')}, "
              f"records={biz.get('record_count')}")

    # Test summary
    summary = am.get_inventory_summary()
    print(f"\nInventory Summary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
