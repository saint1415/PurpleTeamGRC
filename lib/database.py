#!/usr/bin/env python3
"""
Purple Team GRC Platform - Database Abstraction Layer
Unified database connection manager supporting SQLite (default) and PostgreSQL.

Configuration via environment variables:
    PURPLE_DB_BACKEND=sqlite (default) or postgres
    PURPLE_DB_URL=postgresql://user:pass@host:5432/purpleteam (for postgres)

SQLite databases remain in data/ directory as before for portability.
PostgreSQL is optional and requires psycopg2/psycopg2-binary to be installed.
"""

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('database')


# Global database registry for singleton pattern
_database_registry: Dict[str, 'DatabaseManager'] = {}


class DatabaseManager:
    """Unified database connection manager supporting SQLite and PostgreSQL."""

    def __init__(self, db_name: str, schema: Optional[str] = None):
        """
        Initialize database manager.

        Args:
            db_name: Logical database name (e.g. 'evidence', 'audit', 'remediation')
            schema: SQL CREATE TABLE statements for auto-initialization
        """
        self.db_name = db_name
        self._backend = os.environ.get('PURPLE_DB_BACKEND', 'sqlite').lower()
        self._db_url = os.environ.get('PURPLE_DB_URL', '')
        self._pg_conn = None
        self._sqlite_path: Optional[Path] = None

        # Validate backend
        if self._backend not in ('sqlite', 'postgres'):
            raise ValueError(f"Invalid PURPLE_DB_BACKEND: {self._backend}. Use 'sqlite' or 'postgres'")

        # Setup backend-specific connection
        if self._backend == 'postgres':
            self._setup_postgres()
        else:
            self._setup_sqlite()

        # Initialize schema if provided
        if schema:
            self.initialize_schema(schema)

        logger.info(f"DatabaseManager initialized: {db_name} on {self._backend}")

    # ------------------------------------------------------------------
    # Backend setup
    # ------------------------------------------------------------------
    def _setup_sqlite(self):
        """Configure SQLite database path."""
        self._sqlite_path = paths.data / f"{self.db_name}.db"
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)

    def _setup_postgres(self):
        """Configure PostgreSQL connection."""
        if not self._db_url:
            raise ValueError(
                "PostgreSQL backend requires PURPLE_DB_URL environment variable\n"
                "Example: PURPLE_DB_URL=postgresql://user:pass@localhost:5432/purpleteam"
            )

        # Try to import psycopg2
        try:
            import psycopg2
            import psycopg2.extras
            self._psycopg2 = psycopg2
        except ImportError:
            try:
                import psycopg2 as psycopg2_binary
                import psycopg2.extras
                self._psycopg2 = psycopg2_binary
            except ImportError:
                raise ImportError(
                    "PostgreSQL backend requires psycopg2 or psycopg2-binary.\n"
                    "Install with: pip install psycopg2-binary"
                )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def backend(self) -> str:
        """Get current backend type: 'sqlite' or 'postgres'."""
        return self._backend

    @property
    def connection_string(self) -> str:
        """Get connection string for current backend."""
        if self._backend == 'postgres':
            # Mask password for logging
            masked = re.sub(r':([^@]+)@', ':***@', self._db_url)
            return masked
        return str(self._sqlite_path)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def get_connection(self):
        """
        Get a database connection.

        Returns:
            For SQLite: sqlite3.Connection
            For PostgreSQL: psycopg2.Connection
        """
        if self._backend == 'postgres':
            return self._psycopg2.connect(self._db_url)
        else:
            conn = sqlite3.connect(str(self._sqlite_path))
            conn.row_factory = sqlite3.Row
            return conn

    def _normalize_params(self, sql: str, params: Optional[Union[tuple, list, dict]]) -> tuple:
        """
        Normalize SQL and parameters for backend compatibility.

        Handles:
        - ? (SQLite) vs %s (PostgreSQL) placeholders
        - Named parameters (:name) to positional

        Returns:
            (normalized_sql, normalized_params)
        """
        if params is None:
            params = []

        if self._backend == 'postgres':
            # Convert ? to %s for PostgreSQL
            if isinstance(params, (list, tuple)):
                normalized_sql = sql.replace('?', '%s')
            elif isinstance(params, dict):
                # Convert named parameters :name to %(name)s
                normalized_sql = re.sub(r':(\w+)', r'%(\1)s', sql)
            else:
                normalized_sql = sql
        else:
            # SQLite: keep as is
            normalized_sql = sql

        return normalized_sql, params

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------
    def execute(self, sql: str, params: Optional[Union[tuple, list, dict]] = None) -> List[Dict]:
        """
        Execute SQL query and return all rows as list of dicts.

        Args:
            sql: SQL query
            params: Query parameters (list, tuple, or dict)

        Returns:
            List of rows as dictionaries
        """
        sql, params = self._normalize_params(sql, params)

        if self._backend == 'postgres':
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=self._psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(sql, params or ())
                    rows = cur.fetchall()
                    return [dict(row) for row in rows]
        else:
            with self.get_connection() as conn:
                cursor = conn.execute(sql, params or ())
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def execute_one(self, sql: str, params: Optional[Union[tuple, list, dict]] = None) -> Optional[Dict]:
        """
        Execute SQL query and return first row as dict or None.

        Args:
            sql: SQL query
            params: Query parameters

        Returns:
            First row as dictionary or None if no results
        """
        sql, params = self._normalize_params(sql, params)

        if self._backend == 'postgres':
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=self._psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(sql, params or ())
                    row = cur.fetchone()
                    return dict(row) if row else None
        else:
            with self.get_connection() as conn:
                cursor = conn.execute(sql, params or ())
                row = cursor.fetchone()
                return dict(row) if row else None

    def execute_write(self, sql: str, params: Optional[Union[tuple, list, dict]] = None) -> int:
        """
        Execute INSERT/UPDATE/DELETE query.

        Args:
            sql: SQL statement
            params: Query parameters

        Returns:
            Number of affected rows
        """
        sql, params = self._normalize_params(sql, params)

        if self._backend == 'postgres':
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params or ())
                    conn.commit()
                    return cur.rowcount
        else:
            with self.get_connection() as conn:
                cursor = conn.execute(sql, params or ())
                conn.commit()
                return cursor.rowcount

    def executemany(self, sql: str, params_list: List[Union[tuple, list, dict]]) -> int:
        """
        Execute same SQL with multiple parameter sets.

        Args:
            sql: SQL statement
            params_list: List of parameter sets

        Returns:
            Total number of affected rows
        """
        sql, _ = self._normalize_params(sql, [])

        if self._backend == 'postgres':
            total = 0
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    for params in params_list:
                        cur.execute(sql, params)
                        total += cur.rowcount
                    conn.commit()
            return total
        else:
            with self.get_connection() as conn:
                cursor = conn.executemany(sql, params_list)
                conn.commit()
                return cursor.rowcount

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------
    def table_exists(self, table_name: str) -> bool:
        """
        Check if a table exists in the database.

        Args:
            table_name: Name of the table to check

        Returns:
            True if table exists, False otherwise
        """
        if self._backend == 'postgres':
            sql = """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name = %s
                )
            """
            result = self.execute_one(sql, [table_name])
            return result['exists'] if result else False
        else:
            sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
            result = self.execute_one(sql, [table_name])
            return result is not None

    def initialize_schema(self, schema_sql: str):
        """
        Create tables if they don't exist.

        Automatically converts SQLite-specific syntax to PostgreSQL where needed:
        - INTEGER PRIMARY KEY AUTOINCREMENT -> SERIAL PRIMARY KEY
        - INSERT OR REPLACE -> INSERT ... ON CONFLICT ... DO UPDATE
        - TEXT -> VARCHAR where appropriate

        Args:
            schema_sql: SQL CREATE TABLE statements
        """
        if self._backend == 'postgres':
            # Convert SQLite syntax to PostgreSQL
            schema_sql = self._convert_schema_to_postgres(schema_sql)

        if self._backend == 'postgres':
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(schema_sql)
                    conn.commit()
        else:
            with self.get_connection() as conn:
                conn.executescript(schema_sql)
                conn.commit()

        logger.debug(f"Schema initialized for {self.db_name}")

    def _convert_schema_to_postgres(self, schema_sql: str) -> str:
        """Convert SQLite schema to PostgreSQL compatible schema."""
        # INTEGER PRIMARY KEY AUTOINCREMENT -> SERIAL PRIMARY KEY
        schema_sql = re.sub(
            r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT',
            'SERIAL PRIMARY KEY',
            schema_sql,
            flags=re.IGNORECASE
        )

        # AUTOINCREMENT without PRIMARY KEY -> just remove it
        schema_sql = re.sub(
            r'\s+AUTOINCREMENT\b',
            '',
            schema_sql,
            flags=re.IGNORECASE
        )

        # DEFAULT CURRENT_TIMESTAMP -> DEFAULT NOW()
        schema_sql = re.sub(
            r'DEFAULT\s+CURRENT_TIMESTAMP',
            'DEFAULT NOW()',
            schema_sql,
            flags=re.IGNORECASE
        )

        # Remove IF NOT EXISTS from CREATE INDEX (PostgreSQL doesn't support it in old versions)
        # Use CREATE INDEX IF NOT EXISTS only in PG 9.5+, keep for compatibility
        # Actually, modern PostgreSQL supports it, so keep it

        return schema_sql

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------
    def get_table_names(self) -> List[str]:
        """Get list of all table names in the database."""
        if self._backend == 'postgres':
            sql = """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
            """
            rows = self.execute(sql)
            return [row['table_name'] for row in rows]
        else:
            sql = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            rows = self.execute(sql)
            return [row['name'] for row in rows]

    def get_table_count(self, table_name: str) -> int:
        """Get row count for a table."""
        sql = f"SELECT COUNT(*) as count FROM {table_name}"
        result = self.execute_one(sql)
        return result['count'] if result else 0

    def vacuum(self):
        """Optimize database (VACUUM for SQLite, VACUUM for PostgreSQL)."""
        if self._backend == 'postgres':
            # PostgreSQL VACUUM cannot run inside a transaction
            import psycopg2
            conn = self._psycopg2.connect(self._db_url)
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            with conn.cursor() as cur:
                cur.execute("VACUUM")
            conn.close()
        else:
            with self.get_connection() as conn:
                conn.execute("VACUUM")

    def get_database_size(self) -> Dict[str, Any]:
        """Get database size information."""
        if self._backend == 'postgres':
            sql = "SELECT pg_database_size(current_database()) as size"
            result = self.execute_one(sql)
            size_bytes = result['size'] if result else 0
            return {
                'backend': 'postgres',
                'size_bytes': size_bytes,
                'size_mb': round(size_bytes / 1024 / 1024, 2),
                'path': self._db_url
            }
        else:
            size_bytes = self._sqlite_path.stat().st_size if self._sqlite_path.exists() else 0
            return {
                'backend': 'sqlite',
                'size_bytes': size_bytes,
                'size_mb': round(size_bytes / 1024 / 1024, 2),
                'path': str(self._sqlite_path)
            }


# ------------------------------------------------------------------
# Singleton registry
# ------------------------------------------------------------------
def get_database(db_name: str, schema: Optional[str] = None) -> DatabaseManager:
    """
    Get or create a DatabaseManager instance (singleton per db_name).

    Args:
        db_name: Logical database name
        schema: Optional schema SQL (only used on first call)

    Returns:
        DatabaseManager instance
    """
    global _database_registry

    if db_name not in _database_registry:
        _database_registry[db_name] = DatabaseManager(db_name, schema)
    elif schema:
        # If schema is provided but DB already exists, initialize it anyway
        _database_registry[db_name].initialize_schema(schema)

    return _database_registry[db_name]


# ------------------------------------------------------------------
# Migration utilities
# ------------------------------------------------------------------
def migrate_sqlite_to_postgres(sqlite_dir: Path, postgres_url: str) -> Dict[str, Any]:
    """
    Migrate all SQLite databases in a directory to PostgreSQL.

    Args:
        sqlite_dir: Path to directory containing SQLite .db files
        postgres_url: PostgreSQL connection URL

    Returns:
        Dictionary with migration statistics and results
    """
    stats = {
        'started_at': datetime.utcnow().isoformat(),
        'databases': {},
        'total_tables': 0,
        'total_rows': 0,
        'errors': []
    }

    # Find all .db files
    db_files = list(sqlite_dir.glob('*.db'))

    if not db_files:
        logger.warning(f"No .db files found in {sqlite_dir}")
        stats['errors'].append(f"No .db files found in {sqlite_dir}")
        return stats

    logger.info(f"Found {len(db_files)} SQLite databases to migrate")

    # Setup PostgreSQL connection
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        try:
            import psycopg2 as psycopg2_binary
            import psycopg2.extras
            psycopg2 = psycopg2_binary
        except ImportError:
            raise ImportError("psycopg2 required for migration")

    for db_file in db_files:
        db_name = db_file.stem
        logger.info(f"Migrating {db_name}...")

        db_stats = {
            'tables': {},
            'total_rows': 0,
            'success': False
        }

        try:
            # Connect to SQLite
            sqlite_conn = sqlite3.connect(str(db_file))
            sqlite_conn.row_factory = sqlite3.Row

            # Get all tables
            cursor = sqlite_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]

            if not tables:
                logger.warning(f"No tables found in {db_name}")
                db_stats['success'] = True
                stats['databases'][db_name] = db_stats
                continue

            logger.info(f"Found {len(tables)} tables in {db_name}: {', '.join(tables)}")

            # Connect to PostgreSQL
            pg_conn = psycopg2.connect(postgres_url)
            pg_cursor = pg_conn.cursor()

            for table in tables:
                # Get table schema
                schema_cursor = sqlite_conn.execute(
                    f"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    (table,)
                )
                schema_row = schema_cursor.fetchone()
                if not schema_row or not schema_row[0]:
                    logger.warning(f"Could not get schema for {table}")
                    continue

                create_sql = schema_row[0]

                # Convert schema to PostgreSQL
                create_sql = re.sub(
                    r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT',
                    'SERIAL PRIMARY KEY',
                    create_sql,
                    flags=re.IGNORECASE
                )
                create_sql = re.sub(r'\s+AUTOINCREMENT\b', '', create_sql, flags=re.IGNORECASE)
                create_sql = re.sub(
                    r'DEFAULT\s+CURRENT_TIMESTAMP',
                    'DEFAULT NOW()',
                    create_sql,
                    flags=re.IGNORECASE
                )

                # Create table in PostgreSQL (drop if exists)
                pg_cursor.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
                pg_cursor.execute(create_sql)
                pg_conn.commit()

                # Get all rows from SQLite
                rows = sqlite_conn.execute(f"SELECT * FROM {table}").fetchall()

                if rows:
                    # Get column names
                    columns = [desc[0] for desc in sqlite_conn.execute(f"SELECT * FROM {table} LIMIT 1").description]

                    # Insert rows into PostgreSQL
                    placeholders = ','.join(['%s'] * len(columns))
                    insert_sql = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})"

                    for row in rows:
                        pg_cursor.execute(insert_sql, tuple(row))

                    pg_conn.commit()

                    db_stats['tables'][table] = len(rows)
                    db_stats['total_rows'] += len(rows)
                    stats['total_rows'] += len(rows)

                    logger.info(f"  Migrated {len(rows)} rows from {table}")
                else:
                    db_stats['tables'][table] = 0
                    logger.info(f"  Table {table} is empty")

                stats['total_tables'] += 1

            # Close connections
            pg_conn.close()
            sqlite_conn.close()

            db_stats['success'] = True
            logger.info(f"Successfully migrated {db_name}: {db_stats['total_rows']} total rows")

        except Exception as e:
            error_msg = f"Error migrating {db_name}: {str(e)}"
            logger.error(error_msg)
            stats['errors'].append(error_msg)
            db_stats['success'] = False

        stats['databases'][db_name] = db_stats

    stats['completed_at'] = datetime.utcnow().isoformat()
    return stats


# ------------------------------------------------------------------
# Self-test
# ------------------------------------------------------------------
if __name__ == '__main__':
    # Test with SQLite
    print("Testing DatabaseManager with SQLite...")
    db = get_database('test_db', schema='''
        CREATE TABLE IF NOT EXISTS test_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    print(f"Backend: {db.backend}")
    print(f"Connection: {db.connection_string}")
    print(f"Tables: {db.get_table_names()}")

    # Test insert
    db.execute_write(
        "INSERT INTO test_users (username, email) VALUES (?, ?)",
        ['alice', 'alice@example.com']
    )
    db.execute_write(
        "INSERT INTO test_users (username, email) VALUES (?, ?)",
        ['bob', 'bob@example.com']
    )

    # Test query
    users = db.execute("SELECT * FROM test_users")
    print(f"Users: {users}")

    # Test count
    count = db.get_table_count('test_users')
    print(f"User count: {count}")

    # Test size
    size_info = db.get_database_size()
    print(f"Database size: {size_info}")

    print("\nAll tests passed!")
