#!/usr/bin/env python3
"""
Purple Team GRC Platform - Database Migration Tool

Migrate SQLite databases to PostgreSQL or check migration status.

Usage:
    python bin/migrate-db.py --status
    python bin/migrate-db.py --to postgres --url postgresql://user:pass@localhost:5432/purpleteam
    python bin/migrate-db.py --to postgres --url $PURPLE_DB_URL --dry-run
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add lib to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'lib'))

from database import migrate_sqlite_to_postgres, get_database
from paths import paths
from logger import get_logger

logger = get_logger('migrate-db')


def print_header(text: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def show_status():
    """Show current database backend and statistics."""
    print_header("Purple Team GRC - Database Status")

    backend = os.environ.get('PURPLE_DB_BACKEND', 'sqlite')
    db_url = os.environ.get('PURPLE_DB_URL', 'Not configured')

    print(f"\nCurrent Backend: {backend.upper()}")
    print(f"Database URL:    {db_url if backend == 'postgres' else 'N/A (using SQLite)'}")

    # Find all SQLite databases
    print_header("SQLite Databases in data/")

    db_files = list(paths.data.glob('*.db'))
    if not db_files:
        print("No SQLite databases found.\n")
        return

    total_size = 0
    total_tables = 0

    print(f"\n{'Database':<20} {'Size (MB)':<12} {'Tables':<10} {'Path'}")
    print("-" * 70)

    for db_file in sorted(db_files):
        size_bytes = db_file.stat().st_size
        size_mb = size_bytes / 1024 / 1024

        # Try to get table count
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_file))
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            table_count = len(tables)
            conn.close()
        except Exception as e:
            table_count = 0
            logger.warning(f"Could not read {db_file.name}: {e}")

        total_size += size_mb
        total_tables += table_count

        print(f"{db_file.stem:<20} {size_mb:>10.2f}  {table_count:>8}  {db_file}")

    print("-" * 70)
    print(f"{'TOTAL':<20} {total_size:>10.2f}  {total_tables:>8}")
    print()


def migrate_to_postgres(postgres_url: str, dry_run: bool = False):
    """Migrate all SQLite databases to PostgreSQL."""
    print_header("Purple Team GRC - Database Migration")

    print(f"\nMigration Type:  SQLite -> PostgreSQL")
    print(f"PostgreSQL URL:  {postgres_url}")
    print(f"Source Dir:      {paths.data}")
    print(f"Dry Run:         {dry_run}")

    if dry_run:
        print("\nDRY RUN MODE - No changes will be made")
        print("\nWould migrate the following databases:")

        db_files = list(paths.data.glob('*.db'))
        if not db_files:
            print("  No SQLite databases found.")
            return

        for db_file in sorted(db_files):
            print(f"  - {db_file.name}")

        print("\nRun without --dry-run to perform actual migration.")
        return

    # Confirm with user
    print("\nWARNING: This will:")
    print("  1. Connect to the PostgreSQL database")
    print("  2. DROP existing tables if they exist")
    print("  3. Create new tables from SQLite schema")
    print("  4. Copy all data from SQLite to PostgreSQL")
    print("\nYour SQLite files will NOT be modified or deleted.")

    confirm = input("\nContinue? (yes/no): ").strip().lower()
    if confirm not in ('yes', 'y'):
        print("Migration cancelled.")
        return

    # Test PostgreSQL connection first
    print("\nTesting PostgreSQL connection...")
    try:
        import psycopg2
    except ImportError:
        try:
            import psycopg2 as psycopg2_binary
            psycopg2 = psycopg2_binary
        except ImportError:
            print("\nERROR: psycopg2 not installed.")
            print("Install with: pip install psycopg2-binary")
            sys.exit(1)

    try:
        conn = psycopg2.connect(postgres_url)
        conn.close()
        print("Connection successful!")
    except Exception as e:
        print(f"\nERROR: Could not connect to PostgreSQL: {e}")
        sys.exit(1)

    # Perform migration
    print("\nStarting migration...")
    stats = migrate_sqlite_to_postgres(paths.data, postgres_url)

    # Display results
    print_header("Migration Results")

    print(f"\nStarted:  {stats['started_at']}")
    print(f"Completed: {stats['completed_at']}")

    if stats['errors']:
        print(f"\nErrors: {len(stats['errors'])}")
        for error in stats['errors']:
            print(f"  - {error}")

    print(f"\nDatabases Migrated: {len(stats['databases'])}")
    print(f"Total Tables:       {stats['total_tables']}")
    print(f"Total Rows:         {stats['total_rows']}")

    print("\nPer-Database Stats:")
    print(f"{'Database':<20} {'Success':<10} {'Tables':<10} {'Rows'}")
    print("-" * 70)

    for db_name, db_stats in sorted(stats['databases'].items()):
        success = "✓ Yes" if db_stats['success'] else "✗ No"
        tables = len(db_stats['tables'])
        rows = db_stats['total_rows']
        print(f"{db_name:<20} {success:<10} {tables:>8}  {rows:>10}")

    print()

    # Save migration report
    report_path = paths.data / 'migration_report.json'
    with open(report_path, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"Detailed report saved to: {report_path}")

    # Show next steps
    print("\nNext Steps:")
    print("  1. Verify the migration by checking your PostgreSQL database")
    print("  2. Update your environment to use PostgreSQL:")
    print(f"     export PURPLE_DB_BACKEND=postgres")
    print(f"     export PURPLE_DB_URL='{postgres_url}'")
    print("  3. Test the application with the new database")
    print("  4. Once verified, you can archive or delete the SQLite files")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Purple Team GRC Database Migration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Show current database status:
    python bin/migrate-db.py --status

  Migrate to PostgreSQL:
    python bin/migrate-db.py --to postgres --url postgresql://user:pass@localhost:5432/purpleteam

  Dry run (preview only):
    python bin/migrate-db.py --to postgres --url $PURPLE_DB_URL --dry-run

  Use environment variable for URL:
    export PURPLE_DB_URL=postgresql://user:pass@localhost:5432/purpleteam
    python bin/migrate-db.py --to postgres --url $PURPLE_DB_URL
        """
    )

    parser.add_argument(
        '--status',
        action='store_true',
        help='Show current database backend and statistics'
    )

    parser.add_argument(
        '--to',
        choices=['postgres'],
        help='Target database backend for migration'
    )

    parser.add_argument(
        '--url',
        help='PostgreSQL connection URL (postgresql://user:pass@host:port/database)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview migration without making changes'
    )

    args = parser.parse_args()

    # Show status if requested or no args
    if args.status or len(sys.argv) == 1:
        show_status()
        return

    # Validate migration arguments
    if args.to:
        if not args.url:
            parser.error("--url is required when using --to")

        if args.to == 'postgres':
            migrate_to_postgres(args.url, dry_run=args.dry_run)
        else:
            parser.error(f"Unsupported target: {args.to}")
    else:
        parser.error("Specify --status or --to with --url")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\nERROR: {e}")
        sys.exit(1)
