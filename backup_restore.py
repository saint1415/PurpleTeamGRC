#!/usr/bin/env python3

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

BACKUP_DIR = Path.home() / 'purple-team-backups'
# Note: Backup directory intentionally separate from BASE_DIR for safety
"""
Backup & Restore Utility
Backs up Purple Team platform data and configuration

What gets backed up:
- Evidence database
- Risk database
- Configuration files
- Scan reports
- Logs (optional)
"""

import shutil
import tarfile
from pathlib import Path
from datetime import datetime
import json
import logging
import subprocess

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths already defined at top of file (line 11)


class BackupManager:
    """Manage backups of Purple Team platform"""
    
    def __init__(self):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, include_logs=False, include_reports=True):
        """
        Create complete backup of platform
        
        Args:
            include_logs: Include log files (can be large)
            include_reports: Include scan reports
        
        Returns:
            Path to backup file
        """
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f'purple-team-backup_{timestamp}.tar.gz'
        backup_path = BACKUP_DIR / backup_name
        
        logger.info(f"Creating backup: {backup_name}")
        
        # Items to backup
        backup_items = []
        
        # Configuration
        config_dir = BASE_DIR / 'config'
        if config_dir.exists():
            backup_items.append(('config', config_dir))
            logger.info("  Ã¢Å“â€œ Including configuration")
        
        # Evidence database
        evidence_db = BASE_DIR / 'evidence' / 'evidence.db'
        if evidence_db.exists():
            backup_items.append(('evidence/evidence.db', evidence_db))
            logger.info("  Ã¢Å“â€œ Including evidence database")
        
        # Evidence files
        evidence_dir = BASE_DIR / 'evidence'
        if evidence_dir.exists():
            backup_items.append(('evidence', evidence_dir))
            logger.info("  Ã¢Å“â€œ Including evidence files")
        
        # Risk database
        risk_db = BASE_DIR / 'risk' / 'risk.db'
        if risk_db.exists():
            backup_items.append(('risk/risk.db', risk_db))
            logger.info("  Ã¢Å“â€œ Including risk database")
        
        # Questionnaires
        questionnaire_dir = BASE_DIR / 'questionnaires'
        if questionnaire_dir.exists():
            backup_items.append(('questionnaires', questionnaire_dir))
            logger.info("  Ã¢Å“â€œ Including questionnaires")
        
        # Reports (optional)
        if include_reports:
            reports_dir = BASE_DIR / 'reports'
            if reports_dir.exists():
                backup_items.append(('reports', reports_dir))
                logger.info("  Ã¢Å“â€œ Including reports")
        
        # Logs (optional)
        if include_logs:
            logs_dir = BASE_DIR / 'logs'
            if logs_dir.exists():
                backup_items.append(('logs', logs_dir))
                logger.info("  Ã¢Å“â€œ Including logs")
        
        # Scripts
        scripts_dir = BASE_DIR / 'scripts'
        if scripts_dir.exists():
            backup_items.append(('scripts', scripts_dir))
            logger.info("  Ã¢Å“â€œ Including scripts")
        
        # Create tar.gz archive
        with tarfile.open(backup_path, 'w:gz') as tar:
            for arcname, path in backup_items:
                tar.add(path, arcname=arcname)
        
        # Create backup manifest
        manifest = {
            'backup_date': datetime.now().isoformat(),
            'backup_file': backup_name,
            'includes_logs': include_logs,
            'includes_reports': include_reports,
            'items_backed_up': [item[0] for item in backup_items],
            'backup_size_mb': backup_path.stat().st_size / (1024 * 1024)
        }
        
        manifest_path = BACKUP_DIR / f'manifest_{timestamp}.json'
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"\nÃ¢Å“â€¦ Backup created: {backup_path}")
        logger.info(f"   Size: {manifest['backup_size_mb']:.2f} MB")
        logger.info(f"   Manifest: {manifest_path}")
        
        return backup_path
    
    def list_backups(self):
        """List all available backups"""
        
        backups = []
        
        for backup_file in BACKUP_DIR.glob('purple-team-backup_*.tar.gz'):
            timestamp = backup_file.stem.replace('purple-team-backup_', '')
            manifest_file = BACKUP_DIR / f'manifest_{timestamp}.json'
            
            backup_info = {
                'file': backup_file.name,
                'path': str(backup_file),
                'size_mb': backup_file.stat().st_size / (1024 * 1024),
                'created': datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat()
            }
            
            # Add manifest info if available
            if manifest_file.exists():
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    backup_info['manifest'] = manifest
            
            backups.append(backup_info)
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
        return backups
    
    def restore_backup(self, backup_file, target_dir=None, dry_run=False):
        """
        Restore from backup
        
        Args:
            backup_file: Path to backup file
            target_dir: Directory to restore to (default: /opt/purple-team)
            dry_run: If True, only show what would be restored
        """
        
        if not target_dir:
            target_dir = BASE_DIR
        
        backup_path = Path(backup_file)
        
        if not backup_path.exists():
            # Try to find it in backup directory
            backup_path = BACKUP_DIR / backup_file
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False
        
        logger.info(f"Restoring from: {backup_path}")
        
        if dry_run:
            logger.info("DRY RUN - No files will be modified")
            
            # List contents
            with tarfile.open(backup_path, 'r:gz') as tar:
                print("\nContents of backup:")
                for member in tar.getmembers():
                    print(f"  {member.name} ({member.size} bytes)")
            
            return True
        
        # Confirm restore
        print(f"\nÃ¢Å¡Â Ã¯Â¸Â  WARNING: This will restore data to {target_dir}")
        print("   Existing files may be overwritten!")
        response = input("\nProceed with restore? [y/N]: ")
        
        if response.lower() != 'y':
            logger.info("Restore cancelled")
            return False
        
        # Stop services before restore
        logger.info("Stopping services...")
        subprocess.run(['systemctl', 'stop', 'purple-team-dashboard'], 
                      capture_output=True)
        subprocess.run(['systemctl', 'stop', 'purple-team-scheduler'], 
                      capture_output=True)
        
        # Extract backup
        logger.info("Extracting backup...")
        with tarfile.open(backup_path, 'r:gz') as tar:
            tar.extractall(path=target_dir)
        
        logger.info("Ã¢Å“â€¦ Restore complete!")
        
        # Restart services
        logger.info("Restarting services...")
        subprocess.run(['systemctl', 'start', 'purple-team-dashboard'], 
                      capture_output=True)
        subprocess.run(['systemctl', 'start', 'purple-team-scheduler'], 
                      capture_output=True)
        
        logger.info("Ã¢Å“â€¦ Services restarted")
        
        return True
    
    def delete_old_backups(self, keep_count=10):
        """Delete old backups, keeping the most recent ones"""
        
        backups = self.list_backups()
        
        if len(backups) <= keep_count:
            logger.info(f"Only {len(backups)} backups exist, keeping all")
            return
        
        to_delete = backups[keep_count:]
        
        print(f"\nFound {len(backups)} backups, keeping {keep_count} newest")
        print(f"Will delete {len(to_delete)} old backups:")
        for backup in to_delete:
            print(f"  Ã¢â‚¬Â¢ {backup['file']} ({backup['size_mb']:.2f} MB)")
        
        response = input("\nProceed with deletion? [y/N]: ")
        
        if response.lower() != 'y':
            logger.info("Deletion cancelled")
            return
        
        for backup in to_delete:
            # Delete backup file
            Path(backup['path']).unlink()
            
            # Delete manifest if exists
            timestamp = Path(backup['file']).stem.replace('purple-team-backup_', '')
            manifest_file = BACKUP_DIR / f'manifest_{timestamp}.json'
            if manifest_file.exists():
                manifest_file.unlink()
            
            logger.info(f"  Deleted: {backup['file']}")
        
        logger.info(f"Ã¢Å“â€¦ Deleted {len(to_delete)} old backups")

def main():
    """Main entry point"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Purple Team Platform Backup & Restore'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Create backup
    backup_parser = subparsers.add_parser('create', help='Create new backup')
    backup_parser.add_argument('--include-logs', action='store_true',
                              help='Include log files')
    backup_parser.add_argument('--no-reports', action='store_true',
                              help='Exclude reports')
    
    # List backups
    list_parser = subparsers.add_parser('list', help='List available backups')
    
    # Restore backup
    restore_parser = subparsers.add_parser('restore', help='Restore from backup')
    restore_parser.add_argument('backup_file', help='Backup file to restore')
    restore_parser.add_argument('--dry-run', action='store_true',
                               help='Show what would be restored')
    
    # Cleanup old backups
    cleanup_parser = subparsers.add_parser('cleanup', help='Delete old backups')
    cleanup_parser.add_argument('--keep', type=int, default=10,
                               help='Number of backups to keep (default: 10)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        exit(1)
    
    manager = BackupManager()
    
    if args.command == 'create':
        manager.create_backup(
            include_logs=args.include_logs,
            include_reports=not args.no_reports
        )
    
    elif args.command == 'list':
        backups = manager.list_backups()
        
        if not backups:
            print("No backups found")
        else:
            print("\n" + "="*70)
            print("AVAILABLE BACKUPS")
            print("="*70)
            
            for i, backup in enumerate(backups, 1):
                print(f"\n{i}. {backup['file']}")
                print(f"   Created: {backup['created']}")
                print(f"   Size: {backup['size_mb']:.2f} MB")
                
                if 'manifest' in backup:
                    manifest = backup['manifest']
                    print(f"   Items: {len(manifest.get('items_backed_up', []))}")
                    print(f"   Logs: {'Yes' if manifest.get('includes_logs') else 'No'}")
                    print(f"   Reports: {'Yes' if manifest.get('includes_reports') else 'No'}")
            
            print("\n" + "="*70)
    
    elif args.command == 'restore':
        manager.restore_backup(args.backup_file, dry_run=args.dry_run)
    
    elif args.command == 'cleanup':
        manager.delete_old_backups(keep_count=args.keep)

if __name__ == '__main__':
    main()
