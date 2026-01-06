#!/usr/bin/env python3
"""
Purple Team GRC Platform v4.0
Results Organizer - Creates timestamped scan session directories

Creates a centralized results folder in the current directory with:
- Timestamped session folder
- Organized subdirectories for each scan type
- Symlinks to actual result files

Usage:
  python3 results_organizer.py [--session-name "Client Name"]
"""

import os
import sys
import shutil
from pathlib import Path
from datetime import datetime
import json

class ResultsOrganizer:
    """Organize scan results into session-based directories"""
    
    def __init__(self, session_name=None, launch_dir=None):
        self.launch_dir = Path(launch_dir) if launch_dir else Path.cwd()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if session_name:
            self.session_name = f"{self.timestamp}_{session_name.replace(' ', '_')}"
        else:
            self.session_name = f"{self.timestamp}_scan_session"
        
        self.session_dir = self.launch_dir / "purple-team-results" / self.session_name
        
        # Source directories
        self.source_results = Path.home() / ".purple-team" / "results"
        self.source_reports = Path.home() / ".purple-team" / "reports"
        
    def create_session_structure(self):
        """Create organized directory structure"""
        print(f"Creating scan session directory: {self.session_dir}")
        
        # Create main session directory
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        subdirs = [
            "network-scans",
            "vulnerability-scans",
            "compliance-reports",
            "executive-reports",
            "evidence-packages",
            "logs",
            "raw-data"
        ]
        
        for subdir in subdirs:
            (self.session_dir / subdir).mkdir(exist_ok=True)
        
        print(f"✓ Session structure created")
    
    def copy_recent_results(self, minutes=60):
        """Copy results from last N minutes to session directory"""
        cutoff_time = datetime.now().timestamp() - (minutes * 60)
        copied_files = []
        
        # Copy from results directory
        if self.source_results.exists():
            for file in self.source_results.glob("*.json"):
                if file.stat().st_mtime > cutoff_time:
                    # Determine destination based on filename
                    if "NetworkScan" in file.name:
                        dest_dir = self.session_dir / "network-scans"
                    elif "VulnerabilityScan" in file.name:
                        dest_dir = self.session_dir / "vulnerability-scans"
                    elif "ComplianceCheck" in file.name:
                        dest_dir = self.session_dir / "compliance-reports"
                    elif "complete_assessment" in file.name:
                        dest_dir = self.session_dir / "raw-data"
                    else:
                        dest_dir = self.session_dir / "raw-data"
                    
                    shutil.copy2(file, dest_dir / file.name)
                    copied_files.append(file.name)
            
            # Copy HTML reports
            for file in self.source_results.glob("*.html"):
                if file.stat().st_mtime > cutoff_time:
                    if "NetworkScan" in file.name:
                        dest_dir = self.session_dir / "network-scans"
                    elif "ComplianceCheck" in file.name:
                        dest_dir = self.session_dir / "compliance-reports"
                    else:
                        dest_dir = self.session_dir / "raw-data"
                    
                    shutil.copy2(file, dest_dir / file.name)
                    copied_files.append(file.name)
        
        # Copy from reports directory
        if self.source_reports.exists():
            # Executive reports
            exec_dir = self.source_reports / "executive"
            if exec_dir.exists():
                for file in exec_dir.glob("*.txt"):
                    if file.stat().st_mtime > cutoff_time:
                        shutil.copy2(file, self.session_dir / "executive-reports" / file.name)
                        copied_files.append(f"executive/{file.name}")
            
            # Recommendations
            for file in self.source_reports.glob("recommendations_*.json"):
                if file.stat().st_mtime > cutoff_time:
                    shutil.copy2(file, self.session_dir / "compliance-reports" / file.name)
                    copied_files.append(file.name)
        
        return copied_files
    
    def create_session_manifest(self, copied_files):
        """Create a manifest file for the session"""
        manifest = {
            "session_name": self.session_name,
            "created": datetime.now().isoformat(),
            "launch_directory": str(self.launch_dir),
            "total_files": len(copied_files),
            "files": copied_files,
            "directories": {
                "network_scans": str(self.session_dir / "network-scans"),
                "vulnerability_scans": str(self.session_dir / "vulnerability-scans"),
                "compliance_reports": str(self.session_dir / "compliance-reports"),
                "executive_reports": str(self.session_dir / "executive-reports"),
                "evidence_packages": str(self.session_dir / "evidence-packages")
            }
        }
        
        manifest_file = self.session_dir / "SESSION_MANIFEST.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Create README
        readme = self.session_dir / "README.txt"
        with open(readme, 'w') as f:
            f.write(f"Purple Team GRC Platform - Scan Session Results\n")
            f.write(f"{'='*60}\n\n")
            f.write(f"Session: {self.session_name}\n")
            f.write(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Location: {self.session_dir}\n\n")
            f.write(f"Directory Structure:\n")
            f.write(f"  network-scans/        - Network discovery and port scans\n")
            f.write(f"  vulnerability-scans/  - Vulnerability assessment results\n")
            f.write(f"  compliance-reports/   - Compliance framework analysis\n")
            f.write(f"  executive-reports/    - Executive summaries\n")
            f.write(f"  evidence-packages/    - Evidence for auditors\n")
            f.write(f"  logs/                 - Scan logs and debugging info\n")
            f.write(f"  raw-data/             - Raw JSON data\n\n")
            f.write(f"Total Files: {len(copied_files)}\n")
    
    def organize(self):
        """Main organization workflow"""
        print(f"\n{'='*60}")
        print(f"Purple Team Results Organizer")
        print(f"{'='*60}\n")
        
        # Create structure
        self.create_session_structure()
        
        # Copy recent results
        print(f"Copying recent scan results...")
        copied_files = self.copy_recent_results(minutes=120)  # Last 2 hours
        
        if not copied_files:
            print(f"⚠ No recent results found (last 2 hours)")
            print(f"  Run some scans first, then organize results")
            return
        
        print(f"✓ Copied {len(copied_files)} files")
        
        # Create manifest
        self.create_session_manifest(copied_files)
        print(f"✓ Created session manifest")
        
        # Summary
        print(f"\n{'='*60}")
        print(f"Session directory created!")
        print(f"{'='*60}\n")
        print(f"Location: {self.session_dir}\n")
        print(f"Files organized:")
        print(f"  Network scans:        {len(list((self.session_dir / 'network-scans').glob('*')))} files")
        print(f"  Vulnerability scans:  {len(list((self.session_dir / 'vulnerability-scans').glob('*')))} files")
        print(f"  Compliance reports:   {len(list((self.session_dir / 'compliance-reports').glob('*')))} files")
        print(f"  Executive reports:    {len(list((self.session_dir / 'executive-reports').glob('*')))} files")
        print(f"\nView results: cd {self.session_dir}\n")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Organize Purple Team scan results into session directory'
    )
    parser.add_argument(
        '--session-name',
        help='Custom session name (e.g., "ACME Corp Q1 2026")'
    )
    parser.add_argument(
        '--launch-dir',
        default=os.getcwd(),
        help='Directory to create results folder in (default: current directory)'
    )
    
    args = parser.parse_args()
    
    organizer = ResultsOrganizer(
        session_name=args.session_name,
        launch_dir=args.launch_dir
    )
    organizer.organize()

if __name__ == '__main__':
    main()
