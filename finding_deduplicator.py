#!/usr/bin/env python3
"""

Version: 3.0 - Updated for dynamic path detectionFinding Deduplicator - Automatically merge duplicate vulnerability findings"""
import json, hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import path helper for dynamic paths
from utils.path_helper import BASE_DIR, CONFIG_FILE, RESULTS_DIR, LOGS_DIR

BASE_DIR.mkdir(parents=True, exist_ok=True)

class FindingDeduplicator:
    def generate_signature(self, finding):
        """Generate unique signature for finding"""
        key = f"{finding.get('host')}_{finding.get('title')}_{finding.get('severity')}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def deduplicate(self, findings):
        """Merge duplicate findings"""
        grouped = defaultdict(list)
        
        for finding in findings:
            sig = self.generate_signature(finding)
            grouped[sig].append(finding)
        
        deduplicated = []
        duplicates = []
        
        for sig, group in grouped.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Merge duplicates
                merged = group[0].copy()
                merged['duplicate_count'] = len(group)
                merged['first_seen'] = min(f.get('date', '') for f in group)
                merged['last_seen'] = max(f.get('date', '') for f in group)
                deduplicated.append(merged)
                duplicates.extend(group[1:])
        
        return deduplicated, duplicates
    
    def load_findings(self, filepath):
        """Load findings from JSON"""
        with open(filepath) as f:
            return json.load(f)
    
    def save_findings(self, findings, filepath):
        """Save deduplicated findings"""
        with open(filepath, 'w') as f:
            json.dump(findings, f, indent=2)
    
    def print_report(self, original_count, dedup_count, dup_count):
        print("\n" + "="*70)
        print("FINDING DEDUPLICATION REPORT")
        print("="*70)
        print(f"Original Findings: {original_count}")
        print(f"Unique Findings: {dedup_count}")
        print(f"Duplicates Removed: {dup_count}")
        print(f"Reduction: {(dup_count/original_count*100):.1f}%")
        print("="*70 + "\n")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Finding Deduplicator')
    parser.add_argument('input', help='Input findings JSON file')
    parser.add_argument('--output', help='Output file for deduplicated findings')
    
    args = parser.parse_args()
    
    deduper = FindingDeduplicator()
    findings = deduper.load_findings(args.input)
    dedup, dups = deduper.deduplicate(findings)
    
    if args.output:
        deduper.save_findings(dedup, args.output)
    
    deduper.print_report(len(findings), len(dedup), len(dups))
