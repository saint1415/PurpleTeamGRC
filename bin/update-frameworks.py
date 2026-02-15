#!/usr/bin/env python3
"""
Sync compliance framework YAML files from the PolicyUpdate repo.

Checks saint1415/PolicyUpdate on GitHub for updated framework YAMLs
and downloads any that are newer than the local copies.

Usage:
    python3 bin/update-frameworks.py
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Resolve project paths
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
FRAMEWORKS_DIR = PROJECT_ROOT / 'config' / 'frameworks'

# GitHub API settings
REPO_OWNER = "saint1415"
REPO_NAME = "PolicyUpdate"
REPO_FRAMEWORKS_PATH = "frameworks"
API_BASE = "https://api.github.com"

USER_AGENT = "PurpleTeamGRC/7.0 FrameworkSync"


def github_headers():
    """Build request headers, using GITHUB_TOKEN if available."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3+json",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def fetch_json(url):
    """Fetch JSON from a URL with proper headers."""
    req = urllib.request.Request(url, headers=github_headers())
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  HTTP error {e.code} fetching {url}")
        if e.code == 403:
            print("  Rate limited - set GITHUB_TOKEN for higher limits")
        return None
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return None


def fetch_raw(url):
    """Fetch raw file content from a URL."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3.raw",
        **({
            "Authorization": f"token {os.environ['GITHUB_TOKEN']}"
        } if os.environ.get("GITHUB_TOKEN") else {}),
    })
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        return resp.read()
    except Exception as e:
        print(f"  Error downloading {url}: {e}")
        return None


def file_sha(path):
    """Compute the git blob SHA for a local file to compare with GitHub."""
    if not path.exists():
        return None
    content = path.read_bytes()
    # Git blob SHA = sha1("blob <size>\0<content>")
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()


def validate_yaml(content_bytes, filename):
    """Validate that content is valid YAML with a 'framework' key."""
    try:
        import yaml
    except ImportError:
        # Can't validate without PyYAML, accept the file
        return True

    try:
        data = yaml.safe_load(content_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            print(f"  INVALID: {filename} is not a YAML mapping")
            return False
        if 'framework' not in data:
            print(f"  INVALID: {filename} missing 'framework' key")
            return False
        return True
    except Exception as e:
        print(f"  INVALID: {filename} failed YAML parse: {e}")
        return False


def main():
    print()
    print("  ============================================================")
    print("   Purple Team Platform v7.0 - Framework Sync")
    print("  ============================================================")
    print()

    # Ensure frameworks directory exists
    FRAMEWORKS_DIR.mkdir(parents=True, exist_ok=True)

    # List files in the PolicyUpdate repo frameworks directory
    api_url = f"{API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{REPO_FRAMEWORKS_PATH}"
    print(f"  Checking {REPO_OWNER}/{REPO_NAME}/{REPO_FRAMEWORKS_PATH}...")
    print()

    files = fetch_json(api_url)
    if files is None:
        print("  ERROR: Could not fetch file listing from GitHub")
        sys.exit(1)

    if not isinstance(files, list):
        print("  ERROR: Unexpected API response (not a list)")
        print(f"  Response: {files}")
        sys.exit(1)

    yaml_files = [f for f in files if f.get('name', '').endswith(('.yaml', '.yml'))]

    if not yaml_files:
        print("  No YAML files found in remote repository")
        return

    updated = 0
    unchanged = 0
    new_files = 0
    failed = 0

    for remote_file in yaml_files:
        name = remote_file['name']
        remote_sha = remote_file.get('sha', '')
        download_url = remote_file.get('download_url', '')

        local_path = FRAMEWORKS_DIR / name
        local_sha = file_sha(local_path)

        if local_sha == remote_sha:
            unchanged += 1
            continue

        # Download the file
        if not download_url:
            print(f"  SKIP: {name} (no download URL)")
            failed += 1
            continue

        content = fetch_raw(download_url)
        if content is None:
            failed += 1
            continue

        # Validate YAML structure
        if not validate_yaml(content, name):
            failed += 1
            continue

        # Write the file
        local_path.write_bytes(content)

        if local_sha is None:
            new_files += 1
            print(f"  NEW:     {name}")
        else:
            updated += 1
            print(f"  UPDATED: {name}")

    print()
    print(f"  Summary:")
    print(f"    Remote files:  {len(yaml_files)}")
    print(f"    Unchanged:     {unchanged}")
    print(f"    Updated:       {updated}")
    print(f"    New:           {new_files}")
    if failed:
        print(f"    Failed:        {failed}")
    print()

    total_changes = updated + new_files
    if total_changes > 0:
        print(f"  {total_changes} framework(s) synced successfully.")
    else:
        print("  All frameworks are up to date.")


if __name__ == '__main__':
    main()
