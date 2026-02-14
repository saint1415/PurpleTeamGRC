#!/usr/bin/env python3
"""Test runner with Windows console UTF-8 fix."""

import sys
import os
import io

# Fix Windows console encoding BEFORE any output
if sys.platform == 'win32':
    # Wrap stdout/stderr with UTF-8 encoding
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add lib to path
base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(base_dir, 'lib'))
sys.path.insert(0, os.path.join(base_dir, 'scanners'))
sys.path.insert(0, os.path.join(base_dir, 'utilities'))
sys.path.insert(0, base_dir)

# Now import and run
os.chdir(base_dir)
exec(open(os.path.join(base_dir, 'bin', 'purple-launcher')).read())
