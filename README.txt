╔═══════════════════════════════════════════════════════════════╗
║          PURPLE TEAM PLATFORM v5.0                            ║
║          Systems Thinking Security Assessment                 ║
╚═══════════════════════════════════════════════════════════════╝

QUICK START
-----------
1. Run setup (first time only):
   bash setup.sh

2. Launch the platform (NEW polished interface):
   python3 bin/purple-launcher

3. Or use CLI commands:
   python3 bin/purple-launcher quick    # Quick scan
   python3 bin/purple-launcher tools    # Check available tools
   python3 bin/purple-launcher deep     # Full assessment

LEGACY CLI (still works):
   bash bin/purple-team                 # Interactive menu
   bash bin/purple-team quick           # Quick scan
   bash bin/purple-team check           # System check


DESIGN PHILOSOPHY
-----------------
This platform uses Gharajedaghi's Systems Thinking approach:

• OPENNESS - Adapts to available tools in the environment
• PURPOSEFULNESS - Multi-dimensional goals (security, compliance, resilience)
• MULTIDIMENSIONALITY - Red Team + Blue Team + Purple Team integration
• EMERGENT PROPERTIES - Gap analysis emerges from integration
• COUNTER-INTUITIVE - Human-like behavior to test detection capabilities


FEATURES
--------
RED TEAM (Offensive):
  • Network reconnaissance and port scanning
  • Vulnerability assessment
  • Web application testing
  • ATT&CK technique simulation

BLUE TEAM (Defensive):
  • Security hardening audits
  • Malware and rootkit detection
  • Log analysis
  • File integrity monitoring

PURPLE TEAM (Integration):
  • Detection gap analysis
  • Control effectiveness measurement
  • Continuous validation


TOOL DISCOVERY
--------------
The platform auto-detects 40+ security tools including:
  • Scanning: nmap, nuclei, nikto, testssl.sh, masscan
  • Red Team: metasploit, impacket, bloodhound
  • Blue Team: yara, clamav, rkhunter, suricata
  • Forensics: autopsy, volatility, binwalk
  • Web: burpsuite, zaproxy, sqlmap

Run 'python3 bin/purple-launcher tools' to see available tools.


COMPLIANCE FRAMEWORKS
---------------------
• NIST SP 800-53 Rev 5
• HIPAA Security Rule
• PCI-DSS v4.0
• SOC 1 & SOC 2 Type II
• ISO 27001:2022
• CMMC, FedRAMP, GDPR, SOX


HUMAN-LIKE BEHAVIOR
-------------------
Four behavior profiles for realistic scanning:
• stealth   - Very slow, maximum evasion (for testing detection)
• normal    - Balanced speed and stealth (default)
• fast      - Quick but still human-like
• aggressive- Minimal delays, speed priority

This helps test detection of "low and slow" attacks.


FILE STRUCTURE
--------------
purple-final/
├── bin/                 # Launcher scripts
│   ├── purple-launcher  # Main TUI launcher (NEW v5.0)
│   ├── purple-team      # Legacy CLI launcher
│   └── scheduler.py     # Cron scheduler
├── lib/                 # Core libraries
│   ├── tui.py          # Terminal UI components (NEW)
│   ├── tool_discovery.py# Auto tool detection (NEW)
│   ├── human_behavior.py# Human-like timing (NEW)
│   ├── paths.py        # Portable path resolver
│   ├── config.py       # Configuration manager
│   ├── evidence.py     # Evidence database
│   └── compliance.py   # Compliance mapping
├── scanners/           # Scanner modules
├── utilities/          # Reporting and export
├── config/             # Configuration files
├── data/               # All results stored here
│   ├── results/        # Scan results
│   ├── reports/        # Generated reports
│   ├── evidence/       # Audit evidence
│   └── logs/           # Activity logs
└── docs/               # Documentation


USB PORTABILITY
---------------
This package runs entirely from USB:
• All paths auto-detect from script location
• Results stored on USB in data/ folder
• No files written outside the package
• Works on any Linux system with Python 3.9+


RETENTION
---------
All results, logs, and evidence retained for 365 days.
Automatic compression after 30 days.


SUPPORT
-------
• Documentation: docs/ folder
• Design Philosophy: DESIGN_PHILOSOPHY.md
• Auditor Guide: AUDITOR_GUIDE.md


================================================================================
                         SYSTEMS THINKING SECURITY
                   Red + Blue + Purple = Comprehensive Defense
================================================================================
