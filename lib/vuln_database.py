#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - Vulnerability Intelligence Database

Unified vulnerability knowledge base combining multiple authoritative sources:
- NVD (NIST National Vulnerability Database) - CVE details via API 2.0
- CISA KEV - Known Exploited Vulnerabilities (via threat_intel.py)
- EPSS - Exploit Prediction Scoring (via threat_intel.py)
- OWASP Top 10 2021 - Web application risk categories (embedded)
- CWE Top 25 2024 - Most dangerous software weaknesses (embedded)
- CAPEC - Common Attack Pattern Enumeration (embedded subset)
- MITRE ATT&CK - Enterprise technique mapping (embedded subset)

Operates offline with embedded/cached data for USB portable mode.
Live API queries when network available for NVD enrichment.
"""

import json
import os
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .logger import get_logger
    from .threat_intel import get_threat_intel
except ImportError:
    from paths import paths
    from logger import get_logger
    from threat_intel import get_threat_intel

logger = get_logger('vuln_database')

# NVD API 2.0 base URL (no API key required, but rate-limited to 5 req/30s)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

# Rate limit: 5 req/30s without key (6s delay), 50 req/30s with key (0.6s delay)
def _nvd_rate_delay():
    return 0.7 if os.environ.get('NVD_API_KEY') else 6.0

# Cache TTL: 7 days for NVD data (it changes less frequently than KEV/EPSS)
NVD_CACHE_TTL = 7 * 86400

# ============================================================
# OWASP Top 10 - 2021 (embedded, static)
# Source: https://owasp.org/Top10/
# ============================================================
OWASP_TOP_10_2021 = {
    'A01:2021': {
        'id': 'A01:2021',
        'name': 'Broken Access Control',
        'description': 'Access control enforces policy such that users cannot act outside of '
                       'their intended permissions. Failures typically lead to unauthorized '
                       'information disclosure, modification, or destruction of data.',
        'cwes': ['CWE-200', 'CWE-201', 'CWE-352', 'CWE-284', 'CWE-285',
                 'CWE-862', 'CWE-863', 'CWE-22', 'CWE-425', 'CWE-611',
                 'CWE-639', 'CWE-918'],
        'risk_level': 'Critical',
        'prevalence': '94% of applications tested for some form of broken access control',
        'remediation': 'Deny by default, implement access control mechanisms once and reuse, '
                       'enforce record ownership, disable directory listing, log access control failures.',
    },
    'A02:2021': {
        'id': 'A02:2021',
        'name': 'Cryptographic Failures',
        'description': 'Failures related to cryptography which often leads to sensitive data '
                       'exposure. Formerly known as Sensitive Data Exposure.',
        'cwes': ['CWE-259', 'CWE-327', 'CWE-328', 'CWE-330', 'CWE-331',
                 'CWE-312', 'CWE-319', 'CWE-326', 'CWE-261'],
        'risk_level': 'High',
        'prevalence': 'Shifted from #3 in 2017; related to use of weak crypto or lack of encryption',
        'remediation': 'Classify data, encrypt at rest and in transit, use strong algorithms, '
                       'disable caching for sensitive data, use authenticated encryption.',
    },
    'A03:2021': {
        'id': 'A03:2021',
        'name': 'Injection',
        'description': 'Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when '
                       'untrusted data is sent to an interpreter as part of a command or query.',
        'cwes': ['CWE-79', 'CWE-89', 'CWE-73', 'CWE-77', 'CWE-78',
                 'CWE-94', 'CWE-917', 'CWE-116'],
        'risk_level': 'Critical',
        'prevalence': '94% of applications tested for some form of injection',
        'remediation': 'Use parameterized queries, use positive server-side input validation, '
                       'escape special characters, use LIMIT and other SQL controls.',
    },
    'A04:2021': {
        'id': 'A04:2021',
        'name': 'Insecure Design',
        'description': 'Risks related to design and architectural flaws, calling for more use of '
                       'threat modeling, secure design patterns, and reference architectures.',
        'cwes': ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522', 'CWE-266',
                 'CWE-269', 'CWE-280', 'CWE-311', 'CWE-798'],
        'risk_level': 'High',
        'prevalence': 'New category for 2021; focuses on risks from design flaws',
        'remediation': 'Establish secure development lifecycle, use threat modeling, '
                       'use secure design patterns, write unit and integration tests for critical flows.',
    },
    'A05:2021': {
        'id': 'A05:2021',
        'name': 'Security Misconfiguration',
        'description': 'Missing appropriate security hardening or improperly configured permissions '
                       'on cloud services, unnecessary features enabled, default accounts unchanged.',
        'cwes': ['CWE-16', 'CWE-611', 'CWE-1004', 'CWE-1032', 'CWE-756',
                 'CWE-2', 'CWE-215'],
        'risk_level': 'High',
        'prevalence': '90% of applications tested for some form of misconfiguration',
        'remediation': 'Repeatable hardening process, minimal platform, review and update configs, '
                       'segmented architecture, send security directives to clients.',
    },
    'A06:2021': {
        'id': 'A06:2021',
        'name': 'Vulnerable and Outdated Components',
        'description': 'Components such as libraries, frameworks, and other software modules run '
                       'with the same privileges. If a vulnerable component is exploited, it can '
                       'facilitate serious data loss or server takeover.',
        'cwes': ['CWE-1035', 'CWE-1104', 'CWE-937'],
        'risk_level': 'High',
        'prevalence': 'Moved up from #9 in 2017; known issue that is difficult to test for',
        'remediation': 'Remove unused dependencies, inventory component versions, monitor CVE/NVD, '
                       'only obtain components from official sources over secure links.',
    },
    'A07:2021': {
        'id': 'A07:2021',
        'name': 'Identification and Authentication Failures',
        'description': 'Confirmation of identity, authentication, and session management is critical. '
                       'Weaknesses here can allow attackers to compromise passwords, keys, or tokens.',
        'cwes': ['CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290',
                 'CWE-294', 'CWE-295', 'CWE-297', 'CWE-300', 'CWE-302',
                 'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384',
                 'CWE-521', 'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798'],
        'risk_level': 'High',
        'prevalence': 'Previously Broken Authentication; standardized frameworks help but still prevalent',
        'remediation': 'Implement MFA, no default credentials, weak password checks, '
                       'harden against credential stuffing, limit failed login attempts.',
    },
    'A08:2021': {
        'id': 'A08:2021',
        'name': 'Software and Data Integrity Failures',
        'description': 'Failures relating to code and infrastructure that does not protect against '
                       'integrity violations. Includes insecure CI/CD pipelines and auto-updates.',
        'cwes': ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502',
                 'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830', 'CWE-915'],
        'risk_level': 'High',
        'prevalence': 'New category for 2021; includes deserialization, CI/CD integrity',
        'remediation': 'Verify software and data integrity using signatures, use trusted repos, '
                       'review code and config changes in CI/CD, ensure deserialization has integrity checks.',
    },
    'A09:2021': {
        'id': 'A09:2021',
        'name': 'Security Logging and Monitoring Failures',
        'description': 'Without logging and monitoring, breaches cannot be detected. Insufficient '
                       'logging, detection, monitoring, and active response.',
        'cwes': ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
        'risk_level': 'Medium',
        'prevalence': 'Difficult to test; typically assessed via interviews and review',
        'remediation': 'Log all login, access control, and server-side input validation failures, '
                       'ensure logs are in a format log management solutions can consume, '
                       'establish effective monitoring and alerting.',
    },
    'A10:2021': {
        'id': 'A10:2021',
        'name': 'Server-Side Request Forgery (SSRF)',
        'description': 'SSRF flaws occur when a web application fetches a remote resource without '
                       'validating the user-supplied URL. Allows attackers to coerce the application '
                       'to send requests to unexpected destinations.',
        'cwes': ['CWE-918'],
        'risk_level': 'High',
        'prevalence': 'New category for 2021; increasing with cloud services and complex architectures',
        'remediation': 'Sanitize and validate all client-supplied input data, enforce URL schema/port/destination, '
                       'do not send raw responses to clients, disable HTTP redirections.',
    },
}

# ============================================================
# CWE Top 25 - 2024 Most Dangerous Software Weaknesses
# Source: https://cwe.mitre.org/top25/archive/2024/2024_top25_list.html
# ============================================================
CWE_TOP_25_2024 = [
    {'rank': 1, 'cwe_id': 'CWE-79', 'name': 'Improper Neutralization of Input During Web Page Generation (XSS)',
     'score': 56.92, 'kev_count': 3, 'owasp': 'A03:2021'},
    {'rank': 2, 'cwe_id': 'CWE-787', 'name': 'Out-of-bounds Write',
     'score': 45.20, 'kev_count': 18, 'owasp': None},
    {'rank': 3, 'cwe_id': 'CWE-89', 'name': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
     'score': 35.88, 'kev_count': 4, 'owasp': 'A03:2021'},
    {'rank': 4, 'cwe_id': 'CWE-352', 'name': 'Cross-Site Request Forgery (CSRF)',
     'score': 19.57, 'kev_count': 0, 'owasp': 'A01:2021'},
    {'rank': 5, 'cwe_id': 'CWE-22', 'name': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
     'score': 12.74, 'kev_count': 4, 'owasp': 'A01:2021'},
    {'rank': 6, 'cwe_id': 'CWE-125', 'name': 'Out-of-bounds Read',
     'score': 11.42, 'kev_count': 3, 'owasp': None},
    {'rank': 7, 'cwe_id': 'CWE-78', 'name': 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
     'score': 11.30, 'kev_count': 5, 'owasp': 'A03:2021'},
    {'rank': 8, 'cwe_id': 'CWE-416', 'name': 'Use After Free',
     'score': 10.19, 'kev_count': 5, 'owasp': None},
    {'rank': 9, 'cwe_id': 'CWE-862', 'name': 'Missing Authorization',
     'score': 10.11, 'kev_count': 0, 'owasp': 'A01:2021'},
    {'rank': 10, 'cwe_id': 'CWE-434', 'name': 'Unrestricted Upload of File with Dangerous Type',
     'score': 10.03, 'kev_count': 6, 'owasp': None},
    {'rank': 11, 'cwe_id': 'CWE-94', 'name': 'Improper Control of Generation of Code (Code Injection)',
     'score': 7.13, 'kev_count': 7, 'owasp': 'A03:2021'},
    {'rank': 12, 'cwe_id': 'CWE-20', 'name': 'Improper Input Validation',
     'score': 6.78, 'kev_count': 1, 'owasp': None},
    {'rank': 13, 'cwe_id': 'CWE-77', 'name': 'Improper Neutralization of Special Elements used in a Command (Command Injection)',
     'score': 6.74, 'kev_count': 4, 'owasp': 'A03:2021'},
    {'rank': 14, 'cwe_id': 'CWE-287', 'name': 'Improper Authentication',
     'score': 5.94, 'kev_count': 4, 'owasp': 'A07:2021'},
    {'rank': 15, 'cwe_id': 'CWE-269', 'name': 'Improper Privilege Management',
     'score': 5.22, 'kev_count': 0, 'owasp': 'A04:2021'},
    {'rank': 16, 'cwe_id': 'CWE-502', 'name': 'Deserialization of Untrusted Data',
     'score': 5.07, 'kev_count': 5, 'owasp': 'A08:2021'},
    {'rank': 17, 'cwe_id': 'CWE-200', 'name': 'Exposure of Sensitive Information to an Unauthorized Actor',
     'score': 5.07, 'kev_count': 0, 'owasp': 'A01:2021'},
    {'rank': 18, 'cwe_id': 'CWE-863', 'name': 'Incorrect Authorization',
     'score': 4.05, 'kev_count': 0, 'owasp': 'A01:2021'},
    {'rank': 19, 'cwe_id': 'CWE-306', 'name': 'Missing Authentication for Critical Function',
     'score': 3.95, 'kev_count': 2, 'owasp': 'A07:2021'},
    {'rank': 20, 'cwe_id': 'CWE-190', 'name': 'Integer Overflow or Wraparound',
     'score': 3.92, 'kev_count': 3, 'owasp': None},
    {'rank': 21, 'cwe_id': 'CWE-918', 'name': 'Server-Side Request Forgery (SSRF)',
     'score': 3.68, 'kev_count': 2, 'owasp': 'A10:2021'},
    {'rank': 22, 'cwe_id': 'CWE-476', 'name': 'NULL Pointer Dereference',
     'score': 3.58, 'kev_count': 0, 'owasp': None},
    {'rank': 23, 'cwe_id': 'CWE-276', 'name': 'Incorrect Default Permissions',
     'score': 3.16, 'kev_count': 0, 'owasp': 'A04:2021'},
    {'rank': 24, 'cwe_id': 'CWE-798', 'name': 'Use of Hard-coded Credentials',
     'score': 2.66, 'kev_count': 2, 'owasp': 'A07:2021'},
    {'rank': 25, 'cwe_id': 'CWE-119', 'name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
     'score': 2.38, 'kev_count': 4, 'owasp': None},
]

# Build CWE lookup from Top 25
_CWE_BY_ID = {entry['cwe_id']: entry for entry in CWE_TOP_25_2024}

# ============================================================
# CAPEC - Common Attack Pattern Enumeration and Classification
# Embedded subset: most common patterns linked to CWE Top 25
# Source: https://capec.mitre.org/
# ============================================================
CAPEC_PATTERNS = {
    'CAPEC-66': {
        'id': 'CAPEC-66', 'name': 'SQL Injection',
        'description': 'Attacker exploits poorly sanitized input to manipulate SQL queries.',
        'severity': 'High', 'likelihood': 'High',
        'cwes': ['CWE-89'], 'attack_techniques': ['T1190'],
    },
    'CAPEC-86': {
        'id': 'CAPEC-86', 'name': 'XSS via HTTP Headers',
        'description': 'Attacker injects malicious script via HTTP header fields.',
        'severity': 'Medium', 'likelihood': 'Medium',
        'cwes': ['CWE-79'], 'attack_techniques': ['T1189'],
    },
    'CAPEC-88': {
        'id': 'CAPEC-88', 'name': 'OS Command Injection',
        'description': 'Attacker injects operating system commands through application input.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-78', 'CWE-77'], 'attack_techniques': ['T1059'],
    },
    'CAPEC-126': {
        'id': 'CAPEC-126', 'name': 'Path Traversal',
        'description': 'Attacker manipulates file path references to access files outside intended scope.',
        'severity': 'High', 'likelihood': 'High',
        'cwes': ['CWE-22'], 'attack_techniques': ['T1083'],
    },
    'CAPEC-62': {
        'id': 'CAPEC-62', 'name': 'Cross Site Request Forgery',
        'description': 'Attacker tricks victim into submitting a malicious request to a web app they are authenticated to.',
        'severity': 'Medium', 'likelihood': 'Medium',
        'cwes': ['CWE-352'], 'attack_techniques': ['T1189'],
    },
    'CAPEC-17': {
        'id': 'CAPEC-17', 'name': 'Using Malicious Files',
        'description': 'Attacker uploads malicious files to gain code execution on the server.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-434'], 'attack_techniques': ['T1204.002'],
    },
    'CAPEC-586': {
        'id': 'CAPEC-586', 'name': 'Object Injection',
        'description': 'Attacker exploits deserialization of untrusted data to execute arbitrary code.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-502'], 'attack_techniques': ['T1059'],
    },
    'CAPEC-664': {
        'id': 'CAPEC-664', 'name': 'Server Side Request Forgery',
        'description': 'Attacker induces server-side application to make HTTP requests to an arbitrary domain.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-918'], 'attack_techniques': ['T1090'],
    },
    'CAPEC-114': {
        'id': 'CAPEC-114', 'name': 'Authentication Abuse',
        'description': 'Attacker exploits flaws in authentication mechanisms to gain unauthorized access.',
        'severity': 'High', 'likelihood': 'High',
        'cwes': ['CWE-287', 'CWE-306'], 'attack_techniques': ['T1078'],
    },
    'CAPEC-122': {
        'id': 'CAPEC-122', 'name': 'Privilege Abuse',
        'description': 'Attacker exploits improper privilege management to escalate their access level.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-269', 'CWE-862', 'CWE-863'], 'attack_techniques': ['T1068'],
    },
    'CAPEC-242': {
        'id': 'CAPEC-242', 'name': 'Code Injection',
        'description': 'Attacker exploits application to inject and execute arbitrary code.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-94'], 'attack_techniques': ['T1059'],
    },
    'CAPEC-196': {
        'id': 'CAPEC-196', 'name': 'Session Credential Falsification through Forging',
        'description': 'Attacker creates falsified credentials to bypass authentication.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-798', 'CWE-287'], 'attack_techniques': ['T1078.001'],
    },
    'CAPEC-100': {
        'id': 'CAPEC-100', 'name': 'Overflow Buffers',
        'description': 'Attacker writes data past the allocated buffer boundary to corrupt memory.',
        'severity': 'High', 'likelihood': 'Medium',
        'cwes': ['CWE-119', 'CWE-787', 'CWE-125'], 'attack_techniques': ['T1203'],
    },
    'CAPEC-169': {
        'id': 'CAPEC-169', 'name': 'Footprinting',
        'description': 'Attacker discovers information about the target through active or passive reconnaissance.',
        'severity': 'Low', 'likelihood': 'High',
        'cwes': ['CWE-200'], 'attack_techniques': ['T1592', 'T1590'],
    },
    'CAPEC-560': {
        'id': 'CAPEC-560', 'name': 'Use of Known Domain Credentials',
        'description': 'Attacker uses previously compromised credentials to access systems.',
        'severity': 'High', 'likelihood': 'High',
        'cwes': ['CWE-798', 'CWE-287'], 'attack_techniques': ['T1078'],
    },
}

# Build CAPEC-to-CWE reverse mapping
_CAPEC_BY_CWE = {}
for capec_id, capec in CAPEC_PATTERNS.items():
    for cwe_id in capec['cwes']:
        _CAPEC_BY_CWE.setdefault(cwe_id, []).append(capec_id)

# ============================================================
# MITRE ATT&CK Enterprise - Technique subset
# Source: https://attack.mitre.org/techniques/enterprise/
# ============================================================
ATTACK_TECHNIQUES = {
    'T1190': {
        'id': 'T1190', 'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'description': 'Adversaries may attempt to exploit a vulnerability in an Internet-facing host or system.',
        'platforms': ['Linux', 'Windows', 'macOS', 'Containers'],
        'data_sources': ['Application Log', 'Network Traffic'],
        'cwes': ['CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-94', 'CWE-918', 'CWE-502'],
    },
    'T1189': {
        'id': 'T1189', 'name': 'Drive-by Compromise',
        'tactic': 'Initial Access',
        'description': 'Adversaries may gain access through a user visiting a website that exploits browser vulnerabilities.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['Network Traffic', 'File Creation'],
        'cwes': ['CWE-79', 'CWE-352'],
    },
    'T1059': {
        'id': 'T1059', 'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse command and script interpreters to execute commands or scripts.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['Command Execution', 'Process Creation'],
        'cwes': ['CWE-78', 'CWE-77', 'CWE-94', 'CWE-502'],
    },
    'T1203': {
        'id': 'T1203', 'name': 'Exploitation for Client Execution',
        'tactic': 'Execution',
        'description': 'Adversaries may exploit software vulnerabilities in client applications to execute code.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['Process Creation', 'Application Log'],
        'cwes': ['CWE-119', 'CWE-787', 'CWE-125', 'CWE-416', 'CWE-190'],
    },
    'T1068': {
        'id': 'T1068', 'name': 'Exploitation for Privilege Escalation',
        'tactic': 'Privilege Escalation',
        'description': 'Adversaries may exploit software vulnerabilities to gain elevated privileges.',
        'platforms': ['Linux', 'Windows', 'macOS', 'Containers'],
        'data_sources': ['Process Creation', 'Kernel Log'],
        'cwes': ['CWE-269', 'CWE-862', 'CWE-863', 'CWE-276'],
    },
    'T1078': {
        'id': 'T1078', 'name': 'Valid Accounts',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may use legitimate credentials to gain access, maintain persistence, and escalate privileges.',
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud'],
        'data_sources': ['Logon Session', 'User Account'],
        'cwes': ['CWE-287', 'CWE-306', 'CWE-798'],
    },
    'T1078.001': {
        'id': 'T1078.001', 'name': 'Valid Accounts: Default Accounts',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries may use default credentials of devices and services.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['Logon Session', 'User Account'],
        'cwes': ['CWE-798'],
    },
    'T1204.002': {
        'id': 'T1204.002', 'name': 'User Execution: Malicious File',
        'tactic': 'Execution',
        'description': 'Adversaries may trick users into executing malicious uploaded files.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['File Creation', 'Process Creation'],
        'cwes': ['CWE-434'],
    },
    'T1083': {
        'id': 'T1083', 'name': 'File and Directory Discovery',
        'tactic': 'Discovery',
        'description': 'Adversaries may enumerate files and directories to find information of interest.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['Command Execution', 'Process Creation'],
        'cwes': ['CWE-22', 'CWE-200'],
    },
    'T1090': {
        'id': 'T1090', 'name': 'Proxy',
        'tactic': 'Command and Control',
        'description': 'Adversaries may use proxies to direct network traffic between systems or act as intermediary.',
        'platforms': ['Linux', 'Windows', 'macOS'],
        'data_sources': ['Network Traffic'],
        'cwes': ['CWE-918'],
    },
    'T1592': {
        'id': 'T1592', 'name': 'Gather Victim Host Information',
        'tactic': 'Reconnaissance',
        'description': 'Adversaries may gather information about the victim host that can be used during targeting.',
        'platforms': ['PRE'],
        'data_sources': ['Internet Scan'],
        'cwes': ['CWE-200'],
    },
    'T1590': {
        'id': 'T1590', 'name': 'Gather Victim Network Information',
        'tactic': 'Reconnaissance',
        'description': 'Adversaries may gather information about the victim network that can be used during targeting.',
        'platforms': ['PRE'],
        'data_sources': ['Internet Scan'],
        'cwes': ['CWE-200'],
    },
    'T1110': {
        'id': 'T1110', 'name': 'Brute Force',
        'tactic': 'Credential Access',
        'description': 'Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.',
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud'],
        'data_sources': ['Logon Session', 'User Account'],
        'cwes': ['CWE-287', 'CWE-307', 'CWE-521'],
    },
    'T1595': {
        'id': 'T1595', 'name': 'Active Scanning',
        'tactic': 'Reconnaissance',
        'description': 'Adversaries may execute active reconnaissance scans to gather information for targeting.',
        'platforms': ['PRE'],
        'data_sources': ['Network Traffic'],
        'cwes': [],
    },
}

# Build ATT&CK-to-CWE reverse mapping
_ATTACK_BY_CWE = {}
for tech_id, tech in ATTACK_TECHNIQUES.items():
    for cwe_id in tech.get('cwes', []):
        _ATTACK_BY_CWE.setdefault(cwe_id, []).append(tech_id)

# Build CWE-to-OWASP reverse mapping from OWASP data
_CWE_TO_OWASP = {}
for owasp_id, owasp in OWASP_TOP_10_2021.items():
    for cwe_id in owasp['cwes']:
        _CWE_TO_OWASP.setdefault(cwe_id, []).append(owasp_id)


class VulnDatabase:
    """Unified vulnerability intelligence database with offline and online modes."""

    _instance: Optional['VulnDatabase'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.db_dir = paths.data / 'vuln_db'
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / 'vuln_intel.db'

        self._threat_intel = get_threat_intel()
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite cache database."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS nvd_cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_v31_score REAL,
                    cvss_v31_vector TEXT,
                    cvss_v31_severity TEXT,
                    cvss_v2_score REAL,
                    cwe_ids TEXT,
                    references_json TEXT,
                    published TEXT,
                    last_modified TEXT,
                    configurations TEXT,
                    cached_at REAL
                );

                CREATE TABLE IF NOT EXISTS cwe_details (
                    cwe_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    extended_description TEXT,
                    likelihood_of_exploit TEXT,
                    common_consequences TEXT,
                    detection_methods TEXT,
                    mitigations TEXT,
                    related_cwes TEXT,
                    cached_at REAL
                );

                CREATE TABLE IF NOT EXISTS update_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    update_type TEXT,
                    records_count INTEGER,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_nvd_cwe ON nvd_cves(cwe_ids);
                CREATE INDEX IF NOT EXISTS idx_nvd_severity ON nvd_cves(cvss_v31_severity);
                CREATE INDEX IF NOT EXISTS idx_nvd_cached ON nvd_cves(cached_at);

                CREATE TABLE IF NOT EXISTS epss_scores (
                    cve_id TEXT PRIMARY KEY,
                    epss REAL NOT NULL,
                    percentile REAL NOT NULL,
                    model_version TEXT,
                    score_date TEXT,
                    cached_at REAL
                );

                CREATE TABLE IF NOT EXISTS exploit_refs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    ref_id TEXT,
                    title TEXT,
                    url TEXT,
                    cached_at REAL,
                    UNIQUE(cve_id, source, ref_id)
                );
                CREATE INDEX IF NOT EXISTS idx_exploit_refs_cve ON exploit_refs(cve_id);
                CREATE INDEX IF NOT EXISTS idx_exploit_refs_source ON exploit_refs(source);

                CREATE TABLE IF NOT EXISTS vulnrichment (
                    cve_id TEXT PRIMARY KEY,
                    exploitation TEXT,
                    automatable TEXT,
                    technical_impact TEXT,
                    provider TEXT,
                    cached_at REAL
                );
            ''')

    # ============================================================
    # NVD API 2.0 Integration
    # ============================================================

    def _nvd_api_request(self, params: Dict[str, str], timeout: int = 30) -> Optional[Dict]:
        """Make a request to the NVD API 2.0."""
        try:
            import urllib.request
            import urllib.parse
            import ssl

            query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            url = f"{NVD_API_BASE}?{query}"

            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'PurpleTeamPlatform/7.0',
                    'Accept': 'application/json',
                }
            )

            # NVD API key from environment (optional, increases rate limit)
            api_key = os.environ.get('NVD_API_KEY', '')
            if api_key:
                req.add_header('apiKey', api_key)

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                return json.loads(response.read().decode('utf-8'))

        except Exception as e:
            logger.warning(f"NVD API request failed: {e}")
            return None

    def _parse_nvd_cve(self, cve_item: Dict) -> Dict:
        """Parse a CVE item from NVD API 2.0 response."""
        cve = cve_item.get('cve', {})
        cve_id = cve.get('id', '')

        # Description (English)
        description = ''
        for desc in cve.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # CVSS v3.1
        cvss31_score = 0.0
        cvss31_vector = ''
        cvss31_severity = ''
        metrics = cve.get('metrics', {})
        for cvss31 in metrics.get('cvssMetricV31', []):
            data = cvss31.get('cvssData', {})
            cvss31_score = data.get('baseScore', 0.0)
            cvss31_vector = data.get('vectorString', '')
            cvss31_severity = data.get('baseSeverity', '')
            break
        # Fallback to v3.0 if no v3.1
        if not cvss31_score:
            for cvss30 in metrics.get('cvssMetricV30', []):
                data = cvss30.get('cvssData', {})
                cvss31_score = data.get('baseScore', 0.0)
                cvss31_vector = data.get('vectorString', '')
                cvss31_severity = data.get('baseSeverity', '')
                break

        # CVSS v2 (fallback)
        cvss2_score = 0.0
        for cvss2 in metrics.get('cvssMetricV2', []):
            data = cvss2.get('cvssData', {})
            cvss2_score = data.get('baseScore', 0.0)
            break

        # CWE IDs
        cwe_ids = []
        for weakness in cve.get('weaknesses', []):
            for desc in weakness.get('description', []):
                val = desc.get('value', '')
                if val.startswith('CWE-') and val != 'CWE-Other' and val != 'CWE-NVD-noinfo':
                    cwe_ids.append(val)

        # References
        references = []
        for ref in cve.get('references', []):
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', ''),
                'tags': ref.get('tags', []),
            })

        # Dates
        published = cve.get('published', '')
        last_modified = cve.get('lastModified', '')

        # Configurations (affected products)
        configurations = []
        for config_node in cve.get('configurations', []):
            for node in config_node.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', False):
                        configurations.append(cpe_match.get('criteria', ''))

        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_v31_score': cvss31_score,
            'cvss_v31_vector': cvss31_vector,
            'cvss_v31_severity': cvss31_severity,
            'cvss_v2_score': cvss2_score,
            'cwe_ids': cwe_ids,
            'references': references,
            'published': published,
            'last_modified': last_modified,
            'configurations': configurations,
        }

    def lookup_cve(self, cve_id: str, force_refresh: bool = False) -> Optional[Dict]:
        """
        Look up a CVE by ID. Checks local cache first, then queries NVD API.

        Returns comprehensive CVE data including CVSS, CWE mappings, references,
        OWASP category, CWE Top 25 rank, CAPEC patterns, and ATT&CK techniques.
        """
        cve_id = cve_id.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return None

        # Check cache
        if not force_refresh:
            cached = self._get_cached_cve(cve_id)
            if cached:
                return self._enrich_cve_data(cached)

        # Query NVD API
        response = self._nvd_api_request({'cveId': cve_id})
        if response and response.get('vulnerabilities'):
            parsed = self._parse_nvd_cve(response['vulnerabilities'][0])
            self._cache_cve(parsed)
            return self._enrich_cve_data(parsed)

        # Return cached even if stale (better than nothing for offline mode)
        cached = self._get_cached_cve(cve_id, ignore_ttl=True)
        if cached:
            cached['_stale_cache'] = True
            return self._enrich_cve_data(cached)

        return None

    def lookup_cves_batch(self, cve_ids: List[str], force_refresh: bool = False) -> Dict[str, Dict]:
        """Look up multiple CVEs. Returns dict of cve_id -> cve_data."""
        results = {}
        uncached = []

        for cve_id in cve_ids:
            cve_id = cve_id.upper().strip()
            if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
                continue

            if not force_refresh:
                cached = self._get_cached_cve(cve_id)
                if cached:
                    results[cve_id] = self._enrich_cve_data(cached)
                    continue

            uncached.append(cve_id)

        # Batch query NVD API for uncached CVEs (API supports keyword search)
        # NVD API 2.0 doesn't support batch CVE lookup by ID list directly,
        # so we query individually with rate limiting
        for i, cve_id in enumerate(uncached):
            if i > 0 and i % 5 == 0:
                time.sleep(_nvd_rate_delay())

            response = self._nvd_api_request({'cveId': cve_id})
            if response and response.get('vulnerabilities'):
                parsed = self._parse_nvd_cve(response['vulnerabilities'][0])
                self._cache_cve(parsed)
                results[cve_id] = self._enrich_cve_data(parsed)
            else:
                # Try stale cache
                cached = self._get_cached_cve(cve_id, ignore_ttl=True)
                if cached:
                    cached['_stale_cache'] = True
                    results[cve_id] = self._enrich_cve_data(cached)

        return results

    def _get_cached_cve(self, cve_id: str, ignore_ttl: bool = False) -> Optional[Dict]:
        """Get CVE from local cache."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM nvd_cves WHERE cve_id = ?', (cve_id,)
                ).fetchone()

                if not row:
                    return None

                if not ignore_ttl and (time.time() - row['cached_at']) > NVD_CACHE_TTL:
                    return None

                return {
                    'cve_id': row['cve_id'],
                    'description': row['description'] or '',
                    'cvss_v31_score': row['cvss_v31_score'] or 0.0,
                    'cvss_v31_vector': row['cvss_v31_vector'] or '',
                    'cvss_v31_severity': row['cvss_v31_severity'] or '',
                    'cvss_v2_score': row['cvss_v2_score'] or 0.0,
                    'cwe_ids': json.loads(row['cwe_ids']) if row['cwe_ids'] else [],
                    'references': json.loads(row['references_json']) if row['references_json'] else [],
                    'published': row['published'] or '',
                    'last_modified': row['last_modified'] or '',
                    'configurations': json.loads(row['configurations']) if row['configurations'] else [],
                }
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.warning(f"Cache read error for {cve_id}: {e}")
            return None

    def _cache_cve(self, cve_data: Dict):
        """Cache CVE data to local database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO nvd_cves
                    (cve_id, description, cvss_v31_score, cvss_v31_vector, cvss_v31_severity,
                     cvss_v2_score, cwe_ids, references_json, published, last_modified,
                     configurations, cached_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_data['cve_id'],
                    cve_data['description'],
                    cve_data['cvss_v31_score'],
                    cve_data['cvss_v31_vector'],
                    cve_data['cvss_v31_severity'],
                    cve_data['cvss_v2_score'],
                    json.dumps(cve_data['cwe_ids']),
                    json.dumps(cve_data['references']),
                    cve_data['published'],
                    cve_data['last_modified'],
                    json.dumps(cve_data['configurations']),
                    time.time(),
                ))
        except sqlite3.Error as e:
            logger.warning(f"Cache write error for {cve_data.get('cve_id')}: {e}")

    def _enrich_cve_data(self, cve_data: Dict) -> Dict:
        """Enrich CVE data with OWASP, CWE Top 25, CAPEC, and ATT&CK mappings."""
        enriched = dict(cve_data)

        # OWASP Top 10 mapping
        owasp_categories = set()
        for cwe_id in cve_data.get('cwe_ids', []):
            for owasp_id in _CWE_TO_OWASP.get(cwe_id, []):
                owasp_categories.add(owasp_id)
        enriched['owasp_categories'] = sorted(owasp_categories)
        enriched['owasp_details'] = [
            OWASP_TOP_10_2021[oid] for oid in enriched['owasp_categories']
            if oid in OWASP_TOP_10_2021
        ]

        # CWE Top 25 rank
        cwe_top25_hits = []
        for cwe_id in cve_data.get('cwe_ids', []):
            if cwe_id in _CWE_BY_ID:
                cwe_top25_hits.append(_CWE_BY_ID[cwe_id])
        enriched['cwe_top25'] = cwe_top25_hits

        # CAPEC attack patterns
        capec_ids = set()
        for cwe_id in cve_data.get('cwe_ids', []):
            for capec_id in _CAPEC_BY_CWE.get(cwe_id, []):
                capec_ids.add(capec_id)
        enriched['capec_patterns'] = [
            CAPEC_PATTERNS[cid] for cid in sorted(capec_ids) if cid in CAPEC_PATTERNS
        ]

        # MITRE ATT&CK techniques
        attack_ids = set()
        for cwe_id in cve_data.get('cwe_ids', []):
            for tech_id in _ATTACK_BY_CWE.get(cwe_id, []):
                attack_ids.add(tech_id)
        enriched['attack_techniques'] = [
            ATTACK_TECHNIQUES[tid] for tid in sorted(attack_ids) if tid in ATTACK_TECHNIQUES
        ]

        # KEV and EPSS from existing threat_intel
        cve_id = cve_data['cve_id']
        ti_enrichment = self._threat_intel.enrich_finding(cve_id)
        enriched['kev_status'] = ti_enrichment.get('kev_status', False)
        enriched['kev_due_date'] = ti_enrichment.get('kev_due_date')
        enriched['kev_required_action'] = ti_enrichment.get('kev_required_action')
        enriched['epss_score'] = ti_enrichment.get('epss_score', 0.0)
        enriched['epss_percentile'] = ti_enrichment.get('epss_percentile', 0.0)

        # Effective priority (CVSS * 0.4 + EPSS * 0.3 + KEV * 0.3)
        from threat_intel import ThreatIntelManager
        cvss = enriched.get('cvss_v31_score') or enriched.get('cvss_v2_score') or 0.0
        enriched['effective_priority'] = ThreatIntelManager.calculate_effective_priority(
            cvss, enriched['epss_score'], enriched['kev_status']
        )

        return enriched

    # ============================================================
    # CWE Lookup
    # ============================================================

    def lookup_cwe(self, cwe_id: str) -> Optional[Dict]:
        """
        Look up a CWE by ID. Returns embedded data for Top 25 CWEs,
        and cached data for others.
        """
        cwe_id = cwe_id.upper().strip()
        if not cwe_id.startswith('CWE-'):
            cwe_id = f'CWE-{cwe_id}'

        result = {
            'cwe_id': cwe_id,
            'in_top_25': False,
            'top_25_rank': None,
            'owasp_categories': _CWE_TO_OWASP.get(cwe_id, []),
            'capec_patterns': [],
            'attack_techniques': [],
        }

        # Check Top 25
        if cwe_id in _CWE_BY_ID:
            top25 = _CWE_BY_ID[cwe_id]
            result['in_top_25'] = True
            result['top_25_rank'] = top25['rank']
            result['name'] = top25['name']
            result['top_25_score'] = top25['score']
            result['top_25_kev_count'] = top25['kev_count']

        # CAPEC patterns for this CWE
        for capec_id in _CAPEC_BY_CWE.get(cwe_id, []):
            if capec_id in CAPEC_PATTERNS:
                result['capec_patterns'].append(CAPEC_PATTERNS[capec_id])

        # ATT&CK techniques for this CWE
        for tech_id in _ATTACK_BY_CWE.get(cwe_id, []):
            if tech_id in ATTACK_TECHNIQUES:
                result['attack_techniques'].append(ATTACK_TECHNIQUES[tech_id])

        # Check cached details
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM cwe_details WHERE cwe_id = ?', (cwe_id,)
                ).fetchone()
                if row:
                    result['name'] = result.get('name') or row['name']
                    result['description'] = row['description'] or ''
                    result['extended_description'] = row['extended_description'] or ''
                    result['likelihood_of_exploit'] = row['likelihood_of_exploit'] or ''
                    result['mitigations'] = json.loads(row['mitigations']) if row['mitigations'] else []
        except (sqlite3.Error, json.JSONDecodeError):
            pass

        return result

    # ============================================================
    # OWASP Top 10 Lookup
    # ============================================================

    def get_owasp_top_10(self) -> Dict[str, Dict]:
        """Get the full OWASP Top 10 2021 list."""
        return OWASP_TOP_10_2021

    def get_owasp_category(self, category_id: str) -> Optional[Dict]:
        """Get a specific OWASP Top 10 category by ID (e.g., 'A01:2021')."""
        return OWASP_TOP_10_2021.get(category_id.upper().strip())

    def get_owasp_for_cwe(self, cwe_id: str) -> List[Dict]:
        """Get OWASP Top 10 categories for a CWE."""
        cwe_id = cwe_id.upper().strip()
        return [
            OWASP_TOP_10_2021[oid]
            for oid in _CWE_TO_OWASP.get(cwe_id, [])
            if oid in OWASP_TOP_10_2021
        ]

    # ============================================================
    # CWE Top 25 Lookup
    # ============================================================

    def get_cwe_top_25(self) -> List[Dict]:
        """Get the full CWE Top 25 2024 list."""
        return CWE_TOP_25_2024

    def get_cwe_rank(self, cwe_id: str) -> Optional[int]:
        """Get a CWE's rank in the Top 25 (or None if not ranked)."""
        cwe_id = cwe_id.upper().strip()
        entry = _CWE_BY_ID.get(cwe_id)
        return entry['rank'] if entry else None

    # ============================================================
    # CAPEC Attack Pattern Lookup
    # ============================================================

    def get_capec_patterns(self) -> Dict[str, Dict]:
        """Get all embedded CAPEC attack patterns."""
        return CAPEC_PATTERNS

    def get_attack_patterns_for_cwe(self, cwe_id: str) -> List[Dict]:
        """Get CAPEC attack patterns linked to a CWE."""
        cwe_id = cwe_id.upper().strip()
        return [
            CAPEC_PATTERNS[cid]
            for cid in _CAPEC_BY_CWE.get(cwe_id, [])
            if cid in CAPEC_PATTERNS
        ]

    # ============================================================
    # MITRE ATT&CK Lookup
    # ============================================================

    def get_attack_techniques(self) -> Dict[str, Dict]:
        """Get all embedded MITRE ATT&CK techniques."""
        return ATTACK_TECHNIQUES

    def get_attack_for_cwe(self, cwe_id: str) -> List[Dict]:
        """Get ATT&CK techniques linked to a CWE."""
        cwe_id = cwe_id.upper().strip()
        return [
            ATTACK_TECHNIQUES[tid]
            for tid in _ATTACK_BY_CWE.get(cwe_id, [])
            if tid in ATTACK_TECHNIQUES
        ]

    def get_attack_by_tactic(self, tactic: str) -> List[Dict]:
        """Get ATT&CK techniques by tactic name."""
        tactic_lower = tactic.lower()
        return [
            tech for tech in ATTACK_TECHNIQUES.values()
            if tech['tactic'].lower() == tactic_lower
        ]

    # ============================================================
    # Search
    # ============================================================

    def search(self, query: str, max_results: int = 50) -> Dict[str, List]:
        """
        Search across all vulnerability intelligence sources.
        Returns matching entries from NVD cache, CWE, OWASP, CAPEC, ATT&CK.
        """
        query_lower = query.lower().strip()
        results = {
            'cves': [],
            'cwes': [],
            'owasp': [],
            'capec': [],
            'attack': [],
        }

        # CVE ID pattern
        if re.match(r'^cve-\d{4}-\d{4,}$', query_lower):
            cve = self.lookup_cve(query.upper())
            if cve:
                results['cves'].append(cve)
            return results

        # Search cached CVEs by description
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    'SELECT * FROM nvd_cves WHERE description LIKE ? LIMIT ?',
                    (f'%{query}%', max_results)
                ).fetchall()
                for row in rows:
                    results['cves'].append({
                        'cve_id': row['cve_id'],
                        'description': row['description'],
                        'cvss_v31_score': row['cvss_v31_score'],
                        'cvss_v31_severity': row['cvss_v31_severity'],
                    })
        except sqlite3.Error:
            pass

        # Search CWE Top 25
        for entry in CWE_TOP_25_2024:
            if query_lower in entry['name'].lower() or query_lower in entry['cwe_id'].lower():
                results['cwes'].append(entry)

        # Search OWASP Top 10
        for owasp in OWASP_TOP_10_2021.values():
            if (query_lower in owasp['name'].lower() or
                    query_lower in owasp['description'].lower() or
                    query_lower in owasp['id'].lower()):
                results['owasp'].append(owasp)

        # Search CAPEC
        for capec in CAPEC_PATTERNS.values():
            if (query_lower in capec['name'].lower() or
                    query_lower in capec['description'].lower()):
                results['capec'].append(capec)

        # Search ATT&CK
        for tech in ATTACK_TECHNIQUES.values():
            if (query_lower in tech['name'].lower() or
                    query_lower in tech['description'].lower() or
                    query_lower in tech['id'].lower()):
                results['attack'].append(tech)

        return results

    # ============================================================
    # EPSS Bulk Scores
    # ============================================================

    def bulk_import_epss(self, scores: List[Dict]):
        """Bulk import EPSS scores into the epss_scores table."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                now = time.time()
                conn.executemany(
                    '''INSERT OR REPLACE INTO epss_scores
                       (cve_id, epss, percentile, model_version, score_date, cached_at)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    [
                        (
                            s['cve_id'],
                            s['epss'],
                            s['percentile'],
                            s.get('model_version', ''),
                            s.get('score_date', ''),
                            now,
                        )
                        for s in scores
                    ]
                )
                logger.info(f"Bulk imported {len(scores)} EPSS scores")
        except sqlite3.Error as e:
            logger.warning(f"EPSS bulk import error: {e}")

    def get_epss_score(self, cve_id: str) -> Optional[Dict]:
        """Look up EPSS score from the epss_scores table."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM epss_scores WHERE cve_id = ?', (cve_id,)
                ).fetchone()
                if row:
                    return {
                        'epss': row['epss'],
                        'percentile': row['percentile'],
                        'model_version': row['model_version'] or '',
                        'score_date': row['score_date'] or '',
                    }
        except sqlite3.Error as e:
            logger.warning(f"EPSS lookup error for {cve_id}: {e}")
        return None

    # ============================================================
    # Exploit References
    # ============================================================

    def bulk_import_exploit_refs(self, refs: List[Dict]):
        """Bulk import exploit references into the exploit_refs table."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                now = time.time()
                conn.executemany(
                    '''INSERT OR IGNORE INTO exploit_refs
                       (cve_id, source, ref_id, title, url, cached_at)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    [
                        (
                            r['cve_id'],
                            r['source'],
                            r.get('ref_id', ''),
                            r.get('title', ''),
                            r.get('url', ''),
                            now,
                        )
                        for r in refs
                    ]
                )
                logger.info(f"Bulk imported {len(refs)} exploit references")
        except sqlite3.Error as e:
            logger.warning(f"Exploit refs bulk import error: {e}")

    def get_exploit_refs(self, cve_id: str) -> List[Dict]:
        """Look up all exploit references for a CVE."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    'SELECT * FROM exploit_refs WHERE cve_id = ?', (cve_id,)
                ).fetchall()
                return [
                    {
                        'source': row['source'],
                        'ref_id': row['ref_id'] or '',
                        'title': row['title'] or '',
                        'url': row['url'] or '',
                    }
                    for row in rows
                ]
        except sqlite3.Error as e:
            logger.warning(f"Exploit refs lookup error for {cve_id}: {e}")
        return []

    def has_public_exploit(self, cve_id: str) -> Dict:
        """Check if a CVE has any known public exploits."""
        refs = self.get_exploit_refs(cve_id)
        sources = list({r['source'] for r in refs})
        return {
            'has_exploit': len(refs) > 0,
            'exploit_count': len(refs),
            'sources': sources,
            'has_metasploit': 'metasploit' in sources,
            'has_nuclei_template': 'nuclei' in sources,
        }

    # ============================================================
    # CISA Vulnrichment (SSVC)
    # ============================================================

    def bulk_import_vulnrichment(self, entries: List[Dict]):
        """Bulk import CISA Vulnrichment SSVC data."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                now = time.time()
                conn.executemany(
                    '''INSERT OR REPLACE INTO vulnrichment
                       (cve_id, exploitation, automatable, technical_impact, provider, cached_at)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    [
                        (
                            e['cve_id'],
                            e.get('exploitation', ''),
                            e.get('automatable', ''),
                            e.get('technical_impact', ''),
                            e.get('provider', ''),
                            now,
                        )
                        for e in entries
                    ]
                )
                logger.info(f"Bulk imported {len(entries)} vulnrichment entries")
        except sqlite3.Error as e:
            logger.warning(f"Vulnrichment bulk import error: {e}")

    def get_vulnrichment(self, cve_id: str) -> Optional[Dict]:
        """Look up SSVC data for a CVE from the vulnrichment table."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM vulnrichment WHERE cve_id = ?', (cve_id,)
                ).fetchone()
                if row:
                    return {
                        'exploitation': row['exploitation'] or '',
                        'automatable': row['automatable'] or '',
                        'technical_impact': row['technical_impact'] or '',
                        'provider': row['provider'] or '',
                    }
        except sqlite3.Error as e:
            logger.warning(f"Vulnrichment lookup error for {cve_id}: {e}")
        return None

    # ============================================================
    # Finding Enrichment (integrates with scan pipeline)
    # ============================================================

    def enrich_finding(self, finding: Dict) -> Dict:
        """
        Enrich a scan finding with full vulnerability intelligence.

        Accepts a finding dict with optional keys: cve_ids, cwe_ids, title, description.
        Returns the finding with added intelligence fields.
        """
        enriched = dict(finding)

        cve_ids = finding.get('cve_ids', [])
        if isinstance(cve_ids, str):
            try:
                cve_ids = json.loads(cve_ids)
            except (json.JSONDecodeError, TypeError):
                cve_ids = [c.strip() for c in cve_ids.split(',') if c.strip()]

        # Extract CVE IDs from title/description if none provided
        if not cve_ids:
            text = f"{finding.get('title', '')} {finding.get('description', '')}"
            cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
            cve_ids = [c.upper() for c in cve_ids]

        if not cve_ids:
            return enriched

        # Enrich with first CVE's data (primary)
        enriched['vuln_intel'] = {}
        enriched['all_cve_intel'] = {}

        for cve_id in cve_ids[:10]:  # Limit to 10 CVEs per finding
            cve_data = self.lookup_cve(cve_id)
            if cve_data:
                enriched['all_cve_intel'][cve_id] = cve_data
                if not enriched['vuln_intel']:
                    # Primary CVE enrichment
                    enriched['vuln_intel'] = {
                        'primary_cve': cve_id,
                        'cvss_v31_score': cve_data.get('cvss_v31_score', 0.0),
                        'cvss_v31_severity': cve_data.get('cvss_v31_severity', ''),
                        'cvss_v31_vector': cve_data.get('cvss_v31_vector', ''),
                        'cwe_ids': cve_data.get('cwe_ids', []),
                        'owasp_categories': cve_data.get('owasp_categories', []),
                        'cwe_top25': cve_data.get('cwe_top25', []),
                        'capec_patterns': [p['name'] for p in cve_data.get('capec_patterns', [])],
                        'attack_techniques': [t['name'] for t in cve_data.get('attack_techniques', [])],
                        'kev_status': cve_data.get('kev_status', False),
                        'epss_score': cve_data.get('epss_score', 0.0),
                        'effective_priority': cve_data.get('effective_priority', 0.0),
                        'nvd_description': cve_data.get('description', ''),
                        'published': cve_data.get('published', ''),
                    }

        # Add exploit intelligence
        if enriched.get('vuln_intel') and enriched['vuln_intel'].get('primary_cve'):
            primary_cve = enriched['vuln_intel']['primary_cve']

            exploit_info = self.has_public_exploit(primary_cve)
            enriched['vuln_intel']['has_public_exploit'] = exploit_info.get('has_exploit', False)
            enriched['vuln_intel']['exploit_sources'] = exploit_info.get('sources', [])
            enriched['vuln_intel']['has_metasploit'] = exploit_info.get('has_metasploit', False)
            enriched['vuln_intel']['has_nuclei_template'] = exploit_info.get('has_nuclei_template', False)

            # Add SSVC triage
            ssvc = self.get_vulnrichment(primary_cve)
            if ssvc:
                enriched['vuln_intel']['ssvc_exploitation'] = ssvc.get('exploitation', '')
                enriched['vuln_intel']['ssvc_automatable'] = ssvc.get('automatable', '')
                enriched['vuln_intel']['ssvc_action'] = 'Act' if ssvc.get('exploitation') == 'active' else (
                    'Attend' if ssvc.get('automatable') == 'yes' else 'Track')

            # Prefer EPSS from bulk table if available
            epss_bulk = self.get_epss_score(primary_cve)
            if epss_bulk:
                enriched['vuln_intel']['epss_score'] = epss_bulk.get('epss', 0.0)
                enriched['vuln_intel']['epss_percentile'] = epss_bulk.get('percentile', 0.0)

        return enriched

    def enrich_findings_batch(self, findings: List[Dict]) -> List[Dict]:
        """Batch enrich multiple findings."""
        # Collect all CVE IDs first for efficient batch lookup
        all_cve_ids = set()
        for finding in findings:
            cve_ids = finding.get('cve_ids', [])
            if isinstance(cve_ids, str):
                try:
                    cve_ids = json.loads(cve_ids)
                except (json.JSONDecodeError, TypeError):
                    cve_ids = [c.strip() for c in cve_ids.split(',') if c.strip()]

            if not cve_ids:
                text = f"{finding.get('title', '')} {finding.get('description', '')}"
                cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)

            all_cve_ids.update(c.upper() for c in cve_ids[:10])

        # Pre-fetch all CVEs
        if all_cve_ids:
            self.lookup_cves_batch(list(all_cve_ids))

        # Now enrich each finding (cache is warm)
        return [self.enrich_finding(f) for f in findings]

    # ============================================================
    # Bulk Update / Download
    # ============================================================

    def update_nvd_full(self, start_year: int = 1999, callback=None) -> Dict:
        """
        Bulk download ALL CVEs from NVD API by paginating through 120-day chunks.
        ~250K CVEs. Takes 2-4 hours without API key, ~30 min with key.

        Args:
            start_year: First year to download (default 1999)
            callback: Optional callable(year, page, cached_total) for progress

        Returns:
            Dict with download statistics
        """
        from datetime import timedelta

        current_year = datetime.utcnow().year
        total_cached = 0
        total_skipped = 0
        years_processed = 0
        rate_delay = _nvd_rate_delay()
        start_time = time.time()

        for year in range(start_year, current_year + 1):
            # Check how many CVEs we already have for this year
            try:
                with sqlite3.connect(str(self.db_path)) as conn:
                    existing = conn.execute(
                        "SELECT COUNT(*) FROM nvd_cves WHERE published LIKE ?",
                        (f"{year}%",)
                    ).fetchone()[0]
            except sqlite3.Error:
                existing = 0

            # Split year into 120-day chunks (NVD API max range is 120 days)
            chunk_start = datetime(year, 1, 1)
            year_boundary = datetime(year + 1, 1, 1) if year < current_year else datetime.utcnow()
            year_cached = 0
            year_total = 0
            chunk_num = 0

            while chunk_start < year_boundary:
                chunk_end = min(chunk_start + timedelta(days=119), year_boundary)

                start_str = chunk_start.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                end_str = chunk_end.strftime('%Y-%m-%dT%H:%M:%S.999Z')

                params = {
                    'pubStartDate': start_str,
                    'pubEndDate': end_str,
                    'resultsPerPage': '2000',
                    'startIndex': '0',
                }

                response = self._nvd_api_request(params, timeout=120)
                if not response:
                    logger.warning(f"NVD API failed for {start_str} to {end_str}, skipping chunk")
                    chunk_start = chunk_end + timedelta(seconds=1)
                    time.sleep(rate_delay)
                    continue

                chunk_total = response.get('totalResults', 0)
                year_total += chunk_total

                # Process first page of this chunk
                for item in response.get('vulnerabilities', []):
                    parsed = self._parse_nvd_cve(item)
                    self._cache_cve(parsed)
                    year_cached += 1

                start_index = len(response.get('vulnerabilities', []))
                chunk_num += 1
                page = 1

                logger.info(f"Year {year} chunk {chunk_num}: {chunk_total} CVEs "
                            f"({start_str[:10]} to {end_str[:10]}), page 1")
                if callback:
                    callback(year, page, total_cached + year_cached + total_skipped)

                # Page through remaining results in this chunk
                while start_index < chunk_total:
                    time.sleep(rate_delay)

                    params['startIndex'] = str(start_index)
                    response = self._nvd_api_request(params, timeout=120)

                    if not response:
                        logger.warning(f"Year {year} chunk {chunk_num} page {page + 1}: failed")
                        break

                    vulnerabilities = response.get('vulnerabilities', [])
                    if not vulnerabilities:
                        break

                    for item in vulnerabilities:
                        parsed = self._parse_nvd_cve(item)
                        self._cache_cve(parsed)
                        year_cached += 1

                    start_index += len(vulnerabilities)
                    page += 1

                    logger.info(f"Year {year} chunk {chunk_num}: page {page} ({year_cached} cached)")
                    if callback:
                        callback(year, page, total_cached + year_cached + total_skipped)

                # Move to next chunk
                chunk_start = chunk_end + timedelta(seconds=1)
                time.sleep(rate_delay)

            total_cached += year_cached
            years_processed += 1

            self._log_update('NVD', f'full_year_{year}', year_cached,
                             f'Year {year}: {year_cached}/{year_total} CVEs')

            elapsed_so_far = time.time() - start_time
            logger.info(f"Year {year} complete: {year_cached} CVEs cached "
                        f"(total so far: {total_cached}, elapsed: {elapsed_so_far:.0f}s)")

        elapsed = time.time() - start_time
        self._log_update('NVD', 'full_download', total_cached,
                         f'Full download: {total_cached} new + {total_skipped} existing, '
                         f'{years_processed} years in {elapsed:.0f}s')

        logger.info(f"NVD full download complete: {total_cached} new CVEs cached, "
                    f"{total_skipped} already existed, {elapsed:.0f}s elapsed")

        return {
            'source': 'NVD',
            'type': 'full_download',
            'new_cached': total_cached,
            'already_existed': total_skipped,
            'total_in_db': total_cached + total_skipped,
            'years_processed': years_processed,
            'elapsed_seconds': round(elapsed, 1),
        }

    def update_nvd_incremental(self) -> Dict:
        """
        Incremental update: only fetch CVEs modified since last update.
        Uses lastModStartDate/lastModEndDate parameters.
        Much faster than full download - only grabs new/modified entries.
        """
        from datetime import timedelta

        # Find last update timestamp from update_log
        last_update = None
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                row = conn.execute(
                    "SELECT timestamp FROM update_log "
                    "WHERE source='NVD' AND status='success' "
                    "ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
                if row:
                    last_update = row[0]
        except sqlite3.Error:
            pass

        if last_update:
            try:
                # Parse the timestamp from update_log
                last_dt = datetime.strptime(last_update, '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                # Fallback: 7 days ago
                last_dt = datetime.utcnow() - timedelta(days=7)
        else:
            # No previous update - default to 120 days back
            last_dt = datetime.utcnow() - timedelta(days=120)

        # NVD API allows max 120-day range for lastModified queries
        now = datetime.utcnow()
        if (now - last_dt).days > 120:
            last_dt = now - timedelta(days=120)

        start_date = last_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_date = now.strftime('%Y-%m-%dT%H:%M:%S.999Z')

        logger.info(f"NVD incremental update: {start_date} to {end_date}")

        params = {
            'lastModStartDate': start_date,
            'lastModEndDate': end_date,
            'resultsPerPage': '2000',
        }

        total_cached = 0
        total_results = 0
        start_index = 0
        rate_delay = _nvd_rate_delay()

        while True:
            params['startIndex'] = str(start_index)
            response = self._nvd_api_request(params, timeout=120)

            if not response:
                break

            total_results = response.get('totalResults', 0)
            vulnerabilities = response.get('vulnerabilities', [])

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                parsed = self._parse_nvd_cve(item)
                self._cache_cve(parsed)
                total_cached += 1

            start_index += len(vulnerabilities)

            if start_index >= total_results:
                break

            time.sleep(rate_delay)

        self._log_update('NVD', 'incremental', total_cached,
                         f'Incremental: {total_cached}/{total_results} modified CVEs since {start_date}')

        logger.info(f"NVD incremental: {total_cached}/{total_results} modified CVEs updated")
        return {
            'source': 'NVD',
            'type': 'incremental',
            'total_results': total_results,
            'cached': total_cached,
            'since': start_date,
        }

    def update_nvd_year(self, year: int) -> Dict:
        """Download all CVEs for a specific year (splits into 120-day chunks)."""
        from datetime import timedelta

        total_cached = 0
        total_results = 0
        rate_delay = _nvd_rate_delay()

        # Split year into 120-day chunks (NVD API max range)
        chunk_start = datetime(year, 1, 1)
        year_boundary = datetime(year + 1, 1, 1)
        if year == datetime.utcnow().year:
            year_boundary = datetime.utcnow()

        chunk_num = 0
        while chunk_start < year_boundary:
            chunk_end = min(chunk_start + timedelta(days=119), year_boundary)

            start_str = chunk_start.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_str = chunk_end.strftime('%Y-%m-%dT%H:%M:%S.999Z')

            start_index = 0
            chunk_num += 1

            while True:
                params = {
                    'pubStartDate': start_str,
                    'pubEndDate': end_str,
                    'resultsPerPage': '2000',
                    'startIndex': str(start_index),
                }
                response = self._nvd_api_request(params, timeout=120)

                if not response:
                    break

                chunk_total = response.get('totalResults', 0)
                total_results += chunk_total if start_index == 0 else 0
                vulnerabilities = response.get('vulnerabilities', [])

                if not vulnerabilities:
                    break

                for item in vulnerabilities:
                    parsed = self._parse_nvd_cve(item)
                    self._cache_cve(parsed)
                    total_cached += 1

                start_index += len(vulnerabilities)
                logger.info(f"Year {year} chunk {chunk_num}: {total_cached} CVEs cached")

                if start_index >= chunk_total:
                    break

                time.sleep(rate_delay)

            chunk_start = chunk_end + timedelta(seconds=1)
            time.sleep(rate_delay)

        self._log_update('NVD', f'year_{year}', total_cached,
                         f'Year {year}: {total_cached}/{total_results} CVEs')

        return {
            'source': 'NVD',
            'type': f'year_{year}',
            'total_results': total_results,
            'cached': total_cached,
            'year': year,
        }

    def update_nvd_recent(self, days: int = 7) -> Dict:
        """
        Download recent CVE updates from NVD.
        Uses the pubStartDate/pubEndDate parameters to get recently published CVEs.
        """
        from datetime import timedelta

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000Z'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999Z'),
            'resultsPerPage': '2000',
        }

        total_cached = 0
        total_results = 0
        start_index = 0

        while True:
            params['startIndex'] = str(start_index)
            response = self._nvd_api_request(params, timeout=60)

            if not response:
                break

            total_results = response.get('totalResults', 0)
            vulnerabilities = response.get('vulnerabilities', [])

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                parsed = self._parse_nvd_cve(item)
                self._cache_cve(parsed)
                total_cached += 1

            start_index += len(vulnerabilities)

            if start_index >= total_results:
                break

            # Rate limit
            time.sleep(_nvd_rate_delay())

        # Log the update
        self._log_update('NVD', 'recent_cves', total_cached,
                         f'Downloaded CVEs published in last {days} days')

        logger.info(f"NVD update: cached {total_cached}/{total_results} recent CVEs")
        return {
            'source': 'NVD',
            'total_results': total_results,
            'cached': total_cached,
            'period_days': days,
        }

    def update_nvd_by_keyword(self, keyword: str, max_results: int = 200) -> Dict:
        """Download CVEs matching a keyword from NVD."""
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': str(min(max_results, 200)),
        }

        response = self._nvd_api_request(params, timeout=60)
        if not response:
            return {'source': 'NVD', 'keyword': keyword, 'cached': 0}

        total_cached = 0
        for item in response.get('vulnerabilities', []):
            parsed = self._parse_nvd_cve(item)
            self._cache_cve(parsed)
            total_cached += 1

        self._log_update('NVD', 'keyword_search', total_cached,
                         f'Keyword: {keyword}')

        return {
            'source': 'NVD',
            'keyword': keyword,
            'total_results': response.get('totalResults', 0),
            'cached': total_cached,
        }

    def update_all(self, days: int = 30) -> Dict:
        """
        Run all available updates:
        1. CISA KEV catalog (via threat_intel)
        2. NVD recent CVEs
        """
        results = {}

        # 1. Update KEV
        logger.info("Updating CISA KEV catalog...")
        kev_ok = self._threat_intel.update_kev_catalog()
        kev_stats = self._threat_intel.get_kev_stats()
        results['kev'] = {
            'success': kev_ok,
            'entries': kev_stats.get('total_entries', 0),
        }

        # 2. Update recent NVD CVEs
        logger.info(f"Downloading NVD CVEs from last {days} days...")
        results['nvd'] = self.update_nvd_recent(days=days)

        self._log_update('all', 'full_update', 0,
                         json.dumps(results, default=str))

        return results

    def _log_update(self, source: str, update_type: str, count: int, details: str):
        """Log an update to the database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT INTO update_log (source, update_type, records_count, status, details)
                    VALUES (?, ?, ?, 'success', ?)
                ''', (source, update_type, count, details))
        except sqlite3.Error:
            pass

    # ============================================================
    # Statistics
    # ============================================================

    def get_statistics(self) -> Dict:
        """Get database statistics."""
        stats = {
            'db_path': str(self.db_path),
            'db_size_mb': 0.0,
            'cached_cves': 0,
            'cached_cwes': 0,
            'owasp_top_10_categories': len(OWASP_TOP_10_2021),
            'cwe_top_25_entries': len(CWE_TOP_25_2024),
            'capec_patterns': len(CAPEC_PATTERNS),
            'attack_techniques': len(ATTACK_TECHNIQUES),
            'last_nvd_update': None,
            'last_kev_update': None,
        }

        if self.db_path.exists():
            stats['db_size_mb'] = round(self.db_path.stat().st_size / (1024 * 1024), 2)

        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                stats['cached_cves'] = conn.execute(
                    'SELECT COUNT(*) FROM nvd_cves'
                ).fetchone()[0]

                stats['cached_cwes'] = conn.execute(
                    'SELECT COUNT(*) FROM cwe_details'
                ).fetchone()[0]

                # Last NVD update
                row = conn.execute(
                    "SELECT timestamp FROM update_log WHERE source='NVD' ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
                if row:
                    stats['last_nvd_update'] = row[0]

                # Exploit refs
                try:
                    stats['exploit_db_refs'] = conn.execute(
                        "SELECT COUNT(*) FROM exploit_refs WHERE source='exploit-db'"
                    ).fetchone()[0]
                    stats['metasploit_refs'] = conn.execute(
                        "SELECT COUNT(*) FROM exploit_refs WHERE source='metasploit'"
                    ).fetchone()[0]
                    stats['nuclei_refs'] = conn.execute(
                        "SELECT COUNT(*) FROM exploit_refs WHERE source='nuclei'"
                    ).fetchone()[0]
                    stats['vulnrichment_entries'] = conn.execute(
                        "SELECT COUNT(*) FROM vulnrichment"
                    ).fetchone()[0]
                    stats['epss_bulk_scores'] = conn.execute(
                        "SELECT COUNT(*) FROM epss_scores"
                    ).fetchone()[0]
                except sqlite3.Error:
                    pass

        except sqlite3.Error:
            pass

        # KEV stats from threat_intel
        kev_stats = self._threat_intel.get_kev_stats()
        stats['kev_entries'] = kev_stats.get('total_entries', 0)
        stats['kev_status'] = kev_stats.get('status', 'unknown')

        # EPSS stats
        epss_stats = self._threat_intel.get_epss_stats()
        stats['epss_cached_scores'] = epss_stats.get('cached_scores', 0)

        return stats

    def get_data_sources(self) -> List[Dict]:
        """Get list of all data sources with status."""
        sources = [
            {
                'name': 'NVD (NIST)',
                'description': 'National Vulnerability Database - CVE details, CVSS scores',
                'url': 'https://nvd.nist.gov/',
                'type': 'api',
                'status': 'online' if self._check_nvd_available() else 'offline/cached',
            },
            {
                'name': 'CISA KEV',
                'description': 'Known Exploited Vulnerabilities Catalog',
                'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                'type': 'api',
                'status': 'loaded' if self._threat_intel.get_kev_stats().get('status') == 'loaded' else 'not loaded',
            },
            {
                'name': 'EPSS (FIRST.org)',
                'description': 'Exploit Prediction Scoring System',
                'url': 'https://www.first.org/epss/',
                'type': 'api',
                'status': 'available',
            },
            {
                'name': 'OWASP Top 10 2021',
                'description': 'Web application security risk categories',
                'url': 'https://owasp.org/Top10/',
                'type': 'embedded',
                'status': 'loaded',
                'entries': len(OWASP_TOP_10_2021),
            },
            {
                'name': 'CWE Top 25 2024',
                'description': 'Most dangerous software weaknesses',
                'url': 'https://cwe.mitre.org/top25/',
                'type': 'embedded',
                'status': 'loaded',
                'entries': len(CWE_TOP_25_2024),
            },
            {
                'name': 'CAPEC',
                'description': 'Common Attack Pattern Enumeration and Classification',
                'url': 'https://capec.mitre.org/',
                'type': 'embedded',
                'status': 'loaded',
                'entries': len(CAPEC_PATTERNS),
            },
            {
                'name': 'MITRE ATT&CK Enterprise',
                'description': 'Adversary tactics and techniques',
                'url': 'https://attack.mitre.org/',
                'type': 'embedded',
                'status': 'loaded',
                'entries': len(ATTACK_TECHNIQUES),
            },
            {
                'name': 'EPSS Bulk Scores',
                'description': 'Exploit Prediction Scoring System - bulk imported scores',
                'url': 'https://www.first.org/epss/',
                'type': 'database',
                'status': self._count_table('epss_scores'),
            },
            {
                'name': 'Exploit References',
                'description': 'Public exploit references from Exploit-DB, Metasploit, Nuclei',
                'url': '',
                'type': 'database',
                'status': self._count_table('exploit_refs'),
            },
            {
                'name': 'CISA Vulnrichment (SSVC)',
                'description': 'Stakeholder-Specific Vulnerability Categorization decisions',
                'url': 'https://github.com/cisagov/vulnrichment',
                'type': 'database',
                'status': self._count_table('vulnrichment'),
            },
        ]
        return sources

    def _count_table(self, table: str) -> str:
        """Return a status string with the row count for a table."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                count = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                return f'{count} entries' if count else 'empty'
        except sqlite3.Error:
            return 'unavailable'

    def _check_nvd_available(self) -> bool:
        """Quick check if NVD API is reachable."""
        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                f"{NVD_API_BASE}?cveId=CVE-2021-44228&resultsPerPage=1",
                headers={'User-Agent': 'PurpleTeamPlatform/7.0'}
            )
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                return resp.status == 200
        except Exception:
            return False

    def cleanup_stale_cache(self, days: int = 90):
        """Remove cached CVEs older than specified days."""
        cutoff = time.time() - (days * 86400)
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                deleted = conn.execute(
                    'DELETE FROM nvd_cves WHERE cached_at < ?', (cutoff,)
                ).rowcount
                if deleted:
                    logger.info(f"Cleaned up {deleted} stale CVE cache entries")
                    conn.execute('VACUUM')
        except sqlite3.Error as e:
            logger.warning(f"Cache cleanup error: {e}")


# Singleton accessor
_vuln_db: Optional[VulnDatabase] = None


def get_vuln_database() -> VulnDatabase:
    """Get the vulnerability database singleton."""
    global _vuln_db
    if _vuln_db is None:
        _vuln_db = VulnDatabase()
    return _vuln_db


if __name__ == '__main__':
    # Self-test
    print("=" * 60)
    print("  Vulnerability Intelligence Database - Self Test")
    print("=" * 60)
    print()

    vdb = get_vuln_database()

    # 1. Statistics
    print("[1] Database Statistics:")
    stats = vdb.get_statistics()
    for k, v in stats.items():
        print(f"    {k}: {v}")
    print()

    # 2. Data sources
    print("[2] Data Sources:")
    for src in vdb.get_data_sources():
        print(f"    {src['name']}: {src['status']} ({src['type']})")
    print()

    # 3. OWASP Top 10
    print("[3] OWASP Top 10 2021:")
    for oid, owasp in vdb.get_owasp_top_10().items():
        print(f"    {oid}: {owasp['name']} [{owasp['risk_level']}]")
    print()

    # 4. CWE Top 25
    print("[4] CWE Top 25 2024 (top 5):")
    for entry in vdb.get_cwe_top_25()[:5]:
        owasp_str = entry['owasp'] or 'N/A'
        print(f"    #{entry['rank']} {entry['cwe_id']}: {entry['name']} (KEV:{entry['kev_count']}, OWASP:{owasp_str})")
    print()

    # 5. CAPEC patterns
    print("[5] CAPEC Attack Patterns (sample):")
    for capec_id, capec in list(vdb.get_capec_patterns().items())[:5]:
        print(f"    {capec_id}: {capec['name']} [{capec['severity']}]")
    print()

    # 6. ATT&CK techniques
    print("[6] MITRE ATT&CK Techniques (sample):")
    for tech_id, tech in list(vdb.get_attack_techniques().items())[:5]:
        print(f"    {tech_id}: {tech['name']} [{tech['tactic']}]")
    print()

    # 7. CWE lookup with cross-references
    print("[7] CWE-79 (XSS) Cross-References:")
    cwe_info = vdb.lookup_cwe('CWE-79')
    if cwe_info:
        print(f"    Name: {cwe_info.get('name', 'N/A')}")
        print(f"    Top 25 Rank: #{cwe_info.get('top_25_rank', 'N/A')}")
        print(f"    OWASP Categories: {cwe_info.get('owasp_categories', [])}")
        print(f"    CAPEC Patterns: {[p['name'] for p in cwe_info.get('capec_patterns', [])]}")
        print(f"    ATT&CK Techniques: {[t['name'] for t in cwe_info.get('attack_techniques', [])]}")
    print()

    # 8. Search
    print("[8] Search for 'injection':")
    results = vdb.search('injection')
    print(f"    CWEs: {len(results['cwes'])} matches")
    print(f"    OWASP: {len(results['owasp'])} matches")
    print(f"    CAPEC: {len(results['capec'])} matches")
    print(f"    ATT&CK: {len(results['attack'])} matches")
    print()

    # 9. CVE lookup (requires network)
    print("[9] CVE Lookup Test (CVE-2021-44228 / Log4Shell):")
    cve = vdb.lookup_cve('CVE-2021-44228')
    if cve:
        print(f"    CVSS v3.1: {cve.get('cvss_v31_score', 'N/A')} ({cve.get('cvss_v31_severity', 'N/A')})")
        print(f"    CWEs: {cve.get('cwe_ids', [])}")
        print(f"    OWASP: {cve.get('owasp_categories', [])}")
        print(f"    CWE Top 25: {[f'#{c['rank']} {c['cwe_id']}' for c in cve.get('cwe_top25', [])]}")
        print(f"    CAPEC: {[p['name'] for p in cve.get('capec_patterns', [])]}")
        print(f"    ATT&CK: {[t['name'] for t in cve.get('attack_techniques', [])]}")
        print(f"    KEV Status: {cve.get('kev_status', 'N/A')}")
        print(f"    EPSS Score: {cve.get('epss_score', 'N/A')}")
        print(f"    Effective Priority: {cve.get('effective_priority', 'N/A')}")
        print(f"    Published: {cve.get('published', 'N/A')}")
    else:
        print("    (Network unavailable - CVE lookup requires NVD API access)")
    print()

    # 10. Finding enrichment test
    print("[10] Finding Enrichment Test:")
    test_finding = {
        'title': 'SQL Injection in login form',
        'description': 'CVE-2023-12345 detected in web application',
        'cve_ids': ['CVE-2021-44228'],
        'severity': 'HIGH',
    }
    enriched = vdb.enrich_finding(test_finding)
    intel = enriched.get('vuln_intel', {})
    if intel:
        print(f"    Primary CVE: {intel.get('primary_cve', 'N/A')}")
        print(f"    CVSS: {intel.get('cvss_v31_score', 'N/A')}")
        print(f"    OWASP: {intel.get('owasp_categories', [])}")
        print(f"    Attack Patterns: {intel.get('capec_patterns', [])}")
        print(f"    ATT&CK: {intel.get('attack_techniques', [])}")
    else:
        print("    (No enrichment available - NVD API may be offline)")
    print()

    print("=" * 60)
    print("  Self-test complete")
    print("=" * 60)
