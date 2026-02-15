# PurpleTeamGRC Full Application Test Run

## Objective
Exercise every feature of the PurpleTeamGRC platform on this Windows 11 machine.
For each action: attempt it, log the result (PASS/FAIL), and if it fails, troubleshoot and fix it.

## Test Log Files
- Write results to: `data/test_run_log.json`
- Track: `{"test": "...", "status": "PASS|FAIL|FIXED|SKIPPED", "error": "...", "fix": "..."}`

## Tests to Execute (in order)

### Phase 1: Core Module Imports
1. Import every module in lib/ and verify no import errors
2. Import every scanner in scanners/ and verify no import errors
3. Import every utility in utilities/ and verify no import errors
4. Import web/api.py, web/dashboard.py, web/auth.py

### Phase 2: Singleton Initialization
5. Initialize paths singleton (lib/paths.py)
6. Initialize config singleton (lib/config.py)
7. Initialize evidence manager (lib/evidence.py)
8. Initialize compliance mapper (lib/compliance.py)
9. Initialize notification manager (lib/notifications.py)
10. Initialize scheduler (lib/scheduler.py)
11. Initialize license manager (lib/licensing.py)
12. Initialize AI engine (lib/ai_engine.py)
13. Initialize threat intel (lib/threat_intel.py)
14. Initialize vuln database (lib/vuln_database.py)
15. Initialize risk quantification (lib/risk_quantification.py)
16. Initialize tool discovery (lib/tool_discovery.py)

### Phase 3: Database Operations
17. Create/verify all SQLite databases exist in data/
18. Run a test evidence session (create session, add evidence, add finding)
19. Query findings from evidence DB
20. Test notification DB (create channel, query channels)
21. Test scheduler DB (list schedules)
22. Test audit DB (write audit entry, query)
23. Test risk register DB (add risk, query)
24. Test remediation DB (add item, query)
25. Test exceptions DB (add exception, query)

### Phase 4: Scanner Instantiation
26. Instantiate NetworkScanner
27. Instantiate VulnerabilityScanner
28. Instantiate WebScanner
29. Instantiate SSLScanner
30. Instantiate WindowsScanner
31. Instantiate LinuxScanner (may skip on Windows)
32. Instantiate ComplianceScanner
33. Instantiate ADScanner
34. Instantiate CloudScanner
35. Instantiate ContainerScanner
36. Instantiate SBOMScanner
37. Instantiate MalwareScanner
38. Instantiate CredentialScanner
39. Instantiate ASMScanner
40. Instantiate OpenVASScanner

### Phase 5: Tool Discovery
41. Run tool discovery - detect all available tools (nmap, nuclei, yara, testssl, etc.)
42. Verify bundled tools are found (tools/nmap, tools/nuclei.exe, tools/yara/yara64.exe, tools/testssl)

### Phase 6: Scanner Quick Scans (localhost only)
43. Network scan of 127.0.0.1 (quick)
44. SSL scan of localhost:8443 (quick) - if server is running
45. Windows scanner (quick) - local system checks
46. Compliance scanner (quick)
47. Malware scanner (quick) - scan tools/ directory
48. SBOM scanner (quick) - scan project for dependencies

### Phase 7: Web Server & API
49. Start the web server (bin/start-server.py --no-auth) if not running
50. GET /api/v1/stats - verify response
51. GET /api/v1/scanners - verify 16 scanners returned
52. GET /api/v1/license - verify community tier
53. GET /api/v1/ai/status - verify AI status
54. GET /api/v1/notifications/channels - verify response
55. GET /api/v1/notifications/stats - verify response
56. GET /api/v1/schedules - verify response
57. POST /api/v1/notifications/channels - create test webhook channel
58. GET /api/v1/notifications/history - verify response
59. GET / (dashboard) - verify HTML response with 5 tabs
60. DELETE test webhook channel

### Phase 8: Export & Reporting
61. Export findings to CSV
62. Export findings to JSON
63. Test SARIF export format
64. Test executive report generation

### Phase 9: Compliance Frameworks
65. List all compliance frameworks
66. Map a test finding to NIST 800-53 controls
67. Map a test finding to HIPAA controls
68. Map a test finding to PCI-DSS controls
69. Verify framework config files exist in config/frameworks/

### Phase 10: AI Engine
70. Test AI engine status (template mode expected)
71. Test template-based finding analysis
72. Test template-based triage
73. Test template-based remediation generation
74. Test template-based scan summary
75. Test template-based query

### Phase 11: Licensing
76. Verify community tier is active
77. Test tier limit checks (deep scan blocked, etc.)
78. Test scanner feature gating
79. Test export format gating
80. Test notification channel gating
81. Generate a test pro license and validate it

### Phase 12: Threat Intelligence
82. Query CISA KEV database
83. Query EPSS scores
84. Enrich a test CVE (CVE-2021-44228)
85. Calculate effective priority

### Phase 13: Risk Quantification
86. Run FAIR analysis on a test scenario
87. Verify Monte Carlo simulation output
88. Check industry benchmark data

## Output
After all tests, produce:
1. `data/test_run_log.json` - full test log
2. Summary: X passed, Y failed, Z fixed, W skipped
3. List of outstanding items that need fixing

When complete, output: <promise>FULL TEST COMPLETE</promise>
