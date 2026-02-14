# Purple Team GRC - Data Export Guide

## Overview

The export module (`lib/export.py`) enables Purple Team GRC scan findings and vulnerability data to be ingested by major security platforms using industry-standard formats.

**Key Features:**
- 10+ export formats for all major security platforms
- Zero external dependencies (Python stdlib only)
- Unicode support with proper Windows encoding
- Integrated into purple-launcher with 'x' menu option

## Supported Export Formats

### 1. CEF (Common Event Format)
**Used by:** ArcSight, QRadar, Splunk (via syslog)

**Format:** `CEF:0|PurpleTeamGRC|Scanner|7.0|<finding_type>|<title>|<severity_num>|<extensions>`

**Severity Mapping:**
- CRITICAL = 10
- HIGH = 8
- MEDIUM = 5
- LOW = 3
- INFO = 1

**Extensions:**
- `dst` - Affected asset IP
- `src` - Scanner hostname
- `cs1` - CVE IDs
- `cs2` - Compliance controls
- `cs3` - CWE ID
- `cn1` - CVSS score
- `cs4` - Remediation guidance
- `cat` - Finding type
- `rt` - Timestamp (epoch milliseconds)

**Example:**
```
CEF:0|PurpleTeamGRC|Scanner|7.0|web_vulnerability|SQL Injection|8|dst=192.168.1.100 cs1=CVE-2024-1234 cn1=8.5
```

### 2. STIX 2.1 (JSON)
**Used by:** CrowdStrike, Stellar AI, Microsoft Sentinel, ThreatLocker, any threat intel platform

**Description:** Exports vulnerabilities as STIX Vulnerability objects, findings as STIX Indicator objects with patterns, and includes Relationship objects linking them.

**Bundle Structure:**
- Identity object (scanner identity)
- Vulnerability objects (one per CVE)
- Indicator objects (one per finding)
- Relationship objects (linking indicators to vulnerabilities)

**Use Case:** Import into threat intelligence platforms for correlation with other threat data.

### 3. Splunk HEC JSON
**Used by:** Splunk HTTP Event Collector

**Format:** Line-delimited JSON with Splunk HEC schema

**Schema:**
```json
{
  "time": <epoch_seconds>,
  "source": "purpleteam",
  "sourcetype": "purpleteam:finding",
  "event": {
    "finding_id": "...",
    "severity": "HIGH",
    "title": "...",
    "cvss_score": 8.5,
    ...
  }
}
```

**Ingestion:**
```bash
curl -X POST https://splunk:8088/services/collector/event \
  -H "Authorization: Splunk <HEC_TOKEN>" \
  -d @findings.splunk.json
```

### 4. Microsoft Sentinel / Azure Log Analytics
**Used by:** Microsoft Sentinel, Azure Monitor

**Description:** Flat JSON format compatible with Azure Monitor Data Collection Rules and custom log tables.

**Schema:** All fields are flattened with PascalCase names:
- `TimeGenerated` (required for Sentinel)
- `Severity`, `Title`, `Description`
- `CVSSScore`, `CVEIds`, `Remediation`
- `KEVStatus`, `EPSSScore`, `EffectivePriority`

**Ingestion:** Upload via Azure Monitor Data Collection API or custom log tables.

### 5. QRadar LEEF
**Used by:** IBM QRadar

**Format:** `LEEF:2.0|Vendor|Product|Version|EventID|<tab-delimited-attributes>`

**Attributes:**
- `sev` - Severity level
- `title` - Finding title
- `desc` - Description
- `dst` - Destination (affected asset)
- `devTime` - Device timestamp
- `cvss` - CVSS score
- `cat` - Category (finding type)

### 6. CSV (ServiceNow / Jira)
**Used by:** ServiceNow incident import, Jira ticket creation, Excel analysis

**Columns:**
- Title, Severity, Description, CVE, CVSS, CWE
- Remediation, ComplianceControls, Asset, ScanDate
- Status, FindingType, Scanner, KEVStatus
- EPSSScore, Priority, FalsePositive

**Encoding:** UTF-8 with BOM for Excel compatibility

**Use Case:** Bulk import into ticketing systems or Excel pivot tables.

### 7. ServiceNow JSON
**Used by:** ServiceNow Table API import

**Description:** JSON array of incident records pre-formatted for ServiceNow Import Set or Table API.

**Fields:**
- `short_description`, `description`
- `impact`, `urgency` (mapped from severity)
- `category`, `subcategory`
- Custom fields: `u_affected_asset`, `u_cve_ids`, `u_cvss_score`, `u_kev_status`

**API Import:**
```bash
curl -X POST https://<instance>.service-now.com/api/now/import/u_security_findings \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d @findings.servicenow.json
```

### 8. Qualys XML
**Used by:** Qualys QualysGuard-compatible import tools

**Description:** Basic Qualys-style XML report format with SCAN, HEADER, IP_LIST, and VULNS structure.

**Structure:**
```xml
<SCAN>
  <HEADER>
    <DATETIME>...</DATETIME>
    <TITLE>PurpleTeamGRC Security Scan</TITLE>
  </HEADER>
  <IP_LIST>
    <IP>
      <VALUE>192.168.1.100</VALUE>
      <VULNS>
        <VULN>
          <QID>12345</QID>
          <TITLE>...</TITLE>
          <SEVERITY>4</SEVERITY>
          <CVSS_BASE>8.5</CVSS_BASE>
          <CVE_ID_LIST>...</CVE_ID_LIST>
        </VULN>
      </VULNS>
    </IP>
  </IP_LIST>
</SCAN>
```

### 9. SARIF 2.1.0
**Used by:** GitHub Advanced Security, Azure DevOps, GitLab, Visual Studio

**Description:** Static Analysis Results Interchange Format - the standard for security scanning results in CI/CD.

**Features:**
- Rules (finding types with descriptions)
- Results (individual findings with locations)
- Properties (CVE IDs, CVSS, KEV status, EPSS)
- Levels: error, warning, note, none

**GitHub Integration:**
```bash
# Upload to GitHub Security tab
curl -X POST \
  https://api.github.com/repos/<owner>/<repo>/code-scanning/sarifs \
  -H "Authorization: token <GITHUB_TOKEN>" \
  -d @findings.sarif.json
```

### 10. Syslog RFC 5424
**Used by:** Any SIEM (universal format)

**Format:** `<PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG`

**Priority Calculation:**
- Facility 16 (local0 = security)
- Severity mapped to syslog levels (2-6)
- Priority = Facility * 8 + Severity

**Structured Data:**
```
[finding@32473 finding_id="..." severity="HIGH" cvss="8.5" asset="192.168.1.100"]
```

**Syslog Server:**
```bash
# Send to syslog server
cat findings.syslog | nc -u syslog-server 514
```

### 11. JSON Lines (.jsonl)
**Used by:** Generic data pipelines, log aggregators, data lakes

**Description:** Each line is a complete JSON object representing one finding with all available fields.

**Use Cases:**
- Stream processing with Apache Kafka
- Import into Elasticsearch/OpenSearch
- Data lake ingestion (S3, Azure Data Lake)
- Big data analytics (Spark, Hadoop)

**Example:**
```json
{"finding_id":"FND-001","severity":"HIGH","title":"...","cvss_score":8.5,...}
{"finding_id":"FND-002","severity":"MEDIUM","title":"...","cvss_score":5.3,...}
```

## Usage

### Command Line

**Export all formats:**
```bash
python lib/export.py SESSION-20260214-001
```

**Export specific formats:**
```bash
python lib/export.py SESSION-20260214-001 -f cef stix sarif
```

**Custom output directory:**
```bash
python lib/export.py SESSION-20260214-001 -o /path/to/exports
```

**List supported formats:**
```bash
python lib/export.py --list
```

### Interactive Menu

1. Run purple-launcher
2. Press `x` for "Export Data"
3. Select a session to export
4. Choose export formats (or 0 for all)
5. Files are saved to `results/<session_id>/exports/`

### Python API

```python
from export import ExportManager

# Initialize
exporter = ExportManager()

# Export all formats
results = exporter.export_all(
    session_id='SESSION-20260214-001',
    output_dir=Path('./exports'),
    formats=['cef', 'stix', 'sarif']  # or None for all
)

# Results is a dict: {'cef': Path(...), 'stix': Path(...), ...}
for fmt, path in results.items():
    print(f"Exported {fmt} to {path}")
```

## Platform-Specific Integration

### ArcSight (CEF)
1. Export to CEF format
2. Configure ArcSight Connector for file-based CEF ingestion
3. Point connector to export directory
4. ArcSight will parse CEF and create events

### QRadar (LEEF or Syslog)
1. Export to LEEF or Syslog format
2. Configure QRadar Log Source (Universal LEEF or Syslog)
3. Send logs via syslog protocol or file upload
4. QRadar will parse and create events

### Splunk (CEF, HEC, or Syslog)
**Option 1: HEC (recommended)**
```bash
curl -k https://splunk:8088/services/collector/event \
  -H "Authorization: Splunk <token>" \
  --data-binary @findings.splunk.json
```

**Option 2: CEF via syslog**
Configure Splunk to receive syslog on 514, send CEF logs.

### CrowdStrike Falcon (STIX)
1. Export to STIX 2.1 format
2. Use CrowdStrike Intel API to upload indicators
3. Indicators will appear in Falcon console

### Microsoft Sentinel (Sentinel JSON or STIX)
**Option 1: Custom logs**
1. Export to Sentinel format
2. Upload via Azure Monitor Data Collection API
3. Query in Log Analytics workspace

**Option 2: Threat Intelligence**
1. Export to STIX format
2. Upload to Sentinel Threat Intelligence blade
3. Indicators auto-correlate with logs

### GitHub Advanced Security (SARIF)
```bash
# Via API
curl -X POST \
  https://api.github.com/repos/$OWNER/$REPO/code-scanning/sarifs \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d @upload.json

# upload.json contains:
# {
#   "commit_sha": "<sha>",
#   "ref": "refs/heads/main",
#   "sarif": "<base64-encoded-sarif>"
# }
```

Findings appear in Security > Code scanning alerts.

### ServiceNow (CSV or JSON)
**Option 1: CSV Import**
1. Export to CSV
2. ServiceNow > System Import Sets > Load Data
3. Upload CSV and map columns
4. Transform to target table

**Option 2: Table API**
```bash
curl -X POST \
  https://<instance>.service-now.com/api/now/table/u_security_findings \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d @findings.servicenow.json
```

### Jira (CSV or API)
**CSV Import:**
1. Jira > Issues > Import
2. Upload CSV
3. Map CSV columns to Jira fields

**API (bulk create):**
```python
import requests
import json

with open('findings.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        payload = {
            "fields": {
                "project": {"key": "SEC"},
                "summary": row['Title'],
                "description": row['Description'],
                "issuetype": {"name": "Bug"},
                "priority": {"name": row['Severity']}
            }
        }
        requests.post(
            'https://jira.company.com/rest/api/2/issue',
            auth=('user', 'pass'),
            json=payload
        )
```

## Data Fields Reference

All export formats include these core fields (when available):

**Identification:**
- `finding_id` - Unique finding identifier
- `session_id` - Scan session identifier

**Classification:**
- `severity` - CRITICAL, HIGH, MEDIUM, LOW, INFO
- `finding_type` - Category (web_vulnerability, cve_vulnerability, etc.)
- `title` - Short finding title
- `description` - Detailed description

**Technical Details:**
- `affected_asset` - IP address or hostname
- `cvss_score` - CVSS base score (0.0-10.0)
- `cve_ids` - List of CVE identifiers
- `cwe_id` - CWE identifier (if applicable)

**Enrichment:**
- `kev_status` - CISA KEV catalog status (true/false)
- `epss_score` - Exploit Prediction Scoring System (0.0-1.0)
- `epss_percentile` - EPSS percentile rank
- `effective_priority` - Calculated priority (0.0-10.0)

**Detection:**
- `scanner_name` - Scanner that detected the finding
- `detection_source` - Specific detection method/tool
- `quality_of_detection` - Detection quality score (0.0-1.0)
- `timestamp` - Discovery timestamp (ISO 8601)

**Response:**
- `remediation` - Remediation guidance
- `status` - open, closed, accepted_risk, false_positive
- `false_positive` - False positive flag (0/1)
- `fp_reason` - False positive justification

**Compliance:**
- `compliance_controls` - Mapped compliance controls (NIST, PCI-DSS, etc.)

## Output File Naming

Default naming convention: `findings_<timestamp>.<ext>`

Examples:
- `findings_20260214_120000.cef`
- `findings_20260214_120000.stix.json`
- `findings_20260214_120000.sarif.json`
- `findings_20260214_120000.csv`

## Performance Notes

- **Small datasets** (<100 findings): All formats export in <1 second
- **Medium datasets** (100-1000 findings): 1-5 seconds
- **Large datasets** (>1000 findings): 5-30 seconds

Most time-consuming format: XML (Qualys) due to pretty-printing.
Fastest format: JSON Lines (no parsing overhead).

## Troubleshooting

**Issue: "No findings found for session"**
- Verify session ID is correct
- Ensure scan has completed
- Check that findings exist in database

**Issue: Unicode errors on Windows console**
- Files are still written correctly
- Console encoding issue only (display)
- Use `type filename` or text editor to view

**Issue: Large file sizes**
- STIX generates most verbose output (relationships, metadata)
- CSV/JSON Lines are most compact
- Use compression for large exports: `gzip findings.jsonl`

**Issue: Platform won't accept format**
- Check platform's format version requirements
- Some platforms need specific schema versions
- Validate with platform's import documentation

## Best Practices

1. **Export regularly:** Set up automated exports after each scan
2. **Use multiple formats:** Different platforms for different purposes
3. **Validate critical exports:** Test SARIF/STIX with target platforms
4. **Archive exports:** Keep historical exports for trend analysis
5. **Compress large exports:** Use gzip for >10MB files
6. **Document custom fields:** Track platform-specific custom field mappings
7. **Version control configs:** Keep integration configs in git

## Support Matrix

| Format | Platform | Status | Notes |
|--------|----------|--------|-------|
| CEF | ArcSight | ✓ Full | All extensions supported |
| CEF | QRadar | ✓ Full | Use LEEF for better integration |
| CEF | Splunk | ✓ Full | Also supports HEC |
| STIX | CrowdStrike | ✓ Full | STIX 2.1 compatible |
| STIX | Sentinel | ✓ Full | Threat Intel blade |
| STIX | ThreatLocker | ✓ Full | Via API import |
| Splunk HEC | Splunk | ✓ Full | Native format |
| Sentinel | Sentinel | ✓ Full | Custom log tables |
| LEEF | QRadar | ✓ Full | Recommended for QRadar |
| CSV | ServiceNow | ✓ Full | Import sets or API |
| CSV | Jira | ✓ Full | CSV importer |
| SARIF | GitHub | ✓ Full | Code Scanning |
| SARIF | Azure DevOps | ✓ Full | Pipeline integration |
| SARIF | GitLab | ✓ Partial | Ultimate tier only |
| Syslog | Any SIEM | ✓ Full | RFC 5424 compliant |
| JSON Lines | Elasticsearch | ✓ Full | Bulk API |
| JSON Lines | Kafka | ✓ Full | Stream processing |

## License

Part of Purple Team GRC v7.0
See LICENSE file for details.
