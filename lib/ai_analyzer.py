#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - AI-Powered Analysis Engine
Multi-backend AI analysis: Template (default), Ollama (local), OpenAI-compatible.
All LLM output tagged "AI-Generated - Verify Before Acting".
Template backend works without any LLM - pure Python rule-based analysis.
"""

import json
import re
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
    from .credential_manager import get_credential_manager
except ImportError:
    from paths import paths
    from credential_manager import get_credential_manager

# Try platform_detect for deployment mode check
try:
    from .platform_detect import get_platform_info
except ImportError:
    try:
        from platform_detect import get_platform_info
    except ImportError:
        get_platform_info = None

# Try logger
try:
    from .logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger('ai_analyzer')

# AI output disclaimer
AI_DISCLAIMER = "\n--- AI-Generated - Verify Before Acting ---\n"

# Valid providers
VALID_PROVIDERS = ('template', 'ollama', 'openai')

# Default Ollama endpoint
DEFAULT_OLLAMA_URL = "http://localhost:11434"

# Default OpenAI-compatible endpoint
DEFAULT_OPENAI_URL = "https://api.openai.com/v1"

# Template backend: finding type explanations
FINDING_EXPLANATIONS = {
    'sql_injection': (
        "SQL Injection allows attackers to manipulate database queries through "
        "unsanitized user input. This can lead to unauthorized data access, "
        "data modification, or complete database compromise. It is consistently "
        "ranked among the most critical web application vulnerabilities."
    ),
    'xss': (
        "Cross-Site Scripting (XSS) enables attackers to inject malicious scripts "
        "into web pages viewed by other users. This can result in session hijacking, "
        "credential theft, defacement, or redirection to malicious sites."
    ),
    'ssl_weak_cipher': (
        "Weak SSL/TLS cipher suites allow potential eavesdropping or man-in-the-middle "
        "attacks on encrypted communications. Deprecated ciphers (RC4, DES, 3DES, export "
        "ciphers) can be broken with modern computing resources."
    ),
    'ssl_expired_cert': (
        "An expired SSL/TLS certificate means the identity of the server can no longer "
        "be verified. Users may ignore security warnings, and attackers can exploit "
        "this to perform man-in-the-middle attacks without detection."
    ),
    'ssl_self_signed': (
        "A self-signed certificate has not been validated by a trusted Certificate "
        "Authority. While encryption is still active, the server identity cannot be "
        "verified, making man-in-the-middle attacks feasible."
    ),
    'missing_headers': (
        "Missing HTTP security headers leave the application vulnerable to various "
        "client-side attacks including clickjacking (X-Frame-Options), MIME sniffing "
        "(X-Content-Type-Options), and cross-site scripting (Content-Security-Policy)."
    ),
    'open_port': (
        "An open network port exposes a service to potential attack. Unnecessary open "
        "ports increase the attack surface and may expose vulnerable or misconfigured "
        "services to unauthorized access."
    ),
    'default_credentials': (
        "Default or factory credentials provide trivial access for attackers. "
        "Automated scanning tools and botnets routinely attempt default credential "
        "combinations, making this a high-priority finding."
    ),
    'directory_listing': (
        "Directory listing enabled on a web server exposes the file structure, "
        "potentially revealing sensitive files, backup archives, configuration "
        "files, or internal documentation not intended for public access."
    ),
    'outdated_software': (
        "Running outdated software versions means known security patches have not "
        "been applied. Public exploit code may be available for known vulnerabilities "
        "in older versions, making exploitation straightforward."
    ),
    'command_injection': (
        "Command injection allows attackers to execute arbitrary operating system "
        "commands on the host server. This typically leads to full system compromise "
        "and can serve as a pivot point for lateral movement."
    ),
    'path_traversal': (
        "Path traversal vulnerabilities allow attackers to access files outside "
        "the intended directory structure. This can expose configuration files, "
        "credentials, source code, or system files like /etc/passwd."
    ),
    'snmp_public': (
        "SNMP with default community strings (public/private) allows unauthorized "
        "read or write access to network device configurations. Attackers can "
        "enumerate the entire network topology and modify device settings."
    ),
    'smb_signing_disabled': (
        "Without SMB signing, network traffic between clients and servers can be "
        "intercepted and modified. Attackers on the network can perform relay attacks "
        "to authenticate as legitimate users."
    ),
}

# Template backend: remediation steps by finding type
REMEDIATION_STEPS = {
    'sql_injection': (
        "1. Use parameterized queries (prepared statements) for all database operations\n"
        "2. Implement input validation with allowlists for expected data formats\n"
        "3. Apply the principle of least privilege to database accounts\n"
        "4. Deploy a Web Application Firewall (WAF) as defense-in-depth\n"
        "5. Conduct code review focusing on data access layers"
    ),
    'xss': (
        "1. Encode all user-supplied output using context-appropriate encoding\n"
        "2. Implement Content-Security-Policy headers to restrict script sources\n"
        "3. Use HTTP-only and Secure flags on session cookies\n"
        "4. Validate and sanitize input on both client and server side\n"
        "5. Consider using auto-escaping template engines"
    ),
    'ssl_weak_cipher': (
        "1. Update cipher suite configuration to disable weak ciphers (RC4, DES, 3DES)\n"
        "2. Enable only TLS 1.2+ with AEAD cipher suites (AES-GCM, ChaCha20)\n"
        "3. Configure proper cipher ordering (server preference)\n"
        "4. Test configuration with tools like testssl.sh or SSL Labs\n"
        "5. Implement HSTS to prevent protocol downgrade attacks"
    ),
    'ssl_expired_cert': (
        "1. Renew the SSL/TLS certificate immediately\n"
        "2. Implement automated certificate renewal (e.g., Let's Encrypt with certbot)\n"
        "3. Set up monitoring alerts for certificates expiring within 30 days\n"
        "4. Document certificate inventory and renewal schedules\n"
        "5. Consider using a certificate management platform"
    ),
    'ssl_self_signed': (
        "1. Replace self-signed certificate with one from a trusted Certificate Authority\n"
        "2. For internal services, deploy an internal CA with proper trust chain\n"
        "3. Use Let's Encrypt for public-facing services (free, automated)\n"
        "4. Ensure all intermediate certificates are properly configured\n"
        "5. Implement certificate pinning for critical applications"
    ),
    'missing_headers': (
        "1. Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking\n"
        "2. Add X-Content-Type-Options: nosniff to prevent MIME sniffing\n"
        "3. Add Content-Security-Policy with restrictive directives\n"
        "4. Add Strict-Transport-Security for HTTPS enforcement\n"
        "5. Add Referrer-Policy: strict-origin-when-cross-origin\n"
        "6. Add Permissions-Policy to restrict browser features"
    ),
    'open_port': (
        "1. Identify the service running on the port and verify business need\n"
        "2. Close unnecessary ports at the firewall level\n"
        "3. If the service is required, restrict access by source IP\n"
        "4. Ensure the service is updated and properly configured\n"
        "5. Implement network segmentation to limit exposure"
    ),
    'default_credentials': (
        "1. Change all default passwords immediately\n"
        "2. Implement a strong password policy (minimum 14 characters)\n"
        "3. Enable multi-factor authentication where supported\n"
        "4. Audit all devices and applications for factory defaults\n"
        "5. Include credential change verification in deployment checklists"
    ),
    'directory_listing': (
        "1. Disable directory listing in web server configuration\n"
        "2. Apache: Add 'Options -Indexes' to the directory configuration\n"
        "3. Nginx: Ensure 'autoindex off;' is set (default)\n"
        "4. Add index files to all directories that should be accessible\n"
        "5. Review exposed directories for sensitive file cleanup"
    ),
    'outdated_software': (
        "1. Update to the latest stable version of the affected software\n"
        "2. Review the vendor's security advisories for patched vulnerabilities\n"
        "3. Implement a regular patch management schedule\n"
        "4. Subscribe to security mailing lists for timely update notifications\n"
        "5. Consider automated update mechanisms where appropriate"
    ),
    'command_injection': (
        "1. Never pass user input directly to system commands\n"
        "2. Use language-native APIs instead of shell commands where possible\n"
        "3. If shell commands are necessary, use allowlists for permitted values\n"
        "4. Implement proper input validation and sanitization\n"
        "5. Run application processes with minimal OS privileges"
    ),
    'path_traversal': (
        "1. Validate and canonicalize all file paths before access\n"
        "2. Use a chroot jail or container to restrict filesystem access\n"
        "3. Implement allowlists for permitted file paths or names\n"
        "4. Reject input containing path traversal sequences (../, ..\\)\n"
        "5. Use language-native file access controls and sandboxing"
    ),
    'snmp_public': (
        "1. Change SNMP community strings from default values immediately\n"
        "2. Migrate to SNMPv3 with authentication and encryption\n"
        "3. Restrict SNMP access to management network only\n"
        "4. Disable SNMP write access unless explicitly required\n"
        "5. Monitor SNMP access logs for unauthorized queries"
    ),
    'smb_signing_disabled': (
        "1. Enable SMB signing on all domain controllers (required by default)\n"
        "2. Enable SMB signing on all member servers and workstations\n"
        "3. Configure Group Policy: 'Microsoft network server: Digitally sign communications'\n"
        "4. Test SMB signing impact on legacy systems before enforcement\n"
        "5. Monitor for SMB relay attack indicators"
    ),
}

# Severity ordering for sorting
SEVERITY_ORDER = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}


class AIAnalyzer:
    """
    AI-powered analysis engine for Purple Team findings.

    Three backends:
    - template (default): Pure Python rule-based analysis, always available.
    - ollama: Local LLM via Ollama API, gets full unsanitized data.
    - openai: OpenAI-compatible API with Bearer auth, data sanitized by default.

    NOT a singleton - different instances may use different configurations.
    """

    def __init__(self, provider: str = 'template', model: str = None,
                 api_url: str = None, api_key: str = None,
                 sanitize_external: bool = True):
        """
        Initialize the AI analyzer.

        Args:
            provider: 'template', 'ollama', or 'openai'
            model: Model name (e.g., 'llama3' for Ollama, 'gpt-4' for OpenAI)
            api_url: API base URL (defaults per provider)
            api_key: API key for OpenAI-compatible backends
            sanitize_external: Sanitize data before sending to external LLMs (default True)
        """
        # Check portable deployment mode - only template allowed
        if get_platform_info is not None:
            try:
                platform_info = get_platform_info()
                if platform_info.is_portable and provider != 'template':
                    logger.warning(
                        f"Portable deployment mode detected. "
                        f"Forcing provider from '{provider}' to 'template' "
                        f"(external AI not available in portable mode)"
                    )
                    provider = 'template'
            except Exception:
                pass

        if provider not in VALID_PROVIDERS:
            raise ValueError(
                f"Invalid provider '{provider}'. Must be one of: {VALID_PROVIDERS}"
            )

        self.provider = provider
        self.sanitize_external = sanitize_external
        self._hostname_map: Dict[str, str] = {}
        self._hostname_counter = 0

        # Provider-specific configuration
        if provider == 'ollama':
            self.api_url = api_url or DEFAULT_OLLAMA_URL
            self.model = model or 'llama3'
            self.api_key = None  # Ollama does not need auth
        elif provider == 'openai':
            self.api_url = api_url or DEFAULT_OPENAI_URL
            self.model = model or 'gpt-4'
            self.api_key = api_key
            # Try credential manager if no key provided
            if not self.api_key:
                try:
                    cm = get_credential_manager()
                    cred = cm.get_credential_for_target('openai.com', 'http_basic')
                    if cred and cred.get('params', {}).get('password'):
                        self.api_key = cred['params']['password']
                        logger.info("Loaded OpenAI API key from credential manager")
                except Exception:
                    pass
        else:
            # Template backend - no external config needed
            self.api_url = None
            self.model = None
            self.api_key = None

        logger.info(f"AIAnalyzer initialized: provider={self.provider}, model={self.model}")

    # -------------------------------------------------------------------------
    # Data sanitization
    # -------------------------------------------------------------------------

    def _sanitize_for_external(self, text: str) -> str:
        """
        Sanitize sensitive data before sending to external LLMs.

        Replaces:
        - IP addresses with x.x.x.0 pattern
        - Hostnames with [HOST-N] placeholders
        - Organization-like names with [ORG]

        Preserves:
        - CVE IDs (public data)
        - CVSS scores (public data)
        - Severity levels
        """
        if not text or not isinstance(text, str):
            return text or ''

        result = text

        # Replace IP addresses: keep first three octets pattern, zero last octet
        def _mask_ip(match):
            octets = match.group(0).split('.')
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0"

        result = re.sub(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            _mask_ip,
            result
        )

        # Replace hostnames (FQDN patterns like server.corp.example.com)
        def _mask_hostname(match):
            hostname = match.group(0)
            # Skip CVE IDs and common non-hostname patterns
            if hostname.upper().startswith('CVE-'):
                return hostname
            if hostname in self._hostname_map:
                return self._hostname_map[hostname]
            self._hostname_counter += 1
            placeholder = f"[HOST-{self._hostname_counter}]"
            self._hostname_map[hostname] = placeholder
            return placeholder

        result = re.sub(
            r'\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z][a-zA-Z0-9-]*){2,}\b',
            _mask_hostname,
            result
        )

        # Replace org-like references (capitalized multi-word names after common labels)
        result = re.sub(
            r'(?:organization|company|client|customer|corp|corporation)[:\s]+[A-Z][A-Za-z\s&]+',
            lambda m: m.group(0).split(':')[0].split()[0] + ': [ORG]'
            if ':' in m.group(0)
            else '[ORG]',
            result,
            flags=re.IGNORECASE
        )

        return result

    def _sanitize_dict(self, data: dict) -> dict:
        """Recursively sanitize all string values in a dictionary."""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self._sanitize_for_external(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = self._sanitize_list(value)
            else:
                sanitized[key] = value
        return sanitized

    def _sanitize_list(self, data: list) -> list:
        """Recursively sanitize all string values in a list."""
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized.append(self._sanitize_for_external(item))
            elif isinstance(item, dict):
                sanitized.append(self._sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(self._sanitize_list(item))
            else:
                sanitized.append(item)
        return sanitized

    def _prepare_data(self, data) -> str:
        """Prepare data for LLM submission, with optional sanitization."""
        if self.provider == 'openai' and self.sanitize_external:
            if isinstance(data, dict):
                data = self._sanitize_dict(data)
            elif isinstance(data, list):
                data = self._sanitize_list(data)
            elif isinstance(data, str):
                data = self._sanitize_for_external(data)
        return json.dumps(data, indent=2, default=str) if not isinstance(data, str) else data

    # -------------------------------------------------------------------------
    # LLM call routing
    # -------------------------------------------------------------------------

    def _call_llm(self, prompt: str, context: str = '') -> str:
        """
        Route prompt to the configured LLM backend.

        Falls back to template-style response on any error.
        All LLM responses are prefixed with the AI disclaimer.
        """
        if self.provider == 'template':
            # Template backend does not use _call_llm
            return ''

        full_prompt = prompt
        if context:
            full_prompt = f"{prompt}\n\nContext data:\n{context}"

        try:
            if self.provider == 'ollama':
                return self._call_ollama(full_prompt)
            elif self.provider == 'openai':
                return self._call_openai(full_prompt)
        except Exception as e:
            logger.warning(f"LLM call failed ({self.provider}): {e}. Falling back to template.")
            return ''

        return ''

    def _call_ollama(self, prompt: str) -> str:
        """Call Ollama local LLM API."""
        url = f"{self.api_url.rstrip('/')}/api/generate"

        payload = json.dumps({
            'model': self.model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': 0.3,
                'num_predict': 1024,
            }
        }).encode('utf-8')

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'PurpleTeamPlatform/7.0',
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=120) as response:
            result = json.loads(response.read().decode('utf-8'))

        text = result.get('response', '').strip()
        if text:
            return AI_DISCLAIMER + text
        return ''

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI-compatible API (OpenAI, Azure, vLLM, etc.)."""
        if not self.api_key:
            raise ValueError("OpenAI API key not configured")

        url = f"{self.api_url.rstrip('/')}/chat/completions"

        payload = json.dumps({
            'model': self.model,
            'messages': [
                {
                    'role': 'system',
                    'content': (
                        'You are a cybersecurity analyst assistant for a purple team '
                        'security assessment platform. Provide concise, actionable analysis. '
                        'Focus on business impact and practical remediation.'
                    )
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'temperature': 0.3,
            'max_tokens': 1024,
        }).encode('utf-8')

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}',
                'User-Agent': 'PurpleTeamPlatform/7.0',
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            result = json.loads(response.read().decode('utf-8'))

        choices = result.get('choices', [])
        if choices:
            text = choices[0].get('message', {}).get('content', '').strip()
            if text:
                return AI_DISCLAIMER + text
        return ''

    # -------------------------------------------------------------------------
    # Public analysis methods
    # -------------------------------------------------------------------------

    def generate_executive_summary(self, session_results: dict) -> str:
        """
        Generate an executive summary from session results.

        Args:
            session_results: Dict with 'summary' key containing severity counts,
                             total_hosts_scanned, compliance_rate, etc.
        """
        if self.provider == 'template':
            return self._template_executive_summary(session_results)

        context = self._prepare_data(session_results)
        prompt = (
            "Generate a concise executive summary for a security assessment. "
            "Include: overall risk posture, key statistics, top risk areas, "
            "and a brief compliance status. Use professional language suitable "
            "for C-level stakeholders. Keep it under 200 words."
        )
        result = self._call_llm(prompt, context)
        if result:
            return result
        # Fallback to template
        return self._template_executive_summary(session_results)

    def explain_finding(self, finding_dict: dict) -> str:
        """
        Explain a security finding in plain English business context.

        Args:
            finding_dict: Dict with title, severity, finding_type, cvss_score, etc.
        """
        if self.provider == 'template':
            return self._template_explain_finding(finding_dict)

        context = self._prepare_data(finding_dict)
        prompt = (
            "Explain this security finding in plain English for a non-technical "
            "audience. Include: what the vulnerability is, why it matters to the "
            "business, what an attacker could do with it, and how urgent it is. "
            "Keep it under 150 words."
        )
        result = self._call_llm(prompt, context)
        if result:
            return result
        return self._template_explain_finding(finding_dict)

    def suggest_remediation(self, finding_dict: dict) -> str:
        """
        Suggest specific, actionable remediation steps for a finding.

        Args:
            finding_dict: Dict with finding_type, title, severity, remediation, etc.
        """
        if self.provider == 'template':
            return self._template_suggest_remediation(finding_dict)

        context = self._prepare_data(finding_dict)
        prompt = (
            "Suggest specific, actionable remediation steps for this security "
            "finding. Include: immediate actions, long-term fixes, and verification "
            "steps. Be specific with commands or configuration changes where possible. "
            "Prioritize by impact."
        )
        result = self._call_llm(prompt, context)
        if result:
            return result
        return self._template_suggest_remediation(finding_dict)

    def generate_attack_narrative(self, findings_list: list) -> str:
        """
        Generate a realistic attack narrative from a set of findings.

        Args:
            findings_list: List of finding dicts with severity, title,
                           affected_asset, finding_type, etc.
        """
        if self.provider == 'template':
            return self._template_attack_narrative(findings_list)

        context = self._prepare_data(findings_list)
        prompt = (
            "Given these security findings, describe a realistic attack narrative "
            "showing how an attacker could chain these vulnerabilities together. "
            "Include: initial access, escalation, lateral movement, and impact. "
            "Use numbered steps and reference specific findings."
        )
        result = self._call_llm(prompt, context)
        if result:
            return result
        return self._template_attack_narrative(findings_list)

    def prioritize_findings(self, findings_list: list) -> list:
        """
        Prioritize findings with reasoning.

        Args:
            findings_list: List of finding dicts

        Returns:
            List of dicts with 'finding', 'rank', 'reasoning' keys,
            sorted by priority (highest first).
        """
        if self.provider == 'template':
            return self._template_prioritize(findings_list)

        context = self._prepare_data(findings_list)
        prompt = (
            "Prioritize these security findings from most to least urgent. "
            "For each finding, provide a rank number and brief reasoning "
            "explaining why it has that priority. Consider: exploitability, "
            "business impact, known exploitation in the wild, and ease of fix. "
            "Return as a JSON array with keys: title, rank, reasoning."
        )
        result = self._call_llm(prompt, context)
        if result:
            # Try to parse LLM JSON response
            try:
                # Strip disclaimer and find JSON
                clean = result.replace(AI_DISCLAIMER, '').strip()
                # Find JSON array in the response
                json_match = re.search(r'\[.*\]', clean, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group(0))
                    # Map parsed results back to original findings
                    prioritized = []
                    for idx, item in enumerate(parsed):
                        finding = None
                        for f in findings_list:
                            if f.get('title', '').lower() in item.get('title', '').lower():
                                finding = f
                                break
                        if finding is None and idx < len(findings_list):
                            finding = findings_list[idx]
                        if finding:
                            prioritized.append({
                                'finding': finding,
                                'rank': item.get('rank', idx + 1),
                                'reasoning': AI_DISCLAIMER + item.get('reasoning', 'N/A'),
                            })
                    if prioritized:
                        return prioritized
            except (json.JSONDecodeError, KeyError, IndexError):
                pass

        # Fallback to template
        return self._template_prioritize(findings_list)

    # -------------------------------------------------------------------------
    # Template backend implementations
    # -------------------------------------------------------------------------

    def _template_executive_summary(self, results: dict) -> str:
        """Generate a structured executive summary without any LLM."""
        summary = results.get('summary', {})
        session_id = results.get('session_id', 'UNKNOWN')
        by_sev = summary.get('findings_by_severity', {})
        total = summary.get('total_findings', 0)
        hosts = summary.get('total_hosts_scanned', 0)
        compliance = summary.get('compliance_rate', 0.0)

        critical = by_sev.get('CRITICAL', 0)
        high = by_sev.get('HIGH', 0)
        medium = by_sev.get('MEDIUM', 0)
        low = by_sev.get('LOW', 0)
        info = by_sev.get('INFO', 0)

        # Determine overall risk posture
        if critical > 0:
            risk_posture = "CRITICAL"
            risk_desc = "Immediate action required. Critical vulnerabilities were identified."
        elif high > 0:
            risk_posture = "HIGH"
            risk_desc = "Significant risks detected requiring prompt remediation."
        elif medium > 0:
            risk_posture = "MODERATE"
            risk_desc = "Moderate risks identified. Remediation recommended within 30 days."
        elif low > 0:
            risk_posture = "LOW"
            risk_desc = "Minor issues found. Address during normal maintenance cycles."
        else:
            risk_posture = "MINIMAL"
            risk_desc = "No significant vulnerabilities identified in this assessment."

        # Compliance status
        if compliance >= 90:
            compliance_status = "STRONG"
        elif compliance >= 70:
            compliance_status = "ADEQUATE"
        elif compliance >= 50:
            compliance_status = "NEEDS IMPROVEMENT"
        else:
            compliance_status = "FAILING"

        lines = [
            f"EXECUTIVE SUMMARY - Security Assessment {session_id}",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "=" * 60,
            "",
            f"Overall Risk Posture: {risk_posture}",
            f"  {risk_desc}",
            "",
            "Assessment Statistics:",
            f"  Hosts Scanned:    {hosts}",
            f"  Total Findings:   {total}",
            f"  Critical:         {critical}",
            f"  High:             {high}",
            f"  Medium:           {medium}",
            f"  Low:              {low}",
            f"  Informational:    {info}",
            "",
            f"Compliance Rate: {compliance:.1f}% ({compliance_status})",
            "",
        ]

        # Top risks
        if critical > 0 or high > 0:
            lines.append("Priority Actions:")
            if critical > 0:
                lines.append(f"  - Address {critical} CRITICAL finding(s) within 24 hours")
            if high > 0:
                lines.append(f"  - Remediate {high} HIGH finding(s) within 7 days")
            if medium > 0:
                lines.append(f"  - Plan remediation for {medium} MEDIUM finding(s) within 30 days")
            lines.append("")

        lines.append("Recommendation: " + (
            "Engage incident response for critical findings and schedule "
            "emergency patching cycle."
            if critical > 0
            else "Review findings report and incorporate remediation into "
                 "the next maintenance window."
            if high > 0
            else "Continue current security posture with routine improvements."
        ))

        return '\n'.join(lines)

    def _template_explain_finding(self, finding: dict) -> str:
        """Explain a finding using the template knowledge base."""
        finding_type = finding.get('finding_type', 'unknown')
        title = finding.get('title', 'Unknown Finding')
        severity = finding.get('severity', 'UNKNOWN')
        cvss = finding.get('cvss_score', 0.0)
        cve_ids = finding.get('cve_ids', [])
        asset = finding.get('affected_asset', 'Unknown')
        epss = finding.get('epss_score', 0.0)
        kev = finding.get('kev_status')

        explanation = FINDING_EXPLANATIONS.get(
            finding_type,
            f"This is a {severity.lower()} severity security finding that "
            f"may expose the affected system to unauthorized access or data compromise."
        )

        lines = [
            f"Finding: {title}",
            f"Severity: {severity} (CVSS {cvss:.1f})",
            f"Affected Asset: {asset}",
        ]

        if cve_ids:
            lines.append(f"CVE(s): {', '.join(cve_ids)}")

        if epss and epss > 0:
            lines.append(f"Exploit Probability (EPSS): {epss:.1%}")

        if kev and str(kev).lower() in ('true', '1', 'yes'):
            lines.append("CISA KEV: YES - Known actively exploited vulnerability")

        lines.extend(["", "Explanation:", explanation])

        # Add business impact note based on severity
        lines.append("")
        if severity == 'CRITICAL':
            lines.append(
                "Business Impact: This vulnerability poses an immediate threat "
                "to organizational security. Exploitation could result in complete "
                "system compromise, data breach, or service disruption."
            )
        elif severity == 'HIGH':
            lines.append(
                "Business Impact: This vulnerability represents a significant "
                "risk. Exploitation could lead to unauthorized data access, "
                "privilege escalation, or partial service compromise."
            )
        elif severity == 'MEDIUM':
            lines.append(
                "Business Impact: This vulnerability presents a moderate risk. "
                "While not immediately exploitable in most scenarios, it could "
                "contribute to a larger attack chain."
            )
        else:
            lines.append(
                "Business Impact: This finding represents a lower risk but "
                "should be addressed as part of defense-in-depth hardening."
            )

        return '\n'.join(lines)

    def _template_suggest_remediation(self, finding: dict) -> str:
        """Suggest remediation steps from the template knowledge base."""
        finding_type = finding.get('finding_type', 'unknown')
        title = finding.get('title', 'Unknown Finding')
        severity = finding.get('severity', 'UNKNOWN')
        existing_remediation = finding.get('remediation', '')

        steps = REMEDIATION_STEPS.get(finding_type, None)

        lines = [
            f"Remediation Plan: {title}",
            f"Priority: {severity}",
            "=" * 50,
            "",
        ]

        if steps:
            lines.append("Recommended Steps:")
            lines.append(steps)
        elif existing_remediation:
            lines.append("Recommended Steps:")
            lines.append(f"1. {existing_remediation}")
            lines.append("2. Verify the fix has been applied correctly")
            lines.append("3. Re-scan the affected asset to confirm remediation")
        else:
            lines.extend([
                "Recommended Steps:",
                "1. Research the specific vulnerability and vendor advisories",
                "2. Apply available patches or configuration changes",
                "3. Implement compensating controls if patching is not immediately possible",
                "4. Verify remediation through re-scanning",
                "5. Document the remediation actions taken",
            ])

        # Add urgency guidance
        lines.append("")
        if severity == 'CRITICAL':
            lines.append("Timeline: Remediate within 24 hours. Consider emergency change process.")
        elif severity == 'HIGH':
            lines.append("Timeline: Remediate within 7 days. Schedule priority maintenance window.")
        elif severity == 'MEDIUM':
            lines.append("Timeline: Remediate within 30 days during regular maintenance.")
        else:
            lines.append("Timeline: Address during next scheduled maintenance cycle.")

        lines.extend([
            "",
            "Verification:",
            "  - Re-run the security scan against the affected asset",
            "  - Confirm the finding no longer appears in results",
            "  - Document remediation actions for audit trail",
        ])

        return '\n'.join(lines)

    def _template_attack_narrative(self, findings: list) -> str:
        """Generate an attack narrative by grouping findings by asset."""
        if not findings:
            return "No findings to analyze for attack narrative."

        # Group findings by asset
        assets: Dict[str, List[dict]] = {}
        for f in findings:
            asset = f.get('affected_asset', 'Unknown')
            if asset not in assets:
                assets[asset] = []
            assets[asset].append(f)

        # Sort findings within each asset by severity
        for asset in assets:
            assets[asset].sort(
                key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'INFO'), 0),
                reverse=True
            )

        lines = [
            "ATTACK NARRATIVE ANALYSIS",
            "=" * 50,
            "",
            f"Scope: {len(findings)} findings across {len(assets)} asset(s)",
            "",
        ]

        # Identify entry points (critical/high findings)
        entry_points = [
            f for f in findings
            if f.get('severity') in ('CRITICAL', 'HIGH')
            and f.get('finding_type') in (
                'sql_injection', 'command_injection', 'default_credentials',
                'xss', 'path_traversal'
            )
        ]

        # Build narrative steps
        step = 0

        # Phase 1: Reconnaissance
        open_ports = [f for f in findings if f.get('finding_type') == 'open_port']
        info_findings = [f for f in findings if f.get('severity') == 'INFO']
        if open_ports or info_findings:
            step += 1
            lines.append(f"Phase {step}: Reconnaissance")
            lines.append("-" * 40)
            if open_ports:
                ports_desc = ', '.join(
                    f.get('title', 'open port') for f in open_ports[:5]
                )
                lines.append(f"  Attacker identifies exposed services: {ports_desc}")
            dir_listings = [f for f in findings if f.get('finding_type') == 'directory_listing']
            if dir_listings:
                lines.append("  Directory listing reveals internal file structure and potential targets")
            header_findings = [f for f in findings if f.get('finding_type') == 'missing_headers']
            if header_findings:
                lines.append("  Missing security headers indicate weak application hardening")
            lines.append("")

        # Phase 2: Initial Access
        if entry_points:
            step += 1
            lines.append(f"Phase {step}: Initial Access")
            lines.append("-" * 40)
            for ep in entry_points:
                lines.append(
                    f"  Exploit {ep.get('title', 'vulnerability')} on "
                    f"{ep.get('affected_asset', 'target')} "
                    f"(CVSS {ep.get('cvss_score', 'N/A')})"
                )
                if ep.get('finding_type') == 'sql_injection':
                    lines.append("  -> Extract database credentials and user data")
                elif ep.get('finding_type') == 'command_injection':
                    lines.append("  -> Achieve remote code execution on the server")
                elif ep.get('finding_type') == 'default_credentials':
                    lines.append("  -> Log in with factory credentials for administrative access")
            lines.append("")

        # Phase 3: Escalation / Lateral Movement
        ssl_findings = [f for f in findings if 'ssl' in f.get('finding_type', '')]
        smb_findings = [f for f in findings if 'smb' in f.get('finding_type', '')]
        snmp_findings = [f for f in findings if 'snmp' in f.get('finding_type', '')]
        lateral_findings = ssl_findings + smb_findings + snmp_findings
        if lateral_findings and len(assets) > 1:
            step += 1
            lines.append(f"Phase {step}: Lateral Movement")
            lines.append("-" * 40)
            if smb_findings:
                lines.append("  Exploit disabled SMB signing to relay credentials across the network")
            if snmp_findings:
                lines.append("  Use SNMP with default community strings to map network topology")
            if ssl_findings:
                lines.append("  Intercept traffic through weak SSL/TLS to capture credentials")
            lines.append(f"  Pivot across {len(assets)} identified assets")
            lines.append("")

        # Phase 4: Impact
        if findings:
            step += 1
            lines.append(f"Phase {step}: Impact")
            lines.append("-" * 40)
            critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
            kev_findings = [
                f for f in findings
                if str(f.get('kev_status', '')).lower() in ('true', '1', 'yes')
            ]
            if critical_count > 0:
                lines.append(f"  {critical_count} critical vulnerability/vulnerabilities enable full system compromise")
            if kev_findings:
                lines.append(
                    f"  {len(kev_findings)} finding(s) are in CISA KEV "
                    f"(known actively exploited in the wild)"
                )
            lines.append("  Potential outcomes: data exfiltration, ransomware deployment, "
                         "service disruption")
            lines.append("")

        # If no clear attack chain
        if step == 0:
            lines.append("No high-severity attack chain identified from current findings.")
            lines.append("Individual findings should still be remediated to reduce attack surface.")
            lines.append("")

        # Multi-asset risk
        if len(assets) > 1:
            lines.append("Multi-Asset Risk:")
            for asset, asset_findings in assets.items():
                sev_counts = {}
                for f in asset_findings:
                    s = f.get('severity', 'INFO')
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                sev_str = ', '.join(f"{v} {k}" for k, v in sorted(
                    sev_counts.items(),
                    key=lambda x: SEVERITY_ORDER.get(x[0], 0),
                    reverse=True
                ))
                lines.append(f"  {asset}: {sev_str}")

        return '\n'.join(lines)

    def _template_prioritize(self, findings: list) -> list:
        """
        Prioritize findings using a weighted scoring formula.

        Score = effective_priority * 1.0 + (kev_bonus * 2.0) + (epss * 1.5)
        Where kev_bonus = 1.0 if in KEV, 0.0 otherwise.
        """
        if not findings:
            return []

        scored = []
        for f in findings:
            effective_priority = float(f.get('effective_priority', 0.0))
            epss = float(f.get('epss_score', 0.0))
            kev = str(f.get('kev_status', '')).lower() in ('true', '1', 'yes')
            cvss = float(f.get('cvss_score', 0.0))

            kev_bonus = 1.0 if kev else 0.0
            score = (effective_priority * 1.0) + (kev_bonus * 2.0) + (epss * 1.5)

            # Build reasoning
            reasons = []
            severity = f.get('severity', 'UNKNOWN')
            reasons.append(f"Severity: {severity} (CVSS {cvss:.1f})")

            if kev:
                reasons.append("CISA KEV: actively exploited in the wild")
            if epss >= 0.7:
                reasons.append(f"High exploit probability (EPSS {epss:.0%})")
            elif epss >= 0.3:
                reasons.append(f"Moderate exploit probability (EPSS {epss:.0%})")

            if effective_priority >= 8.0:
                reasons.append("Very high effective priority")
            elif effective_priority >= 6.0:
                reasons.append("High effective priority")

            scored.append({
                'finding': f,
                'score': score,
                'reasoning': '; '.join(reasons),
            })

        # Sort by score descending
        scored.sort(key=lambda x: x['score'], reverse=True)

        # Assign ranks
        result = []
        for rank, item in enumerate(scored, start=1):
            result.append({
                'finding': item['finding'],
                'rank': rank,
                'reasoning': item['reasoning'],
            })

        return result

    def __repr__(self) -> str:
        return (
            f"AIAnalyzer(provider='{self.provider}', "
            f"model={self.model!r}, "
            f"sanitize_external={self.sanitize_external})"
        )


if __name__ == '__main__':
    # Test template backend (always works)
    ai = AIAnalyzer(provider='template')
    print("AI Analyzer initialized (template backend)")

    sample_findings = [
        {'severity': 'CRITICAL', 'title': 'SQL Injection', 'cvss_score': 9.8, 'affected_asset': '10.0.0.1',
         'finding_type': 'sql_injection', 'cve_ids': ['CVE-2024-1234'], 'epss_score': 0.9, 'kev_status': 'true',
         'effective_priority': 9.5, 'remediation': 'Use parameterized queries'},
        {'severity': 'HIGH', 'title': 'Weak SSL/TLS', 'cvss_score': 7.5, 'affected_asset': '10.0.0.2',
         'finding_type': 'ssl_weak_cipher', 'cve_ids': [], 'epss_score': 0.1, 'kev_status': None,
         'effective_priority': 6.0, 'remediation': 'Update cipher suite'},
        {'severity': 'MEDIUM', 'title': 'Missing Security Headers', 'cvss_score': 5.0, 'affected_asset': '10.0.0.1',
         'finding_type': 'missing_headers', 'cve_ids': [], 'epss_score': 0.05, 'kev_status': None,
         'effective_priority': 4.0, 'remediation': 'Add security headers'},
    ]

    sample_results = {
        'session_id': 'SESSION-TEST',
        'summary': {
            'total_findings': 3,
            'findings_by_severity': {'CRITICAL': 1, 'HIGH': 1, 'MEDIUM': 1, 'LOW': 0, 'INFO': 0},
            'total_hosts_scanned': 2,
            'compliance_rate': 75.0,
        }
    }

    print("\n--- Executive Summary ---")
    print(ai.generate_executive_summary(sample_results))

    print("\n--- Finding Explanation ---")
    print(ai.explain_finding(sample_findings[0]))

    print("\n--- Remediation ---")
    print(ai.suggest_remediation(sample_findings[0]))

    print("\n--- Attack Narrative ---")
    print(ai.generate_attack_narrative(sample_findings))

    print("\n--- Prioritized Findings ---")
    prioritized = ai.prioritize_findings(sample_findings)
    for p in prioritized:
        print(f"  #{p['rank']}: {p['finding']['title']} - {p['reasoning']}")

    # Test sanitization
    ai_ext = AIAnalyzer(provider='template', sanitize_external=True)
    test_data = "Server 192.168.1.100 (web-server.corp.example.com) has CVE-2024-1234"
    sanitized = ai_ext._sanitize_for_external(test_data)
    print(f"\nSanitization test:")
    print(f"  Original:  {test_data}")
    print(f"  Sanitized: {sanitized}")
