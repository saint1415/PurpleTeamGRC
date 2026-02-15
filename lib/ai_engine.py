#!/usr/bin/env python3
"""
Purple Team GRC Platform - AI Engine

Unified AI backend that auto-detects the best available provider:
  1. Local Ollama instance   (air-gapped friendly, full data stays local)
  2. Step 3.5 Flash          (via STEPFUN_API_KEY -- 196B MoE, 11B active, fast)
  3. Anthropic Claude API    (via ANTHROPIC_API_KEY env var)
  4. Google Gemini API       (via GEMINI_API_KEY env var -- fast & cheap)
  5. OpenAI-compatible API   (via OPENAI_API_KEY env var)
  6. Template fallback       (pure-Python, always available, no LLM needed)

All LLM-generated output is tagged for human review.
Only stdlib imports are used for HTTP calls (urllib).
"""

import json
import os
import logging
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Dict, List, Optional
from datetime import datetime

# ---------------------------------------------------------------------------
# Internal imports (relative / absolute fallback pattern)
# ---------------------------------------------------------------------------
try:
    from .paths import paths
except ImportError:
    try:
        from paths import paths
    except ImportError:
        paths = None

try:
    from .ai_prompts import (
        SYSTEM_PROMPT,
        FINDING_ANALYSIS_PROMPT,
        TRIAGE_PROMPT,
        REMEDIATION_PROMPT,
        SCAN_SUMMARY_PROMPT,
        QUERY_PROMPT,
        MODELFILE_TEMPLATE,
    )
except ImportError:
    try:
        from ai_prompts import (
            SYSTEM_PROMPT,
            FINDING_ANALYSIS_PROMPT,
            TRIAGE_PROMPT,
            REMEDIATION_PROMPT,
            SCAN_SUMMARY_PROMPT,
            QUERY_PROMPT,
            MODELFILE_TEMPLATE,
        )
    except ImportError:
        # Minimal fallback if ai_prompts is missing entirely
        SYSTEM_PROMPT = "You are a cybersecurity analyst."
        FINDING_ANALYSIS_PROMPT = "Analyze this finding:\n{finding_json}"
        TRIAGE_PROMPT = "Prioritize these findings:\n{findings_json}"
        REMEDIATION_PROMPT = "Provide remediation for:\n{finding_json}"
        SCAN_SUMMARY_PROMPT = "Summarize this scan:\n{scan_data_json}"
        QUERY_PROMPT = "Question: {question}\nContext: {context_json}"
        MODELFILE_TEMPLATE = "FROM {base_model}\nSYSTEM \"You are a cybersecurity analyst.\""

try:
    from .logger import get_logger
except ImportError:
    try:
        from logger import get_logger
    except ImportError:
        get_logger = None

if get_logger is not None:
    logger = get_logger('ai_engine')
else:
    logger = logging.getLogger('ai_engine')
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AI_DISCLAIMER = "\n--- AI-Generated - Verify Before Acting ---\n"

OLLAMA_BASE_URL = "http://localhost:11434"
STEPFUN_API_URL = "https://api.stepfun.ai/v1/chat/completions"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# Model preference order when scanning Ollama for available models
_OLLAMA_MODEL_PREFERENCE = [
    'step-3.5-flash', 'purpleteam-security',
    'llama3.2', 'llama3.1', 'llama3', 'mistral', 'codellama',
    'mixtral', 'phi3', 'gemma2', 'deepseek-coder', 'qwen2',
]

# Severity helpers for template fallback
_SEVERITY_ORDER = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
_SLA_MAP = {
    'CRITICAL': 'IMMEDIATE (24h)',
    'HIGH': 'URGENT (7d)',
    'MEDIUM': 'STANDARD (30d)',
    'LOW': 'PLANNED (90d)',
    'INFO': 'PLANNED (90d)',
}


class AIEngine:
    """
    Unified AI analysis engine for the Purple Team GRC Platform.

    Auto-detects the best available backend on initialisation and exposes
    high-level analysis methods.  Every method has a template fallback that
    produces structured output without any LLM, so the platform always
    functions even in fully air-gapped environments.
    """

    def __init__(self):
        self.backend: str = 'template'
        self.model_name: Optional[str] = None
        self._detect_backend()
        logger.info(
            "AIEngine initialised: backend=%s, model=%s",
            self.backend, self.model_name,
        )

    # ------------------------------------------------------------------
    # Backend detection
    # ------------------------------------------------------------------

    def _detect_backend(self) -> None:
        """
        Probe available AI backends in priority order.

        1. Local Ollama instance (best for air-gapped / privacy).
        2. Anthropic Claude API  (ANTHROPIC_API_KEY).
        3. OpenAI-compatible API (OPENAI_API_KEY).
        4. Template fallback     (always available).
        """
        # 1. Ollama
        try:
            req = urllib.request.Request(
                f"{OLLAMA_BASE_URL}/api/tags",
                headers={'User-Agent': 'PurpleTeamGRC/1.0'},
                method='GET',
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                models = [m.get('name', '') for m in data.get('models', [])]
                if models:
                    self.backend = 'ollama'
                    self.model_name = self._pick_best_ollama_model(models)
                    return
        except Exception:
            pass

        # 2. StepFun Step 3.5 Flash (196B MoE, 11B active, fast agentic model)
        if os.environ.get('STEPFUN_API_KEY'):
            self.backend = 'stepfun'
            self.model_name = 'step-3.5-flash'
            return

        # 3. Anthropic
        if os.environ.get('ANTHROPIC_API_KEY'):
            self.backend = 'anthropic'
            self.model_name = 'claude-sonnet-4-20250514'
            return

        # 4. Google Gemini (fast, cheap, generous free tier)
        if os.environ.get('GEMINI_API_KEY'):
            self.backend = 'gemini'
            self.model_name = 'gemini-2.5-flash'
            return

        # 5. OpenAI
        if os.environ.get('OPENAI_API_KEY'):
            self.backend = 'openai'
            self.model_name = 'gpt-4'
            return

        # 6. Fallback
        self.backend = 'template'
        self.model_name = None

    @staticmethod
    def _pick_best_ollama_model(available: List[str]) -> str:
        """Choose the best Ollama model from the available list."""
        # Strip tag suffixes for matching (e.g. "llama3:latest" -> "llama3")
        normalised = {m.split(':')[0].lower(): m for m in available}
        for preferred in _OLLAMA_MODEL_PREFERENCE:
            if preferred in normalised:
                return normalised[preferred]
        # Fall back to whatever is first
        return available[0] if available else 'mistral'

    # ------------------------------------------------------------------
    # Low-level backend calls
    # ------------------------------------------------------------------

    def _call_ollama(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to the local Ollama /api/generate endpoint (streaming)."""
        url = f"{OLLAMA_BASE_URL}/api/generate"
        payload = {
            'model': self.model_name,
            'prompt': prompt,
            'stream': True,
            'options': {
                'temperature': 0.3,
                'num_predict': 2048,
            },
        }
        if system_prompt:
            payload['system'] = system_prompt

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'PurpleTeamGRC/1.0',
            },
            method='POST',
        )

        chunks: List[str] = []
        with urllib.request.urlopen(req, timeout=180) as resp:
            for line in resp:
                if not line:
                    continue
                try:
                    obj = json.loads(line.decode('utf-8'))
                    token = obj.get('response', '')
                    if token:
                        chunks.append(token)
                    if obj.get('done', False):
                        break
                except json.JSONDecodeError:
                    continue

        return ''.join(chunks).strip()

    def _call_anthropic(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to the Anthropic Messages API using stdlib urllib."""
        api_key = os.environ.get('ANTHROPIC_API_KEY', '')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

        payload = {
            'model': self.model_name or 'claude-sonnet-4-20250514',
            'max_tokens': 2048,
            'messages': [
                {'role': 'user', 'content': prompt},
            ],
        }
        if system_prompt:
            payload['system'] = system_prompt

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            ANTHROPIC_API_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
                'User-Agent': 'PurpleTeamGRC/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        content_blocks = result.get('content', [])
        texts = [b.get('text', '') for b in content_blocks if b.get('type') == 'text']
        return '\n'.join(texts).strip()

    def _call_stepfun(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to StepFun Step 3.5 Flash API (OpenAI-compatible format).

        Step 3.5 Flash: 196B-parameter sparse MoE with 11B active params.
        Excels at coding (86.4% LiveCodeBench), math, agent tasks, and
        tool use.  100-350 tok/s throughput via Multi-Token Prediction.

        Providers:
          - StepFun direct: STEPFUN_API_KEY + https://api.stepfun.ai/v1
          - OpenRouter:     OPENROUTER_API_KEY (free tier available)
        """
        # Support OpenRouter as fallback provider
        api_key = os.environ.get('STEPFUN_API_KEY', '')
        url = STEPFUN_API_URL
        model = self.model_name or 'step-3.5-flash'

        if not api_key and os.environ.get('OPENROUTER_API_KEY'):
            api_key = os.environ['OPENROUTER_API_KEY']
            url = 'https://openrouter.ai/api/v1/chat/completions'
            model = 'stepfun/step-3.5-flash'

        if not api_key:
            raise ValueError("STEPFUN_API_KEY (or OPENROUTER_API_KEY) not set")

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': prompt})

        payload = {
            'model': model,
            'messages': messages,
            'temperature': 0.3,
            'max_tokens': 2048,
        }

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}',
                'User-Agent': 'PurpleTeamGRC/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        choices = result.get('choices', [])
        if choices:
            return choices[0].get('message', {}).get('content', '').strip()
        return ''

    def _call_gemini(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to the Google Gemini generateContent endpoint (stdlib only).

        Uses the v1beta REST API with an API key query parameter.
        Supports Gemini 2.5 Flash (fast, 1M context, free tier: 500 req/day).
        """
        api_key = os.environ.get('GEMINI_API_KEY', '')
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")

        model = self.model_name or 'gemini-2.5-flash'
        url = f"{GEMINI_API_URL}/{model}:generateContent?key={api_key}"

        # Build Gemini-format request
        contents: List[Dict] = []
        if system_prompt:
            contents.append({
                'role': 'user',
                'parts': [{'text': f"[System Instructions]\n{system_prompt}\n\n[User Query]\n{prompt}"}],
            })
        else:
            contents.append({
                'role': 'user',
                'parts': [{'text': prompt}],
            })

        payload = {
            'contents': contents,
            'generationConfig': {
                'temperature': 0.3,
                'maxOutputTokens': 2048,
            },
        }

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'PurpleTeamGRC/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        # Parse Gemini response format
        candidates = result.get('candidates', [])
        if candidates:
            content = candidates[0].get('content', {})
            parts = content.get('parts', [])
            texts = [p.get('text', '') for p in parts if 'text' in p]
            return '\n'.join(texts).strip()
        return ''

    def _call_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to an OpenAI-compatible chat completions endpoint."""
        api_key = os.environ.get('OPENAI_API_KEY', '')
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set")

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': prompt})

        payload = {
            'model': self.model_name or 'gpt-4',
            'messages': messages,
            'temperature': 0.3,
            'max_tokens': 2048,
        }

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            OPENAI_API_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}',
                'User-Agent': 'PurpleTeamGRC/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        choices = result.get('choices', [])
        if choices:
            return choices[0].get('message', {}).get('content', '').strip()
        return ''

    def _call_ai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Route to the detected backend and return the raw text response."""
        if self.backend == 'ollama':
            return self._call_ollama(prompt, system_prompt)
        elif self.backend == 'stepfun':
            return self._call_stepfun(prompt, system_prompt)
        elif self.backend == 'anthropic':
            return self._call_anthropic(prompt, system_prompt)
        elif self.backend == 'gemini':
            return self._call_gemini(prompt, system_prompt)
        elif self.backend == 'openai':
            return self._call_openai(prompt, system_prompt)
        return ''

    # ------------------------------------------------------------------
    # JSON extraction helper
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Try to extract a JSON object or array from raw LLM output."""
        if not text:
            return None
        # Strip markdown fences if present
        cleaned = text.strip()
        if cleaned.startswith('```'):
            lines = cleaned.split('\n')
            lines = [l for l in lines if not l.strip().startswith('```')]
            cleaned = '\n'.join(lines).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        # Try to find first { or [ and last } or ]
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            start = cleaned.find(start_char)
            end = cleaned.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(cleaned[start:end + 1])
                except json.JSONDecodeError:
                    continue
        return None

    # ------------------------------------------------------------------
    # High-level analysis methods
    # ------------------------------------------------------------------

    def analyze_finding(self, finding: Dict) -> Dict:
        """
        Analyse a single security finding.

        Returns a dict with keys: severity_validated, exploit_likelihood,
        business_impact, attack_vector, mitre_techniques, confidence, notes.
        Falls back to template analysis if no LLM is available.
        """
        if self.backend == 'template':
            return self._template_analyze_finding(finding)

        finding_json = json.dumps(finding, indent=2, default=str)
        prompt = FINDING_ANALYSIS_PROMPT.format(finding_json=finding_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            parsed = self._extract_json(raw)
            if isinstance(parsed, dict):
                parsed['_ai_generated'] = True
                parsed['_backend'] = self.backend
                parsed['_disclaimer'] = AI_DISCLAIMER.strip()
                return parsed
        except Exception as exc:
            logger.warning("AI finding analysis failed (%s), using template: %s", self.backend, exc)

        return self._template_analyze_finding(finding)

    def triage_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Prioritise a batch of findings from most to least urgent.

        Returns a list of dicts with keys: title, rank, reasoning,
        recommended_sla.
        """
        if self.backend == 'template':
            return self._template_triage_findings(findings)

        findings_json = json.dumps(findings, indent=2, default=str)
        prompt = TRIAGE_PROMPT.format(findings_json=findings_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            parsed = self._extract_json(raw)
            if isinstance(parsed, list) and parsed:
                for item in parsed:
                    item['_ai_generated'] = True
                return parsed
        except Exception as exc:
            logger.warning("AI triage failed (%s), using template: %s", self.backend, exc)

        return self._template_triage_findings(findings)

    def generate_remediation(self, finding: Dict) -> str:
        """
        Generate step-by-step remediation instructions.

        Returns a formatted string (or JSON string when AI-generated).
        """
        if self.backend == 'template':
            return self._template_generate_remediation(finding)

        finding_json = json.dumps(finding, indent=2, default=str)
        prompt = REMEDIATION_PROMPT.format(finding_json=finding_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            if raw:
                return AI_DISCLAIMER + raw
        except Exception as exc:
            logger.warning("AI remediation failed (%s), using template: %s", self.backend, exc)

        return self._template_generate_remediation(finding)

    def summarize_scan(self, session_id: str) -> str:
        """
        Generate an executive-friendly summary for a scan session.

        Pulls scan data from the evidence manager when available.
        """
        scan_data = self._load_scan_data(session_id)
        if not scan_data:
            return f"No scan data found for session {session_id}."

        if self.backend == 'template':
            return self._template_summarize_scan(scan_data)

        scan_data_json = json.dumps(scan_data, indent=2, default=str)
        prompt = SCAN_SUMMARY_PROMPT.format(scan_data_json=scan_data_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            if raw:
                return AI_DISCLAIMER + raw
        except Exception as exc:
            logger.warning("AI scan summary failed (%s), using template: %s", self.backend, exc)

        return self._template_summarize_scan(scan_data)

    def query(self, question: str, context: Optional[Dict] = None) -> str:
        """
        Answer a natural-language question, optionally with scan context.
        """
        if self.backend == 'template':
            return self._template_query(question, context)

        context_json = json.dumps(context or {}, indent=2, default=str)
        prompt = QUERY_PROMPT.format(question=question, context_json=context_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            if raw:
                return AI_DISCLAIMER + raw
        except Exception as exc:
            logger.warning("AI query failed (%s), using template: %s", self.backend, exc)

        return self._template_query(question, context)

    # ------------------------------------------------------------------
    # Scan data loader
    # ------------------------------------------------------------------

    def _load_scan_data(self, session_id: str) -> Optional[Dict]:
        """Load scan session data from the evidence manager."""
        try:
            try:
                from .evidence import get_evidence_manager
            except ImportError:
                from evidence import get_evidence_manager

            em = get_evidence_manager()
            summary = em.get_session_summary(session_id)
            if not summary:
                return None

            findings = em.get_findings_for_session(session_id)
            return {
                'session_id': session_id,
                'session': summary.get('session', {}),
                'evidence_count': summary.get('evidence_count', 0),
                'findings_by_severity': summary.get('findings_by_severity', {}),
                'findings': findings,
                'total_findings': len(findings),
            }
        except Exception as exc:
            logger.debug("Could not load scan data for %s: %s", session_id, exc)
            return None

    # ------------------------------------------------------------------
    # Template fallback implementations
    # ------------------------------------------------------------------

    def _template_analyze_finding(self, finding: Dict) -> Dict:
        """Rule-based finding analysis (no LLM required)."""
        severity = finding.get('severity', 'MEDIUM').upper()
        cvss = float(finding.get('cvss_score', 0.0))
        epss = float(finding.get('epss_score', 0.0))
        kev = str(finding.get('kev_status', '')).lower() in ('true', '1', 'yes')
        finding_type = finding.get('finding_type', 'unknown')

        # Validate severity against CVSS
        if cvss >= 9.0:
            validated = 'CRITICAL'
        elif cvss >= 7.0:
            validated = 'HIGH'
        elif cvss >= 4.0:
            validated = 'MEDIUM'
        elif cvss > 0:
            validated = 'LOW'
        else:
            validated = severity

        # Exploit likelihood
        if kev:
            exploit_likelihood = 'CONFIRMED'
        elif epss >= 0.7:
            exploit_likelihood = 'HIGH'
        elif epss >= 0.3:
            exploit_likelihood = 'MEDIUM'
        elif epss >= 0.1:
            exploit_likelihood = 'LOW'
        else:
            exploit_likelihood = 'THEORETICAL'

        # Business impact
        impact_map = {
            'CRITICAL': (
                "Exploitation could result in complete system compromise, "
                "data breach, or significant service disruption."
            ),
            'HIGH': (
                "Exploitation could lead to unauthorized data access, "
                "privilege escalation, or partial service compromise."
            ),
            'MEDIUM': (
                "Exploitation could contribute to a broader attack chain "
                "or expose limited sensitive information."
            ),
            'LOW': (
                "Minimal direct business impact, but contributes to overall "
                "attack surface."
            ),
            'INFO': "Informational finding with no direct exploitable risk.",
        }

        return {
            'severity_validated': validated,
            'exploit_likelihood': exploit_likelihood,
            'business_impact': impact_map.get(validated, impact_map['MEDIUM']),
            'attack_vector': f"Exploitation of {finding_type} on "
                             f"{finding.get('affected_asset', 'target asset')}",
            'mitre_techniques': [],
            'confidence': 0.6,
            'notes': f"Template-based analysis (no LLM). CVSS={cvss}, EPSS={epss:.2f}, KEV={kev}.",
            '_ai_generated': False,
            '_backend': 'template',
        }

    def _template_triage_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by severity/CVSS/EPSS without an LLM."""
        if not findings:
            return []

        def _score(f: Dict) -> float:
            sev_val = _SEVERITY_ORDER.get(f.get('severity', 'INFO').upper(), 1)
            cvss = float(f.get('cvss_score', 0.0))
            epss = float(f.get('epss_score', 0.0))
            kev = 2.0 if str(f.get('kev_status', '')).lower() in ('true', '1', 'yes') else 0.0
            return sev_val * 2.0 + cvss + epss * 1.5 + kev

        scored = sorted(findings, key=_score, reverse=True)
        result = []
        for rank, f in enumerate(scored, start=1):
            severity = f.get('severity', 'MEDIUM').upper()
            result.append({
                'title': f.get('title', 'Unknown'),
                'rank': rank,
                'reasoning': (
                    f"Severity {severity}, CVSS {f.get('cvss_score', 0.0)}, "
                    f"EPSS {f.get('epss_score', 0.0):.2f}"
                ),
                'recommended_sla': _SLA_MAP.get(severity, 'STANDARD (30d)'),
                '_ai_generated': False,
            })
        return result

    def _template_generate_remediation(self, finding: Dict) -> str:
        """Generate basic remediation steps from finding metadata."""
        title = finding.get('title', 'Unknown Finding')
        severity = finding.get('severity', 'MEDIUM').upper()
        finding_type = finding.get('finding_type', 'unknown')
        existing = finding.get('remediation', '')

        lines = [
            f"Remediation Plan: {title}",
            f"Priority: {severity}",
            "=" * 55,
            "",
        ]

        if existing:
            lines.append("Recommended Steps:")
            lines.append(f"  1. {existing}")
            lines.append("  2. Validate the fix in a staging environment")
            lines.append("  3. Apply the fix in production during a maintenance window")
            lines.append("  4. Re-scan the affected asset to confirm remediation")
            lines.append("  5. Document the change for audit trail")
        else:
            lines.append("Recommended Steps:")
            lines.append("  1. Research the specific vulnerability and vendor advisories")
            lines.append("  2. Apply available patches or configuration changes")
            lines.append("  3. Implement compensating controls if immediate patching is not feasible")
            lines.append("  4. Test the fix in a non-production environment first")
            lines.append("  5. Re-scan to verify remediation effectiveness")
            lines.append("  6. Document all actions taken for compliance records")

        lines.append("")
        sla = _SLA_MAP.get(severity, 'STANDARD (30d)')
        lines.append(f"Target SLA: {sla}")

        lines.extend([
            "",
            "Verification:",
            "  - Re-run the security scan against the affected asset",
            "  - Confirm the finding no longer appears in results",
            "  - Document remediation actions for audit trail",
        ])

        return '\n'.join(lines)

    def _template_summarize_scan(self, scan_data: Dict) -> str:
        """Generate a structured executive summary without any LLM."""
        by_sev = scan_data.get('findings_by_severity', {})
        total = scan_data.get('total_findings', 0)
        session_id = scan_data.get('session_id', 'UNKNOWN')

        critical = by_sev.get('CRITICAL', 0)
        high = by_sev.get('HIGH', 0)
        medium = by_sev.get('MEDIUM', 0)
        low = by_sev.get('LOW', 0)
        info = by_sev.get('INFO', 0)

        if critical > 0:
            posture = "CRITICAL"
            headline = "Critical vulnerabilities require immediate attention."
        elif high > 0:
            posture = "HIGH"
            headline = "Significant risks detected requiring prompt remediation."
        elif medium > 0:
            posture = "MODERATE"
            headline = "Moderate risks identified; remediation recommended within 30 days."
        elif low > 0:
            posture = "LOW"
            headline = "Minor issues found; address during normal maintenance."
        else:
            posture = "MINIMAL"
            headline = "No significant vulnerabilities identified."

        lines = [
            f"EXECUTIVE SUMMARY - Session {session_id}",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "=" * 60,
            "",
            f"Risk Posture: {posture}",
            f"  {headline}",
            "",
            "Findings:",
            f"  Total:          {total}",
            f"  Critical:       {critical}",
            f"  High:           {high}",
            f"  Medium:         {medium}",
            f"  Low:            {low}",
            f"  Informational:  {info}",
            "",
        ]

        if critical > 0 or high > 0:
            lines.append("Priority Actions:")
            if critical > 0:
                lines.append(f"  - Address {critical} CRITICAL finding(s) within 24 hours")
            if high > 0:
                lines.append(f"  - Remediate {high} HIGH finding(s) within 7 days")
            if medium > 0:
                lines.append(f"  - Plan remediation for {medium} MEDIUM finding(s)")
            lines.append("")

        lines.append("(Template-generated summary - no AI backend available)")
        return '\n'.join(lines)

    def _template_query(self, question: str, context: Optional[Dict] = None) -> str:
        """Provide a basic response when no LLM is available."""
        lines = [
            "AI query engine is running in template mode (no LLM backend detected).",
            "",
            f"Your question: {question}",
            "",
        ]

        if context:
            findings = context.get('findings', [])
            if findings:
                lines.append(f"Context contains {len(findings)} finding(s).")
                severities: Dict[str, int] = {}
                for f in findings:
                    s = f.get('severity', 'UNKNOWN')
                    severities[s] = severities.get(s, 0) + 1
                lines.append("Severity breakdown:")
                for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
                    count = severities.get(sev, 0)
                    if count:
                        lines.append(f"  {sev}: {count}")
                lines.append("")

        lines.extend([
            "To enable AI-powered answers, configure one of:",
            "  1. Install Ollama locally with Step 3.5 Flash (air-gapped, recommended)",
            "  2. Set STEPFUN_API_KEY for Step 3.5 Flash cloud API",
            "  3. Set ANTHROPIC_API_KEY for Anthropic Claude",
            "  4. Set GEMINI_API_KEY for Google Gemini (fast & free tier)",
            "  5. Set OPENAI_API_KEY for OpenAI GPT-4",
        ])
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_status(self) -> Dict:
        """Return current engine status for diagnostics."""
        return {
            'backend': self.backend,
            'model_name': self.model_name,
            'ai_available': self.backend != 'template',
            'timestamp': datetime.utcnow().isoformat(),
        }

    def __repr__(self) -> str:
        return f"AIEngine(backend='{self.backend}', model={self.model_name!r})"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_ai_engine: Optional[AIEngine] = None


def get_ai_engine() -> AIEngine:
    """Get the singleton AIEngine instance."""
    global _ai_engine
    if _ai_engine is None:
        _ai_engine = AIEngine()
    return _ai_engine


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    engine = get_ai_engine()
    print(f"AI Engine: {engine}")
    print(f"Status: {json.dumps(engine.get_status(), indent=2)}")

    sample_finding = {
        'title': 'SQL Injection in Login Form',
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'epss_score': 0.92,
        'kev_status': 'true',
        'finding_type': 'sql_injection',
        'affected_asset': '10.0.0.5',
        'description': 'Unsanitized user input in login POST parameter allows SQL injection.',
        'remediation': 'Use parameterized queries for all database operations.',
    }

    print("\n--- Finding Analysis ---")
    analysis = engine.analyze_finding(sample_finding)
    print(json.dumps(analysis, indent=2))

    print("\n--- Remediation ---")
    remediation = engine.generate_remediation(sample_finding)
    print(remediation)

    print("\n--- Triage ---")
    triaged = engine.triage_findings([sample_finding])
    print(json.dumps(triaged, indent=2))

    print("\n--- Query ---")
    answer = engine.query("What is the most critical finding?", {'findings': [sample_finding]})
    print(answer)
