#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - CI/CD Integration
Generate pipeline configs, SARIF reports, and security gates.
Supports GitHub Actions, GitLab CI, Jenkins.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('cicd_integration')


class CICDIntegrator:
    """CI/CD integration for automated security scanning pipelines."""

    _instance: Optional['CICDIntegrator'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.reports_dir = paths.reports
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        logger.info("CI/CD Integrator initialized")

    def generate_github_actions(self, scan_type: str = 'quick',
                                fail_on: str = 'critical') -> str:
        """Generate a complete GitHub Actions workflow YAML.

        Args:
            scan_type: Type of scan to run (quick, full, compliance).
            fail_on: Minimum severity to fail the build (critical, high, medium, low).

        Returns:
            Complete GitHub Actions YAML workflow as a string.
        """
        workflow = (
            "name: Purple Team Security Scan\n"
            "\n"
            "on: [push, pull_request]\n"
            "\n"
            "permissions:\n"
            "  security-events: write\n"
            "  contents: read\n"
            "\n"
            "jobs:\n"
            "  security-scan:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Checkout repository\n"
            "        uses: actions/checkout@v4\n"
            "\n"
            "      - name: Setup Python\n"
            "        uses: actions/setup-python@v5\n"
            "        with:\n"
            "          python-version: '3.11'\n"
            "\n"
            "      - name: Install dependencies\n"
            "        run: |\n"
            "          python3 -m pip install --upgrade pip\n"
            "          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n"
            "\n"
            f"      - name: Run Security Scan ({scan_type})\n"
            f"        run: python3 bin/purple-launcher {scan_type}\n"
            "\n"
            "      - name: Export SARIF results\n"
            "        if: always()\n"
            "        run: python3 -c \"\n"
            "          from lib.cicd_integration import get_cicd_integrator;\n"
            "          import json;\n"
            "          ci = get_cicd_integrator();\n"
            "          findings = json.load(open('data/reports/latest_findings.json')) if __import__('pathlib').Path('data/reports/latest_findings.json').exists() else [];\n"
            "          ci.export_sarif(findings)\n"
            "          \"\n"
            "\n"
            "      - name: Upload SARIF to GitHub Security\n"
            "        if: always()\n"
            "        uses: github/codeql-action/upload-sarif@v3\n"
            "        with:\n"
            "          sarif_file: data/reports/results.sarif\n"
            "\n"
            f"      - name: Evaluate Security Gate (fail on {fail_on})\n"
            "        run: python3 -c \"\n"
            "          from lib.cicd_integration import get_cicd_integrator;\n"
            "          import json, sys;\n"
            "          ci = get_cicd_integrator();\n"
            "          findings = json.load(open('data/reports/latest_findings.json')) if __import__('pathlib').Path('data/reports/latest_findings.json').exists() else [];\n"
            f"          gate = ci.evaluate_security_gate(findings, {{'fail_on': '{fail_on}'}});\n"
            "          print('Security Gate:', 'PASSED' if gate['passed'] else 'FAILED');\n"
            "          print('Reason:', gate['reason']);\n"
            "          sys.exit(gate['exit_code'])\n"
            "          \"\n"
        )
        return workflow

    def generate_gitlab_ci(self, scan_type: str = 'quick',
                           fail_on: str = 'critical') -> str:
        """Generate a complete .gitlab-ci.yml configuration.

        Args:
            scan_type: Type of scan to run (quick, full, compliance).
            fail_on: Minimum severity to fail the build.

        Returns:
            Complete GitLab CI YAML content as a string.
        """
        config = (
            "stages:\n"
            "  - security\n"
            "\n"
            "security-scan:\n"
            "  stage: security\n"
            "  image: python:3.11-slim\n"
            "  before_script:\n"
            "    - pip install --upgrade pip\n"
            "    - if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n"
            "  script:\n"
            f"    - python3 bin/purple-launcher {scan_type}\n"
            "    - python3 -c \"\n"
            "      from lib.cicd_integration import get_cicd_integrator;\n"
            "      import json, sys;\n"
            "      ci = get_cicd_integrator();\n"
            "      findings = json.load(open('data/reports/latest_findings.json')) if __import__('pathlib').Path('data/reports/latest_findings.json').exists() else [];\n"
            "      ci.export_sarif(findings);\n"
            f"      gate = ci.evaluate_security_gate(findings, {{'fail_on': '{fail_on}'}});\n"
            "      print('Security Gate:', 'PASSED' if gate['passed'] else 'FAILED');\n"
            "      print('Reason:', gate['reason']);\n"
            "      sys.exit(gate['exit_code'])\n"
            "      \"\n"
            "  artifacts:\n"
            "    paths:\n"
            "      - data/reports/\n"
            "    reports:\n"
            "      sast: data/reports/results.sarif\n"
            "    when: always\n"
            "    expire_in: 30 days\n"
            "  allow_failure: false\n"
        )
        return config

    def generate_jenkins_pipeline(self, scan_type: str = 'quick',
                                  fail_on: str = 'critical') -> str:
        """Generate a declarative Jenkinsfile.

        Args:
            scan_type: Type of scan to run (quick, full, compliance).
            fail_on: Minimum severity to fail the build.

        Returns:
            Complete Jenkinsfile content as a string.
        """
        pipeline = (
            "pipeline {\n"
            "    agent any\n"
            "\n"
            "    environment {\n"
            f"        SCAN_TYPE = '{scan_type}'\n"
            f"        FAIL_ON = '{fail_on}'\n"
            "    }\n"
            "\n"
            "    stages {\n"
            "        stage('Setup') {\n"
            "            steps {\n"
            "                sh 'python3 -m pip install --upgrade pip'\n"
            "                sh 'if [ -f requirements.txt ]; then pip install -r requirements.txt; fi'\n"
            "            }\n"
            "        }\n"
            "\n"
            "        stage('Security Scan') {\n"
            "            steps {\n"
            f"                sh 'python3 bin/purple-launcher {scan_type}'\n"
            "            }\n"
            "        }\n"
            "\n"
            "        stage('Export Results') {\n"
            "            steps {\n"
            "                sh '''\n"
            "                    python3 -c \"\n"
            "                    from lib.cicd_integration import get_cicd_integrator;\n"
            "                    import json;\n"
            "                    ci = get_cicd_integrator();\n"
            "                    findings = json.load(open('data/reports/latest_findings.json')) if __import__('pathlib').Path('data/reports/latest_findings.json').exists() else [];\n"
            "                    ci.export_sarif(findings)\n"
            "                    \"\n"
            "                '''\n"
            "            }\n"
            "        }\n"
            "\n"
            "        stage('Security Gate') {\n"
            "            steps {\n"
            "                sh '''\n"
            "                    python3 -c \"\n"
            "                    from lib.cicd_integration import get_cicd_integrator;\n"
            "                    import json, sys;\n"
            "                    ci = get_cicd_integrator();\n"
            "                    findings = json.load(open('data/reports/latest_findings.json')) if __import__('pathlib').Path('data/reports/latest_findings.json').exists() else [];\n"
            f"                    gate = ci.evaluate_security_gate(findings, {{'fail_on': '{fail_on}'}});\n"
            "                    print('Security Gate:', 'PASSED' if gate['passed'] else 'FAILED');\n"
            "                    print('Reason:', gate['reason']);\n"
            "                    sys.exit(gate['exit_code'])\n"
            "                    \"\n"
            "                '''\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "\n"
            "    post {\n"
            "        always {\n"
            "            archiveArtifacts artifacts: 'data/reports/**', allowEmptyArchive: true\n"
            "        }\n"
            "        failure {\n"
            "            echo 'Security scan failed - check report artifacts for details'\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        return pipeline

    def export_sarif(self, findings: List[Dict],
                     output_path: Optional[str] = None) -> Path:
        """Export findings in SARIF v2.1.0 format.

        SARIF (Static Analysis Results Interchange Format) is compatible
        with the GitHub Security tab and other code scanning tools.

        Args:
            findings: List of finding dicts with keys: finding_id, severity,
                      title, description, affected_asset, cvss_score, cve_ids,
                      remediation.
            output_path: Optional output file path. Defaults to
                         data/reports/results.sarif.

        Returns:
            Path to the generated SARIF file.
        """
        if output_path:
            sarif_path = Path(output_path)
        else:
            sarif_path = self.reports_dir / 'results.sarif'
        sarif_path.parent.mkdir(parents=True, exist_ok=True)

        # Build rules from findings
        rules = []
        seen_rule_ids = set()
        for finding in findings:
            rule_id = finding.get('finding_id', 'UNKNOWN')
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)

            rule = {
                'id': rule_id,
                'name': finding.get('title', 'Unknown Finding'),
                'shortDescription': {
                    'text': finding.get('title', 'Unknown Finding')
                },
                'fullDescription': {
                    'text': finding.get('description', '')
                },
                'help': {
                    'text': finding.get('remediation', 'No remediation available'),
                    'markdown': finding.get('remediation', 'No remediation available')
                },
                'properties': {}
            }

            # Add CVE tags if present
            cve_ids = finding.get('cve_ids', [])
            if cve_ids:
                rule['properties']['tags'] = cve_ids

            cvss = finding.get('cvss_score')
            if cvss is not None:
                rule['properties']['security-severity'] = str(cvss)

            rules.append(rule)

        # Build results from findings
        results = []
        for finding in findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity in ('CRITICAL', 'HIGH'):
                level = 'error'
            elif severity == 'MEDIUM':
                level = 'warning'
            else:
                level = 'note'

            result = {
                'ruleId': finding.get('finding_id', 'UNKNOWN'),
                'level': level,
                'message': {
                    'text': finding.get('title', 'Unknown Finding')
                },
                'locations': [
                    {
                        'physicalLocation': {
                            'artifactLocation': {
                                'uri': finding.get('affected_asset', 'unknown'),
                                'uriBaseId': 'ROOTPATH'
                            }
                        }
                    }
                ]
            }

            # Add fingerprints for deduplication
            result['fingerprints'] = {
                'primaryLocationLineHash': finding.get('finding_id', '')
            }

            results.append(result)

        # Assemble SARIF document
        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'Purple Team Platform',
                            'version': '7.0',
                            'informationUri': 'https://github.com/saint1415/PurpleTeamGRC',
                            'rules': rules
                        }
                    },
                    'results': results,
                    'invocations': [
                        {
                            'executionSuccessful': True,
                            'endTimeUtc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        }
                    ]
                }
            ]
        }

        with open(sarif_path, 'w') as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"SARIF report exported: {sarif_path} ({len(results)} results)")
        return sarif_path

    def evaluate_security_gate(self, findings: List[Dict],
                               policy: Optional[Dict] = None) -> Dict:
        """Evaluate findings against a security gate policy.

        Default policy: fail on any CRITICAL, or more than 5 HIGH findings.

        Args:
            findings: List of finding dicts with 'severity' key.
            policy: Optional custom policy dict with severity thresholds.
                    Example: {'critical': 0, 'high': 5, 'medium': 20}

        Returns:
            Dict with keys: passed (bool), reason (str), exit_code (int),
            summary (dict of severity counts).
        """
        # Count findings by severity
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            sev = finding.get('severity', 'INFO').lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts['info'] += 1

        # Apply policy thresholds
        if policy is None:
            policy = {'critical': 0, 'high': 5, 'medium': -1}

        passed = True
        reason = 'All security gate checks passed'

        # Check each severity level against thresholds
        for severity in ('critical', 'high', 'medium', 'low'):
            threshold = policy.get(severity, -1)
            if threshold < 0:
                continue  # -1 means no limit for this severity
            if counts.get(severity, 0) > threshold:
                passed = False
                reason = (
                    f"FAILED: {counts[severity]} {severity.upper()} findings "
                    f"exceed threshold of {threshold}"
                )
                break

        exit_code = 0 if passed else 1

        return {
            'passed': passed,
            'reason': reason,
            'exit_code': exit_code,
            'summary': counts
        }

    def generate_pre_commit_hook(self) -> str:
        """Generate a git pre-commit hook shell script.

        The hook runs a quick security scan before each commit and blocks
        the commit if critical findings are detected.

        Returns:
            Shell script content for .git/hooks/pre-commit.
        """
        hook = (
            "#!/bin/bash\n"
            "# Purple Team Platform - Pre-commit Security Hook\n"
            "# Runs a quick security scan before each commit.\n"
            "#\n"
            "# Install: cp this file .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit\n"
            "\n"
            'echo "[Purple Team] Running pre-commit security scan..."\n'
            "\n"
            "# Determine project root (location of bin/purple-launcher)\n"
            "SCRIPT_DIR=\"$(cd \"$(dirname \"$0\")/../..\" && pwd)\"\n"
            "\n"
            "# Run quick scan\n"
            "python3 \"${SCRIPT_DIR}/bin/purple-launcher\" quick --quiet 2>/dev/null\n"
            "SCAN_EXIT=$?\n"
            "\n"
            "if [ $SCAN_EXIT -ne 0 ]; then\n"
            '    echo "[Purple Team] Security scan found critical issues."\n'
            '    echo "[Purple Team] Review findings in data/reports/ before committing."\n'
            '    echo "[Purple Team] To bypass: git commit --no-verify"\n'
            "    exit 1\n"
            "fi\n"
            "\n"
            "# Evaluate security gate\n"
            "python3 -c \"\n"
            "from lib.cicd_integration import get_cicd_integrator\n"
            "import json, sys\n"
            "ci = get_cicd_integrator()\n"
            "try:\n"
            "    findings = json.load(open('data/reports/latest_findings.json'))\n"
            "except (FileNotFoundError, json.JSONDecodeError):\n"
            "    findings = []\n"
            "gate = ci.evaluate_security_gate(findings)\n"
            "if not gate['passed']:\n"
            "    print('[Purple Team]', gate['reason'])\n"
            "    sys.exit(1)\n"
            "\" 2>/dev/null\n"
            "GATE_EXIT=$?\n"
            "\n"
            "if [ $GATE_EXIT -ne 0 ]; then\n"
            '    echo "[Purple Team] Security gate FAILED. Commit blocked."\n'
            "    exit 1\n"
            "fi\n"
            "\n"
            'echo "[Purple Team] Security gate PASSED."\n'
            "exit 0\n"
        )
        return hook

    def save_pipeline_config(self, provider: str,
                             output_dir: Optional[str] = None) -> Path:
        """Save the generated pipeline config to the appropriate file.

        Args:
            provider: CI/CD provider ('github', 'gitlab', 'jenkins').
            output_dir: Base output directory. Defaults to paths.home.

        Returns:
            Path to the saved configuration file.
        """
        base_dir = Path(output_dir) if output_dir else paths.home

        if provider == 'github':
            config_content = self.generate_github_actions()
            config_path = base_dir / '.github' / 'workflows' / 'security-scan.yml'
        elif provider == 'gitlab':
            config_content = self.generate_gitlab_ci()
            config_path = base_dir / '.gitlab-ci.yml'
        elif provider == 'jenkins':
            config_content = self.generate_jenkins_pipeline()
            config_path = base_dir / 'Jenkinsfile'
        else:
            raise ValueError(
                f"Unsupported provider: {provider}. "
                f"Supported: github, gitlab, jenkins"
            )

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_content)

        logger.info(f"Pipeline config saved: {config_path}")
        return config_path


# Singleton accessor
_cicd_integrator: Optional[CICDIntegrator] = None


def get_cicd_integrator() -> CICDIntegrator:
    """Get the CI/CD integrator singleton."""
    global _cicd_integrator
    if _cicd_integrator is None:
        _cicd_integrator = CICDIntegrator()
    return _cicd_integrator


if __name__ == '__main__':
    ci = get_cicd_integrator()
    print("CI/CD Integrator initialized")

    # Test GitHub Actions generation
    gh_yaml = ci.generate_github_actions()
    print("\n--- GitHub Actions Workflow ---")
    print(gh_yaml[:500] + "..." if len(gh_yaml) > 500 else gh_yaml)

    # Test GitLab CI generation
    gl_yaml = ci.generate_gitlab_ci()
    print("\n--- GitLab CI Config ---")
    print(gl_yaml[:500] + "..." if len(gl_yaml) > 500 else gl_yaml)

    # Test Jenkins pipeline generation
    jk_file = ci.generate_jenkins_pipeline()
    print("\n--- Jenkinsfile ---")
    print(jk_file[:500] + "..." if len(jk_file) > 500 else jk_file)

    # Test SARIF export
    sample_findings = [
        {'finding_id': 'FND-001', 'severity': 'CRITICAL', 'title': 'SQL Injection',
         'description': 'SQL injection in login form', 'affected_asset': '10.0.0.1',
         'cvss_score': 9.8, 'cve_ids': ['CVE-2024-1234'], 'remediation': 'Use parameterized queries'},
        {'finding_id': 'FND-002', 'severity': 'HIGH', 'title': 'Weak TLS',
         'description': 'TLS 1.0 enabled', 'affected_asset': '10.0.0.2',
         'cvss_score': 7.4, 'cve_ids': [], 'remediation': 'Disable TLS 1.0/1.1'},
    ]

    sarif_path = ci.export_sarif(sample_findings)
    print(f"\nSARIF exported: {sarif_path}")

    # Test security gate
    gate = ci.evaluate_security_gate(sample_findings)
    print(f"\nSecurity Gate: {'PASSED' if gate['passed'] else 'FAILED'}")
    print(f"  Reason: {gate['reason']}")
    print(f"  Exit code: {gate['exit_code']}")
    print(f"  Summary: {gate['summary']}")

    # Test pre-commit hook generation
    hook = ci.generate_pre_commit_hook()
    print(f"\n--- Pre-commit Hook ({len(hook)} bytes) ---")
    print(hook[:300] + "..." if len(hook) > 300 else hook)

    print("\nCI/CD Integrator ready")
