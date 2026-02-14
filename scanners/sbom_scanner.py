#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - SBOM / Dependency Scanner

Scans project directories for dependency manifest files, extracts package
names and versions, cross-references with NVD/CVE data via vuln_database.py,
generates CycloneDX SBOM output, and flags license risks.

Supported manifest formats:
  - package.json / package-lock.json  (Node.js)
  - requirements.txt / Pipfile.lock   (Python)
  - go.mod / go.sum                   (Go)
  - pom.xml / build.gradle            (Java)
  - Gemfile.lock                      (Ruby)
  - Cargo.lock                        (Rust)
  - *.csproj / packages.config        (.NET)

Scan types:
  quick    - parse manifests, count dependencies
  standard - parse + vulnerability lookup
  deep     - parse + vulnerability lookup + license check + full SBOM
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from vuln_database import get_vuln_database
except ImportError:
    get_vuln_database = None


class SBOMScanner(BaseScanner):
    """Software Bill of Materials and dependency vulnerability scanner."""

    SCANNER_NAME = "sbom"
    SCANNER_DESCRIPTION = "Dependency and SBOM security analysis"

    # Manifest file patterns and their types
    MANIFEST_PATTERNS: Dict[str, str] = {
        'package.json': 'npm',
        'package-lock.json': 'npm_lock',
        'requirements.txt': 'pip',
        'Pipfile.lock': 'pipfile_lock',
        'go.mod': 'gomod',
        'go.sum': 'gosum',
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'Gemfile.lock': 'rubygems',
        'Cargo.lock': 'cargo',
        'packages.config': 'nuget',
    }

    # Copyleft / restrictive licenses that may be risky in proprietary code
    RISKY_LICENSES = (
        'GPL', 'AGPL', 'LGPL', 'SSPL', 'EUPL',
        'CC-BY-SA', 'CC-BY-NC',
        'OSL',
    )

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.vuln_db = None
        if get_vuln_database is not None:
            try:
                self.vuln_db = get_vuln_database()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Main scan entry point
    # -----------------------------------------------------------------------

    def scan(self, targets: List[str] = None,
             scan_type: str = 'standard', **kwargs) -> Dict:
        """Execute SBOM / dependency scan.

        Args:
            targets: Directory paths to scan. Defaults to current directory.
            scan_type: 'quick', 'standard', or 'deep'.

        Returns:
            Dict with scan results and summary.
        """
        self.start_time = datetime.utcnow()
        self.scan_logger.info(f"Starting {scan_type} SBOM scan")

        if not targets:
            targets = [str(Path.cwd())]

        all_dependencies: List[Dict] = []
        all_manifests: List[Tuple[str, str]] = []

        for directory in targets:
            directory = str(Path(directory).resolve())
            self.scan_logger.info(f"Scanning directory: {directory}")

            manifests = self._find_manifests(directory)
            all_manifests.extend(manifests)
            self.scan_logger.info(
                f"Found {len(manifests)} manifest files in {directory}"
            )

            for manifest_path, manifest_type in manifests:
                deps = self._parse_dependencies(
                    manifest_path, manifest_type
                )
                for dep in deps:
                    dep['manifest_path'] = manifest_path
                    dep['manifest_type'] = manifest_type
                all_dependencies.extend(deps)
                self.human_delay()

        self.add_result(
            'manifest_summary',
            {
                'directories_scanned': len(targets),
                'manifests_found': len(all_manifests),
                'total_dependencies': len(all_dependencies),
            },
            ','.join(targets),
        )

        if not all_dependencies:
            self.add_finding(
                severity='INFO',
                title='No Dependencies Found',
                description=(
                    'No supported manifest files or dependencies found '
                    'in the scanned directories.'
                ),
                affected_asset=','.join(targets),
                finding_type='sbom_info',
                detection_method='manifest_parse',
            )
            self.end_time = datetime.utcnow()
            self.save_results()
            return self.get_summary()

        # De-duplicate dependencies
        unique_deps = self._deduplicate(all_dependencies)
        self.scan_logger.info(
            f"Total: {len(all_dependencies)} deps, "
            f"{len(unique_deps)} unique"
        )

        # Quick scan: just summary
        self.add_finding(
            severity='INFO',
            title=(
                f'Dependency Summary: {len(unique_deps)} Unique Packages'
            ),
            description=(
                f"Found {len(all_dependencies)} dependency entries "
                f"({len(unique_deps)} unique) across "
                f"{len(all_manifests)} manifest files."
            ),
            affected_asset=','.join(targets),
            finding_type='sbom_summary',
            raw_data={
                'total': len(all_dependencies),
                'unique': len(unique_deps),
                'manifests': len(all_manifests),
            },
            detection_method='manifest_parse',
        )

        # Standard + Deep: vulnerability lookup
        if scan_type in ('standard', 'deep'):
            self.scan_logger.info("Checking vulnerabilities...")
            vuln_findings = self._check_vulnerabilities(unique_deps)
            self.scan_logger.info(
                f"Found {len(vuln_findings)} vulnerability matches"
            )

        # Deep: license check + SBOM generation
        if scan_type == 'deep':
            self.scan_logger.info("Checking license risks...")
            self._check_license_risks(unique_deps)

            self.scan_logger.info("Generating CycloneDX SBOM...")
            sbom_json = self._generate_sbom(
                unique_deps, format='cyclonedx'
            )
            if sbom_json:
                sbom_path = self._save_sbom(sbom_json)
                self.add_result(
                    'sbom_output',
                    {'path': str(sbom_path), 'format': 'cyclonedx'},
                    ','.join(targets),
                )

        self.end_time = datetime.utcnow()
        self.save_results()

        summary = self.get_summary()
        self.scan_logger.info(
            f"SBOM scan complete: {summary['findings_count']} findings"
        )
        return summary

    # -----------------------------------------------------------------------
    # Manifest discovery
    # -----------------------------------------------------------------------

    def _find_manifests(self, directory: str) -> List[Tuple[str, str]]:
        """Find all supported manifest files in a directory tree.

        Returns list of (absolute_path, manifest_type) tuples.
        """
        manifests: List[Tuple[str, str]] = []
        skip_dirs = {
            'node_modules', '.git', '__pycache__', 'venv', '.venv',
            'vendor', 'target', 'bin', 'obj', '.tox', 'dist',
        }

        for root, dirs, files in os.walk(directory):
            # Prune directories we want to skip
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for filename in files:
                # Check exact matches
                if filename in self.MANIFEST_PATTERNS:
                    fpath = os.path.join(root, filename)
                    mtype = self.MANIFEST_PATTERNS[filename]
                    manifests.append((fpath, mtype))
                    continue

                # Check .csproj files
                if filename.endswith('.csproj'):
                    fpath = os.path.join(root, filename)
                    manifests.append((fpath, 'csproj'))

        return manifests

    # -----------------------------------------------------------------------
    # Dependency parsing
    # -----------------------------------------------------------------------

    def _parse_dependencies(self, manifest_path: str,
                            manifest_type: str) -> List[Dict]:
        """Extract dependencies from a manifest file.

        Returns list of dicts with keys: name, version, ecosystem.
        """
        try:
            with open(manifest_path, 'r', encoding='utf-8',
                       errors='replace') as f:
                content = f.read()
        except Exception as exc:
            self.scan_logger.warning(
                f"Cannot read {manifest_path}: {exc}"
            )
            return []

        parsers = {
            'npm': self._parse_npm,
            'npm_lock': self._parse_npm_lock,
            'pip': self._parse_pip,
            'pipfile_lock': self._parse_pipfile_lock,
            'gomod': self._parse_gomod,
            'gosum': self._parse_gosum,
            'maven': self._parse_maven,
            'gradle': self._parse_gradle,
            'rubygems': self._parse_gemfile_lock,
            'cargo': self._parse_cargo_lock,
            'nuget': self._parse_nuget,
            'csproj': self._parse_csproj,
        }

        parser = parsers.get(manifest_type)
        if not parser:
            return []

        try:
            return parser(content)
        except Exception as exc:
            self.scan_logger.warning(
                f"Parse error for {manifest_path} ({manifest_type}): {exc}"
            )
            return []

    def _parse_npm(self, content: str) -> List[Dict]:
        """Parse package.json for dependencies."""
        data = json.loads(content)
        deps: List[Dict] = []
        for section in ('dependencies', 'devDependencies',
                        'peerDependencies', 'optionalDependencies'):
            for name, version in data.get(section, {}).items():
                # Strip range operators
                ver = re.sub(r'^[\^~>=<*|]+', '', str(version)).strip()
                deps.append({
                    'name': name, 'version': ver, 'ecosystem': 'npm',
                })
        return deps

    def _parse_npm_lock(self, content: str) -> List[Dict]:
        """Parse package-lock.json."""
        data = json.loads(content)
        deps: List[Dict] = []

        # lockfileVersion 2/3 uses "packages"
        packages = data.get('packages', {})
        if packages:
            for pkg_path, info in packages.items():
                if not pkg_path:  # root package
                    continue
                name = pkg_path.split('node_modules/')[-1]
                version = info.get('version', '')
                if name and version:
                    deps.append({
                        'name': name, 'version': version,
                        'ecosystem': 'npm',
                    })
        else:
            # lockfileVersion 1
            for name, info in data.get('dependencies', {}).items():
                version = info.get('version', '')
                if version:
                    deps.append({
                        'name': name, 'version': version,
                        'ecosystem': 'npm',
                    })
        return deps

    def _parse_pip(self, content: str) -> List[Dict]:
        """Parse requirements.txt."""
        deps: List[Dict] = []
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Remove inline comments
            line = line.split('#')[0].strip()
            # Handle various operators: ==, >=, <=, ~=, !=
            match = re.match(
                r'^([a-zA-Z0-9_.-]+)\s*(?:[=~!<>]=?\s*(.+))?$', line
            )
            if match:
                name = match.group(1)
                version = (match.group(2) or '').split(',')[0].strip()
                deps.append({
                    'name': name, 'version': version,
                    'ecosystem': 'pypi',
                })
        return deps

    def _parse_pipfile_lock(self, content: str) -> List[Dict]:
        """Parse Pipfile.lock."""
        data = json.loads(content)
        deps: List[Dict] = []
        for section in ('default', 'develop'):
            for name, info in data.get(section, {}).items():
                version = info.get('version', '').lstrip('=')
                deps.append({
                    'name': name, 'version': version,
                    'ecosystem': 'pypi',
                })
        return deps

    def _parse_gomod(self, content: str) -> List[Dict]:
        """Parse go.mod."""
        deps: List[Dict] = []
        in_require = False
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('require ('):
                in_require = True
                continue
            if line == ')':
                in_require = False
                continue
            if in_require or line.startswith('require '):
                parts = line.replace('require ', '').strip().split()
                if len(parts) >= 2:
                    deps.append({
                        'name': parts[0],
                        'version': parts[1].lstrip('v'),
                        'ecosystem': 'go',
                    })
        return deps

    def _parse_gosum(self, content: str) -> List[Dict]:
        """Parse go.sum (supplementary to go.mod)."""
        deps: List[Dict] = []
        seen = set()
        for line in content.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].split('/')[0].lstrip('v')
                key = f"{name}@{version}"
                if key not in seen:
                    seen.add(key)
                    deps.append({
                        'name': name, 'version': version,
                        'ecosystem': 'go',
                    })
        return deps

    def _parse_maven(self, content: str) -> List[Dict]:
        """Parse pom.xml (basic regex extraction)."""
        deps: List[Dict] = []
        # Match <dependency> blocks
        dep_pattern = re.compile(
            r'<dependency>\s*'
            r'<groupId>([^<]+)</groupId>\s*'
            r'<artifactId>([^<]+)</artifactId>\s*'
            r'(?:<version>([^<]+)</version>)?',
            re.DOTALL,
        )
        for m in dep_pattern.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = (m.group(3) or '').strip()
            # Skip property references like ${...}
            if version.startswith('$'):
                version = ''
            deps.append({
                'name': f"{group}:{artifact}",
                'version': version,
                'ecosystem': 'maven',
            })
        return deps

    def _parse_gradle(self, content: str) -> List[Dict]:
        """Parse build.gradle (basic regex extraction)."""
        deps: List[Dict] = []
        # Match patterns like: implementation 'group:artifact:version'
        patterns = [
            re.compile(
                r"(?:implementation|api|compile|testImplementation|"
                r"runtimeOnly|compileOnly)\s+"
                r"['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
            ),
            re.compile(
                r"(?:implementation|api|compile|testImplementation|"
                r"runtimeOnly|compileOnly)\s*\(\s*"
                r"['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
            ),
        ]
        for pattern in patterns:
            for m in pattern.finditer(content):
                deps.append({
                    'name': f"{m.group(1)}:{m.group(2)}",
                    'version': m.group(3),
                    'ecosystem': 'maven',
                })
        return deps

    def _parse_gemfile_lock(self, content: str) -> List[Dict]:
        """Parse Gemfile.lock."""
        deps: List[Dict] = []
        in_specs = False
        for line in content.split('\n'):
            if line.strip() == 'specs:':
                in_specs = True
                continue
            if in_specs:
                # Gem entries are indented with 4 spaces
                match = re.match(r'^\s{4}(\S+)\s+\((.+)\)', line)
                if match:
                    deps.append({
                        'name': match.group(1),
                        'version': match.group(2),
                        'ecosystem': 'rubygems',
                    })
                elif line.strip() and not line.startswith(' '):
                    in_specs = False
        return deps

    def _parse_cargo_lock(self, content: str) -> List[Dict]:
        """Parse Cargo.lock."""
        deps: List[Dict] = []
        current: Dict[str, str] = {}
        for line in content.split('\n'):
            line = line.strip()
            if line == '[[package]]':
                if current.get('name') and current.get('version'):
                    deps.append({
                        'name': current['name'],
                        'version': current['version'],
                        'ecosystem': 'crates',
                    })
                current = {}
            elif '=' in line:
                key, _, val = line.partition('=')
                current[key.strip()] = val.strip().strip('"')

        # Last entry
        if current.get('name') and current.get('version'):
            deps.append({
                'name': current['name'],
                'version': current['version'],
                'ecosystem': 'crates',
            })
        return deps

    def _parse_nuget(self, content: str) -> List[Dict]:
        """Parse packages.config (.NET)."""
        deps: List[Dict] = []
        pattern = re.compile(
            r'<package\s+id="([^"]+)"\s+version="([^"]+)"'
        )
        for m in pattern.finditer(content):
            deps.append({
                'name': m.group(1),
                'version': m.group(2),
                'ecosystem': 'nuget',
            })
        return deps

    def _parse_csproj(self, content: str) -> List[Dict]:
        """Parse .csproj PackageReference elements."""
        deps: List[Dict] = []
        pattern = re.compile(
            r'<PackageReference\s+Include="([^"]+)"\s+'
            r'Version="([^"]+)"'
        )
        for m in pattern.finditer(content):
            deps.append({
                'name': m.group(1),
                'version': m.group(2),
                'ecosystem': 'nuget',
            })
        return deps

    # -----------------------------------------------------------------------
    # Deduplication
    # -----------------------------------------------------------------------

    def _deduplicate(self, dependencies: List[Dict]) -> List[Dict]:
        """Deduplicate dependencies by name+version+ecosystem."""
        seen = set()
        unique: List[Dict] = []
        for dep in dependencies:
            key = (
                dep.get('name', ''),
                dep.get('version', ''),
                dep.get('ecosystem', ''),
            )
            if key not in seen:
                seen.add(key)
                unique.append(dep)
        return unique

    # -----------------------------------------------------------------------
    # Vulnerability checking
    # -----------------------------------------------------------------------

    def _check_vulnerabilities(self,
                               dependencies: List[Dict]) -> List[Dict]:
        """Cross-reference dependencies with vulnerability database.

        Returns list of vulnerability finding dicts.
        """
        if self.vuln_db is None:
            self.scan_logger.warning(
                "Vulnerability database not available, skipping CVE check"
            )
            self.add_finding(
                severity='INFO',
                title='Vulnerability Database Not Available',
                description=(
                    'The vuln_database module could not be loaded. '
                    'CVE cross-referencing was skipped.'
                ),
                affected_asset='sbom-scanner',
                finding_type='sbom_info',
                detection_method='vuln_db',
            )
            return []

        vuln_findings: List[Dict] = []

        for dep in dependencies:
            name = dep.get('name', '')
            version = dep.get('version', '')
            ecosystem = dep.get('ecosystem', '')

            if not name:
                continue

            # Search by package name
            query = name.split(':')[-1] if ':' in name else name
            try:
                results = self.vuln_db.search(query, max_results=20)
            except Exception as exc:
                self.scan_logger.debug(
                    f"Vuln search error for {name}: {exc}"
                )
                continue

            cves = results.get('cves', [])
            if not cves:
                continue

            # Filter CVEs that mention this package
            matching_cves = []
            for cve in cves:
                cve_desc = str(
                    cve.get('description', '')
                ).lower()
                cve_id = cve.get('id', cve.get('cve_id', ''))
                # Check if the package name appears in the CVE description
                if query.lower() in cve_desc:
                    matching_cves.append(cve)

            if not matching_cves:
                continue

            # Determine severity from highest CVSS
            max_cvss = 0.0
            cve_ids = []
            for cve in matching_cves:
                cvss = cve.get('cvss_score', cve.get('cvss', 0.0))
                if isinstance(cvss, (int, float)) and cvss > max_cvss:
                    max_cvss = cvss
                cve_id = cve.get('id', cve.get('cve_id', ''))
                if cve_id:
                    cve_ids.append(cve_id)

            if max_cvss >= 9.0:
                severity = 'CRITICAL'
            elif max_cvss >= 7.0:
                severity = 'HIGH'
            elif max_cvss >= 4.0:
                severity = 'MEDIUM'
            elif max_cvss > 0:
                severity = 'LOW'
            else:
                severity = 'MEDIUM'

            finding_data = {
                'package': name,
                'version': version,
                'ecosystem': ecosystem,
                'cve_count': len(matching_cves),
                'max_cvss': max_cvss,
                'cve_ids': cve_ids,
            }
            vuln_findings.append(finding_data)

            self.add_finding(
                severity=severity,
                title=(
                    f'Vulnerable Dependency: {name}@{version} '
                    f'({len(matching_cves)} CVEs)'
                ),
                description=(
                    f"Package '{name}' version '{version}' ({ecosystem}) "
                    f"has {len(matching_cves)} known vulnerabilities. "
                    f"Highest CVSS: {max_cvss}."
                ),
                affected_asset=f'{ecosystem}:{name}@{version}',
                finding_type='sbom_vulnerability',
                cvss_score=max_cvss,
                cve_ids=cve_ids[:10],
                remediation=(
                    f'Update {name} to the latest patched version.'
                ),
                raw_data=finding_data,
                detection_method='vuln_db',
            )

        return vuln_findings

    # -----------------------------------------------------------------------
    # License risk checking
    # -----------------------------------------------------------------------

    def _check_license_risks(self,
                             dependencies: List[Dict]) -> List[Dict]:
        """Flag dependencies with potentially risky licenses.

        This is a basic heuristic check. For accurate license data,
        a dedicated license scanner should be used.
        """
        risky: List[Dict] = []

        for dep in dependencies:
            name = dep.get('name', '')
            license_info = dep.get('license', '')

            # For npm packages, license may be in the parsed data
            if not license_info:
                continue

            license_upper = str(license_info).upper()
            for risky_lic in self.RISKY_LICENSES:
                if risky_lic.upper() in license_upper:
                    risky.append({
                        'package': name,
                        'version': dep.get('version', ''),
                        'license': license_info,
                        'risk': risky_lic,
                    })
                    break

        if risky:
            self.add_finding(
                severity='MEDIUM',
                title=(
                    f'{len(risky)} Dependencies With Restrictive Licenses'
                ),
                description=(
                    f"{len(risky)} dependencies use copyleft or restrictive "
                    f"licenses (GPL, AGPL, etc.) that may be incompatible "
                    f"with proprietary use."
                ),
                affected_asset='project-dependencies',
                finding_type='sbom_license',
                remediation=(
                    'Review license compatibility. Consider replacing '
                    'packages with permissive-licensed alternatives.'
                ),
                raw_data=risky,
                detection_method='license_check',
            )

        return risky

    # -----------------------------------------------------------------------
    # SBOM generation
    # -----------------------------------------------------------------------

    def _generate_sbom(self, dependencies: List[Dict],
                       format: str = 'cyclonedx') -> str:
        """Generate a CycloneDX JSON SBOM from dependency list.

        Args:
            dependencies: List of dependency dicts.
            format: Output format (only 'cyclonedx' supported).

        Returns:
            JSON string of the SBOM.
        """
        if format != 'cyclonedx':
            self.scan_logger.warning(
                f"Unsupported SBOM format: {format}"
            )
            return ''

        components = []
        for dep in dependencies:
            name = dep.get('name', '')
            version = dep.get('version', '')
            ecosystem = dep.get('ecosystem', '')

            # Map ecosystem to CycloneDX purl type
            purl_type_map = {
                'npm': 'npm',
                'pypi': 'pypi',
                'go': 'golang',
                'maven': 'maven',
                'rubygems': 'gem',
                'crates': 'cargo',
                'nuget': 'nuget',
            }
            purl_type = purl_type_map.get(ecosystem, ecosystem)

            # Build Package URL (purl)
            if ':' in name and ecosystem == 'maven':
                group, artifact = name.split(':', 1)
                purl = f"pkg:{purl_type}/{group}/{artifact}@{version}"
            else:
                purl = f"pkg:{purl_type}/{name}@{version}"

            component = {
                'type': 'library',
                'name': name,
                'version': version,
                'purl': purl,
            }

            if dep.get('license'):
                component['licenses'] = [{
                    'license': {'id': dep['license']}
                }]

            components.append(component)

        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'serialNumber': f'urn:uuid:{uuid.uuid4()}',
            'version': 1,
            'metadata': {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'tools': [{
                    'vendor': 'PurpleTeamGRC',
                    'name': 'sbom_scanner',
                    'version': '7.0',
                }],
                'component': {
                    'type': 'application',
                    'name': 'scanned-project',
                },
            },
            'components': components,
        }

        return json.dumps(sbom, indent=2)

    def _save_sbom(self, sbom_json: str) -> Path:
        """Save SBOM JSON to file and return the path."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"sbom_{timestamp}.cdx.json"

        if self.session_id:
            output_dir = self.paths.session_dir(self.session_id)
        else:
            output_dir = self.paths.results

        output_path = output_dir / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sbom_json)

        self.scan_logger.info(f"SBOM saved to {output_path}")
        return output_path


if __name__ == '__main__':
    scanner = SBOMScanner()
    print(f"SBOM Scanner initialized: {scanner.SCANNER_NAME}")
    print(f"Vuln DB available: {scanner.vuln_db is not None}")

    # Quick test: scan current directory
    manifests = scanner._find_manifests(str(Path.cwd()))
    print(f"Manifests found: {len(manifests)}")
    for path, mtype in manifests:
        print(f"  {mtype}: {path}")
