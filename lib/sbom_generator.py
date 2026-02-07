#!/usr/bin/env python3
"""
Purple Team Platform v7.0 - SBOM Generator
Generates Software Bill of Materials in CycloneDX and SPDX formats.
Parses package manifests with honest coverage indicators.
"""

import json
import os
import re
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('sbom_generator')

# Package manifest filenames mapped to their parser method names
MANIFEST_FILES = {
    'requirements.txt': 'parse_requirements_txt',
    'Pipfile.lock': 'parse_pipfile_lock',
    'package-lock.json': 'parse_package_lock_json',
    'package.json': 'parse_package_json',
    'go.mod': 'parse_go_mod',
    'Cargo.lock': 'parse_cargo_lock',
    'Cargo.toml': 'parse_cargo_toml',
    'pom.xml': 'parse_pom_xml',
    'Gemfile.lock': 'parse_gemfile_lock',
    'composer.lock': 'parse_composer_lock',
}

# Lock files that supersede their manifest counterpart
LOCK_FILE_PREFERENCE = {
    'package.json': 'package-lock.json',
    'Cargo.toml': 'Cargo.lock',
    'requirements.txt': 'Pipfile.lock',
}

# PURL type mapping by ecosystem
PURL_TYPES = {
    'python': 'pypi',
    'node': 'npm',
    'go': 'golang',
    'rust': 'cargo',
    'java': 'maven',
    'ruby': 'gem',
    'php': 'composer',
}


class SBOMGenerator:
    """Generates Software Bill of Materials from package manifests."""

    _instance: Optional['SBOMGenerator'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.output_dir = paths.reports
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._warnings: List[str] = []

        logger.info("SBOM Generator initialized")

    # ------------------------------------------------------------------
    # Directory scanning
    # ------------------------------------------------------------------

    def scan_directory(self, path, recursive=True) -> dict:
        """
        Walk a directory tree finding all package manifest files,
        parse each one, and return a combined SBOM with coverage info.

        Args:
            path: Root directory to scan.
            recursive: Whether to descend into subdirectories.

        Returns:
            dict with keys: components, files_parsed, total_components,
                            warnings, ecosystems found (python, node, etc.)
        """
        path = Path(path).resolve()
        if not path.is_dir():
            logger.error(f"Not a directory: {path}")
            return {'components': [], 'files_parsed': [], 'total_components': 0}

        self._warnings = []
        all_components: List[Dict] = []
        files_parsed: List[str] = []
        ecosystems: Dict[str, bool] = {}

        # Collect all manifest files first, grouped by directory
        dir_manifests: Dict[Path, List[str]] = {}

        if recursive:
            for root, dirs, files in os.walk(path):
                # Skip common non-project directories
                dirs[:] = [d for d in dirs if d not in (
                    'node_modules', '.git', 'venv', '.venv', '__pycache__',
                    '.tox', '.mypy_cache', 'dist', 'build', '.eggs',
                    'vendor', 'target',
                )]
                root_path = Path(root)
                for fname in files:
                    if fname in MANIFEST_FILES:
                        dir_manifests.setdefault(root_path, []).append(fname)
        else:
            for fname in os.listdir(path):
                if fname in MANIFEST_FILES and (path / fname).is_file():
                    dir_manifests.setdefault(path, []).append(fname)

        # Process each directory, applying lock-file preference
        for dir_path, manifest_names in dir_manifests.items():
            skip_set = set()
            for manifest, lock in LOCK_FILE_PREFERENCE.items():
                if manifest in manifest_names and lock in manifest_names:
                    skip_set.add(manifest)
                    self._warnings.append(
                        f"Skipping {dir_path / manifest} in favor of "
                        f"lock file {lock}"
                    )
                elif manifest in manifest_names and lock not in manifest_names:
                    self._warnings.append(
                        f"Using {manifest} without lock file - "
                        f"versions may be imprecise"
                    )

            for fname in manifest_names:
                if fname in skip_set:
                    continue

                file_path = dir_path / fname
                parser_name = MANIFEST_FILES[fname]
                parser = getattr(self, parser_name, None)
                if parser is None:
                    continue

                try:
                    components = parser(file_path)
                    if components:
                        all_components.extend(components)
                        files_parsed.append(str(file_path))

                        # Track ecosystem
                        eco = components[0].get('type', 'unknown')
                        ecosystems[eco] = True

                        logger.debug(
                            f"Parsed {file_path}: {len(components)} components"
                        )
                except Exception as e:
                    self._warnings.append(f"Error parsing {file_path}: {e}")
                    logger.warning(f"Error parsing {file_path}: {e}")

        # De-duplicate components (same name+version+type)
        seen = set()
        unique_components: List[Dict] = []
        for comp in all_components:
            key = (comp.get('name', ''), comp.get('version', ''),
                   comp.get('type', ''))
            if key not in seen:
                seen.add(key)
                unique_components.append(comp)

        result = {
            'components': unique_components,
            'files_parsed': files_parsed,
            'total_components': len(unique_components),
            'warnings': self._warnings,
            'scan_path': str(path),
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        # Set ecosystem flags for coverage indicator
        for eco in ecosystems:
            result[eco] = True

        return result

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def parse_requirements_txt(self, path) -> List[Dict]:
        """Parse Python requirements.txt file."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    # Skip blanks, comments, options
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    # Skip URLs and editable installs
                    if line.startswith('http://') or line.startswith('https://'):
                        continue
                    if line.startswith('git+') or line.startswith('svn+'):
                        continue

                    # Parse name and version specifier
                    # Patterns: name==1.0, name>=1.0, name~=1.0, name[extra]==1.0
                    match = re.match(
                        r'^([A-Za-z0-9_][A-Za-z0-9._-]*)'
                        r'(?:\[.*?\])?'
                        r'(?:\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;,#]+))?',
                        line
                    )
                    if match:
                        name = match.group(1).strip()
                        version = match.group(3) or '*'
                        components.append({
                            'name': name,
                            'version': version,
                            'type': 'python',
                        })
        except OSError as e:
            logger.warning(f"Cannot read {path}: {e}")

        return components

    def parse_pipfile_lock(self, path) -> List[Dict]:
        """Parse Python Pipfile.lock (JSON format)."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for section in ('default', 'develop'):
                packages = data.get(section, {})
                for name, info in packages.items():
                    version = info.get('version', '*')
                    # Pipfile.lock versions are prefixed with ==
                    if version.startswith('=='):
                        version = version[2:]
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'python',
                    })
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot parse {path}: {e}")

        return components

    def parse_package_json(self, path) -> List[Dict]:
        """Parse Node.js package.json file."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for dep_key in ('dependencies', 'devDependencies'):
                deps = data.get(dep_key, {})
                for name, version_spec in deps.items():
                    # Strip version prefixes like ^, ~, >=
                    version = re.sub(r'^[\^~>=<]*', '', version_spec).strip()
                    if not version:
                        version = '*'
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'node',
                    })
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot parse {path}: {e}")

        return components

    def parse_package_lock_json(self, path) -> List[Dict]:
        """Parse Node.js package-lock.json file (lockfile v2/v3)."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # lockfileVersion 2 and 3 use "packages" key
            packages = data.get('packages', {})
            if packages:
                for pkg_path, info in packages.items():
                    # Skip the root package (empty key)
                    if not pkg_path:
                        continue
                    # Extract package name from the path
                    name = info.get('name', '')
                    if not name:
                        # Derive from path: node_modules/foo or
                        # node_modules/@scope/foo
                        parts = pkg_path.split('node_modules/')
                        name = parts[-1] if parts else pkg_path

                    version = info.get('version', '*')
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'node',
                    })
            else:
                # lockfileVersion 1 uses "dependencies" key
                deps = data.get('dependencies', {})
                for name, info in deps.items():
                    version = info.get('version', '*')
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'node',
                    })
                    # Recurse into nested dependencies
                    self._parse_npm_nested(info.get('dependencies', {}),
                                           components)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot parse {path}: {e}")

        return components

    def _parse_npm_nested(self, deps: Dict, components: List[Dict]):
        """Recursively parse nested npm dependencies (lockfile v1)."""
        for name, info in deps.items():
            version = info.get('version', '*')
            components.append({
                'name': name,
                'version': version,
                'type': 'node',
            })
            if 'dependencies' in info:
                self._parse_npm_nested(info['dependencies'], components)

    def parse_go_mod(self, path) -> List[Dict]:
        """Parse Go go.mod file."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse require blocks: require ( ... )
            require_blocks = re.findall(
                r'require\s*\((.*?)\)', content, re.DOTALL
            )
            for block in require_blocks:
                for line in block.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith('//'):
                        continue
                    # Indirect dependencies have // indirect comment
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        components.append({
                            'name': name,
                            'version': version,
                            'type': 'go',
                        })

            # Parse single-line requires: require module/path v1.2.3
            single_requires = re.findall(
                r'^require\s+(\S+)\s+(\S+)',
                content, re.MULTILINE
            )
            for name, version in single_requires:
                components.append({
                    'name': name,
                    'version': version,
                    'type': 'go',
                })

        except OSError as e:
            logger.warning(f"Cannot read {path}: {e}")

        return components

    def parse_cargo_toml(self, path) -> List[Dict]:
        """Parse Rust Cargo.toml file (basic TOML-like parsing)."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            in_deps = False
            for line in content.splitlines():
                stripped = line.strip()

                # Check section headers
                if stripped.startswith('['):
                    section = stripped.strip('[]').strip().lower()
                    in_deps = section in (
                        'dependencies', 'dev-dependencies',
                        'build-dependencies',
                    )
                    continue

                if not in_deps or not stripped or stripped.startswith('#'):
                    continue

                # Parse: name = "version" or name = { version = "..." }
                match = re.match(r'^(\S+)\s*=\s*"([^"]*)"', stripped)
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'rust',
                    })
                    continue

                # Inline table: name = { version = "1.0", features = [...] }
                match = re.match(
                    r'^(\S+)\s*=\s*\{.*?version\s*=\s*"([^"]*)"', stripped
                )
                if match:
                    name = match.group(1)
                    version = match.group(2)
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'rust',
                    })

        except OSError as e:
            logger.warning(f"Cannot read {path}: {e}")

        return components

    def parse_cargo_lock(self, path) -> List[Dict]:
        """Parse Rust Cargo.lock file."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Each package block: [[package]]\nname = "..."\nversion = "..."
            blocks = content.split('[[package]]')
            for block in blocks[1:]:  # skip preamble before first [[package]]
                name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                ver_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                if name_match:
                    components.append({
                        'name': name_match.group(1),
                        'version': ver_match.group(1) if ver_match else '*',
                        'type': 'rust',
                    })

        except OSError as e:
            logger.warning(f"Cannot read {path}: {e}")

        return components

    def parse_pom_xml(self, path) -> List[Dict]:
        """Parse Java Maven pom.xml file using ElementTree."""
        path = Path(path)
        components = []

        try:
            tree = ET.parse(path)
            root = tree.getroot()

            # Handle Maven namespace
            ns = ''
            ns_match = re.match(r'\{(.+?)\}', root.tag)
            if ns_match:
                ns = ns_match.group(0)

            # Parse <dependencies> section
            for dep in root.iter(f'{ns}dependency'):
                group_id = dep.findtext(f'{ns}groupId', '').strip()
                artifact_id = dep.findtext(f'{ns}artifactId', '').strip()
                version = dep.findtext(f'{ns}version', '*').strip()

                if artifact_id:
                    name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                    # Resolve property references like ${project.version}
                    if version.startswith('${'):
                        version = '*'
                    components.append({
                        'name': name,
                        'version': version,
                        'type': 'java',
                    })

        except (ET.ParseError, OSError) as e:
            logger.warning(f"Cannot parse {path}: {e}")

        return components

    def parse_gemfile_lock(self, path) -> List[Dict]:
        """Parse Ruby Gemfile.lock file."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                in_specs = False
                for line in f:
                    stripped = line.rstrip()

                    # The specs section contains indented gem entries
                    if stripped == '  specs:' or stripped == '    specs:':
                        in_specs = True
                        continue
                    elif stripped and not stripped.startswith(' '):
                        in_specs = False
                        continue

                    if not in_specs:
                        continue

                    # Gem lines: "    name (version)"
                    match = re.match(r'^\s{4}(\S+)\s+\(([^)]+)\)', stripped)
                    if match:
                        name = match.group(1)
                        version = match.group(2)
                        components.append({
                            'name': name,
                            'version': version,
                            'type': 'ruby',
                        })

        except OSError as e:
            logger.warning(f"Cannot read {path}: {e}")

        return components

    def parse_composer_lock(self, path) -> List[Dict]:
        """Parse PHP composer.lock file (JSON)."""
        path = Path(path)
        components = []

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for section in ('packages', 'packages-dev'):
                packages = data.get(section, [])
                for pkg in packages:
                    name = pkg.get('name', '')
                    version = pkg.get('version', '*')
                    # Composer versions can have 'v' prefix
                    if version.startswith('v'):
                        version = version[1:]
                    if name:
                        components.append({
                            'name': name,
                            'version': version,
                            'type': 'php',
                        })

        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot parse {path}: {e}")

        return components

    # ------------------------------------------------------------------
    # Export formats
    # ------------------------------------------------------------------

    def _make_purl(self, component: Dict) -> str:
        """Generate a Package URL (purl) for a component."""
        eco = component.get('type', 'unknown')
        purl_type = PURL_TYPES.get(eco, eco)
        name = component.get('name', 'unknown')
        version = component.get('version', '')

        # Encode slashes in Go module paths
        if purl_type == 'golang' and '/' in name:
            encoded_name = name.replace('/', '%2F')
        else:
            encoded_name = name

        if version and version != '*':
            return f"pkg:{purl_type}/{encoded_name}@{version}"
        return f"pkg:{purl_type}/{encoded_name}"

    def export_cyclonedx(self, components: List[Dict], output_path) -> Path:
        """
        Export components as CycloneDX 1.4 JSON format.

        Args:
            components: List of component dicts from parsing.
            output_path: Path to write the JSON file.

        Returns:
            Path to the written file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'tools': [{
                    'vendor': 'Purple Team Platform',
                    'name': 'sbom-generator',
                    'version': '7.0',
                }],
            },
            'components': [],
        }

        for comp in components:
            entry = {
                'type': 'library',
                'name': comp.get('name', 'unknown'),
                'version': comp.get('version', ''),
                'purl': self._make_purl(comp),
            }
            bom['components'].append(entry)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(bom, f, indent=2)

        logger.info(
            f"CycloneDX BOM exported: {output_path} "
            f"({len(components)} components)"
        )
        return output_path

    def export_spdx(self, components: List[Dict], output_path) -> Path:
        """
        Export components as SPDX 2.3 JSON format.

        Args:
            components: List of component dicts from parsing.
            output_path: Path to write the JSON file.

        Returns:
            Path to the written file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc_namespace = (
            f"https://spdx.org/spdxdocs/purple-team-sbom-"
            f"{uuid.uuid4()}"
        )

        spdx = {
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'purple-team-sbom',
            'documentNamespace': doc_namespace,
            'creationInfo': {
                'created': datetime.now(timezone.utc).isoformat(),
                'creators': [
                    'Tool: PurpleTeamPlatform-sbom-generator-7.0',
                ],
                'licenseListVersion': '3.19',
            },
            'packages': [],
            'relationships': [],
        }

        for i, comp in enumerate(components):
            spdx_id = f"SPDXRef-Package-{i}"
            name = comp.get('name', 'unknown')
            version = comp.get('version', '')

            package = {
                'SPDXID': spdx_id,
                'name': name,
                'versionInfo': version if version and version != '*' else 'NOASSERTION',
                'downloadLocation': 'NOASSERTION',
                'filesAnalyzed': False,
                'supplier': 'NOASSERTION',
                'externalRefs': [{
                    'referenceCategory': 'PACKAGE-MANAGER',
                    'referenceType': 'purl',
                    'referenceLocator': self._make_purl(comp),
                }],
            }
            spdx['packages'].append(package)

            spdx['relationships'].append({
                'spdxElementId': 'SPDXRef-DOCUMENT',
                'relatedSpdxElement': spdx_id,
                'relationshipType': 'DESCRIBES',
            })

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(spdx, f, indent=2)

        logger.info(
            f"SPDX document exported: {output_path} "
            f"({len(components)} packages)"
        )
        return output_path

    # ------------------------------------------------------------------
    # Coverage indicator
    # ------------------------------------------------------------------

    def get_coverage_indicator(self, scan_result: Dict) -> str:
        """
        Return an honest coverage string describing what was and was
        NOT analyzed.  Critical for transparency: we must never claim
        more coverage than we actually provide.

        Args:
            scan_result: The dict returned by scan_directory().

        Returns:
            Human-readable coverage string.
        """
        analyzed = []
        not_analyzed = [
            'system packages',
            'C/C++ libraries',
            'static binaries',
            'vendored / copied source',
        ]

        if scan_result.get('python'):
            analyzed.append('Python (pip)')
        if scan_result.get('node'):
            analyzed.append('Node.js (npm)')
        if scan_result.get('go'):
            analyzed.append('Go (modules)')
        if scan_result.get('rust'):
            analyzed.append('Rust (cargo)')
        if scan_result.get('java'):
            analyzed.append('Java (Maven)')
        if scan_result.get('ruby'):
            analyzed.append('Ruby (gems)')
        if scan_result.get('php'):
            analyzed.append('PHP (Composer)')

        indicator = (
            f"Analyzed: {', '.join(analyzed) if analyzed else 'None'}. "
            f"NOT analyzed: {', '.join(not_analyzed)}."
        )
        return indicator

    # ------------------------------------------------------------------
    # Vulnerability checking (external tool integration)
    # ------------------------------------------------------------------

    def check_vulnerabilities(self, components: List[Dict]) -> List[Dict]:
        """
        Run vulnerability checking against discovered components using
        trivy or grype if available on the system.

        Args:
            components: List of component dicts from parsing.

        Returns:
            List of vulnerability dicts, or empty list with a note
            if no scanner is available.
        """
        # Check for trivy
        trivy_path = shutil.which('trivy')
        if trivy_path:
            return self._check_with_trivy(components, trivy_path)

        # Check for grype
        grype_path = shutil.which('grype')
        if grype_path:
            return self._check_with_grype(components, grype_path)

        logger.info(
            "No vulnerability scanner found. "
            "Install trivy or grype for vulnerability checking."
        )
        return [{
            'note': 'Install trivy or grype for vulnerability checking',
            'scanners_checked': ['trivy', 'grype'],
            'vulnerabilities': [],
        }]

    def _check_with_trivy(self, components: List[Dict],
                          trivy_path: str) -> List[Dict]:
        """Run trivy sbom scan against a CycloneDX export."""
        vulns = []

        try:
            # Export a temporary CycloneDX BOM for trivy to scan
            tmp_bom = self.output_dir / '.tmp_trivy_sbom.json'
            self.export_cyclonedx(components, tmp_bom)

            result = subprocess.run(
                [trivy_path, 'sbom', '--format', 'json', str(tmp_bom)],
                capture_output=True, text=True, timeout=120,
            )

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                for target in data.get('Results', []):
                    for v in target.get('Vulnerabilities', []):
                        vulns.append({
                            'id': v.get('VulnerabilityID', ''),
                            'package': v.get('PkgName', ''),
                            'installed_version': v.get('InstalledVersion', ''),
                            'fixed_version': v.get('FixedVersion', ''),
                            'severity': v.get('Severity', ''),
                            'title': v.get('Title', ''),
                        })

            # Clean up temp file
            if tmp_bom.exists():
                tmp_bom.unlink()

        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
            logger.warning(f"Trivy scan failed: {e}")

        return vulns

    def _check_with_grype(self, components: List[Dict],
                          grype_path: str) -> List[Dict]:
        """Run grype scan against a CycloneDX export."""
        vulns = []

        try:
            tmp_bom = self.output_dir / '.tmp_grype_sbom.json'
            self.export_cyclonedx(components, tmp_bom)

            result = subprocess.run(
                [grype_path, f'sbom:{tmp_bom}', '-o', 'json'],
                capture_output=True, text=True, timeout=120,
            )

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                for match in data.get('matches', []):
                    v = match.get('vulnerability', {})
                    artifact = match.get('artifact', {})
                    vulns.append({
                        'id': v.get('id', ''),
                        'package': artifact.get('name', ''),
                        'installed_version': artifact.get('version', ''),
                        'fixed_version': ', '.join(
                            v.get('fix', {}).get('versions', [])
                        ),
                        'severity': v.get('severity', ''),
                        'title': v.get('description', '')[:120],
                    })

            # Clean up temp file
            if tmp_bom.exists():
                tmp_bom.unlink()

        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
            logger.warning(f"Grype scan failed: {e}")

        return vulns


# ------------------------------------------------------------------
# Singleton accessor
# ------------------------------------------------------------------

_sbom_generator: Optional[SBOMGenerator] = None


def get_sbom_generator() -> SBOMGenerator:
    """Get the SBOM generator singleton."""
    global _sbom_generator
    if _sbom_generator is None:
        _sbom_generator = SBOMGenerator()
    return _sbom_generator


# ------------------------------------------------------------------
# Self-test
# ------------------------------------------------------------------

if __name__ == '__main__':
    sg = get_sbom_generator()
    print("SBOM Generator initialized")

    # Test parsing our own project
    project_root = Path(__file__).parent.parent
    print(f"Scanning: {project_root}")

    result = sg.scan_directory(project_root)
    print(f"\nComponents found: {result.get('total_components', 0)}")
    print(f"Package files found: {len(result.get('files_parsed', []))}")
    print(f"\nCoverage: {sg.get_coverage_indicator(result)}")

    if result.get('warnings'):
        print(f"\nWarnings:")
        for w in result['warnings']:
            print(f"  - {w}")

    if result.get('components'):
        print(f"\nFirst 10 components:")
        for comp in result['components'][:10]:
            print(f"  {comp['name']} {comp.get('version', '?')} ({comp['type']})")

        # Test CycloneDX export
        output = paths.reports / 'sbom_cyclonedx.json'
        sg.export_cyclonedx(result['components'], output)
        print(f"\nCycloneDX exported: {output}")

        # Test SPDX export
        output_spdx = paths.reports / 'sbom_spdx.json'
        sg.export_spdx(result['components'], output_spdx)
        print(f"SPDX exported: {output_spdx}")

        # Test vulnerability checking
        print("\nVulnerability check:")
        vuln_results = sg.check_vulnerabilities(result['components'])
        if vuln_results and 'note' in vuln_results[0]:
            print(f"  {vuln_results[0]['note']}")
        else:
            print(f"  Found {len(vuln_results)} vulnerabilities")
            for v in vuln_results[:5]:
                print(f"    {v['id']} {v['package']} ({v['severity']})")
    else:
        print("\nNo components found (no package files in project)")
