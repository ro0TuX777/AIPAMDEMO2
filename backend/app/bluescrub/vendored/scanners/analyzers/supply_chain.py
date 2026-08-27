"""Supply Chain Analyzer — detects dependency and supply chain security issues."""

import os
import re
import json

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer


class SupplyChainAnalyzer(BaseAnalyzer):
    """Analyzes dependency manifests for supply chain risks.

    This analyzer overrides ``run()`` because it doesn't follow the
    standard "read every source file" pattern — it targets specific
    manifest files (requirements.txt, package.json, etc.).
    """

    LABEL = "📦 Supply chain scan"

    # We handle file filtering ourselves.
    EXTENSIONS = None

    _MANIFEST_NAMES = {
        'requirements.txt', 'requirements-dev.txt',
        'setup.py', 'pyproject.toml', 'Pipfile',
    }

    _SUSPICIOUS_PATTERNS = {
        'unpinned_versions': r'([a-zA-Z0-9_-]+)(?:\s*[><=!]+\s*[\d.]+)?\s*$',
        'dev_dependencies': r'(?i)(test|dev|debug|mock)',
        'typosquatting': r'(?i)(reqeusts|urlib|numpy|scipy|pandas|flask|django)',
        'suspicious_names': r'(?i)(access_point|threat|infection|wrapper|keylog)',
    }

    def run(self, directory):
        from backend.app.bluescrub.vendored.scanners.analyzers.base import DEFAULT_SKIP_DIRS
        skip = DEFAULT_SKIP_DIRS | self.EXTRA_SKIP_DIRS
        issues = []

        req_files = []
        pkg_files = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                if fname in self._MANIFEST_NAMES:
                    req_files.append(os.path.join(root, fname))
                if fname == 'package.json':
                    pkg_files.append(os.path.join(root, fname))

        issues.extend(self._scan_requirements(req_files))
        issues.extend(self._scan_package_json(pkg_files))

        self._log_summary(issues)
        return issues

    # Not used (run is overridden) but required by ABC.
    def analyze_file(self, file_path, content, root_directory):
        return []

    # ------------------------------------------------------------------

    def _scan_requirements(self, req_files):
        issues = []
        for req_file in req_files:
            try:
                with open(req_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except IOError:
                continue
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    for category, pattern in self._SUSPICIOUS_PATTERNS.items():
                        if re.search(pattern, line):
                            issues.append({
                                'file': req_file,
                                'line': line_num,
                                'category': category,
                                'match': line,
                                'severity': 'HIGH' if category in ('typosquatting', 'suspicious_names') else 'MEDIUM',
                            })
        return issues

    def _scan_package_json(self, pkg_files):
        issues = []
        for pkg_file in pkg_files:
            try:
                with open(pkg_file, 'r', encoding='utf-8', errors='ignore') as f:
                    pkg_data = json.loads(f.read())
            except (IOError, json.JSONDecodeError):
                continue
            for dep_type in ('dependencies', 'devDependencies'):
                if dep_type not in pkg_data:
                    continue
                for dep_name, dep_version in pkg_data[dep_type].items():
                    if re.search(r'(?i)(access_point|threat|infection|wrapper)', dep_name):
                        issues.append({
                            'file': pkg_file,
                            'line': 0,
                            'category': 'suspicious_dependency',
                            'match': f"{dep_name}: {dep_version}",
                            'severity': 'HIGH',
                        })
                    elif not re.search(r'[\d.]+', dep_version):
                        issues.append({
                            'file': pkg_file,
                            'line': 0,
                            'category': 'unpinned_version',
                            'match': f"{dep_name}: {dep_version}",
                            'severity': 'MEDIUM',
                        })
        return issues

