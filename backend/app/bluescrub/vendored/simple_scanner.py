#!/usr/bin/env python3
"""
Enhanced Security Scanner for Exploit Code
Uses BlueScrub comprehensive analysis modules
"""

import importlib
import json
import os
import re
import sys
from datetime import datetime
from collections import defaultdict


from backend.app.bluescrub.vendored.scanners.source_checkers import CoreChecksMixin, VulnChecksMixin, OpsecChecksMixin


import logging

logger = logging.getLogger(__name__)
DEFENSIVE_TYPED_SCANS = {
    'enhanced_secrets',
    'information_disclosure',
    'memory_safety',
    'crypto_vulnerabilities',
    'supply_chain',
    'opsec_analysis',
    'exploitation_analysis',
    'shellcode_security',
    'exploit_reliability',
    'payload_obfuscation',
    'code_similarity',
    'metadata_leakage',
    'network_security',
    'anti_analysis',
    'forensic_artifacts',
    'privilege_escalation',
}

class SimpleSecurityScanner(CoreChecksMixin, VulnChecksMixin, OpsecChecksMixin):
    """Scan code for security issues.

    Check methods are provided by the mixin base classes in
    ``scanners.source_checkers``.
    """

    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.findings = defaultdict(list)
        self.files_scanned = 0
        self.issues_found = 0
        self.tooling = {}

    def scan(self):
        """Run the comprehensive security scan"""
        logger.info(f"🔍 Scanning: {self.target_dir}")

        # Get all code files
        files = self._get_code_files()
        logger.info(f"📁 Found {len(files)} code files")

        # Run comprehensive analysis
        logger.info("\n📊 Running comprehensive security analysis...")

        # Try to use BlueScrub defensive_security_scanner if available
        if self._try_defensive_scanner(files):
            logger.info("✅ Using BlueScrub comprehensive analysis")
        else:
            logger.info("⚠️  Using basic pattern matching analysis")
            # Fallback to basic scanning
            for filepath in files:
                self._scan_file(filepath)
            self._set_basic_scan_tooling()

        return self._generate_report()

    def _try_defensive_scanner(self, files=None):
        """Try to use BlueScrub defensive_security_scanner for comprehensive analysis"""
        try:
            defensive_module = importlib.import_module('defensive_security_scanner')
            analyze_defensive_security = getattr(defensive_module, 'analyze_defensive_security', None)
            if analyze_defensive_security is None:
                return False

            logger.info("🔍 Running BlueScrub defensive security scanner...")
            report_data = analyze_defensive_security(self.target_dir)
            self._merge_defensive_findings(report_data, fallback_files_scanned=len(files or []))
            return True
        except Exception as e:
            logger.info(f"⚠️  Could not use defensive scanner: {e}")
            return False

    def _merge_defensive_findings(self, report_data, fallback_files_scanned=0):
        """Merge findings from defensive scanner"""
        try:
            self.findings = defaultdict(list)
            self.issues_found = 0

            available_tools = report_data.get('available_tools', {}) if isinstance(report_data, dict) else {}
            scans = report_data.get('scans', {}) if isinstance(report_data, dict) else {}
            tool_status = {
                tool_name: {
                    'available': bool(available),
                    'executed': tool_name in scans,
                    'kind': 'external',
                    'findings_count': 0,
                }
                for tool_name, available in available_tools.items()
            }

            for scan_name, scan_results in scans.items():
                grouped_issues = self._extract_scan_findings(scan_name, scan_results)
                findings_count = 0

                for category, issues in grouped_issues.items():
                    if not issues:
                        continue
                    self.findings[category].extend(issues)
                    findings_count += len(issues)

                status = tool_status.setdefault(scan_name, {
                    'available': True,
                    'executed': True,
                    'kind': 'builtin',
                    'findings_count': 0,
                })
                status['executed'] = True
                status['findings_count'] = findings_count
                if isinstance(scan_results, dict) and scan_results.get('error'):
                    status['error'] = scan_results.get('error')

                self.issues_found += findings_count

            self.files_scanned = report_data.get('files_scanned') or fallback_files_scanned
            self.tooling = {
                'mode': 'defensive_security_scanner',
                'scanner': 'defensive_security_scanner',
                'fallback_used': False,
                'available_tools': available_tools,
                'executed_scans': sorted(scans.keys()),
                'skipped_tools': sorted(
                    tool_name
                    for tool_name, status in tool_status.items()
                    if status.get('kind') == 'external' and not status.get('executed')
                ),
                'tool_status': tool_status,
                'execution_time': report_data.get('execution_time'),
            }
        except Exception as e:
            logger.info(f"⚠️  Error merging findings: {e}")

    def _set_basic_scan_tooling(self):
        """Record fallback scanner metadata for UI/report consumers."""
        self.tooling = {
            'mode': 'basic_pattern_matching',
            'scanner': 'SimpleSecurityScanner',
            'fallback_used': True,
            'available_tools': {},
            'executed_scans': ['basic_pattern_matching'],
            'skipped_tools': [],
            'tool_status': {
                'basic_pattern_matching': {
                    'available': True,
                    'executed': True,
                    'kind': 'builtin',
                    'findings_count': self.issues_found,
                }
            },
        }

    def _format_scan_name(self, scan_name):
        return str(scan_name or 'source_scan').replace('_', ' ').title()

    def _normalize_severity(self, value):
        severity = str(value or 'MEDIUM').upper()
        return severity if severity in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'} else 'MEDIUM'

    def _scan_uses_typed_categories(self, scan_name):
        return scan_name in DEFENSIVE_TYPED_SCANS

    # ── Shellcode / exploit enrichment ──────────────────────────────
    def _explode_rich_scanner_results(self, scan_name, raw_results):
        """Break per-file scanner dicts (shellcode, exploit-reliability, etc.)
        into individual sub-findings with specific descriptions and offsets.

        Delegates to ``scanners.finding_exploders`` for the actual conversion.
        """
        from backend.app.bluescrub.vendored.scanners.finding_exploders import explode_rich_scanner_results
        return explode_rich_scanner_results(scan_name, raw_results)

    # ── End enrichment ──────────────────────────────────────────────
    # Individual _explode_* methods extracted to scanners/finding_exploders.py

    _STUB_LINE = True  # placeholder
    def _extract_scan_findings(self, scan_name, scan_results):
        grouped_issues = defaultdict(list)
        issues = []

        # Try to explode rich scanner results first
        exploded = self._explode_rich_scanner_results(scan_name, scan_results)
        if exploded is not None:
            for issue in exploded:
                normalized = self._normalize_external_issue(scan_name, issue)
                category = self._resolve_issue_category(scan_name, issue)
                grouped_issues[category].append(normalized)
            return grouped_issues

        if isinstance(scan_results, list):
            issues = [issue for issue in scan_results if isinstance(issue, dict)]
        elif isinstance(scan_results, dict):
            if isinstance(scan_results.get('results'), list):
                issues = [issue for issue in scan_results['results'] if isinstance(issue, dict)]
            elif isinstance(scan_results.get('results'), dict):
                for file_path, file_issues in scan_results['results'].items():
                    if not isinstance(file_issues, list):
                        continue
                    for issue in file_issues:
                        if isinstance(issue, dict):
                            issues.append(self._normalize_external_issue(scan_name, issue, file_hint=file_path))
            elif isinstance(scan_results.get('issues'), list):
                issues = [issue for issue in scan_results['issues'] if isinstance(issue, dict)]
            elif isinstance(scan_results.get('Issues'), list):
                issues = [issue for issue in scan_results['Issues'] if isinstance(issue, dict)]
            elif isinstance(scan_results.get('findings'), dict):
                for category, category_issues in scan_results['findings'].items():
                    if not isinstance(category_issues, list):
                        continue
                    for issue in category_issues:
                        if isinstance(issue, dict):
                            normalized_issue = self._normalize_external_issue(
                                scan_name,
                                issue,
                                category_hint=category,
                            )
                            grouped_issues[category].append(normalized_issue)
            elif any(scan_results.get(key) for key in ('file', 'path', 'filename', 'File')):
                issues = [scan_results]

        for issue in issues:
            normalized_issue = self._normalize_external_issue(scan_name, issue)
            category = self._resolve_issue_category(scan_name, issue)
            grouped_issues[category].append(normalized_issue)

        return grouped_issues

    def _resolve_issue_category(self, scan_name, issue):
        if self._scan_uses_typed_categories(scan_name):
            return issue.get('category') or issue.get('type') or self._format_scan_name(scan_name)
        return self._format_scan_name(scan_name)

    def _normalize_external_issue(self, scan_name, issue, file_hint=None, category_hint=None):
        extra = issue.get('extra', {}) if isinstance(issue.get('extra'), dict) else {}
        metadata = extra.get('metadata', {}) if isinstance(extra.get('metadata'), dict) else {}
        source_metadata = issue.get('SourceMetadata', {}) if isinstance(issue.get('SourceMetadata'), dict) else {}
        source_data = source_metadata.get('Data', {}) if isinstance(source_metadata.get('Data'), dict) else {}
        filesystem_data = source_data.get('Filesystem', {}) if isinstance(source_data.get('Filesystem'), dict) else {}
        start = issue.get('start', {}) if isinstance(issue.get('start'), dict) else {}

        file_path = (
            file_hint
            or issue.get('file')
            or issue.get('file_path')
            or issue.get('path')
            or issue.get('Path')
            or issue.get('filename')
            or issue.get('File')
            or filesystem_data.get('file')
            or 'N/A'
        )
        line_number = (
            issue.get('line')
            or issue.get('line_number')
            or issue.get('StartLine')
            or start.get('line')
        )
        title = (
            issue.get('type')
            or issue.get('issue')
            or issue.get('RuleID')
            or issue.get('rule')
            or issue.get('check_id')
            or issue.get('test_name')
            or category_hint
            or self._format_scan_name(scan_name)
        )
        description = (
            issue.get('description')
            or issue.get('issue')
            or issue.get('issue_text')
            or issue.get('Description')
            or extra.get('message')
            or issue.get('DetectorName')
            or title
        )
        code = issue.get('code') or issue.get('pattern') or issue.get('match') or issue.get('Match') or issue.get('secret') or issue.get('Raw') or description
        recommendation = issue.get('recommended_fix') or issue.get('recommendation') or issue.get('Resolution') or metadata.get('fix')

        return {
            'file': file_path,
            'line': line_number,
            'code': str(code)[:500],
            'severity': self._normalize_severity(
                issue.get('severity')
                or issue.get('issue_severity')
                or issue.get('Severity')
                or extra.get('severity')
                or metadata.get('severity')
            ),
            'type': title,
            'description': description,
            'recommendation': recommendation,
        }

    def _get_code_files(self):
        """Get all code files"""
        extensions = {'.py', '.js', '.go', '.c', '.cpp', '.h', '.java', '.rb', '.php', '.sh'}
        files = []

        for root, dirs, filenames in os.walk(self.target_dir):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]

            for filename in filenames:
                if any(filename.endswith(ext) for ext in extensions):
                    files.append(os.path.join(root, filename))

        return files

    def _scan_file(self, filepath):
        """Scan a single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            self.files_scanned += 1

            # Check for various security issues
            self._check_hardcoded_secrets(filepath, content)
            self._check_suspicious_patterns(filepath, content)
            self._check_unsafe_functions(filepath, content)
            self._check_network_indicators(filepath, content)
            self._check_forensic_artifacts(filepath, content)
            self._check_metadata_leakage(filepath, content)
            # Phase 2 vulnerability checks
            self._check_format_string_vulns(filepath, content)
            self._check_integer_overflow(filepath, content)
            self._check_use_after_free(filepath, content)
            self._check_race_conditions(filepath, content)
            self._check_deserialization_sinks(filepath, content)
            # Detectability checks
            self._check_etw_amsi_bypass(filepath, content)
            self._check_syscall_vs_api(filepath, content)
            # Attribution checks
            self._check_timezone_locale_leakage(filepath, content)
            self._check_build_env_leakage(filepath, content)
            self._check_unicode_homoglyphs(filepath, content)
            # OPSEC checks
            self._check_dns_tunneling(filepath, content)
            self._check_timestamp_stomping(filepath, content)
            self._check_log_evasion(filepath, content)
            self._check_process_injection_classification(filepath, content)
            self._check_cleanup_routines(filepath, content)
            # Exploitation checks
            self._check_stack_pivot(filepath, content)
            self._check_kernel_exploit_patterns(filepath, content)
            self._check_sandbox_escape(filepath, content)

        except Exception as e:
            logger.info(f"Error scanning {filepath}: {e}")

    # ── _check_* methods and helpers are provided by the three mixin classes ──
    # CoreChecksMixin  → _check_hardcoded_secrets, _check_suspicious_patterns,
    #                     _check_unsafe_functions, _check_network_indicators
    # VulnChecksMixin  → _check_forensic_artifacts, _check_metadata_leakage,
    #                     _check_format_string_vulns, _check_integer_overflow,
    #                     _check_use_after_free, _check_race_conditions,
    #                     _check_deserialization_sinks
    # OpsecChecksMixin → _check_etw_amsi_bypass, _check_syscall_vs_api,
    #                     _check_timezone_locale_leakage, _check_build_env_leakage,
    #                     _check_unicode_homoglyphs, _check_dns_tunneling,
    #                     _check_timestamp_stomping, _check_log_evasion,
    #                     _check_process_injection_classification,
    #                     _check_cleanup_routines, _check_stack_pivot,
    #                     _check_kernel_exploit_patterns, _check_sandbox_escape

    def _generate_report(self):
        """Generate the security report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_dir,
            'files_scanned': self.files_scanned,
            'issues_found': self.issues_found,
            'findings': dict(self.findings),
            'tooling': self.tooling,
            'summary': self._calculate_risk_score()
        }
        return report

    def _calculate_risk_score(self):
        """Calculate overall risk score"""
        critical = 0
        high = 0
        medium = 0
        low = 0

        for issues in self.findings.values():
            for issue in issues:
                severity = self._normalize_severity(issue.get('severity'))
                if severity == 'CRITICAL':
                    critical += 1
                elif severity == 'HIGH':
                    high += 1
                elif severity == 'MEDIUM':
                    medium += 1
                else:
                    low += 1

        risk_score = min(100, (critical * 30) + (high * 15) + (medium * 5) + low)

        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'recommendation': f'Your code has a {risk_level} security risk level'
        }

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        logger.info("Usage: python3 simple_scanner.py <directory>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = SimpleSecurityScanner(target)
    report = scanner.scan()

    # Save report
    report_file = f'security_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"\n✅ Report saved: {report_file}")
    logger.info(json.dumps(report, indent=2))

