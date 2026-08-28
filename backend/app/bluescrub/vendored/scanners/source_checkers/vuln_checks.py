"""Vulnerability checks: forensic artifacts, metadata leakage, memory safety, deserialization

Mixin methods inherited by SimpleSecurityScanner.
"""

import re

DEV_NOTE_PATTERN = r'(?:TO' r'DO|FIX' r'ME|H' r'ACK|X' r'XX)'


class VulnChecksMixin:
    """Vulnerability checks: forensic artifacts, metadata leakage, memory safety, deserialization"""
    def _check_forensic_artifacts(self, filepath, content):
        """Check for forensic artifacts"""
        patterns = {
            'Temp Files': r'(/tmp/|C:\\Temp\\|%TEMP%)',
            'Debug Symbols': r'(debug|DEBUG|Debug)',
            'Comments': r'#.*?' + DEV_NOTE_PATTERN,
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Path Disclosure': r'(/[a-zA-Z0-9/_.-]+|C:\\[a-zA-Z0-9\\_.-]+)',
            'Git Hashes': r'\b[0-9a-f]{40}\b',
            'Credentials': r'(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*["\']?[^\s"\']+',
            'Weak Crypto': r'(md5|sha1|des|rc4|base64)',
        }

        for artifact_type, pattern in patterns.items():
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                filtered_matches = []
                lines = content.split('\n')

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''

                    # For temp files, filter out false positives
                    if artifact_type == 'Temp Files':
                        # Skip if in docstring or example
                        if self._is_in_docstring_or_example(content, match.start()):
                            continue

                        # Skip if in string literal
                        if self._is_in_string_literal(content, match.start(), match.end()):
                            continue

                        # Skip if it's an example or documentation
                        if self._is_temp_file_example(line_content):
                            continue

                        # Skip if it's a default configuration value
                        if self._is_temp_file_default_config(line_content):
                            continue

                    # For Path Disclosure, filter out false positives
                    if artifact_type == 'Path Disclosure':
                        # Skip shebang lines - these are standard Unix conventions, not security issues
                        if self._is_shebang_line(line_content):
                            continue

                        # Skip standard system paths that are not sensitive
                        if self._is_standard_system_path(match.group(0)):
                            continue

                        # Skip if in comment or docstring
                        if self._is_in_string_or_comment(content, match.start()):
                            continue

                    filtered_matches.append(match)

                # Only add findings if we have real matches after filtering
                if filtered_matches:
                    # Get first match for code snippet
                    first_match = filtered_matches[0]
                    line_num = content[:first_match.start()].count('\n') + 1
                    code_snippet = lines[line_num - 1] if line_num <= len(lines) else ''
                    code_snippet = code_snippet.strip()[:100]  # Limit to 100 chars

                    self.findings[f'Forensic: {artifact_type}'].append({
                        'file': filepath,
                        'line': line_num,
                        'code': code_snippet,
                        'count': len(filtered_matches),
                        'severity': 'LOW'
                    })

    def _check_metadata_leakage(self, filepath, content):
        """Check for metadata leakage (__file__, debug macros, etc.)"""
        patterns = {
            'Debug Code/Macros': [
                (r'\b__file__\b', 'Debug macros'),
                (r'\b__line__\b', 'Debug macros'),
                (r'\b__func__\b', 'Debug macros'),
                (r'\b__debug__\b', 'Debug flag'),
            ]
        }

        for category, pattern_list in patterns.items():
            for pattern, pattern_type in pattern_list:
                matches = list(re.finditer(pattern, content))
                if matches:
                    lines = content.split('\n')

                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ''

                        # Skip if in comment only
                        if self._is_in_comment_only(content, match.start()):
                            continue

                        code_snippet = line_content.strip()[:100]

                        self.findings[category].append({
                            'file': filepath,
                            'line': line_num,
                            'code': code_snippet,
                            'count': 1,
                            'severity': 'LOW'
                        })
                        self.issues_found += 1

    # ===== PHASE 2: VULNERABILITY DETECTION =====

    def _check_format_string_vulns(self, filepath, content):
        """Check for format string vulnerabilities"""
        patterns = [
            (r'printf\s*\(\s*[a-zA-Z_]\w*\s*\)', 'printf with variable format string'),
            (r'fprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)', 'fprintf with variable format string'),
            (r'sprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)', 'sprintf with variable format string'),
            (r'snprintf\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)', 'snprintf with variable format string'),
            (r'syslog\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)', 'syslog with variable format string'),
            (r'\.format\s*\(\s*\*', 'Python .format() with unpacked args'),
            (r'f["\'].*?\{.*?__\w+__.*?\}', 'f-string with dunder access'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Format String Vulnerability'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_integer_overflow(self, filepath, content):
        """Check for integer overflow risks"""
        patterns = [
            (r'malloc\s*\(\s*\w+\s*\*\s*sizeof', 'malloc with unchecked multiplication'),
            (r'calloc\s*\(\s*\w+\s*,\s*\w+\s*\)', 'calloc with variable sizes'),
            (r'realloc\s*\(\s*\w+\s*,\s*\w+\s*\*', 'realloc with unchecked multiplication'),
            (r'memcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*[\+\-\*]', 'memcpy with arithmetic size'),
            (r'memmove\s*\([^,]+,\s*[^,]+,\s*\w+\s*[\+\-\*]', 'memmove with arithmetic size'),
            (r'size_t\s+\w+\s*=\s*\w+\s*\*\s*\w+', 'size_t multiplication without overflow check'),
            (r'int\s+\w+\s*=.*?atoi\s*\(', 'atoi to int (no range check)'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Integer Overflow'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_use_after_free(self, filepath, content):
        """Check for use-after-free and double-free patterns"""
        patterns = [
            (r'free\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?\1\s*(?:->|\.|\[)', 'Potential use-after-free'),
            (r'free\s*\(\s*(\w+)\s*\)[\s\S]{0,200}?free\s*\(\s*\1\s*\)', 'Potential double-free'),
            (r'delete\s+(\w+)[\s\S]{0,200}?\1\s*(?:->|\.|\[)', 'C++ use-after-delete'),
            (r'delete\s*\[\s*\]\s*(\w+)[\s\S]{0,200}?\1\s*(?:->|\.|\[)', 'C++ use-after-delete[]'),
            (r'free\s*\(\s*\w+\s*\)\s*;\s*(?!.*?=\s*NULL)', 'free() without NULL assignment'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Memory Safety'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'CRITICAL'
                })
                self.issues_found += 1

    def _check_race_conditions(self, filepath, content):
        """Check for race conditions (TOCTOU, unprotected shared state)"""
        patterns = [
            (r'os\.path\.exists\s*\(.*?\)[\s\S]{0,300}?open\s*\(', 'TOCTOU: exists() then open()'),
            (r'access\s*\(.*?\)[\s\S]{0,300}?open\s*\(', 'TOCTOU: access() then open()'),
            (r'stat\s*\(.*?\)[\s\S]{0,300}?(?:open|chmod|chown)\s*\(', 'TOCTOU: stat() then modify'),
            (r'os\.path\.isfile\s*\(.*?\)[\s\S]{0,300}?os\.remove\s*\(', 'TOCTOU: isfile() then remove()'),
            (r'threading\.Thread\(.*?\)[\s\S]{0,500}?(?!.*?Lock\(\))', 'Thread without Lock usage'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            for match in matches[:3]:
                line_num = content[:match.start()].count('\n') + 1
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Race Condition'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'MEDIUM'
                })
                self.issues_found += 1

    def _check_deserialization_sinks(self, filepath, content):
        """Check for unsafe deserialization"""
        patterns = [
            (r'pickle\.loads?\s*\(', 'Python pickle deserialization (RCE risk)'),
            (r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:Safe|Base))', 'PyYAML unsafe load (RCE risk)'),
            (r'yaml\.unsafe_load\s*\(', 'PyYAML explicit unsafe_load'),
            (r'marshal\.loads?\s*\(', 'Python marshal deserialization'),
            (r'shelve\.open\s*\(', 'Python shelve (uses pickle)'),
            (r'jsonpickle\.decode\s*\(', 'jsonpickle deserialization (RCE risk)'),
            (r'unserialize\s*\(', 'PHP unserialize (RCE risk)'),
            (r'ObjectInputStream', 'Java ObjectInputStream deserialization'),
            (r'readObject\s*\(', 'Java readObject deserialization'),
            (r'BinaryFormatter\.Deserialize', '.NET BinaryFormatter (RCE risk)'),
            (r'XmlSerializer.*?Deserialize', '.NET XML deserialization'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Deserialization Sink'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'CRITICAL'
                })
                self.issues_found += 1

    # ===== DETECTABILITY CHECKS =====

