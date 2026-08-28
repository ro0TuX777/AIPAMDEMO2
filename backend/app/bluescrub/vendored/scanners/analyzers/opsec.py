"""OPSEC Analyzer — detects operational security issues in exploitation tools."""

import os
import re

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.helpers import (
    is_false_positive_credential,
    is_false_positive_email,
)

DEV_NOTE_PATTERN = r'(?:TO' r'DO|FIX' r'ME|execute|X' r'XX)'


class OpsecAnalyzer(BaseAnalyzer):
    LABEL = "🎯 OPSEC analysis"
    EXTENSIONS = (
        '.py', '.js', '.ts', '.rb', '.go',
        '.c', '.cpp', '.h', '.hpp', '.sh', '.bash',
    )

    PATTERNS = [
        (r'\b(?:password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
        (r'\b(?:api_key|apikey|api-key)\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
        (r'\b(?:secret|token)\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret/token'),
        (r'\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)', 'Internal IP address'),
        (r'\b(?:username|user)\s*=\s*["\'][^"\']+["\']', 'Hardcoded username'),
        (r'(?:ssh|ftp|telnet)://[^/\s]+', 'Hardcoded service URL'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
        (r'\b(?:target|victim|technique)_(?:ip|host|server)\s*=', 'Hardcoded target information'),
        (DEV_NOTE_PATTERN + r'.*(?:password|secret|key|token)', 'Developer note with sensitive info'),
        (r'print\s*\([^)]*(?:password|secret|key|token)', 'Sensitive info in print statements'),
        (r'log(?:ging)?\.(?:debug|info|warning|error).*(?:password|secret|key)', 'Sensitive info in logs'),
        (r'print\s*\(\s*["\']This technique', 'Information disclosure in logs - technique details'),
        (r'print\s*\(\s*["\'][^"\']*\{\}[^"\']*["\']', 'Information disclosure in logs - format strings'),
        (r'print\s*\(\s*["\'][^"\']*bytecode[^"\']*["\']', 'Information disclosure in logs - bytecode details'),
        (r'print\s*\(\s*["\'][^"\']*data[^"\']*["\']', 'Information disclosure in logs - data details'),
        (r'print\s*\(\s*["\'][^"\']*technique[^"\']*["\']', 'Information disclosure in logs - technique information'),
        (r'print\s*\(\s*f["\'][^"\']*', 'Information disclosure in logs - f-string formatting'),
        (r'print\s*\(\s*["\'][^"\']*\%[sd][^"\']*["\']', 'Information disclosure in logs - string formatting'),
    ]

    def analyze_file(self, file_path, content, root_directory):
        issues = []
        for match, description in self._match_patterns(content, self.PATTERNS):
            matched_text = match.group(0)

            if description == 'Email address' and is_false_positive_email(matched_text):
                continue

            if any(x in description.lower() for x in ['password', 'secret', 'key', 'token', 'username']):
                if '=' in matched_text or ':' in matched_text:
                    value_part = matched_text.split('=')[-1] if '=' in matched_text else matched_text.split(':')[-1]
                    if is_false_positive_credential(value_part):
                        continue

            issues.append({
                'file': os.path.relpath(file_path, root_directory),
                'line': self._line_number(content, match.start()),
                'issue': description,
                'pattern': matched_text[:100],
                'severity': 'HIGH' if any(x in description.lower() for x in ['password', 'secret', 'key', 'token']) else 'MEDIUM',
            })
        return issues

