"""Memory Safety Analyzer — detects buffer overflows, use-after-free, etc."""

import re

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer


class MemorySafetyAnalyzer(BaseAnalyzer):
    LABEL = "🛡️ Memory safety scan"
    EXTENSIONS = ('.py', '.c', '.cpp', '.h', '.hpp', '.cc', '.cxx')

    PATTERN_MAP = {
        'buffer_overflow': [
            r'(?i)(strcpy|strcat|sprintf|gets|scanf)\s*\(',
            r'(?i)memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
            r'(?i)buffer\[[^\]]*\]\s*=',
            r'(?i)char\s+[a-zA-Z_][a-zA-Z0-9_]*\[\d+\]',
        ],
        'format_string': [
            r'(?i)(printf|fprintf|sprintf|snprintf)\s*\([^,)]*%[^,)]*\)',
            r'(?i)format\s*\([^)]*%[^)]*\)',
            # Note: Python .format() is NOT a format-string vulnerability.
            # Only flag the dangerous subset: unpacked args or dunder access.
            r'\.format\s*\(\s*\*',          # .format(*user_input) — potential issue
        ],
        'integer_overflow': [
            r'(?i)(int|long|short)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^;]*\*[^;]*',
            r'(?i)size\s*\*\s*count',
            r'(?i)length\s*\+\s*offset',
        ],
        'use_after_free': [
            r'(?i)free\s*\([^)]+\)',
            r'(?i)delete\s+[a-zA-Z_][a-zA-Z0-9_]*',
            r'(?i)malloc\s*\([^)]+\)',
            r'(?i)calloc\s*\([^)]+\)',
        ],
        'python_unsafe': [
            r'(?i)eval\s*\(',
            r'(?i)exec\s*\(',
            r'(?i)compile\s*\(',
            r'(?i)__import__\s*\(',
        ],
    }

    # Skip categories that don't apply to the file's language.
    _C_ONLY = {'buffer_overflow', 'use_after_free', 'integer_overflow'}
    _PY_ONLY = {'python_unsafe'}
    HIGH_SEVERITY = {'buffer_overflow', 'use_after_free', 'python_unsafe'}

    def analyze_file(self, file_path, content, root_directory):
        is_python = file_path.endswith('.py')
        issues = []

        for category, patterns in self.PATTERN_MAP.items():
            if is_python and category in self._C_ONLY:
                continue
            if not is_python and category in self._PY_ONLY:
                continue

            for pattern in patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    # Filter out comments in Python
                    if is_python and category == 'python_unsafe':
                        line_start = content.rfind('\n', 0, match.start()) + 1
                        line_end = content.find('\n', match.start())
                        if line_end == -1:
                            line_end = len(content)
                        line_content = content[line_start:line_end]
                        comment_pos = line_content.find('#')
                        match_pos = match.start() - line_start
                        if comment_pos != -1 and match_pos > comment_pos:
                            continue

                    issues.append({
                        'file': file_path,
                        'line': self._line_number(content, match.start()),
                        'category': category,
                        'pattern': pattern,
                        'match': match.group(0)[:100],
                        'severity': 'HIGH' if category in self.HIGH_SEVERITY else 'MEDIUM',
                    })
        return issues

