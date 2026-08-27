"""Information Disclosure Analyzer — detects leakage of sensitive information."""

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.helpers import (
    get_disclosure_fix_recommendation,
    is_false_positive_path,
    is_logger_debug_call,
    is_hex_format_string,
    is_argparse_help_text,
)


class InformationDisclosureAnalyzer(BaseAnalyzer):
    LABEL = "📋 Information disclosure scan"
    EXTENSIONS = (
        '.py', '.js', '.php', '.rb', '.go', '.java',
        '.cpp', '.c', '.h', '.sh', '.bat', '.ps1',
    )

    PATTERN_MAP = {
        'debug_info': [
            r'(?i)(print|echo|console\.log|logger)\s*\([^)]*(?:error|exception|stack|trace)[^)]*\)',
            r'(?i)(debug|trace|verbose)\s*[=:]\s*true',
            r'(?i)traceback\.print_exc\(\)',
            r'(?i)printStackTrace\(\)',
        ],
        'system_info': [
            r'(?i)(hostname|computername|username|whoami)',
            r'(?i)os\.environ\[',
            r'(?i)system\(["\'][^"\']*whoami[^"\']*["\']',
            r'(?i)getenv\(["\'][^"\']+["\']',
        ],
        'path_disclosure': [
            r'[C-Z]:[\\\/][^\\\/\s"\']+[\\\/][^\\\/\s"\']+',
            r'\/(?:home|root|usr|opt|var)\/[^\s"\']+',
            r'(?i)__file__|__path__|getcwd\(\)',
        ],
        'tool_signatures': [
            r'(?i)(version|build|release)\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)(author|creator|developer)\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)user-agent\s*[=:]\s*["\'][^"\']+["\']',
        ],
        'network_info': [
            r'(?i)(server|host|endpoint)\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)(port|listen)\s*[=:]\s*\d+',
            r'(?i)bind\(["\'][^"\']+["\'],\s*\d+\)',
        ],
    }

    HIGH_SEVERITY_CATEGORIES = {'system_info', 'path_disclosure'}

    def analyze_file(self, file_path, content, root_directory):
        issues = []
        for match, category in self._match_categorized_patterns(content, self.PATTERN_MAP):
            # --- false-positive filters ---
            if category == 'debug_info':
                if is_logger_debug_call(content, match.start(), match.end()):
                    continue
            if category == 'path_disclosure':
                matched = match.group(0)
                if is_hex_format_string(matched):
                    continue
                if is_argparse_help_text(content, match.start()):
                    continue
                if is_false_positive_path(matched):
                    continue
                if '__file__' in matched.lower():
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.start())
                    if line_end == -1:
                        line_end = len(content)
                    line_content = content[line_start:line_end]
                    if any(x in line_content.lower() for x in ['print(', 'logging', 'logger', 'format', 'f"', "f'"]):
                        continue
            if category == 'network_info':
                match_text = match.group(0)
                if 'port' in match_text.lower() and '=' in match_text:
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.start())
                    if line_end == -1:
                        line_end = len(content)
                    line_content = content[line_start:line_end]
                    if any(x in line_content.lower() for x in ['self._', 'self.', 'port =', 'port=']):
                        continue

            issues.append({
                'file': file_path,
                'line': self._line_number(content, match.start()),
                'category': category,
                'pattern': match.re.pattern,
                'match': match.group(0)[:150],
                'severity': 'HIGH' if category in self.HIGH_SEVERITY_CATEGORIES else 'MEDIUM',
                'recommended_fix': get_disclosure_fix_recommendation(category, match.group(0)),
            })
        return issues

