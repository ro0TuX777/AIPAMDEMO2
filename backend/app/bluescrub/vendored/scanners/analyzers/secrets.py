"""Enhanced Secrets Analyzer — detects secrets and credentials in source code."""

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.helpers import get_secrets_fix_recommendation


class SecretsAnalyzer(BaseAnalyzer):
    LABEL = "🔍 Enhanced secrets scan"
    EXTENSIONS = (
        '.py', '.js', '.php', '.rb', '.go', '.java', '.cpp', '.c', '.h',
        '.sh', '.bat', '.ps1', '.txt', '.md', '.yml', '.yaml',
        '.json', '.xml', '.conf', '.cfg', '.ini',
    )

    PATTERN_MAP = {
        'target_info': [
            r'(?i)(target|victim)_ip\s*[=:]\s*["\']?[\d.]+["\']?',
            r'(?i)(target|victim)_host\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)(target|victim)_domain\s*[=:]\s*["\'][^"\']+["\']',
        ],
        'exploitation_secrets': [
            r'(?i)(data|bytecode)_[a-z0-9_]+\s*[=:]',
            r'(?i)(technique|rce|lfi|sqli)_[a-z0-9_]+\s*[=:]',
            r'(?i)(access_point|webshell)_[a-z0-9_]+\s*[=:]',
        ],
        'credentials': [
            r'(?i)password\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'(?i)(user|admin)_pass\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)(db|database)_pass\s*[=:]\s*["\'][^"\']+["\']',
        ],
        'api_keys': [
            r'(?i)api[_-]?key\s*[=:]\s*["\'][^"\']{20,}["\']',
            r'(?i)(secret|token)[_-]?key\s*[=:]\s*["\'][^"\']{20,}["\']',
            r'(?i)(aws|azure|gcp)[_-]?(key|secret)\s*[=:]\s*["\'][^"\']{20,}["\']',
        ],
        'crypto_material': [
            r'-----BEGIN [A-Z ]+-----',
            r'-----END [A-Z ]+-----',
            r'(?i)(private|public)[_-]?key\s*[=:]\s*["\'][^"\']{50,}["\']',
        ],
        'internal_info': [
            r'(?i)(hostname|computer)\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)(username|user)\s*[=:]\s*["\'][^"\']+["\']',
            r'(?i)(path|directory)\s*[=:]\s*["\'][C-Z]:[\\\/][^"\']+["\']',
            r'(?i)(path|directory)\s*[=:]\s*["\']\/[^"\']+["\']',
        ],
    }

    HIGH_SEVERITY_CATEGORIES = {'credentials', 'api_keys', 'crypto_material'}

    def analyze_file(self, file_path, content, root_directory):
        issues = []
        for match, category in self._match_categorized_patterns(content, self.PATTERN_MAP):
            issues.append({
                'file': file_path,
                'line': self._line_number(content, match.start()),
                'category': category,
                'pattern': match.re.pattern,
                'match': match.group(0)[:100],
                'severity': 'HIGH' if category in self.HIGH_SEVERITY_CATEGORIES else 'MEDIUM',
                'recommended_fix': get_secrets_fix_recommendation(category),
            })
        return issues

