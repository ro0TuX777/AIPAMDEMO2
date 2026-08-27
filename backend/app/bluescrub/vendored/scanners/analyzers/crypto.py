"""Cryptographic Vulnerability Analyzer — detects weak crypto usage."""

import re

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.helpers import (
    get_crypto_fix_recommendation,
    is_weak_crypto_security_context,
)


class CryptoVulnerabilityAnalyzer(BaseAnalyzer):
    LABEL = "🔐 Crypto vulnerability scan"
    EXTENSIONS = (
        '.py', '.js', '.php', '.rb', '.go', '.java',
        '.cpp', '.c', '.h',
    )

    PATTERN_MAP = {
        'weak_algorithms': [
            r'(?i)(md5|sha1|des|rc4|md4)\s*\(',
            r'(?i)(MD5|SHA1|DES|RC4|MD4)\.new\(',
            r'(?i)hashlib\.(md5|sha1)\(',
            r'(?i)Cipher\.(DES|RC4|ARC4)',
        ],
        'weak_random': [
            r'(?i)random\.random\(\)',
            r'(?i)Math\.random\(\)',
            r'(?i)rand\(\)',
            r'(?i)srand\([^)]*time[^)]*\)',
        ],
        'hardcoded_keys': [
            r'(?i)(key|secret|password)\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']',
            r'(?i)(aes|rsa|dsa)_key\s*[=:]\s*["\'][^"\']{20,}["\']',
            r'(?i)(private|public)_key\s*[=:]\s*["\'][^"\']{50,}["\']',
        ],
        'weak_key_generation': [
            r'(?i)generate_key\([^)]*\d{1,3}[^)]*\)',
            r'(?i)RSA\.generate\([^)]*(?:512|768|1024)[^)]*\)',
            r'(?i)key_size\s*[=:]\s*(?:512|768|1024)',
        ],
        'insecure_protocols': [
            r'(?i)(ssl|tls)_version\s*[=:]\s*["\']?(?:SSLv2|SSLv3|TLSv1\.0)["\']?',
            r'(?i)PROTOCOL_(?:SSLv2|SSLv3|TLSv1)',
            r'(?i)verify_mode\s*[=:]\s*ssl\.CERT_NONE',
        ],
        'custom_crypto': [
            r'(?i)def\s+(encrypt|decrypt|hash|sign|verify)\s*\(',
            r'(?i)class\s+[a-zA-Z_][a-zA-Z0-9_]*(?:Cipher|Crypto|Hash|Sign)',
            r'(?i)(xor|rot13|caesar)\s*\(',
        ],
    }

    HIGH_SEVERITY = {'weak_algorithms', 'hardcoded_keys', 'custom_crypto'}

    def analyze_file(self, file_path, content, root_directory):
        issues = []
        for category, patterns in self.PATTERN_MAP.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    if category == 'weak_algorithms':
                        if not is_weak_crypto_security_context(content, match.start()):
                            continue
                    issues.append({
                        'file': file_path,
                        'line': self._line_number(content, match.start()),
                        'category': category,
                        'pattern': pattern,
                        'match': match.group(0)[:100],
                        'severity': 'HIGH' if category in self.HIGH_SEVERITY else 'MEDIUM',
                        'recommended_fix': get_crypto_fix_recommendation(category, match.group(0)),
                    })
        return issues

