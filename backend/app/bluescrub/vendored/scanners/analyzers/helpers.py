"""
Shared helper / false-positive filters used by multiple analyzers.
Extracted from scanners/custom_analyzers.py.
"""


def is_false_positive_credential(credential_value):
    """Filter out false positive credentials (placeholders and test values)."""
    value_lower = credential_value.lower().strip('"\'')
    if len(value_lower) < 4:
        return True
    placeholder_values = {
        'test', 'password', 'admin', 'user', 'root',
        'guest', 'demo', 'sample', 'example', 'dummy',
        'placeholder', 'fake', 'invalid', 'none', 'null',
        'your_api_key_here', 'your_secret_here', 'your_token_here',
        'replace_me', 'change_me', 'update_me', 'fixme',
        '123456', '12345678', 'qwerty', 'password123',
        'admin123', 'test123', 'user123',
    }
    return value_lower in placeholder_values


def is_false_positive_email(email):
    """Filter out false positive emails (test/example emails)."""
    email_lower = email.lower()
    false_positive_domains = {
        'example.com', 'test.com', 'localhost', 'email.com',
        'domain.com', 'company.com', 'org.com', 'foo.com',
        'bar.com', 'sample.com', 'placeholder.com', 'noreply.com',
    }
    false_positive_prefixes = {
        'test', 'example', 'user', 'admin', 'info', 'support',
        'noreply', 'no-reply', 'hello', 'contact', 'mail',
        'demo', 'sample', 'your', 'name', 'email',
    }
    if any(email_lower.endswith(f'@{d}') for d in false_positive_domains):
        return True
    local_part = email_lower.split('@')[0] if '@' in email_lower else ''
    return local_part in false_positive_prefixes


def is_false_positive_path(path_str):
    """Filter out false positive paths (standard system paths)."""
    standard_paths = {
        '/usr/bin', '/usr/lib', '/usr/local', '/usr/share',
        '/usr/include', '/opt/', '/var/log', '/var/run',
        '/tmp', '/etc/', '/dev/', '/proc/', '/sys/',
        '/home/', '/root/', '/bin/', '/sbin/',
    }
    path_lower = path_str.lower()
    return any(path_lower.startswith(p) or p in path_lower for p in standard_paths)


def get_disclosure_fix_recommendation(category, match_str):
    """Get recommended fix for information disclosure issues."""
    fixes = {
        'debug_info': 'Remove debug output or use conditional logging',
        'system_info': 'Avoid exposing system information; use abstractions',
        'path_disclosure': 'Use relative paths or environment variables',
        'tool_signatures': 'Remove or randomize tool signatures',
        'network_info': 'Use configuration files for network settings',
    }
    return fixes.get(category, 'Review and remediate information disclosure')


def get_crypto_fix_recommendation(category, match_str):
    """Get recommended fix for cryptographic vulnerabilities."""
    fixes = {
        'weak_algorithms': 'Use SHA-256+ for hashing, AES-256 for encryption',
        'weak_random': 'Use secrets module (Python) or crypto.randomBytes (Node)',
        'hardcoded_keys': 'Use environment variables or key management service',
        'weak_key_generation': 'Use minimum 2048-bit RSA, 256-bit AES keys',
        'insecure_protocols': 'Use TLS 1.2+ with strong cipher suites',
        'custom_crypto': 'Use established cryptographic libraries instead',
    }
    return fixes.get(category, 'Review cryptographic implementation')


def get_secrets_fix_recommendation(category):
    """Get recommended fix for secrets/credentials issues."""
    fixes = {
        'target_info': 'Move target information to configuration files',
        'exploitation_secrets': 'Use environment variables for sensitive data',
        'credentials': 'Use credential manager or environment variables',
        'api_keys': 'Use secret management service (e.g., HashiCorp Vault)',
        'crypto_material': 'Store keys in secure key store, not in code',
        'internal_info': 'Remove internal information from source code',
    }
    return fixes.get(category, 'Review and secure sensitive information')


def is_logger_debug_call(content, match_start, match_end):
    """Check if match is part of a logger.debug() call."""
    context_start = max(0, match_start - 100)
    context = content[context_start:match_start]
    return 'logger.debug' in context.lower() or 'logging.debug' in context.lower()


def is_hex_format_string(match_str):
    """Check if match is a hex format string (0x%04X, 0x%08x, etc.)."""
    import re
    return bool(re.search(r'0x%[0-9]*[xX]', match_str))


def is_argparse_help_text(content, match_start):
    """Check if match is part of argparse help text."""
    context_start = max(0, match_start - 200)
    context_end = min(len(content), match_start + 200)
    context = content[context_start:context_end]
    return 'help=' in context or 'description=' in context or 'metavar=' in context


def is_weak_crypto_security_context(content, match_start):
    """Check if weak crypto is used in security context vs non-security."""
    context_start = max(0, match_start - 200)
    context_end = min(len(content), match_start + 200)
    context = content[context_start:context_end].lower()
    non_security = {
        'checksum', 'hash', 'integrity', 'verify', 'compare',
        'git', 'commit', 'file', 'download', 'archive',
        'fingerprint', 'digest', 'etag', 'cache',
    }
    security = {
        'password', 'secret', 'key', 'token', 'credential',
        'encrypt', 'decrypt', 'sign', 'verify_signature',
        'hmac', 'authentication', 'authorization',
    }
    if any(kw in context for kw in security):
        return True
    if any(kw in context for kw in non_security):
        return False
    return True

