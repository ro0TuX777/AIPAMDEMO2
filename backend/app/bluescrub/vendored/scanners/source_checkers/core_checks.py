"""Core security checks: secrets, suspicious patterns, unsafe functions, network indicators

Mixin methods inherited by SimpleSecurityScanner.
"""

import re


class CoreChecksMixin:
    """Core security checks: secrets, suspicious patterns, unsafe functions, network indicators"""
    def _check_hardcoded_secrets(self, filepath, content):
        """Check for hardcoded secrets"""
        patterns = {
            'API Key': r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
            'Password': r'password\s*[=:]\s*["\']([^"\']+)["\']',
            'Token': r'token\s*[=:]\s*["\']([^"\']+)["\']',
            'Private Key': r'-----BEGIN.*PRIVATE KEY-----',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
        }

        for issue_type, pattern in patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                # Extract code snippet
                lines = content.split('\n')
                code_snippet = lines[line_num - 1] if line_num <= len(lines) else ''
                code_snippet = code_snippet.strip()[:100]  # Limit to 100 chars

                self.findings[issue_type].append({
                    'file': filepath,
                    'line': line_num,
                    'code': code_snippet,
                    'severity': 'CRITICAL'
                })
                self.issues_found += 1

    def _is_legitimate_exec_usage(self, line_content):
        """Check if exec/eval usage is legitimate (e.g., dynamic imports)"""
        # Legitimate patterns for exec/eval
        legitimate_patterns = [
            'import',  # exec(f"from X import Y")
            'from',    # exec(f"from X import Y")
            '__name__',  # exec(..., globals(), locals())
            '__dict__',  # exec(..., __dict__)
        ]

        # If the line contains import-related keywords, it's likely legitimate
        for pattern in legitimate_patterns:
            if pattern in line_content.lower():
                return True

        return False

    def _is_part_of_identifier(self, content, match_start, match_end):
        """Check if a match is part of a larger identifier (class/function name)"""
        # Check if preceded by alphanumeric or underscore
        if match_start > 0 and content[match_start - 1] in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':
            return True

        # Check if followed by alphanumeric or underscore
        if match_end < len(content) and content[match_end] in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':
            return True

        return False

    def _is_in_import_statement(self, line_content):
        """Check if the line is an import statement"""
        stripped = line_content.strip()
        return stripped.startswith('import ') or stripped.startswith('from ')

    def _is_in_function_definition(self, line_content):
        """Check if the line is a function/method definition"""
        stripped = line_content.strip()
        return stripped.startswith('def ') and '(' in stripped

    def _is_in_comment_only(self, content, match_start):
        """Check if the match is in a comment (not in code)"""
        # Get the line containing the match
        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_start)
        if line_end == -1:
            line_end = len(content)

        line = content[line_start:line_end]
        match_pos_in_line = match_start - line_start

        # Find the comment marker
        comment_pos = line.find('#')
        if comment_pos != -1 and comment_pos < match_pos_in_line:
            return True

        return False

    def _is_variable_assignment(self, line_content):
        """Check if the line is a variable assignment (e.g., payload = ...)"""
        stripped = line_content.strip()
        # Check if it's a simple variable assignment
        return '=' in stripped and not stripped.startswith('def ') and not stripped.startswith('class ')

    def _is_logging_statement(self, line_content):
        """Check if the line is a logging statement"""
        stripped = line_content.strip()
        # Check for common logging patterns
        logging_patterns = ['logger.', 'print(', 'logging.']
        return any(pattern in stripped for pattern in logging_patterns)

    def _is_in_docstring(self, content, match_start):
        """Check if the match is inside a docstring"""
        # Count triple quotes before the match in the entire content
        before_match = content[:match_start]

        # Count triple quotes
        triple_single_count = before_match.count('"""')
        triple_double_count = before_match.count("'''")

        # If odd number of triple quotes, we're inside a docstring
        return (triple_single_count % 2 == 1) or (triple_double_count % 2 == 1)

    def _is_function_call_argument(self, line_content):
        """Check if the line is a function call with the keyword as argument"""
        stripped = line_content.strip()
        # Check if it looks like a function call (has parentheses)
        return '(' in stripped and ')' in stripped

    def _is_return_statement(self, line_content):
        """Check if the line is a return statement"""
        stripped = line_content.strip()
        return stripped.startswith('return ')

    def _is_socket_import(self, line_content):
        """Check if the line is importing socket module"""
        stripped = line_content.strip()
        return stripped.startswith('import socket') or 'from socket import' in stripped

    def _is_legitimate_networking(self, line_content):
        """Check if the line is legitimate networking code (not C2)"""
        stripped = line_content.strip()

        # Legitimate networking patterns
        legitimate_patterns = [
            'socket.socket',  # Creating a socket
            'socket.AF_',     # Socket address family
            'socket.SOCK_',   # Socket type
            'bind(',          # Binding to a port
            'listen(',        # Listening for connections
            'accept(',        # Accepting connections
            'close(',         # Closing connections
            'timeout',        # Setting timeout
            'setsockopt',     # Socket options
            'getsockopt',     # Getting socket options
        ]

        return any(pattern in stripped for pattern in legitimate_patterns)

    def _is_suspicious_c2_pattern(self, line_content):
        """Check if the line contains suspicious C2 patterns"""
        stripped = line_content.strip().lower()

        # Suspicious C2 patterns - use word boundaries to avoid false positives
        suspicious_patterns = [
            'http://',        # HTTP connections
            'https://',       # HTTPS connections
            'connect(',       # Explicit connect calls
            'recv(',          # Receiving data
            'exfiltrate',     # Data exfiltration
            ' c2 ',           # C2 reference (with word boundaries)
            'c2_',            # C2 reference (with underscore)
            '_c2',            # C2 reference (with underscore)
            'command_control',# Command control
            'callback',       # Callback patterns
        ]

        return any(pattern in stripped for pattern in suspicious_patterns)

    def _is_socket_method_call(self, line_content):
        """Check if the line is a socket method call (e.g., s.send(), s.recv())"""
        stripped = line_content.strip()
        # Pattern: variable.method() where variable is typically a socket
        socket_methods = [
            '.send(',
            '.recv(',
            '.connect(',
            '.bind(',
            '.listen(',
            '.accept(',
            '.close(',
            '.shutdown(',
        ]
        return any(method in stripped for method in socket_methods)

    def _is_in_string_or_comment(self, content, match_start):
        """Check if a match is inside a string literal or comment"""
        # Get the line containing the match
        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_start)
        if line_end == -1:
            line_end = len(content)

        line = content[line_start:line_end]
        match_pos_in_line = match_start - line_start

        # Check if it's in a comment
        comment_pos = line.find('#')
        if comment_pos != -1 and comment_pos < match_pos_in_line:
            return True

        # Count quotes in the line up to the match
        in_single = False
        in_double = False
        i = 0
        while i < match_pos_in_line:
            if line[i] == "'" and (i == 0 or line[i-1] != '\\'):
                in_single = not in_single
            elif line[i] == '"' and (i == 0 or line[i-1] != '\\'):
                in_double = not in_double
            i += 1

        return in_single or in_double

    def _is_shebang_line(self, line_content):
        """Check if the line is a shebang line (#!/...)"""
        stripped = line_content.strip()
        # Shebang lines start with #! and are standard Unix conventions
        return stripped.startswith('#!')

    def _is_standard_system_path(self, path):
        """Check if the path is a standard system path that's not sensitive"""
        # Standard system paths that are not security issues
        standard_paths = [
            '/usr/bin/',
            '/usr/lib/',
            '/usr/local/',
            '/usr/share/',
            '/bin/',
            '/sbin/',
            '/lib/',
            '/etc/',
            '/opt/',
            '/var/log/',
            '/var/run/',
            '/dev/',
            '/proc/',
            '/sys/',
        ]

        path_lower = path.lower()

        # Check if it's a standard system path
        for std_path in standard_paths:
            if path_lower.startswith(std_path):
                return True

        # Also check for common interpreter paths
        interpreter_paths = [
            '/usr/bin/env',
            '/usr/bin/python',
            '/usr/bin/python3',
            '/usr/bin/bash',
            '/usr/bin/sh',
            '/bin/bash',
            '/bin/sh',
        ]

        for interp_path in interpreter_paths:
            if path_lower.startswith(interp_path):
                return True

        return False

    def _is_import_assignment(self, line_content):
        """Check if __import__ is being assigned to a variable (obfuscation technique)"""
        stripped = line_content.strip()
        # Pattern: variable = __import__ or variable,... = ...,__import__,...
        # This is a legitimate use of __import__ for dynamic imports in obfuscated code
        if '=' in stripped and '__import__' in stripped:
            # Check if it's on the right side of an assignment
            parts = stripped.split('=', 1)
            if len(parts) == 2:
                right_side = parts[1].strip()
                # If __import__ is on the right side, it's being assigned
                if '__import__' in right_side:
                    return True
        return False

    def _check_suspicious_patterns(self, filepath, content):
        """Check for suspicious patterns"""
        patterns = {
            'Shellcode': r'\\x[0-9a-f]{2}',
            'Exploit Code': r'(exploit|payload|shellcode|rop|gadget)',
            'Obfuscation': r'(eval|exec|compile|__import__)',
            'C2 Communication': r'(socket|connect|send|recv)',
        }

        for issue_type, pattern in patterns.items():
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                # Filter out false positives for obfuscation
                filtered_matches = []
                lines = content.split('\n')

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                    matched_text = match.group(0).lower()

                    # For obfuscation, filter out legitimate uses
                    if issue_type == 'Obfuscation':
                        # Skip if it's in a string or comment
                        if self._is_in_string_or_comment(content, match.start()):
                            continue

                        # Skip if it's a legitimate exec/eval usage (e.g., dynamic imports)
                        if matched_text in ['exec', 'eval']:
                            if self._is_legitimate_exec_usage(line_content):
                                continue

                        # Skip if it's part of a class name or identifier (e.g., ModuleValidator)
                        if self._is_part_of_identifier(content, match.start(), match.end()):
                            continue

                        # Skip __import__ when used in variable assignment (obfuscation technique)
                        # This is a legitimate use of __import__ for dynamic imports
                        if matched_text == '__import__':
                            if self._is_import_assignment(line_content):
                                continue

                    # For exploit code, filter out legitimate uses
                    if issue_type == 'Exploit Code':
                        # Skip if it's in a string or comment
                        if self._is_in_string_or_comment(content, match.start()):
                            continue

                        # Skip if it's in a comment only (not in code)
                        if self._is_in_comment_only(content, match.start()):
                            continue

                        # Skip if it's in a docstring
                        if self._is_in_docstring(content, match.start()):
                            continue

                        # Skip if it's part of a class/function name (e.g., exploit_plugin, ExploitAdapter)
                        if self._is_part_of_identifier(content, match.start(), match.end()):
                            continue

                        # Skip if it's in an import statement (e.g., "from exploit_plugin import X")
                        if self._is_in_import_statement(line_content):
                            continue

                        # Skip if it's in a function definition (e.g., "def exploit(self):")
                        if self._is_in_function_definition(line_content):
                            continue

                        # Skip if it's in a variable assignment (e.g., "payload = ...")
                        if self._is_variable_assignment(line_content):
                            continue

                        # Skip if it's in a logging statement (e.g., logger.debug(...))
                        if self._is_logging_statement(line_content):
                            continue

                        # Skip if it's a function call argument (e.g., debug_print_words(payload))
                        if self._is_function_call_argument(line_content):
                            continue

                        # Skip if it's a return statement (e.g., return payload)
                        if self._is_return_statement(line_content):
                            continue

                    # For C2 Communication, filter out legitimate uses
                    if issue_type == 'C2 Communication':
                        # Skip if it's in a string or comment
                        if self._is_in_string_or_comment(content, match.start()):
                            continue

                        # Skip if it's in a comment only (not in code)
                        if self._is_in_comment_only(content, match.start()):
                            continue

                        # Skip if it's part of a class/function name
                        if self._is_part_of_identifier(content, match.start(), match.end()):
                            continue

                        # Skip if it's a socket import (e.g., "import socket")
                        if self._is_socket_import(line_content):
                            continue

                        # Skip if it's legitimate networking code
                        if self._is_legitimate_networking(line_content):
                            continue

                        # Skip if it's a socket method call (e.g., s.send(), s.recv())
                        if self._is_socket_method_call(line_content):
                            continue

                        # Only flag if it matches suspicious C2 patterns
                        if not self._is_suspicious_c2_pattern(line_content):
                            continue

                    # For Shellcode, filter out legitimate hex bytes
                    if issue_type == 'Shellcode':
                        # Skip if it's in a string or comment
                        if self._is_in_string_or_comment(content, match.start()):
                            continue

                        # Skip if it's legitimate hex bytes (IV, padding, etc.)
                        if self._is_legitimate_hex_bytes(line_content):
                            continue

                        # Count hex bytes in the line to determine if it's suspicious
                        hex_count = len(re.findall(r'\\x[0-9a-f]{2}', line_content, re.IGNORECASE))

                        # Skip if it doesn't look like actual shellcode
                        if not self._is_suspicious_shellcode_pattern(line_content, hex_count):
                            continue

                    filtered_matches.append(match)

                # Only add findings if we have real matches after filtering
                if filtered_matches:
                    # Get first match for code snippet
                    first_match = filtered_matches[0]
                    line_num = content[:first_match.start()].count('\n') + 1
                    code_snippet = lines[line_num - 1] if line_num <= len(lines) else ''
                    code_snippet = code_snippet.strip()[:100]  # Limit to 100 chars

                    self.findings[issue_type].append({
                        'file': filepath,
                        'line': line_num,
                        'code': code_snippet,
                        'count': len(filtered_matches),
                        'severity': 'MEDIUM'
                    })

    def _is_safe_exec_eval(self, line_content):
        """Check if exec/eval usage is safe (e.g., dynamic imports with hardcoded code)"""
        # Safe patterns for exec/eval
        safe_patterns = [
            'import',  # exec(f"from X import Y")
            'from',    # exec(f"from X import Y")
            '__name__',  # exec(..., globals(), locals())
            '__dict__',  # exec(..., __dict__)
        ]

        # If the line contains import-related keywords, it's likely safe
        for pattern in safe_patterns:
            if pattern in line_content.lower():
                return True

        return False

    def _check_unsafe_functions(self, filepath, content):
        """Check for unsafe functions"""
        unsafe = {
            'strcpy': 'Use strncpy instead',
            'sprintf': 'Use snprintf instead',
            'gets': 'Use fgets instead',
            'strcat': 'Use strncat instead',
            'eval': 'Avoid eval()',
            'exec': 'Avoid exec()',
        }

        for func, recommendation in unsafe.items():
            matches = list(re.finditer(rf'\b{func}\s*\(', content))
            if matches:
                lines = content.split('\n')
                filtered_matches = []

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''

                    # For exec/eval, filter out safe usage patterns
                    if func in ['exec', 'eval']:
                        # Skip if it's in a string or comment
                        if self._is_in_string_or_comment(content, match.start()):
                            continue

                        # Skip if it's safe usage (e.g., dynamic imports)
                        if self._is_safe_exec_eval(line_content):
                            continue

                    filtered_matches.append(match)

                # Only add findings if we have real matches after filtering
                if filtered_matches:
                    # Get first match for code snippet
                    first_match = filtered_matches[0]
                    line_num = content[:first_match.start()].count('\n') + 1
                    code_snippet = lines[line_num - 1] if line_num <= len(lines) else ''
                    code_snippet = code_snippet.strip()[:100]  # Limit to 100 chars

                    self.findings['Unsafe Functions'].append({
                        'file': filepath,
                        'line': line_num,
                        'code': code_snippet,
                        'function': func,
                        'recommendation': recommendation,
                        'severity': 'HIGH'
                    })
                    self.issues_found += 1

    def _is_in_string_literal(self, content, match_start, match_end):
        """Check if a match is inside a string literal"""
        # Get the line containing the match
        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_start)
        if line_end == -1:
            line_end = len(content)

        line = content[line_start:line_end]
        match_pos_in_line = match_start - line_start

        # Count quotes in the line up to the match
        in_single = False
        in_double = False
        i = 0
        while i < match_pos_in_line:
            if line[i] == "'" and (i == 0 or line[i-1] != '\\'):
                in_single = not in_single
            elif line[i] == '"' and (i == 0 or line[i-1] != '\\'):
                in_double = not in_double
            i += 1

        return in_single or in_double

    def _is_python_module_pattern(self, matched_text, line_content):
        """Check if the matched domain is a Python module/package pattern"""
        # Common Python package patterns
        python_patterns = [
            'lib.', 'payload.', 'exploit.', 'platform.', 'plugins.',
            'config.', 'utils.', 'helpers.', 'tools.', 'modules.',
            'core.', 'common.', 'base.', 'handler.', 'shell.',
            'exe.', 'gasp.', 'tera.', 'dino.', 'tplink.',
        ]

        # Check if it's part of a Python module path
        for pattern in python_patterns:
            if pattern in matched_text.lower() or pattern in line_content.lower():
                return True

        # Check if it looks like a Python identifier (all lowercase with underscores)
        if re.match(r'^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$', matched_text.lower()):
            return True

        return False

    def _check_network_indicators(self, filepath, content):
        """Check for network indicators"""
        patterns = {
            'IP Address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'Domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'URL': r'https?://[^\s]+',
        }

        for indicator_type, pattern in patterns.items():
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                # Filter out false positives
                filtered_matches = []
                lines = content.split('\n')

                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                    matched_text = match.group(0)

                    # Skip if this is a Python import statement
                    if line_content.strip().startswith(('from ', 'import ')):
                        continue

                    # For domains, only flag if in string literal or URL pattern
                    if indicator_type == 'Domain':
                        # Always flag URLs (they're in the URL pattern)
                        if 'http' in matched_text.lower():
                            filtered_matches.append(match)
                            continue

                        # Skip if it's a Python module pattern
                        if self._is_python_module_pattern(matched_text, line_content):
                            continue

                        # Skip if it's part of attribute access (e.g., self.hostkey, obj.hostname)
                        start_pos = match.start()
                        if start_pos > 0:
                            # Check if preceded by a dot (attribute access)
                            if content[start_pos - 1] == '.':
                                continue
                            # Check if preceded by alphanumeric/underscore (part of identifier)
                            if content[start_pos - 1] in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':
                                continue

                        # For domains, only flag if inside a string literal
                        if not self._is_in_string_literal(content, match.start(), match.end()):
                            continue

                    filtered_matches.append(match)

                # Only add findings if we have real matches after filtering
                if filtered_matches:
                    # Get first match for code snippet
                    first_match = filtered_matches[0]
                    line_num = content[:first_match.start()].count('\n') + 1
                    code_snippet = lines[line_num - 1] if line_num <= len(lines) else ''
                    code_snippet = code_snippet.strip()[:100]  # Limit to 100 chars

                    self.findings[f'Network: {indicator_type}'].append({
                        'file': filepath,
                        'line': line_num,
                        'code': code_snippet,
                        'count': len(filtered_matches),
                        'severity': 'MEDIUM'
                    })

    def _is_in_docstring_or_example(self, content, match_start):
        """Check if the match is in a docstring or example text"""
        # Look for triple quotes before and after the match
        before = content[:match_start]
        after = content[match_start:]

        # Count triple quotes before
        triple_single_before = before.count("'''")
        triple_double_before = before.count('"""')

        # If odd number of triple quotes, we're inside a docstring
        in_docstring = (triple_single_before % 2 == 1) or (triple_double_before % 2 == 1)

        return in_docstring



    def _is_temp_file_example(self, line_content):
        """Check if the line is an example or documentation of temp files"""
        stripped = line_content.strip().lower()

        # Example patterns
        example_patterns = [
            'example:',
            'example ',
            '# ',
            'docstring',
            'help',
            'usage',
            'description',
            '"""',
            "'''",
        ]

        return any(pattern in stripped for pattern in example_patterns)

    def _is_temp_file_default_config(self, line_content):
        """Check if the line is a default configuration value"""
        stripped = line_content.strip()

        # Configuration patterns
        config_patterns = [
            'default=',
            'default_',
            'DEFAULT_',
            'config',
            'CONFIG',
            'setting',
            'SETTING',
        ]

        return any(pattern in stripped for pattern in config_patterns)

    def _is_legitimate_hex_bytes(self, line_content):
        """Check if hex bytes are for legitimate purposes (IV, padding, data formatting)"""
        stripped = line_content.strip().lower()

        # Legitimate patterns for hex bytes
        legitimate_patterns = [
            'iv =',           # Initialization vector
            'iv=',
            'padding',        # Padding operations
            'null',           # Null bytes
            'b"\\x00"',       # Null byte literals
            "b'\\x00'",
            'b"\\x',          # Generic byte strings
            "b'\\x",
            '* 16',           # IV size (16 bytes)
            '* 32',           # Common sizes
            '* 8',
            'encrypt',        # Encryption operations
            'decrypt',
            'cipher',
            'aes',
            'des',
            'hash',
            'digest',
            'hmac',
            'salt',
            'nonce',
            'key',
            'iv',
            'format',         # Data formatting
            'encode',
            'decode',
            'struct',
            'pack',
            'unpack',
            'bytes',
            'bytearray',
            'memoryview',
        ]

        return any(pattern in stripped for pattern in legitimate_patterns)

    def _is_suspicious_shellcode_pattern(self, line_content, hex_count):
        """Check if the hex bytes look like actual shellcode"""
        stripped = line_content.strip().lower()

        # Shellcode would have many hex bytes in sequence, not just 1-2
        if hex_count < 5:
            return False

        # Shellcode patterns would include actual instruction bytes
        # Real shellcode has specific patterns like:
        # - Multiple consecutive \x bytes (not just padding)
        # - Instruction-like patterns (e.g., \x48\x89\xc3 for mov rax, rbx)
        # - Obfuscation patterns

        # Check for suspicious patterns
        suspicious_indicators = [
            'shellcode',
            'payload',
            'rop',
            'gadget',
            'inject',
            'execute',
            'exec',
            'eval',
            'compile',
            'code',
            'machine',
            'instruction',
        ]

        return any(indicator in stripped for indicator in suspicious_indicators)

