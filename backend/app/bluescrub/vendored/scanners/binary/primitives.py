"""Analysis primitives: hashes, file-type, entropy, strings, disassembly, LIEF wrapper.

Mixin methods inherited by :class:`binary_analyzer.BinaryAnalyzer`.
"""

import hashlib
import math
import re
from collections import Counter

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class PrimitivesMixin:
    """Hash / entropy / string / disassembly helpers."""

    def _calculate_hashes(self, content):
        """Calculate file hashes"""
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
        }

    def _detect_file_type(self, content):
        """Detect file type from magic bytes"""
        for magic, file_type in self.MAGIC_BYTES.items():
            if content.startswith(magic):
                return {'type': file_type, 'magic': magic.hex()}

        # Check for raw shellcode indicators
        if self._looks_like_shellcode(content):
            return {'type': 'Possible Raw Shellcode', 'magic': content[:4].hex()}

        return {'type': 'Unknown Binary', 'magic': content[:4].hex()}

    def _looks_like_shellcode(self, content):
        """Heuristic to detect raw shellcode"""
        if len(content) < 32:
            return False

        # Check for common shellcode characteristics
        # 1. High density of x86 instructions
        # 2. NOP sleds
        # 3. Known shellcode patterns

        nop_count = content.count(b'\x90')
        if nop_count > len(content) * 0.1:  # >10% NOPs
            return True

        # Check for multiple shellcode patterns
        pattern_count = 0
        for pattern, _ in self.SHELLCODE_PATTERNS:
            if pattern in content:
                pattern_count += 1

        return pattern_count >= 3

    def _calculate_entropy(self, content):
        """Calculate Shannon entropy of binary data"""
        if not content:
            return {'entropy': 0, 'risk': 'LOW', 'packed': False}

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in content:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        length = len(content)
        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        # Determine if likely packed/encrypted
        packed = entropy > 7.0

        if entropy >= 7.5:
            risk = 'CRITICAL'
        elif entropy >= 7.0:
            risk = 'HIGH'
        elif entropy >= 6.0:
            risk = 'MEDIUM'
        else:
            risk = 'LOW'

        return {
            'entropy': round(entropy, 4),
            'max_entropy': 8.0,
            'risk': risk,
            'packed': packed,
            'explanation': 'High entropy suggests packing/encryption' if packed else 'Normal entropy'
        }

    def _extract_strings(self, content, min_length=6):
        """Extract printable ASCII and Unicode strings"""
        strings = {
            'ascii': [],
            'unicode': [],
            'interesting': []
        }

        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{%d,}' % min_length
        for match in re.finditer(ascii_pattern, content):
            s = match.group().decode('ascii', errors='ignore')
            strings['ascii'].append({
                'value': s[:200],  # Limit length
                'offset': match.start(),
                'length': len(s)
            })

        # Unicode strings (UTF-16LE common in Windows)
        unicode_pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % min_length
        for match in re.finditer(unicode_pattern, content):
            try:
                s = match.group().decode('utf-16le', errors='ignore')
                strings['unicode'].append({
                    'value': s[:200],
                    'offset': match.start(),
                    'length': len(s)
                })
            except:
                pass

        # Find interesting strings
        interesting_patterns = [
            r'https?://[^\s<>"]+',  # URLs
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IPs
            r'[a-zA-Z]:\\[^\s<>"]+',  # Windows paths
            r'/[a-zA-Z0-9/_.-]+',  # Unix paths
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Emails
            r'password|passwd|secret|token|key|credential',  # Secrets
            r'cmd\.exe|powershell|bash|sh\s',  # Shells
        ]

        all_strings = ' '.join([s['value'] for s in strings['ascii']])
        for pattern in interesting_patterns:
            for match in re.finditer(pattern, all_strings, re.IGNORECASE):
                strings['interesting'].append({
                    'value': match.group()[:100],
                    'type': 'suspicious_string'
                })

        return {
            'ascii_count': len(strings['ascii']),
            'unicode_count': len(strings['unicode']),
            'interesting': strings['interesting'][:50],  # Limit
            'sample_ascii': strings['ascii'][:20],  # Sample
            'sample_unicode': strings['unicode'][:10],
        }

    def _detect_shellcode_patterns(self, content):
        """Detect known shellcode patterns"""
        found_patterns = []

        for pattern, description in self.SHELLCODE_PATTERNS:
            positions = []
            start = 0
            while True:
                pos = content.find(pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
                if len(positions) >= 10:  # Limit positions
                    break

            if positions:
                found_patterns.append({
                    'pattern': pattern.hex(),
                    'description': description,
                    'count': len(positions),
                    'positions': positions[:5],
                    'severity': 'HIGH' if 'syscall' in description.lower() else 'MEDIUM'
                })

        return {
            'found': len(found_patterns) > 0,
            'patterns': found_patterns,
            'count': len(found_patterns),
            'risk': 'HIGH' if len(found_patterns) >= 3 else 'MEDIUM' if found_patterns else 'LOW'
        }

    def _find_suspicious_strings(self, content):
        """Find suspicious strings in binary"""
        suspicious = []

        text = content.decode('latin-1', errors='ignore')

        patterns = {
            'url': (r'https?://[^\s<>"\']+', 'CRITICAL'),
            'ip_address': (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'HIGH'),
            'domain': (r'\b[a-z0-9][-a-z0-9]*\.(com|net|org|io|ru|cn)\b', 'MEDIUM'),
            'registry': (r'HKEY_[A-Z_]+\\[^\s]+', 'HIGH'),
            'cmd_exec': (r'cmd\.exe|powershell\.exe|/bin/sh|/bin/bash', 'CRITICAL'),
            'crypto': (r'-----BEGIN [A-Z ]+ KEY-----', 'CRITICAL'),
            'base64_blob': (r'[A-Za-z0-9+/]{50,}={0,2}', 'MEDIUM'),
        }

        for name, (pattern, severity) in patterns.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                suspicious.append({
                    'type': name,
                    'value': match.group()[:100],
                    'offset': match.start(),
                    'severity': severity
                })

        return suspicious[:100]  # Limit results

    def _analyze_with_lief(self, file_path):
        """Additional analysis using LIEF library"""
        if not LIEF_AVAILABLE:
            return None

        try:
            binary = lief.parse(str(file_path))
            if binary is None:
                return None

            result = {
                'format': binary.format.name if hasattr(binary, 'format') else 'Unknown',
                'is_pie': binary.is_pie if hasattr(binary, 'is_pie') else False,
                'has_nx': binary.has_nx if hasattr(binary, 'has_nx') else False,
            }

            return result
        except Exception as e:
            return {'lief_error': str(e)}

    def _disassemble_section(self, content, offset, length=200):
        """Disassemble binary at offset"""
        if not CAPSTONE_AVAILABLE:
            return None

        try:
            # Try x64 first, then x86
            for mode in [CS_MODE_64, CS_MODE_32]:
                md = Cs(CS_ARCH_X86, mode)
                instructions = []

                # Get section to disassemble
                section = content[offset:offset + length]

                for insn in md.disasm(section, offset):
                    instructions.append({
                        'address': hex(insn.address),
                        'mnemonic': insn.mnemonic,
                        'operands': insn.op_str,
                        'bytes': insn.bytes.hex()
                    })
                    if len(instructions) >= 50:
                        break

                if instructions:
                    return {
                        'mode': '64-bit' if mode == CS_MODE_64 else '32-bit',
                        'instructions': instructions
                    }

            return None
        except Exception as e:
            return {'disasm_error': str(e)}


    # ===== PHASE 2: ENHANCED BINARY ANALYSIS =====


    def _per_section_entropy(self, content, sections):
        """Calculate per-section entropy for packing/encryption detection"""
        results = []
        for section in sections:
            offset = section.get('offset', section.get('pointer_to_raw_data', 0))
            size = section.get('size', section.get('size_of_raw_data', 0))
            name = section.get('name', 'unknown')
            if offset and size and offset + size <= len(content):
                section_data = content[offset:offset + size]
                entropy = self._calculate_entropy(section_data)
                entropy_val = entropy.get('value', 0) if isinstance(entropy, dict) else entropy
                assessment = 'normal'
                if entropy_val > 7.5:
                    assessment = 'packed/encrypted'
                elif entropy_val > 6.5:
                    assessment = 'compressed/obfuscated'
                elif entropy_val < 1.0 and size > 64:
                    assessment = 'mostly empty/zeroed'
                results.append({'name': name, 'entropy': round(entropy_val, 4),
                               'size': size, 'assessment': assessment})
        return results

