#!/usr/bin/env python3
"""
bytecode Security Scanner for BlueScrub
Detects vulnerabilities in bytecode that defenders can technique or use for detection

Focus Areas:
- Null byte detection (breaks string operations)
- Bad character analysis (gets filtered by input validation)
- Predictable pattern detection (creates signatures)
- Encoding weakness identification (allows detection)
- Stack alignment validation (affects stability)
- Signature risk assessment (uniqueness scoring)
"""

import os
import re
import binascii
from pathlib import Path
from collections import Counter
import math

import logging

logger = logging.getLogger(__name__)
class ShellcodeSecurityScanner:
    """Analyzes bytecode for security vulnerabilities and detection risks"""
    
    def __init__(self):
        """Initialize with common bad characters that get filtered"""
        # Common bad characters that get filtered
        self.bad_chars = {
            b'\x00': 'NULL byte (breaks string operations)',
            b'\x0a': 'Line Feed (filtered by many parsers)',
            b'\x0d': 'Carriage Return (filtered by many parsers)',
            b'\x20': 'Space (filtered in some contexts)',
            b'\x09': 'Tab (filtered in some contexts)',
            b'\xff': 'High byte (filtered in some contexts)',
        }
        
        # Predictable patterns that create signatures
        self.signature_patterns = [
            (rb'\x90{4,}', 'NOP sled (highly detectable signature)'),
            (rb'\xcc{2,}', 'INT3 debug breakpoints'),
            (rb'(\x00){3,}', 'Multiple NULL bytes'),
            (rb'\x41{4,}', 'Repeated 0x41 (AAAA pattern)'),
            (rb'\x42{4,}', 'Repeated 0x42 (BBBB pattern)'),
            (rb'\x43{4,}', 'Repeated 0x43 (CCCC pattern)'),
            (rb'\x44{4,}', 'Repeated 0x44 (DDDD pattern)'),
            (rb'\xeb[\x00-\xff]\x90{2,}', 'JMP-NOP pattern (common bytecode signature)'),
            (rb'\xe8\x00\x00\x00\x00', 'CALL $+5 (GetPC pattern)'),
        ]
        
        # Common bytecode API patterns (Windows)
        self.api_patterns = [
            (rb'kernel32', 'Kernel32.dll reference'),
            (rb'LoadLibrary', 'LoadLibrary API call'),
            (rb'GetProcAddress', 'GetProcAddress API call'),
            (rb'WinExec', 'WinExec API call'),
            (rb'CreateProcess', 'CreateProcess API call'),
            (rb'VirtualAlloc', 'VirtualAlloc API call'),
            (rb'VirtualProtect', 'VirtualProtect API call'),
            (rb'WriteProcessMemory', 'WriteProcessMemory API call'),
        ]
        
    # Max file size to scan (2 MB) – larger binaries are full executables,
    # not standalone shellcode, and scanning them byte-by-byte is too slow.
    MAX_SCAN_SIZE = 2 * 1024 * 1024

    # Files that are never shellcode regardless of content
    _EXCLUDED_NAMES = {'.ds_store', 'thumbs.db', 'desktop.ini', '.gitignore',
                       '.gitattributes', 'license', 'readme', 'changelog',
                       'makefile', 'dockerfile', 'requirements.txt',
                       'package.json', 'cargo.toml', 'go.mod'}

    def scan_file(self, file_path):
        """Scan a file for bytecode security issues"""
        try:
            # Exclude known non-shellcode files by name
            basename = Path(file_path).name.lower()
            if basename in self._EXCLUDED_NAMES:
                return None

            file_size = os.path.getsize(file_path)
            # Skip files that are too large to be standalone shellcode
            if file_size > self.MAX_SCAN_SIZE:
                return None

            with open(file_path, 'rb') as f:
                content = f.read()

            # Only analyze files that might contain bytecode
            file_type = self._classify_file(content, file_path)
            if file_type == 'skip':
                return None

            # For source files with embedded shellcode, extract only the hex
            # byte sequences — don't analyse the source-code whitespace.
            if file_type == 'source_with_shellcode':
                content = self._extract_embedded_shellcode(content)
                if not content or len(content) < 4:
                    return None

            null_bytes = self._detect_null_bytes(content)
            bad_chars = self._detect_bad_chars(content)
            patterns = self._detect_patterns(content)
            apis = self._detect_api_refs(content)
            entropy = self._calculate_entropy(content)

            results = {
                'file': str(file_path),
                'file_type': file_type,
                'size': len(content),
                'null_bytes': null_bytes,
                'bad_characters': bad_chars,
                'predictable_patterns': patterns,
                'api_references': apis,
                'entropy': entropy,
                'encoding_analysis': self._analyze_encoding(content),
                'alignment_issues': self._check_alignment(content) if file_type == 'binary' else {'issues': [], 'risk': 'LOW'},
                'signature_risk': self._calculate_signature_risk_from(entropy, patterns, apis, bad_chars),
                'severity': 'MEDIUM'
            }

            # Calculate overall severity
            results['severity'] = self._calculate_severity(results)

            return results

        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    # Archive / container extensions — never shellcode
    _ARCHIVE_EXTENSIONS = {
        '.zip', '.7z', '.gz', '.tar', '.rar', '.bz2', '.xz', '.lz',
        '.lzma', '.cab', '.iso', '.dmg', '.pkg', '.deb', '.rpm',
        '.jar', '.war', '.ear', '.apk', '.ipa', '.tgz', '.tbz2',
        '.zipx', '.z', '.lz4', '.zst',
    }

    # Magic bytes for archive detection (no-extension fallback)
    _ARCHIVE_MAGICS = (
        b'PK\x03\x04',          # ZIP
        b'\x1f\x8b',            # GZIP
        b'Rar!\x1a\x07',        # RAR
        b'\x37\x7a\xbc\xaf',    # 7-Zip
        b'\x42\x5a\x68',        # BZ2
        b'\xfd\x37\x7a\x58',    # XZ
    )

    # PE / ELF / Mach-O — full executables, not standalone shellcode
    _EXECUTABLE_MAGICS = (
        b'MZ',                   # PE/DOS
        b'\x7fELF',             # ELF
        b'\xfe\xed\xfa\xce',    # Mach-O 32
        b'\xfe\xed\xfa\xcf',    # Mach-O 64
        b'\xca\xfe\xba\xbe',    # Mach-O Universal
        b'\xcf\xfa\xed\xfe',    # Mach-O 64 LE
        b'\xce\xfa\xed\xfe',    # Mach-O 32 LE
    )

    def _classify_file(self, content, file_path):
        """Classify a file for shellcode analysis.

        Returns one of:
          'binary'                – raw binary / shellcode file
          'source_with_shellcode' – source file containing embedded hex bytes
          'skip'                  – not relevant
        """
        file_ext = Path(file_path).suffix.lower()

        # Archives are never shellcode
        if file_ext in self._ARCHIVE_EXTENSIONS:
            return 'skip'

        # Direct shellcode extensions → binary
        if file_ext in ('.bin', '.raw', '.sc', '.bytecode', '.data'):
            return 'binary'

        # Known executable extensions → skip (binary_analyzer handles these)
        if file_ext in ('.exe', '.dll', '.sys', '.so', '.dylib', '.o', '.obj',
                        '.com', '.scr', '.drv', '.ocx', '.cpl', '.msi'):
            return 'skip'

        # Source files that may embed shellcode hex blobs
        if file_ext in ('.py', '.c', '.cpp', '.h', '.rb', '.go', '.rs'):
            try:
                text_content = content.decode('utf-8', errors='ignore')
                # Need a meaningful amount of hex – at least 8 hex bytes
                hex_matches = re.findall(r'\\x[0-9a-fA-F]{2}', text_content)
                if len(hex_matches) >= 8:
                    return 'source_with_shellcode'
            except Exception:
                pass
            return 'skip'

        # Check magic bytes — skip archives and full executables
        for magic in self._ARCHIVE_MAGICS:
            if content.startswith(magic):
                return 'skip'
        for magic in self._EXECUTABLE_MAGICS:
            if content.startswith(magic):
                return 'skip'

        # High non-printable ratio → likely raw binary shellcode
        if len(content) > 100:
            non_printable = sum(1 for b in content if b < 32 or b > 126)
            if non_printable / len(content) > 0.3:
                return 'binary'

        return 'skip'

    def _extract_embedded_shellcode(self, raw_content):
        """Extract only the shellcode bytes from a source file.

        Parses hex escape sequences (\\x41\\x42...) and 0xFF byte arrays
        and returns the decoded binary payload for analysis.
        """
        text = raw_content.decode('utf-8', errors='ignore')
        chunks = []

        # Extract \xNN sequences (contiguous runs)
        for run in re.finditer(r'(?:\\x[0-9a-fA-F]{2}){4,}', text):
            hex_str = run.group().replace('\\x', '')
            try:
                chunks.append(binascii.unhexlify(hex_str))
            except Exception:
                pass

        # Extract 0xNN byte arrays
        for run in re.finditer(r'(?:0x[0-9a-fA-F]{2}[,\s]+){4,}0x[0-9a-fA-F]{2}', text):
            hex_bytes = re.findall(r'0x([0-9a-fA-F]{2})', run.group())
            try:
                chunks.append(binascii.unhexlify(''.join(hex_bytes)))
            except Exception:
                pass

        return b''.join(chunks)
    
    def _detect_null_bytes(self, content):
        """Detect NULL bytes that break string operations"""
        count = content.count(b'\x00')
        if count == 0:
            return {'found': False, 'count': 0}

        # Only find first 10 positions (avoid huge list)
        positions = []
        start = 0
        for _ in range(10):
            idx = content.find(b'\x00', start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + 1

        return {
            'found': True,
            'count': count,
            'positions': positions,
            'risk': 'HIGH',
            'explanation': 'NULL bytes break string-based exploitation (strcpy, gets, etc.)'
        }
    
    def _detect_bad_chars(self, content):
        """Detect bad characters that get filtered"""
        found_bad_chars = []

        for bad_char, description in self.bad_chars.items():
            count = content.count(bad_char)
            if count > 0:
                # Find only first 5 positions
                positions = []
                start = 0
                for _ in range(5):
                    idx = content.find(bad_char, start)
                    if idx == -1:
                        break
                    positions.append(idx)
                    start = idx + 1
                found_bad_chars.append({
                    'char': f'0x{bad_char[0]:02x}',
                    'description': description,
                    'count': count,
                    'positions': positions
                })
        
        if not found_bad_chars:
            return {'found': False, 'bad_chars': []}
        
        return {
            'found': True,
            'bad_chars': found_bad_chars,
            'risk': 'HIGH',
            'explanation': 'Bad characters get filtered by input validation, breaking bytecode'
        }
    
    def _detect_patterns(self, content):
        """Detect predictable patterns that create signatures"""
        found_patterns = []

        for pattern, description in self.signature_patterns:
            matches = list(re.finditer(pattern, content))
            if matches:
                # Get actual matched bytes for display
                match_sample = matches[0].group()
                if len(match_sample) > 20:
                    match_display = match_sample[:20].hex() + '...'
                else:
                    match_display = match_sample.hex()

                found_patterns.append({
                    'pattern': pattern.decode('unicode_escape', errors='ignore'),
                    'description': description,
                    'count': len(matches),
                    'positions': [m.start() for m in matches[:5]],
                    'length': len(matches[0].group()) if matches else 0,
                    'sample': match_display,  # Hex representation of matched bytes
                    'match_preview': repr(match_sample[:10])  # Preview of matched content
                })

        if not found_patterns:
            return {'found': False, 'patterns': []}

        return {
            'found': True,
            'patterns': found_patterns,
            'risk': 'HIGH',
            'explanation': 'Predictable patterns create unique signatures for detection'
        }
    
    def _detect_api_refs(self, content):
        """Detect API references that create fingerprints"""
        found_apis = []
        
        for pattern, description in self.api_patterns:
            if pattern in content:
                found_apis.append({
                    'api': pattern.decode('utf-8', errors='ignore'),
                    'description': description,
                    'risk': 'MEDIUM'
                })
        
        if not found_apis:
            return {'found': False, 'apis': []}
        
        return {
            'found': True,
            'apis': found_apis,
            'risk': 'MEDIUM',
            'explanation': 'API references create behavioral signatures'
        }
    
    def _calculate_entropy(self, content):
        """Calculate Shannon entropy (randomness measure)"""
        if not content:
            return {'entropy': 0, 'risk': 'LOW'}
        
        # Calculate byte frequency
        byte_counts = Counter(content)
        entropy = 0
        
        for count in byte_counts.values():
            probability = count / len(content)
            entropy -= probability * math.log2(probability)
        
        # Entropy ranges from 0 (not random) to 8 (perfectly random)
        # Low entropy = easily detectable
        risk = 'LOW'
        if entropy < 4.0:
            risk = 'HIGH'
        elif entropy < 6.0:
            risk = 'MEDIUM'
        
        return {
            'entropy': round(entropy, 2),
            'max_entropy': 8.0,
            'risk': risk,
            'explanation': f'Low entropy ({entropy:.2f}/8.0) makes bytecode easily detectable'
        }
    
    def _analyze_encoding(self, content):
        """Analyze encoding effectiveness"""
        issues = []
        
        # Check for common encoding patterns
        if b'\x90' * 4 in content:
            issues.append('NOP sled detected - weak encoding')
        
        # Check for repeated bytes (weak encoding)
        byte_counts = Counter(content)
        most_common = byte_counts.most_common(1)
        if most_common and most_common[0][1] > len(content) * 0.1:
            issues.append(f'Byte 0x{most_common[0][0]:02x} appears {most_common[0][1]} times (weak encoding)')
        
        # Check for XOR encoding patterns
        if self._detect_xor_encoding(content):
            issues.append('Potential XOR encoding detected (common pattern)')
        
        if not issues:
            return {'issues': [], 'risk': 'LOW'}
        
        return {
            'issues': issues,
            'risk': 'MEDIUM',
            'explanation': 'Weak encoding allows signature-based detection'
        }
    
    def _detect_xor_encoding(self, content):
        """Detect simple XOR encoding patterns"""
        # Look for XOR decoder stubs (common patterns)
        xor_patterns = [
            rb'\x31[\xc0-\xff]',  # XOR reg, reg
            rb'\x80[\x30-\x37]',  # XOR byte ptr
        ]
        
        for pattern in xor_patterns:
            if re.search(pattern, content):
                return True
        return False
    
    def _check_alignment(self, content):
        """Check for stack alignment issues"""
        issues = []
        
        # Check if size is aligned to 4 bytes (x86) or 8 bytes (x64)
        if len(content) % 4 != 0:
            issues.append(f'Size {len(content)} not aligned to 4 bytes (x86 alignment issue)')
        
        if len(content) % 8 != 0:
            issues.append(f'Size {len(content)} not aligned to 8 bytes (x64 alignment issue)')
        
        if not issues:
            return {'issues': [], 'risk': 'LOW'}
        
        return {
            'issues': issues,
            'risk': 'MEDIUM',
            'explanation': 'Alignment issues can cause bytecode crashes'
        }
    
    def _calculate_signature_risk(self, content):
        """Calculate overall signature detection risk (standalone, re-runs sub-analyses)"""
        entropy = self._calculate_entropy(content)
        patterns = self._detect_patterns(content)
        apis = self._detect_api_refs(content)
        bad_chars = self._detect_bad_chars(content)
        return self._calculate_signature_risk_from(entropy, patterns, apis, bad_chars)

    def _calculate_signature_risk_from(self, entropy_result, patterns, apis, bad_chars):
        """Calculate signature risk from pre-computed analysis results (no duplicate work)"""
        risk_score = 0
        factors = []

        # Factor 1: Entropy (40% weight)
        if entropy_result['entropy'] < 4.0:
            risk_score += 40
            factors.append('Very low entropy')
        elif entropy_result['entropy'] < 6.0:
            risk_score += 20
            factors.append('Low entropy')

        # Factor 2: Predictable patterns (30% weight)
        if patterns.get('found'):
            risk_score += 30
            factors.append(f"{len(patterns['patterns'])} predictable patterns")

        # Factor 3: API references (20% weight)
        if apis.get('found'):
            risk_score += 20
            factors.append(f"{len(apis['apis'])} API references")

        # Factor 4: Bad characters (10% weight)
        if bad_chars.get('found'):
            risk_score += 10
            factors.append(f"{len(bad_chars['bad_chars'])} bad characters")

        # Determine risk level
        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        return {
            'score': risk_score,
            'max_score': 100,
            'risk_level': risk_level,
            'factors': factors,
            'explanation': f'Signature detection risk: {risk_score}/100 - {", ".join(factors) if factors else "no significant risk factors"}'
        }
    
    def _calculate_severity(self, results):
        """Calculate overall severity based on all findings"""
        severity_score = 0
        
        if results['null_bytes']['found']:
            severity_score += 3
        
        if results['bad_characters']['found']:
            severity_score += 3
        
        if results['predictable_patterns']['found']:
            severity_score += 2
        
        if results['entropy']['risk'] == 'HIGH':
            severity_score += 2
        
        if results['signature_risk']['risk_level'] in ['CRITICAL', 'HIGH']:
            severity_score += 2
        
        if severity_score >= 8:
            return 'CRITICAL'
        elif severity_score >= 5:
            return 'HIGH'
        elif severity_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'

def scan_directory_for_shellcode(directory):
    """Scan a directory for bytecode security issues"""
    scanner = ShellcodeSecurityScanner()
    results = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            result = scanner.scan_file(file_path)
            if result:
                results.append(result)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logger.info("Usage: python3 shellcode_security_scanner.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Scanning {directory} for bytecode security issues...")
    
    results = scan_directory_for_shellcode(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with potential bytecode")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"📏 Size: {result['size']} bytes")
        
        if result['null_bytes']['found']:
            logger.info(f"  🚫 NULL Bytes: {result['null_bytes']['count']} found - {result['null_bytes']['explanation']}")
        
        if result['bad_characters']['found']:
            logger.info(f"  ⚠️  Bad Characters: {len(result['bad_characters']['bad_chars'])} types found")
        
        if result['predictable_patterns']['found']:
            logger.info(f"  🎯 Predictable Patterns: {len(result['predictable_patterns']['patterns'])} found")
        
        logger.info(f"  📊 Entropy: {result['entropy']['entropy']}/8.0 ({result['entropy']['risk']} risk)")
        logger.info(f"  🔍 Signature Risk: {result['signature_risk']['score']}/100 ({result['signature_risk']['risk_level']})")

