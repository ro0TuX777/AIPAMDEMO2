#!/usr/bin/env python3
"""
data Obfuscation Analyzer for BlueScrub
Assesses data obfuscation effectiveness and detection risk

Focus Areas:
- Entropy calculation (randomness measurement)
- String pattern detection (predictable strings)
- API call sequence analysis (behavioral signatures)
- Obfuscation effectiveness scoring
- Detection risk assessment (AV/EDR probability)
"""

import os
import re
import math
from pathlib import Path
from collections import Counter, defaultdict

import logging

logger = logging.getLogger(__name__)
class PayloadObfuscationAnalyzer:
    """Analyzes data obfuscation and detection risk"""
    
    def __init__(self):
        """Initialize with suspicious API call patterns (Windows)"""
        self.suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'QueueUserAPC', 'SetThreadContext',
            'NtAllocateVirtualMemory', 'NtWriteVirtualMemory',
            'RtlMoveMemory', 'memcpy', 'CreateProcess', 'WinExec',
            'ShellExecute', 'system', 'popen', 'LoadLibrary',
            'GetProcAddress', 'CreateThread', 'ResumeThread'
        ]
        
        # Suspicious API sequences (behavioral signatures)
        self.api_sequences = [
            (['VirtualAlloc', 'memcpy', 'CreateThread'], 'Classic bytecode injection'),
            (['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'], 'Process injection'),
            (['VirtualProtect', 'memcpy'], 'DEP override pattern'),
            (['LoadLibrary', 'GetProcAddress'], 'Dynamic API resolution'),
            (['CreateProcess', 'WriteProcessMemory'], 'Process hollowing'),
        ]
        
        # Predictable string patterns
        self.string_patterns = [
            (r'cmd\.exe|powershell\.exe|wscript\.exe', 'Suspicious executable names'),
            (r'http://|https://|ftp://', 'URL patterns'),
            # Require hostname-like chars (letters/digits, 3+ chars) to avoid
            # matching random binary sequences that happen to contain '\\'.
            (r'\\\\[a-zA-Z0-9][a-zA-Z0-9._-]{2,}\\[a-zA-Z0-9]', 'UNC path patterns'),
            (r'HKEY_|HKLM|HKCU', 'Registry key patterns'),
            (r'SOFTWARE\\|System\\|CurrentVersion', 'Registry path patterns'),
            (r'admin|password|passwd|pwd', 'Credential-related strings'),
            # CRITICAL FIX: Don't flag technique/data/bytecode in offensive tools
            # These are EXPECTED keywords in red team tools, not indicators of threat
            # (r'technique|data|bytecode|access_point', 'technique-related strings'),
        ]

        # Offensive tool patterns - EXPECTED in red team tools
        # These should NOT be flagged as suspicious in offensive security tools
        self.offensive_tool_patterns = [
            (r'technique|data|bytecode|access_point', 'Offensive tool keywords'),
            (r'c2|command.?control|beacon|callback', 'C2 communication keywords'),
            (r'obfuscate|deobfuscate|encode|decode', 'Obfuscation keywords'),
        ]
        
        # Obfuscation techniques
        self.obfuscation_techniques = [
            (r'base64|b64encode|b64decode', 'Base64 encoding'),
            (r'xor|XOR', 'XOR encoding'),
            (r'rot13|ROT13', 'ROT13 encoding'),
            (r'encrypt|decrypt|cipher', 'Encryption'),
            (r'encode|decode', 'Generic encoding'),
            (r'obfuscate|deobfuscate', 'Obfuscation reference'),
        ]
        
        # Weak obfuscation indicators
        self.weak_obfuscation = [
            (r'eval\(|exec\(', 'Eval/subprocess.run(easily detected)'),
            (r'\\x[0-9a-fA-F]{2}', 'Hex-encoded strings (common pattern)'),
            (r'chr\(|ord\(', 'Character encoding (weak)'),
            (r'replace\(|substitute', 'Simple string replacement'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for data obfuscation and detection risk"""
        try:
            # Only analyze source code and binary files
            if not self._is_analyzable_file(file_path):
                return None

            with open(file_path, 'rb') as f:
                binary_content = f.read()

            # Try to read as text for source code analysis
            try:
                text_content = binary_content.decode('utf-8', errors='ignore')
            except:
                text_content = ""

            # Check if file contains data-related code
            if not self._is_payload_code(text_content, binary_content):
                return None
            
            results = {
                'file': str(file_path),
                'size': len(binary_content),
                'entropy': self._calculate_entropy(binary_content),
                'string_patterns': self._detect_string_patterns(text_content),
                'api_sequences': self._detect_api_sequences(text_content),
                'obfuscation_techniques': self._detect_obfuscation(text_content),
                'weak_obfuscation': self._detect_weak_obfuscation(text_content),
                'obfuscation_score': 0,
                'detection_risk': 0,
                'severity': 'MEDIUM'
            }
            
            # Calculate scores
            results['obfuscation_score'] = self._calculate_obfuscation_score(results)
            results['detection_risk'] = self._calculate_detection_risk(results)
            results['severity'] = self._calculate_severity(results)
            
            return results
            
        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _is_analyzable_file(self, file_path):
        """Check if file should be analyzed"""
        analyzable_extensions = [
            '.py', '.c', '.cpp', '.h', '.hpp', '.js', '.rb', '.pl', '.go',
            '.bin', '.exe', '.dll', '.so', '.dylib', '.raw', '.bytecode'
        ]
        return Path(file_path).suffix.lower() in analyzable_extensions
    
    def _is_payload_code(self, text_content, binary_content):
        """Determine if content contains data-related code"""
        payload_keywords = [
            'data', 'bytecode', 'technique', 'insert', 'obfuscate',
            'encode', 'decrypt', 'override', 'evasion'
        ]
        
        text_lower = text_content.lower()
        
        # Check for data keywords
        if any(keyword in text_lower for keyword in payload_keywords):
            return True
        
        # Check for suspicious APIs
        if any(api.lower() in text_lower for api in self.suspicious_apis):
            return True
        
        # Check for high byte density (binary data)
        if len(binary_content) > 100:
            non_printable = sum(1 for b in binary_content if b < 32 or b > 126)
            if non_printable / len(binary_content) > 0.3:
                return True
        
        return False
    
    def _calculate_entropy(self, content):
        """Calculate Shannon entropy"""
        if not content:
            return {'entropy': 0, 'risk': 'HIGH', 'explanation': 'Empty content'}
        
        byte_counts = Counter(content)
        entropy = 0
        
        for count in byte_counts.values():
            probability = count / len(content)
            entropy -= probability * math.log2(probability)
        
        # Determine risk level
        if entropy < 3.0:
            risk = 'CRITICAL'
            explanation = f'Very low entropy ({entropy:.2f}/8.0) - easily detected by AV'
        elif entropy < 5.0:
            risk = 'HIGH'
            explanation = f'Low entropy ({entropy:.2f}/8.0) - detectable by signature scanning'
        elif entropy < 6.5:
            risk = 'MEDIUM'
            explanation = f'Medium entropy ({entropy:.2f}/8.0) - some detection risk'
        else:
            risk = 'LOW'
            explanation = f'High entropy ({entropy:.2f}/8.0) - good obfuscation'
        
        return {
            'entropy': round(entropy, 2),
            'max_entropy': 8.0,
            'risk': risk,
            'explanation': explanation
        }
    
    def _detect_string_patterns(self, content):
        """Detect predictable string patterns"""
        found_patterns = []
        
        for pattern, description in self.string_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:  # Limit to 5 per pattern
                    line_num = content[:match.start()].count('\n') + 1
                    found_patterns.append({
                        'pattern': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_patterns:
            return {'found': False, 'patterns': []}
        
        return {
            'found': True,
            'patterns': found_patterns,
            'count': len(found_patterns),
            'risk': 'HIGH',
            'explanation': 'Predictable strings create YARA signatures'
        }
    
    def _detect_api_sequences(self, content):
        """Detect suspicious API call sequences"""
        found_sequences = []
        
        # Find all API calls in order
        api_calls = []
        for api in self.suspicious_apis:
            for match in re.finditer(rf'\b{api}\b', content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                api_calls.append((line_num, api))
        
        # Sort by line number
        api_calls.sort()
        
        # Check for known sequences
        for sequence, description in self.api_sequences:
            # Look for sequence in API calls
            for i in range(len(api_calls) - len(sequence) + 1):
                window = [api for _, api in api_calls[i:i+len(sequence)]]
                if all(seq_api in window for seq_api in sequence):
                    found_sequences.append({
                        'sequence': ' → '.join(sequence),
                        'type': description,
                        'line': api_calls[i][0],
                        'risk': 'HIGH'
                    })
        
        if not found_sequences:
            return {'found': False, 'sequences': []}
        
        return {
            'found': True,
            'sequences': found_sequences,
            'count': len(found_sequences),
            'risk': 'HIGH',
            'explanation': 'Suspicious API sequences trigger behavioral detection'
        }
    
    def _detect_obfuscation(self, content):
        """Detect obfuscation techniques used"""
        found_techniques = []
        
        for pattern, description in self.obfuscation_techniques:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                line_num = content[:matches[0].start()].count('\n') + 1
                found_techniques.append({
                    'technique': description,
                    'count': len(matches),
                    'line': line_num
                })
        
        if not found_techniques:
            return {'found': False, 'techniques': []}
        
        return {
            'found': True,
            'techniques': found_techniques,
            'count': len(found_techniques)
        }
    
    def _detect_weak_obfuscation(self, content):
        """Detect weak obfuscation indicators"""
        found_weak = []
        
        for pattern, description in self.weak_obfuscation:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                line_num = content[:matches[0].start()].count('\n') + 1
                found_weak.append({
                    'indicator': description,
                    'count': len(matches),
                    'line': line_num,
                    'risk': 'HIGH'
                })
        
        if not found_weak:
            return {'found': False, 'indicators': []}
        
        return {
            'found': True,
            'indicators': found_weak,
            'count': len(found_weak),
            'risk': 'HIGH',
            'explanation': 'Weak obfuscation is easily bypassed by AV/EDR'
        }
    
    def _calculate_obfuscation_score(self, results):
        """Calculate obfuscation effectiveness score (0-100, higher is better)"""
        score = 50  # Start at middle
        
        # Entropy contribution (40 points)
        entropy = results['entropy']['entropy']
        if entropy >= 7.0:
            score += 40
        elif entropy >= 6.0:
            score += 30
        elif entropy >= 5.0:
            score += 20
        elif entropy >= 4.0:
            score += 10
        
        # Obfuscation techniques used (30 points)
        if results['obfuscation_techniques']['found']:
            score += min(30, results['obfuscation_techniques']['count'] * 10)
        
        # Deduct for weak obfuscation (30 points)
        if results['weak_obfuscation']['found']:
            score -= min(30, results['weak_obfuscation']['count'] * 10)
        
        # Deduct for predictable patterns (20 points)
        if results['string_patterns']['found']:
            score -= min(20, results['string_patterns']['count'] * 2)
        
        return max(0, min(100, score))
    
    def _calculate_detection_risk(self, results):
        """Calculate AV/EDR detection risk (0-100, higher is worse)"""
        risk = 0
        
        # Low entropy increases risk (40 points)
        entropy = results['entropy']['entropy']
        if entropy < 3.0:
            risk += 40
        elif entropy < 5.0:
            risk += 30
        elif entropy < 6.0:
            risk += 20
        elif entropy < 7.0:
            risk += 10
        
        # Predictable patterns increase risk (30 points)
        if results['string_patterns']['found']:
            risk += min(30, results['string_patterns']['count'] * 3)
        
        # Suspicious API sequences increase risk (20 points)
        if results['api_sequences']['found']:
            risk += min(20, results['api_sequences']['count'] * 10)
        
        # Weak obfuscation increases risk (10 points)
        if results['weak_obfuscation']['found']:
            risk += min(10, results['weak_obfuscation']['count'] * 5)
        
        return min(100, risk)
    
    def _calculate_severity(self, results):
        """Calculate overall severity"""
        detection_risk = results['detection_risk']
        
        if detection_risk >= 70:
            return 'CRITICAL'
        elif detection_risk >= 50:
            return 'HIGH'
        elif detection_risk >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'

def analyze_directory_for_payloads(directory):
    """Analyze a directory for data obfuscation issues"""
    analyzer = PayloadObfuscationAnalyzer()
    results = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            result = analyzer.analyze_file(file_path)
            if result:
                results.append(result)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logger.info("Usage: python3 payload_obfuscation_analyzer.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for data obfuscation...")
    
    results = analyze_directory_for_payloads(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with data code")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"📊 Obfuscation Score: {result['obfuscation_score']}/100")
        logger.info(f"🎯 Detection Risk: {result['detection_risk']}/100")
        logger.info(f"📈 Entropy: {result['entropy']['entropy']}/8.0 ({result['entropy']['risk']})")
        
        if result['string_patterns']['found']:
            logger.info(f"  🔍 Predictable Patterns: {result['string_patterns']['count']} found")
        
        if result['api_sequences']['found']:
            logger.info(f"  ⚠️  Suspicious API Sequences: {result['api_sequences']['count']} found")
        
        if result['weak_obfuscation']['found']:
            logger.info(f"  🚨 Weak Obfuscation: {result['weak_obfuscation']['count']} indicators")

