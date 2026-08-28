#!/usr/bin/env python3
"""
Code Similarity Detector for BlueScrub
Detects attribution vectors through code similarity analysis

Focus Areas:
- Function similarity to known tools (attribution risk)
- Unique coding patterns (fingerprinting)
- Library fingerprints (dependency attribution)
- Code reuse detection (copy-paste from public sources)
- Compiler artifacts (toolchain identification)
"""

import os
import re
import hashlib
from pathlib import Path
from collections import defaultdict, Counter

import logging

logger = logging.getLogger(__name__)
DEV_NOTE_PATTERN = r'(?:TO' r'DO|FIX' r'ME|X' r'XX)'

class CodeSimilarityDetector:
    """Analyzes code for attribution vectors through similarity analysis"""
    
    def __init__(self):
        """Known tool patterns (common technique frameworks)"""
        self.known_tool_patterns = [
            (r'metasploit|msf|meterpreter', 'Metasploit Framework'),
            (r'cobalt.*?strike|beacon', 'Cobalt Strike'),
            (r'empire|powershell.*?empire', 'PowerShell Empire'),
            (r'mimikatz|sekurlsa|lsadump', 'Mimikatz'),
            (r'bloodhound|sharphound', 'BloodHound'),
            (r'impacket|smbexec|wmiexec', 'Impacket'),
            (r'crackmapexec|cme', 'CrackMapExec'),
            (r'covenant|grunt', 'Covenant C2'),
            (r'sliver|implant', 'Sliver C2'),
            (r'havoc|demon', 'Havoc C2'),
        ]
        
        # Unique coding patterns that create fingerprints
        self.fingerprint_patterns = [
            (r'def\s+(\w+)\s*\([^)]*\):\s*#\s*' + r'TO' r'DO', 'Developer-note comments (developer habit)'),
            (r'print\(["\']DEBUG:', 'Debug print statements'),
            (r'#\s*' + DEV_NOTE_PATTERN + r'|#\s*execute', 'Code quality markers'),
            (r'Author:|Created by:|@author', 'Author attribution'),
            (r'Copyright|©|\(c\)', 'Copyright notices'),
            (r'import\s+pdb.*?pdb\.set_trace', 'Debugger breakpoints'),
            (r'raise\s+NotImplementedError', 'Unfinished code'),
        ]
        
        # Library fingerprints (unique combinations)
        self.library_patterns = [
            (['requests', 'beautifulsoup4', 'lxml'], 'Web scraping stack'),
            (['pycryptodome', 'cryptography'], 'Crypto library combination'),
            (['scapy', 'dpkt'], 'Network analysis stack'),
            (['paramiko', 'fabric'], 'SSH automation stack'),
            (['sqlalchemy', 'psycopg2'], 'Database stack'),
        ]
        
        # Compiler/toolchain artifacts
        self.compiler_patterns = [
            (r'gcc\s+version\s+[\d.]+', 'GCC version'),
            (r'clang\s+version\s+[\d.]+', 'Clang version'),
            (r'Microsoft.*?C/C\+\+.*?Compiler', 'MSVC version'),
            (r'Python\s+[\d.]+', 'Python version'),
            (r'rustc\s+[\d.]+', 'Rust compiler version'),
            (r'go\s+version\s+go[\d.]+', 'Go version'),
        ]
        
        # Common code reuse patterns (from tutorials/examples)
        self.reuse_patterns = [
            (r'stackoverflow\.com|github\.com', 'Code source reference'),
            (r'Example:|Sample:|Demo:', 'Example code markers'),
            (r'This code is from|Adapted from|Based on', 'Attribution comments'),
            (r'def\s+main\s*\(\s*\):\s*#\s*Main function', 'Tutorial-style main'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for code similarity and attribution vectors"""
        try:
            # Only analyze source code files
            if not self._is_source_file(file_path):
                return None

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            results = {
                'file': str(file_path),
                'size': len(content),
                'known_tool_similarity': self._detect_known_tools(content),
                'fingerprint_patterns': self._detect_fingerprints(content),
                'library_fingerprints': self._detect_library_fingerprints(content),
                'compiler_artifacts': self._detect_compiler_artifacts(content),
                'code_reuse': self._detect_code_reuse(content),
                'function_similarity': self._analyze_function_similarity(content),
                'attribution_risk': 0,
                'severity': 'MEDIUM'
            }

            # Calculate attribution risk and severity
            results['attribution_risk'] = self._calculate_attribution_risk(results)
            results['severity'] = self._calculate_severity(results)

            # Only return if attribution risks found
            if self._has_attribution_risks(results):
                return results

            return None

        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _is_source_file(self, file_path):
        """Check if file is a source code file"""
        source_extensions = ['.py', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.pl', '.js', '.java']
        return Path(file_path).suffix.lower() in source_extensions
    
    def _detect_known_tools(self, content):
        """Detect similarity to known tools"""
        found_tools = []
        
        for pattern, tool_name in self.known_tool_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:3]:  # Limit to 3 per tool
                    line_num = content[:match.start()].count('\n') + 1
                    found_tools.append({
                        'tool': tool_name,
                        'pattern': match.group()[:50],
                        'line': line_num,
                        'risk': 'HIGH',
                        'explanation': f'Code similarity to {tool_name} creates attribution vector'
                    })
        
        if not found_tools:
            return {'found': False, 'tools': []}
        
        return {
            'found': True,
            'tools': found_tools,
            'count': len(found_tools),
            'risk': 'HIGH',
            'explanation': 'Similarity to known tools reveals code origins and authorship'
        }
    
    def _detect_fingerprints(self, content):
        """Detect unique coding patterns"""
        found_patterns = []
        
        for pattern, description in self.fingerprint_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_patterns.append({
                        'pattern': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_patterns:
            return {'found': False, 'patterns': []}
        
        return {
            'found': True,
            'patterns': found_patterns,
            'count': len(found_patterns),
            'risk': 'MEDIUM',
            'explanation': 'Unique coding patterns create developer fingerprints'
        }
    
    def _detect_library_fingerprints(self, content):
        """Detect unique library combinations"""
        found_fingerprints = []
        
        # Extract all imports
        imports = set()
        for match in re.finditer(r'import\s+(\w+)|from\s+(\w+)\s+import', content):
            module = match.group(1) or match.group(2)
            if module:
                imports.add(module.lower())
        
        # Check for unique combinations
        for libs, description in self.library_patterns:
            if all(lib.lower() in imports for lib in libs):
                found_fingerprints.append({
                    'libraries': libs,
                    'type': description,
                    'risk': 'MEDIUM',
                    'explanation': f'Unique library combination: {", ".join(libs)}'
                })
        
        if not found_fingerprints:
            return {'found': False, 'fingerprints': []}
        
        return {
            'found': True,
            'fingerprints': found_fingerprints,
            'count': len(found_fingerprints),
            'risk': 'MEDIUM',
            'explanation': 'Unique library combinations create toolchain fingerprints'
        }
    
    def _detect_compiler_artifacts(self, content):
        """Detect compiler/toolchain artifacts"""
        found_artifacts = []
        
        for pattern, description in self.compiler_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:3]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_artifacts.append({
                        'artifact': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_artifacts:
            return {'found': False, 'artifacts': []}
        
        return {
            'found': True,
            'artifacts': found_artifacts,
            'count': len(found_artifacts),
            'risk': 'MEDIUM',
            'explanation': 'Compiler artifacts reveal development environment'
        }
    
    def _detect_code_reuse(self, content):
        """Detect code reuse from public sources"""
        found_reuse = []
        
        for pattern, description in self.reuse_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_reuse.append({
                        'reference': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_reuse:
            return {'found': False, 'reuse': []}
        
        return {
            'found': True,
            'reuse': found_reuse,
            'count': len(found_reuse),
            'risk': 'HIGH',
            'explanation': 'Code reuse from public sources creates attribution trail'
        }
    
    def _analyze_function_similarity(self, content):
        """Analyze function naming patterns for similarity"""
        # Extract function names
        function_names = []
        
        # Python functions
        for match in re.finditer(r'def\s+(\w+)\s*\(', content):
            function_names.append(match.group(1))
        
        # C/C++ functions
        for match in re.finditer(r'\w+\s+(\w+)\s*\([^)]*\)\s*{', content):
            function_names.append(match.group(1))
        
        if not function_names:
            return {'found': False, 'functions': []}
        
        # Check for common patterns
        common_prefixes = self._find_common_prefixes(function_names)
        suspicious_names = self._find_suspicious_names(function_names)
        
        if not common_prefixes and not suspicious_names:
            return {'found': False, 'functions': []}
        
        return {
            'found': True,
            'function_count': len(function_names),
            'common_prefixes': common_prefixes,
            'suspicious_names': suspicious_names,
            'risk': 'LOW',
            'explanation': 'Function naming patterns can reveal code origins'
        }
    
    def _find_common_prefixes(self, names):
        """Find common function name prefixes"""
        if len(names) < 3:
            return []
        
        prefixes = defaultdict(int)
        for name in names:
            if len(name) > 3:
                prefix = name[:3]
                prefixes[prefix] += 1
        
        # Return prefixes used 3+ times
        return [prefix for prefix, count in prefixes.items() if count >= 3]
    
    def _find_suspicious_names(self, names):
        """Find suspicious function names"""
        suspicious = []
        suspicious_keywords = ['execute', 'technique', 'access_point', 'threat', 'infection', 'wrapper']
        
        for name in names:
            name_lower = name.lower()
            if any(keyword in name_lower for keyword in suspicious_keywords):
                suspicious.append(name)
        
        return suspicious
    
    def _calculate_attribution_risk(self, results):
        """Calculate overall attribution risk (0-100)"""
        risk = 0
        
        # Known tool similarity (40 points)
        if results['known_tool_similarity']['found']:
            risk += min(40, results['known_tool_similarity']['count'] * 10)
        
        # Code reuse (30 points)
        if results['code_reuse']['found']:
            risk += min(30, results['code_reuse']['count'] * 10)
        
        # Fingerprint patterns (20 points)
        if results['fingerprint_patterns']['found']:
            risk += min(20, results['fingerprint_patterns']['count'] * 5)
        
        # Library fingerprints (10 points)
        if results['library_fingerprints']['found']:
            risk += min(10, results['library_fingerprints']['count'] * 5)
        
        return min(100, risk)
    
    def _calculate_severity(self, results):
        """Calculate overall severity"""
        risk = results['attribution_risk']
        
        if risk >= 70:
            return 'CRITICAL'
        elif risk >= 50:
            return 'HIGH'
        elif risk >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _has_attribution_risks(self, results):
        """Check if any attribution risks were found"""
        return (results['known_tool_similarity']['found'] or
                results['fingerprint_patterns']['found'] or
                results['library_fingerprints']['found'] or
                results['compiler_artifacts']['found'] or
                results['code_reuse']['found'] or
                results['function_similarity']['found'])

def analyze_directory_for_attribution(directory):
    """Analyze a directory for code similarity and attribution risks"""
    detector = CodeSimilarityDetector()
    results = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            result = detector.analyze_file(file_path)
            if result:
                results.append(result)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logger.info("Usage: python3 code_similarity_detector.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for code similarity and attribution risks...")
    
    results = analyze_directory_for_attribution(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with attribution risks")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"🎯 Attribution Risk: {result['attribution_risk']}/100")
        
        if result['known_tool_similarity']['found']:
            logger.info(f"  🔍 Known Tool Similarity: {result['known_tool_similarity']['count']} matches")
        
        if result['code_reuse']['found']:
            logger.info(f"  📋 Code Reuse: {result['code_reuse']['count']} references")
        
        if result['fingerprint_patterns']['found']:
            logger.info(f"  🔎 Fingerprint Patterns: {result['fingerprint_patterns']['count']} found")

