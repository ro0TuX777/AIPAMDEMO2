#!/usr/bin/env python3
"""
Metadata Leakage Scanner for BlueScrub
Detects metadata that reveals attribution and development environment

Focus Areas:
- Compiler version in binaries (toolchain identification)
- Build timestamps (development timeline)
- Debug symbols and PDB paths (source code paths)
- Source code paths (directory structure)
- Username/hostname leakage (developer identity)
- Git metadata (repository information)
"""

import os
import re
import subprocess
from pathlib import Path
from datetime import datetime

import logging

logger = logging.getLogger(__name__)
class MetadataLeakageScanner:
    """Analyzes files for metadata leakage"""
    
    def __init__(self):
        """Path patterns that reveal information"""
        self.path_patterns = [
            (r'[C-Z]:\\Users\\([^\\]+)\\', 'Windows username'),
            (r'/home/([^/]+)/', 'Linux username'),
            (r'/Users/([^/]+)/', 'macOS username'),
            (r'[C-Z]:\\[^\\]+\\[^\\]+\\Desktop', 'Desktop path'),
            (r'[C-Z]:\\[^\\]+\\[^\\]+\\Documents', 'Documents path'),
            (r'[C-Z]:\\[^\\]+\\[^\\]+\\Downloads', 'Downloads path'),
            (r'/tmp/[^/]+', 'Temp directory usage'),
            # Require a hostname-like string (letters/digits/hyphens, 3+ chars)
            # after \\  to avoid matching random binary data.
            (r'\\\\([a-zA-Z0-9][a-zA-Z0-9._-]{2,})\\[a-zA-Z0-9]', 'Network share/hostname'),
        ]
        
        # Compiler/toolchain version patterns
        self.compiler_patterns = [
            (r'GCC:\s*\(.*?\)\s*([\d.]+)', 'GCC version'),
            (r'clang\s+version\s+([\d.]+)', 'Clang version'),
            (r'Microsoft.*?C/C\+\+.*?Compiler.*?([\d.]+)', 'MSVC version'),
            (r'rustc\s+([\d.]+)', 'Rust compiler'),
            # Require "go" followed by a proper semver (e.g. "go1.21.3")
            # to avoid matching random binary sequences like "Go0" / "gO1".
            (r'go1\.\d+(?:\.\d+)?', 'Go version'),
            (r'Python\s+([\d.]+)', 'Python version'),
        ]
        
        # Debug symbol patterns
        self.debug_patterns = [
            (r'\.pdb', 'PDB debug file'),
            (r'__debug__', 'Debug flag'),
            (r'DWARF', 'DWARF debug info'),
            (r'\.dSYM', 'macOS debug symbols'),
            (r'__FILE__|__LINE__|__func__', 'Debug macros'),
        ]
        
        # Build timestamp patterns
        self.timestamp_patterns = [
            (r'__DATE__|__TIME__', 'Compile time macros'),
            (r'Build\s+date:|Built\s+on:', 'Build date string'),
            (r'Compiled\s+on:', 'Compilation date'),
        ]
        
        # Git metadata patterns - MEDIUM FIX
        # Only flag git hashes if they have git context nearby
        # Bare 40-char hex strings could be SHA-1 hashes, crypto keys, etc.
        self.git_patterns = [
            (r'\.git/', 'Git directory'),
            (r'git\s+commit|git\s+hash', 'Git commit reference'),
            # MEDIUM FIX: Require git context for 40-char hex strings
            # (r'[0-9a-f]{40}', 'Git commit hash'),  # TOO BROAD - catches SHA-1, crypto keys
            (r'(?:git|commit|hash|sha1).*?[0-9a-f]{40}', 'Git commit hash (with context)'),
            (r'[0-9a-f]{40}(?:\s|$|[,;:\)])', 'Git commit hash (with context)'),
            (r'origin/|upstream/', 'Git remote reference'),
        ]
        
        # Email/contact patterns
        self.contact_patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email address'),
            (r'mailto:', 'Email link'),
            (r'Contact:|Email:', 'Contact information'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for metadata leakage"""
        try:
            file_ext = Path(file_path).suffix.lower()
            
            # Analyze based on file type
            if file_ext in ['.exe', '.dll', '.so', '.dylib', '.o', '.a']:
                return self._analyze_binary(file_path)
            elif file_ext in ['.py', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.pl', '.js']:
                return self._analyze_source(file_path)
            else:
                return None
                
        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _analyze_binary(self, file_path):
        """Analyze binary file for metadata"""
        results = {
            'file': str(file_path),
            'type': 'binary',
            'compiler_info': self._extract_compiler_info(file_path),
            'debug_symbols': self._check_debug_symbols(file_path),
            'embedded_paths': self._extract_embedded_paths(file_path),
            'build_timestamps': self._extract_build_timestamps(file_path),
            'strings_analysis': self._analyze_strings(file_path),
            'leakage_score': 0,
            'severity': 'MEDIUM'
        }
        
        # Calculate leakage score and severity
        results['leakage_score'] = self._calculate_leakage_score(results)
        results['severity'] = self._calculate_severity(results)
        
        # Only return if leakage found
        if self._has_leakage(results):
            return results
        
        return None
    
    def _analyze_source(self, file_path):
        """Analyze source code file for metadata"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            results = {
                'file': str(file_path),
                'type': 'source',
                'embedded_paths': self._find_paths_in_content(content),
                'compiler_references': self._find_compiler_refs(content),
                'debug_code': self._find_debug_code(content),
                'timestamps': self._find_timestamps(content),
                'git_metadata': self._find_git_metadata(content),
                'contact_info': self._find_contact_info(content),
                'leakage_score': 0,
                'severity': 'MEDIUM'
            }

            # Calculate leakage score and severity
            results['leakage_score'] = self._calculate_leakage_score(results)
            results['severity'] = self._calculate_severity(results)

            # Only return if leakage found
            if self._has_leakage(results):
                return results

            return None

        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _extract_compiler_info(self, file_path):
        """Extract compiler information from binary"""
        found_info = []
        
        try:
            # Use strings command to extract readable strings
            result = subprocess.run(
                ['strings', str(file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                content = result.stdout
                
                for pattern, description in self.compiler_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        found_info.append({
                            'info': match.group()[:100],
                            'type': description,
                            'risk': 'MEDIUM'
                        })
        except:
            pass
        
        if not found_info:
            return {'found': False, 'info': []}
        
        return {
            'found': True,
            'info': found_info[:5],  # Limit to 5
            'count': len(found_info),
            'risk': 'MEDIUM',
            'explanation': 'Compiler information reveals development toolchain'
        }
    
    def _check_debug_symbols(self, file_path):
        """Check for debug symbols in binary"""
        found_symbols = []
        
        try:
            # Check with file command
            result = subprocess.run(
                ['file', str(file_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                if 'not stripped' in output:
                    found_symbols.append({
                        'symbol': 'Not stripped',
                        'type': 'Debug symbols present',
                        'risk': 'HIGH'
                    })
                
                if 'debug' in output:
                    found_symbols.append({
                        'symbol': 'Debug info',
                        'type': 'Debug information present',
                        'risk': 'HIGH'
                    })
        except:
            pass
        
        if not found_symbols:
            return {'found': False, 'symbols': []}
        
        return {
            'found': True,
            'symbols': found_symbols,
            'count': len(found_symbols),
            'risk': 'HIGH',
            'explanation': 'Debug symbols reveal source code structure and function names'
        }
    
    def _extract_embedded_paths(self, file_path):
        """Extract embedded file paths from binary"""
        found_paths = []
        
        try:
            result = subprocess.run(
                ['strings', str(file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                content = result.stdout
                found_paths = self._find_paths_in_content(content)
        except:
            pass
        
        return found_paths
    
    def _extract_build_timestamps(self, file_path):
        """Extract build timestamps from binary content.

        NOTE: File-system mtime is NOT reported — it reflects when the file
        was copied/uploaded, not when the binary was originally built.  Only
        timestamps embedded *inside* the binary (PE header, Build date
        strings) are meaningful for attribution.
        """
        found_timestamps = []

        try:
            # Look for embedded build-date strings via `strings`
            result = subprocess.run(
                ['strings', str(file_path)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for pattern, description in self.timestamp_patterns:
                    for match in re.finditer(pattern, result.stdout, re.IGNORECASE):
                        found_timestamps.append({
                            'timestamp': match.group()[:50],
                            'type': description,
                            'risk': 'MEDIUM',
                        })
                        if len(found_timestamps) >= 3:
                            break
        except Exception:
            pass

        if not found_timestamps:
            return {'found': False, 'timestamps': []}

        return {
            'found': True,
            'timestamps': found_timestamps,
            'count': len(found_timestamps),
            'risk': 'MEDIUM',
            'explanation': 'Embedded build timestamps reveal development timeline',
        }
    
    def _analyze_strings(self, file_path):
        """Analyze strings in binary for sensitive information"""
        found_strings = []
        
        try:
            result = subprocess.run(
                ['strings', '-n', '8', str(file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                # Look for suspicious strings
                for line in lines[:100]:  # Limit analysis
                    if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
                        found_strings.append({
                            'string': line[:50],
                            'type': 'Sensitive keyword',
                            'risk': 'HIGH'
                        })
        except:
            pass
        
        if not found_strings:
            return {'found': False, 'strings': []}
        
        return {
            'found': True,
            'strings': found_strings[:10],
            'count': len(found_strings),
            'risk': 'HIGH',
            'explanation': 'Embedded strings may contain sensitive information'
        }
    
    def _find_paths_in_content(self, content):
        """Find file paths in content"""
        found_paths = []
        
        for pattern, description in self.path_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    found_paths.append({
                        'path': match.group()[:100],
                        'type': description,
                        'risk': 'HIGH',
                        'explanation': f'{description} reveals developer identity'
                    })
        
        if not found_paths:
            return {'found': False, 'paths': []}
        
        return {
            'found': True,
            'paths': found_paths,
            'count': len(found_paths),
            'risk': 'HIGH',
            'explanation': 'Embedded paths reveal development environment and user identity'
        }
    
    def _find_compiler_refs(self, content):
        """Find compiler references in source"""
        found_refs = []
        
        for pattern, description in self.compiler_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:3]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_refs.append({
                        'reference': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_refs:
            return {'found': False, 'references': []}
        
        return {
            'found': True,
            'references': found_refs,
            'count': len(found_refs),
            'risk': 'MEDIUM',
            'explanation': 'Compiler references reveal toolchain information'
        }
    
    def _find_debug_code(self, content):
        """Find debug code in source"""
        found_debug = []

        for pattern, description in self.debug_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    match_start = match.start()

                    # Skip __file__ if it's used in normal Python code (print, logging, etc.)
                    if '__file__' in match.group().lower():
                        # Get the line containing the match
                        line_start = content.rfind('\n', 0, match_start) + 1
                        line_end = content.find('\n', match_start)
                        if line_end == -1:
                            line_end = len(content)
                        line_content = content[line_start:line_end]

                        # Skip if __file__ is used in normal contexts
                        if any(x in line_content.lower() for x in ['print(', 'logging', 'logger', 'format', 'f"', "f'"]):
                            continue

                    found_debug.append({
                        'code': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })

        if not found_debug:
            return {'found': False, 'debug': []}

        return {
            'found': True,
            'debug': found_debug,
            'count': len(found_debug),
            'risk': 'MEDIUM',
            'explanation': 'Debug code reveals development practices'
        }
    
    def _find_timestamps(self, content):
        """Find timestamp references"""
        found_timestamps = []
        
        for pattern, description in self.timestamp_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:3]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_timestamps.append({
                        'timestamp': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'LOW'
                    })
        
        if not found_timestamps:
            return {'found': False, 'timestamps': []}
        
        return {
            'found': True,
            'timestamps': found_timestamps,
            'count': len(found_timestamps),
            'risk': 'LOW',
            'explanation': 'Timestamp macros reveal build time'
        }
    
    def _find_git_metadata(self, content):
        """Find Git metadata"""
        found_git = []
        
        for pattern, description in self.git_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:3]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_git.append({
                        'metadata': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_git:
            return {'found': False, 'git': []}
        
        return {
            'found': True,
            'git': found_git,
            'count': len(found_git),
            'risk': 'MEDIUM',
            'explanation': 'Git metadata reveals repository information'
        }
    
    def _find_contact_info(self, content):
        """Find contact information"""
        found_contact = []
        
        for pattern, description in self.contact_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:3]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_contact.append({
                        'contact': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_contact:
            return {'found': False, 'contact': []}
        
        return {
            'found': True,
            'contact': found_contact,
            'count': len(found_contact),
            'risk': 'HIGH',
            'explanation': 'Contact information reveals developer identity'
        }
    
    def _calculate_leakage_score(self, results):
        """Calculate metadata leakage score (0-100)"""
        score = 0
        
        # Check all possible leakage categories
        categories = [
            'embedded_paths', 'compiler_info', 'debug_symbols', 'contact_info',
            'compiler_references', 'debug_code', 'git_metadata'
        ]
        
        for category in categories:
            if category in results and results[category].get('found'):
                count = results[category].get('count', 1)
                risk = results[category].get('risk', 'MEDIUM')
                
                if risk == 'HIGH':
                    score += min(30, count * 10)
                elif risk == 'MEDIUM':
                    score += min(20, count * 5)
                else:
                    score += min(10, count * 2)
        
        return min(100, score)
    
    def _calculate_severity(self, results):
        """Calculate overall severity"""
        score = results['leakage_score']
        
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _has_leakage(self, results):
        """Check if any metadata leakage was found"""
        categories = [
            'embedded_paths', 'compiler_info', 'debug_symbols', 'contact_info',
            'compiler_references', 'debug_code', 'git_metadata', 'strings_analysis'
        ]
        
        return any(results.get(cat, {}).get('found', False) for cat in categories)

def analyze_directory_for_metadata(directory):
    """Analyze a directory for metadata leakage"""
    scanner = MetadataLeakageScanner()
    results = []
    
    for root, dirs, files in os.walk(directory):
        # Skip .git directories
        if '.git' in dirs:
            dirs.remove('.git')
        
        for file in files:
            file_path = Path(root) / file
            result = scanner.analyze_file(file_path)
            if result:
                results.append(result)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logger.info("Usage: python3 metadata_leakage_scanner.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for metadata leakage...")
    
    results = analyze_directory_for_metadata(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with metadata leakage")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"🎯 Leakage Score: {result['leakage_score']}/100")
        
        if result.get('embedded_paths', {}).get('found'):
            logger.info(f"  📁 Embedded Paths: {result['embedded_paths']['count']} found")
        
        if result.get('debug_symbols', {}).get('found'):
            logger.info(f"  🐛 Debug Symbols: Present")
        
        if result.get('contact_info', {}).get('found'):
            logger.info(f"  📧 Contact Info: {result['contact_info']['count']} found")

