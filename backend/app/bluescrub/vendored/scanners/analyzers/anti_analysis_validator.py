#!/usr/bin/env python3
"""
Anti-Analysis Validator for BlueScrub
Validates effectiveness of anti-debugging and anti-analysis techniques

Focus Areas:
- Debugger detection validation (effectiveness testing)
- VM detection validation (evasion techniques)
- Sandbox evasion verification (behavioral checks)
- Anti-disassembly checks (code obfuscation)
- Timing-based detection (performance checks)
- Environment fingerprinting (system checks)
"""

import os
import re
from pathlib import Path
from collections import defaultdict

import logging

logger = logging.getLogger(__name__)
class AntiAnalysisValidator:
    """Validates anti-analysis techniques for effectiveness"""
    
    def __init__(self):
        """Debugger detection patterns"""
        self.debugger_patterns = [
            (r'IsDebuggerPresent|CheckRemoteDebuggerPresent', 'Windows debugger detection'),
            (r'ptrace\s*\(.*?PTRACE_TRACEME', 'Linux ptrace anti-debug'),
            (r'sysctl.*?P_TRACED', 'macOS sysctl anti-debug'),
            (r'/proc/self/status.*?TracerPid', 'Linux TracerPid check'),
            (r'NtQueryInformationProcess', 'NT API debugger check'),
            (r'OutputDebugString|GetLastError', 'OutputDebugString trick'),
        ]
        
        # VM detection patterns
        self.vm_patterns = [
            (r'VMware|VirtualBox|VBOX|Hyper-V|QEMU|Xen', 'VM vendor detection'),
            (r'cpuid|rdtsc', 'CPU instruction timing'),
            (r'HKEY.*?HARDWARE.*?DEVICEMAP', 'Registry VM detection'),
            (r'VBoxService|vmtoolsd|vmwaretray', 'VM process detection'),
            (r'MAC.*?00:0[cC]:29|00:50:56|08:00:27', 'VM MAC address'),
            (r'SCSI.*?VBOX|VMware', 'VM SCSI detection'),
        ]
        
        # Sandbox detection patterns
        self.sandbox_patterns = [
            (r'sleep\s*\(\s*\d+\s*\)|Sleep\s*\(\s*\d+\s*\)', 'Sleep-based evasion'),
            (r'GetTickCount|time\.time|clock_gettime', 'Timing checks'),
            (r'GetSystemMetrics|GetSystemInfo', 'System metrics check'),
            (r'GetModuleHandle.*?sbiedll|api_log', 'Sandbox DLL detection'),
            (r'C:\\analysis|C:\\sample|C:\\threat', 'Sandbox path detection'),
            (r'CurrentUser.*?Sandbox|maltest|infection', 'Sandbox username detection'),
        ]
        
        # Anti-disassembly patterns
        self.anti_disassembly_patterns = [
            (r'jmp\s+\$\+\d+|call\s+\$\+\d+', 'Jump obfuscation'),
            (r'int\s+3|int3|\xcc', 'Breakpoint instructions'),
            (r'opaque.*?predicate', 'Opaque predicates'),
            (r'junk.*?code|garbage.*?code', 'Junk code insertion'),
            (r'self.*?modifying', 'Self-modifying code'),
        ]
        
        # Weak/ineffective anti-analysis
        self.weak_patterns = [
            (r'if.*?debugger.*?exit|if.*?vm.*?exit', 'Simple exit on detection'),
            (r'assert\s*\(.*?debug', 'Debug assertions only'),
            (r'#ifdef.*?DEBUG|#ifndef.*?NDEBUG', 'Compile-time only'),
            # Removed r'try.*?except.*?pass' — too broad, matches normal Python
            # error handling in every codebase.
        ]
        
        # Environment checks
        self.environment_patterns = [
            (r'GetUserName|getlogin|whoami', 'Username check'),
            (r'GetComputerName|gethostname|hostname', 'Hostname check'),
            (r'GetSystemDirectory|GetWindowsDirectory', 'System directory check'),
            (r'GetDiskFreeSpace|statvfs', 'Disk space check'),
            (r'GetSystemTime|GetLocalTime', 'System time check'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for anti-analysis techniques"""
        try:
            # Only analyze source code files
            if not self._is_source_file(file_path):
                return None

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if file contains anti-analysis code
            if not self._has_anti_analysis(content):
                return None

            results = {
                'file': str(file_path),
                'debugger_detection': self._detect_debugger_checks(content),
                'vm_detection': self._detect_vm_checks(content),
                'sandbox_evasion': self._detect_sandbox_evasion(content),
                'anti_disassembly': self._detect_anti_disassembly(content),
                'environment_checks': self._detect_environment_checks(content),
                'weak_techniques': self._detect_weak_techniques(content),
                'effectiveness_score': 0,
                'severity': 'MEDIUM'
            }

            # Calculate effectiveness score and severity
            results['effectiveness_score'] = self._calculate_effectiveness(results)
            results['severity'] = self._calculate_severity(results)

            return results

        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _is_source_file(self, file_path):
        """Check if file is a source code file"""
        source_extensions = ['.py', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.pl', '.js', '.asm']
        return Path(file_path).suffix.lower() in source_extensions
    
    def _has_anti_analysis(self, content):
        """Check if content has anti-analysis code"""
        keywords = [
            'debug', 'debugger', 'vm', 'virtual', 'sandbox', 'analysis',
            'ptrace', 'isdebuggerpresent', 'vmware', 'vbox', 'qemu'
        ]
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in keywords)
    
    def _detect_debugger_checks(self, content):
        """Detect debugger detection techniques"""
        found_checks = []
        
        for pattern, description in self.debugger_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_checks.append({
                        'technique': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'effectiveness': 'MEDIUM'
                    })
        
        if not found_checks:
            return {'found': False, 'checks': []}
        
        return {
            'found': True,
            'checks': found_checks,
            'count': len(found_checks),
            'risk': 'MEDIUM',
            'explanation': 'Debugger detection can be bypassed by skilled analysts'
        }
    
    def _detect_vm_checks(self, content):
        """Detect VM detection techniques"""
        found_checks = []
        
        for pattern, description in self.vm_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_checks.append({
                        'technique': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'effectiveness': 'MEDIUM'
                    })
        
        if not found_checks:
            return {'found': False, 'checks': []}
        
        return {
            'found': True,
            'checks': found_checks,
            'count': len(found_checks),
            'risk': 'MEDIUM',
            'explanation': 'VM detection can be evaded with proper VM hardening'
        }
    
    def _detect_sandbox_evasion(self, content):
        """Detect sandbox evasion techniques"""
        found_techniques = []
        
        for pattern, description in self.sandbox_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_techniques.append({
                        'technique': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'effectiveness': 'LOW'
                    })
        
        if not found_techniques:
            return {'found': False, 'techniques': []}
        
        return {
            'found': True,
            'techniques': found_techniques,
            'count': len(found_techniques),
            'risk': 'LOW',
            'explanation': 'Basic sandbox evasion is easily detected by modern sandboxes'
        }
    
    def _detect_anti_disassembly(self, content):
        """Detect anti-disassembly techniques"""
        found_techniques = []
        
        for pattern, description in self.anti_disassembly_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_techniques.append({
                        'technique': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'effectiveness': 'MEDIUM'
                    })
        
        if not found_techniques:
            return {'found': False, 'techniques': []}
        
        return {
            'found': True,
            'techniques': found_techniques,
            'count': len(found_techniques),
            'risk': 'MEDIUM',
            'explanation': 'Anti-disassembly slows but does not prevent analysis'
        }
    
    def _detect_environment_checks(self, content):
        """Detect environment fingerprinting"""
        found_checks = []
        
        for pattern, description in self.environment_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_checks.append({
                        'check': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'effectiveness': 'LOW'
                    })
        
        if not found_checks:
            return {'found': False, 'checks': []}
        
        return {
            'found': True,
            'checks': found_checks,
            'count': len(found_checks),
            'risk': 'LOW',
            'explanation': 'Environment checks are easily spoofed'
        }
    
    def _detect_weak_techniques(self, content):
        """Detect weak/ineffective anti-analysis"""
        found_weak = []
        
        for pattern, description in self.weak_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_weak.append({
                        'weakness': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_weak:
            return {'found': False, 'weaknesses': []}
        
        return {
            'found': True,
            'weaknesses': found_weak,
            'count': len(found_weak),
            'risk': 'HIGH',
            'explanation': 'Weak anti-analysis provides false sense of security'
        }
    
    def _calculate_effectiveness(self, results):
        """Calculate anti-analysis effectiveness score (0-100)"""
        score = 0
        
        # Debugger detection (25 points)
        if results['debugger_detection']['found']:
            score += min(25, results['debugger_detection']['count'] * 8)
        
        # VM detection (25 points)
        if results['vm_detection']['found']:
            score += min(25, results['vm_detection']['count'] * 8)
        
        # Sandbox evasion (20 points)
        if results['sandbox_evasion']['found']:
            score += min(20, results['sandbox_evasion']['count'] * 5)
        
        # Anti-disassembly (20 points)
        if results['anti_disassembly']['found']:
            score += min(20, results['anti_disassembly']['count'] * 7)
        
        # Environment checks (10 points)
        if results['environment_checks']['found']:
            score += min(10, results['environment_checks']['count'] * 3)
        
        # Deduct for weak techniques (30 points)
        if results['weak_techniques']['found']:
            score -= min(30, results['weak_techniques']['count'] * 10)
        
        return max(0, min(100, score))
    
    def _calculate_severity(self, results):
        """Calculate overall severity.

        Anti-analysis is *expected* in offensive tooling, so its mere
        presence is not alarming.  Severity reflects how detectable the
        chosen techniques are:
          - Well-known / trivially detectable  → HIGH  (hurts more than helps)
          - Standard but still recognisable    → MEDIUM (default)
          - Sophisticated / hard to signature  → LOW   (good tradecraft)
        """
        effectiveness = results['effectiveness_score']
        has_weak = results.get('weak_techniques', {}).get('found', False)

        # Weak techniques (simple exit-on-detect, debug assertions) are
        # trivially bypassed AND easily signatured — worst of both worlds.
        if has_weak:
            return 'HIGH'

        # Low effectiveness means the techniques used are well-known
        # and catalogued in AV/EDR databases, but still operational.
        if effectiveness < 30:
            return 'MEDIUM'
        elif effectiveness < 50:
            return 'MEDIUM'
        else:
            return 'LOW'

def analyze_directory_for_anti_analysis(directory):
    """Analyze a directory for anti-analysis techniques"""
    validator = AntiAnalysisValidator()
    results = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            result = validator.analyze_file(file_path)
            if result:
                results.append(result)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logger.info("Usage: python3 anti_analysis_validator.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for anti-analysis techniques...")
    
    results = analyze_directory_for_anti_analysis(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with anti-analysis code")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"📊 Effectiveness Score: {result['effectiveness_score']}/100")
        
        if result['debugger_detection']['found']:
            logger.info(f"  🐛 Debugger Detection: {result['debugger_detection']['count']} techniques")
        
        if result['vm_detection']['found']:
            logger.info(f"  💻 VM Detection: {result['vm_detection']['count']} techniques")
        
        if result['weak_techniques']['found']:
            logger.info(f"  ⚠️  Weak Techniques: {result['weak_techniques']['count']} found")

