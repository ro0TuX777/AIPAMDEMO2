#!/usr/bin/env python3
"""
Forensic Artifact Detector for BlueScrub
Identifies forensic artifacts left by technique tools

Focus Areas:
- Log file creation (application logs, system logs)
- Registry modifications (Windows registry keys)
- File system artifacts (temp files, cache, history)
- Memory artifacts (process names, memory dumps)
- Network artifacts (connection logs, DNS cache)
- Persistence mechanisms (startup, scheduled tasks)
"""

import os
import re
from pathlib import Path

import logging

logger = logging.getLogger(__name__)
class ForensicArtifactDetector:
    """Detects forensic artifacts left by technique tools"""
    
    def __init__(self):
        """Log file patterns"""
        self.log_patterns = [
            # Only match actual .log file operations, not the logging module
            (r'\.log\b', 'Log file creation'),
            (r'syslog|eventlog|audit', 'System log access'),
            (r'open\(["\'].*?\.log["\']|fopen\(["\'].*?\.log["\']', 'Log file writing'),
            (r'WriteFile.*?log|write.*?log', 'Log writing'),
            (r'print\(.*?file=|fprintf|fputs', 'File output (potential logging)'),
        ]
        
        # Registry patterns (Windows)
        self.registry_patterns = [
            (r'RegOpenKey|RegCreateKey|RegSetValue', 'Registry modification'),
            (r'HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU', 'Registry key access'),
            (r'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run', 'Startup registry key'),
            (r'winreg|_winreg|RegEdit', 'Registry manipulation'),
            (r'reg\s+add|reg\s+delete|reg\s+query', 'Registry command'),
        ]
        
        # File system artifact patterns
        self.filesystem_patterns = [
            (r'%TEMP%|%TMP%|/tmp/|C:\\\\Temp|AppData\\\\Local\\\\Temp', 'Temp directory usage'),
            (r'\.tmp|\.temp|\.cache', 'Temporary file creation'),
            (r'Recent|RecentDocs|MRU', 'Recent files list'),
            (r'Prefetch|\.pf', 'Windows Prefetch'),
            (r'\.lnk|shortcut', 'Shortcut file creation'),
            (r'Recycle|Trash', 'Deleted files'),
        ]
        
        # Memory artifact patterns - CRITICAL FIX
        # Normal operations like malloc, exec, fork are EXPECTED in legitimate code
        # Only flag SUSPICIOUS patterns like process injection, memory manipulation
        self.memory_patterns = [
            # Suspicious: Process injection and manipulation
            (r'WriteProcessMemory|ReadProcessMemory', 'Process memory access (suspicious)'),
            (r'CreateRemoteThread|QueueUserAPC', 'Remote thread creation (suspicious)'),
            (r'VirtualAllocEx|VirtualProtectEx', 'Remote memory manipulation (suspicious)'),
            (r'SetWindowsHookEx|SetWinEventHook', 'Hook injection (suspicious)'),
            # Normal operations - DON'T flag these
            # (r'CreateProcess|exec|spawn|fork', 'Process creation'),  # NORMAL
            # (r'VirtualAlloc|malloc|calloc|mmap', 'Memory allocation'),  # NORMAL
        ]

        # Normal operations that should NOT be flagged
        self.normal_operations = [
            'CreateProcess', 'exec', 'spawn', 'fork',  # Process creation
            'malloc', 'calloc', 'mmap', 'VirtualAlloc',  # Memory allocation
            'socket', 'connect', 'bind', 'listen',  # Network operations
        ]

        # Network artifact patterns - CRITICAL FIX
        # Normal network operations are EXPECTED in legitimate code
        # Only flag SUSPICIOUS patterns like network enumeration tools
        self.network_patterns = [
            # Suspicious: Network enumeration and discovery tools
            (r'netstat|ipconfig|ifconfig', 'Network enumeration (suspicious)'),
            (r'arp\s+|route\s+|traceroute', 'Network discovery (suspicious)'),
            (r'pcap|tcpdump|wireshark', 'Network capture (suspicious)'),
            (r'nmap|masscan|zmap', 'Network scanning (suspicious)'),
            # Normal operations - DON'T flag these
            # (r'connect\(|socket\(|bind\(|listen\(', 'Network connection'),  # NORMAL
            # (r'getaddrinfo|gethostbyname|dns', 'DNS resolution'),  # NORMAL
        ]
        
        # Persistence mechanism patterns
        self.persistence_patterns = [
            # Only match Windows registry keys, not the word "Run" in strings/help text
            (r'HKEY_LOCAL_MACHINE.*?\\(Startup|Run|RunOnce)|winreg\.SetValueEx.*?(Startup|Run|RunOnce)', 'Startup persistence'),
            # Only match actual scheduled task commands, not the word "at" in variable names
            (r'schtasks|subprocess\.call\(["\']at\s+|os\.system\(["\']at\s+|cron|crontab', 'Scheduled task'),
            # Require word boundaries — bare 'service' matches too broadly
            (r'\bsystemctl\b|\bsc\.exe\b|CreateServiceW?|OpenServiceW?', 'Service creation'),
            (r'WMI.*?Event|WMI.*?Consumer', 'WMI persistence'),
            (r'\.bashrc|\.profile|\.bash_profile', 'Shell profile modification'),
            (r'\bautorun\b|\bautostart\b', 'Auto-start mechanism'),
        ]

        # Evidence of artifact cleanup
        self.cleanup_patterns = [
            # Require word boundaries to avoid matching variable names like "removed"
            (r'\bDeleteFile\b|\bDeleteFileW?\b|\bos\.unlink\b|\bos\.remove\b|\bshutil\.rmtree\b', 'File deletion'),
            (r'\bshred\b|\bwipe\b|secure.*?delete', 'Secure deletion'),
            (r'clear.*?log|truncate.*?log', 'Log clearing'),
            (r'RegDeleteKey|RegDeleteValue', 'Registry cleanup'),
            (r'history\s+-c|clear.*?history', 'History clearing'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for forensic artifacts"""
        try:
            # Only analyze source code files
            if not self._is_source_file(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if file creates forensic artifacts
            if not self._creates_artifacts(content):
                return None

            results = {
                'file': str(file_path),
                'log_artifacts': self._detect_log_artifacts(content),
                'registry_artifacts': self._detect_registry_artifacts(content),
                'filesystem_artifacts': self._detect_filesystem_artifacts(content),
                'memory_artifacts': self._detect_memory_artifacts(content),
                'network_artifacts': self._detect_network_artifacts(content),
                'persistence_artifacts': self._detect_persistence_artifacts(content),
                'cleanup_attempts': self._detect_cleanup(content),
                'artifact_risk': 0,
                'severity': 'MEDIUM'
            }

            # Calculate artifact risk and severity
            results['artifact_risk'] = self._calculate_artifact_risk(results)
            results['severity'] = self._calculate_severity(results)

            return results

        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _is_source_file(self, file_path):
        """Check if file is a source code file"""
        source_extensions = ['.py', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.pl', '.js', '.ps1', '.bat', '.sh']
        return Path(file_path).suffix.lower() in source_extensions
    
    def _creates_artifacts(self, content):
        """Check if content creates forensic artifacts — uses specific patterns
        rather than overly broad keywords like 'file' or 'write'."""
        keywords = [
            'registry', 'hkey_', 'regopen', 'regcreate',
            'schtasks', 'crontab', 'systemctl', 'sc.exe',
            'writeprocessmemory', 'createremotethread',
            'virtualprotectex', 'virtualallocex',
            'prefetch', '.lnk', 'autorun',
            'netstat', 'ipconfig', 'ifconfig',
            'pcap', 'tcpdump', 'nmap',
        ]
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in keywords)
    
    def _detect_log_artifacts(self, content):
        """Detect log file artifacts"""
        found_artifacts = []

        for pattern, description in self.log_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    artifact_text = match.group()

                    # Skip Python logging module usage (import logging, logging.debug, etc.)
                    if 'logging' in artifact_text.lower() or 'logger' in artifact_text.lower():
                        # Check if this is part of Python logging module
                        match_start = match.start()
                        # Look at context around the match
                        context_start = max(0, match_start - 50)
                        context_end = min(len(content), match_start + 100)
                        context = content[context_start:context_end]

                        # Skip if it's Python logging module usage
                        if any(x in context.lower() for x in ['import logging', 'logging.', 'logger.', 'getlogger']):
                            continue

                    line_num = content[:match.start()].count('\n') + 1
                    found_artifacts.append({
                        'artifact': artifact_text[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })

        if not found_artifacts:
            return {'found': False, 'artifacts': []}

        return {
            'found': True,
            'artifacts': found_artifacts,
            'count': len(found_artifacts),
            'risk': 'HIGH',
            'explanation': 'Log files create forensic evidence of tool execution'
        }
    
    def _detect_registry_artifacts(self, content):
        """Detect registry artifacts"""
        found_artifacts = []
        
        for pattern, description in self.registry_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_artifacts.append({
                        'artifact': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_artifacts:
            return {'found': False, 'artifacts': []}
        
        return {
            'found': True,
            'artifacts': found_artifacts,
            'count': len(found_artifacts),
            'risk': 'HIGH',
            'explanation': 'Registry modifications leave permanent forensic traces'
        }
    
    def _detect_filesystem_artifacts(self, content):
        """Detect file system artifacts"""
        found_artifacts = []
        
        for pattern, description in self.filesystem_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
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
            'explanation': 'File system artifacts reveal tool usage patterns'
        }
    
    def _detect_memory_artifacts(self, content):
        """Detect memory artifacts"""
        found_artifacts = []
        
        for pattern, description in self.memory_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
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
            'explanation': 'Memory artifacts can be captured in memory dumps'
        }
    
    def _detect_network_artifacts(self, content):
        """Detect network artifacts"""
        found_artifacts = []
        
        for pattern, description in self.network_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
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
            'explanation': 'Network artifacts leave traces in logs and caches'
        }
    
    def _detect_persistence_artifacts(self, content):
        """Detect persistence mechanism artifacts"""
        found_artifacts = []

        for pattern, description in self.persistence_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    artifact_text = match.group()
                    match_start = match.start()

                    # Skip false positives for "at" command
                    # Only flag if it's actually a scheduled task command, not just the word "at"
                    if description == 'Scheduled task' and artifact_text.lower() == 'at':
                        context_start = max(0, match_start - 30)
                        context_end = min(len(content), match_start + 50)
                        context = content[context_start:context_end]

                        # Skip if it's not part of a command execution
                        if not any(x in context.lower() for x in ['subprocess', 'os.system', 'popen', 'exec', 'call']):
                            continue

                    # Skip false positives for "Run" in strings and help text
                    # Only flag if it's actually a Windows registry key or API call
                    if description == 'Startup persistence' and 'Run' in artifact_text:
                        context_start = max(0, match_start - 50)
                        context_end = min(len(content), match_start + 100)
                        context = content[context_start:context_end]

                        # Skip if it's in a string or help text, not a registry key
                        if any(x in context.lower() for x in ['help=', 'print(', 'f"', "f'", '"""', "'''"]):
                            continue

                    line_num = content[:match.start()].count('\n') + 1
                    found_artifacts.append({
                        'artifact': artifact_text[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })

        if not found_artifacts:
            return {'found': False, 'artifacts': []}

        return {
            'found': True,
            'artifacts': found_artifacts,
            'count': len(found_artifacts),
            'risk': 'HIGH',
            'explanation': 'Persistence mechanisms create highly visible forensic artifacts'
        }
    
    def _detect_cleanup(self, content):
        """Detect artifact cleanup attempts"""
        found_cleanup = []
        
        for pattern, description in self.cleanup_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_cleanup.append({
                        'cleanup': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'effectiveness': 'MEDIUM'
                    })
        
        if not found_cleanup:
            return {'found': False, 'cleanup': []}
        
        return {
            'found': True,
            'cleanup': found_cleanup,
            'count': len(found_cleanup),
            'risk': 'LOW',
            'explanation': 'Cleanup attempts reduce but do not eliminate forensic traces'
        }
    
    def _calculate_artifact_risk(self, results):
        """Calculate forensic artifact risk (0-100)"""
        risk = 0
        
        # Log artifacts (25 points)
        if results['log_artifacts']['found']:
            risk += min(25, results['log_artifacts']['count'] * 8)
        
        # Registry artifacts (25 points)
        if results['registry_artifacts']['found']:
            risk += min(25, results['registry_artifacts']['count'] * 8)
        
        # Persistence artifacts (20 points)
        if results['persistence_artifacts']['found']:
            risk += min(20, results['persistence_artifacts']['count'] * 7)
        
        # File system artifacts (15 points)
        if results['filesystem_artifacts']['found']:
            risk += min(15, results['filesystem_artifacts']['count'] * 5)
        
        # Memory artifacts (10 points)
        if results['memory_artifacts']['found']:
            risk += min(10, results['memory_artifacts']['count'] * 3)
        
        # Network artifacts (5 points)
        if results['network_artifacts']['found']:
            risk += min(5, results['network_artifacts']['count'] * 2)
        
        # Reduce risk if cleanup is present (up to 20 points)
        if results['cleanup_attempts']['found']:
            risk -= min(20, results['cleanup_attempts']['count'] * 5)
        
        return max(0, min(100, risk))
    
    def _calculate_severity(self, results):
        """Calculate overall severity"""
        risk = results['artifact_risk']
        
        if risk >= 70:
            return 'CRITICAL'
        elif risk >= 50:
            return 'HIGH'
        elif risk >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'

def analyze_directory_for_artifacts(directory):
    """Analyze a directory for forensic artifacts"""
    detector = ForensicArtifactDetector()
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
        logger.info("Usage: python3 forensic_artifact_detector.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for forensic artifacts...")
    
    results = analyze_directory_for_artifacts(directory)
    
    logger.info(f"\n📊 Found {len(results)} files creating forensic artifacts")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"🎯 Artifact Risk: {result['artifact_risk']}/100")
        
        if result['log_artifacts']['found']:
            logger.info(f"  📝 Log Artifacts: {result['log_artifacts']['count']} found")
        
        if result['registry_artifacts']['found']:
            logger.info(f"  🗂️  Registry Artifacts: {result['registry_artifacts']['count']} found")
        
        if result['persistence_artifacts']['found']:
            logger.info(f"  🔄 Persistence Artifacts: {result['persistence_artifacts']['count']} found")

