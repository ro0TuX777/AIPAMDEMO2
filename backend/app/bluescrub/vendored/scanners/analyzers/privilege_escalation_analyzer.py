#!/usr/bin/env python3
"""
Privilege Escalation Analyzer for BlueScrub
Analyzes privilege escalation code for security vulnerabilities

Focus Areas:
- Race condition vulnerabilities (TOCTOU)
- Unsafe privilege drops (setuid/setgid issues)
- Capability leakage (Linux capabilities)
- Token manipulation issues (Windows tokens)
- Sudo/UAC override vulnerabilities
- Kernel technique safety (stability issues)
"""

import os
import re
from pathlib import Path

import logging

logger = logging.getLogger(__name__)
class PrivilegeEscalationAnalyzer:
    """Analyzes privilege escalation code for vulnerabilities"""
    
    def __init__(self):
        """Race condition patterns (TOCTOU)
        self.race_condition_patterns = [
            (r'access\s*\([^)]+\).*?open\s*\(', 'TOCTOU: access() then try:
        f = open()'),
            (r'stat\s*\([^)]+\).*?open\s*\(', 'TOCTOU: stat() then try:
        f = open()'),
            (r'lstat\s*\([^)]+\).*?open\s*\(', 'TOCTOU: lstat() then try:
        f = open()'),
            (r'if\s+os\.path\.exists.*?open\(', 'TOCTOU: exists() then try:
        f = open()'),
            (r'if\s+os\.path\.isfile.*?open\(', 'TOCTOU: isfile() then try:
        f = open()'),
        ]
        
        # Unsafe privilege drop patterns
        self.privilege_drop_patterns = [
            (r'setuid\s*\(\s*0\s*\)', 'Unsafe setuid(0)'),
            (r'seteuid\s*\(\s*0\s*\)', 'Unsafe seteuid(0)'),
            (r'setgid\s*\(\s*0\s*\)', 'Unsafe setgid(0)'),
            (r'setegid\s*\(\s*0\s*\)', 'Unsafe setegid(0)'),
            (r'setreuid|setregid', 'Complex privilege manipulation'),
            (r'setresuid|setresgid', 'Complex privilege manipulation'),
        ]
        
        # Capability patterns (Linux)
        self.capability_patterns = [
            (r'cap_set_proc|cap_set_file', 'Capability manipulation'),
            (r'CAP_SYS_ADMIN|CAP_DAC_OVERRIDE', 'Dangerous capability'),
            (r'CAP_SETUID|CAP_SETGID', 'Privilege change capability'),
            (r'prctl\s*\(.*?PR_SET_SECUREBITS', 'Securebits manipulation'),
            (r'prctl\s*\(.*?PR_SET_NO_NEW_PRIVS', 'No new privs flag'),
        ]
        
        # Token manipulation patterns (Windows)
        self.token_patterns = [
            (r'OpenProcessToken|OpenThreadToken', 'Token access'),
            (r'DuplicateToken|DuplicateTokenEx', 'Token duplication'),
            (r'SetThreadToken|ImpersonateLoggedOnUser', 'Token impersonation'),
            (r'AdjustTokenPrivileges', 'Privilege adjustment'),
            (r'SE_DEBUG_NAME|SeDebugPrivilege', 'Debug privilege'),
            (r'SE_IMPERSONATE_NAME|SeImpersonatePrivilege', 'Impersonate privilege'),
        ]
        
        # Sudo/UAC override patterns
        self.bypass_patterns = [
            (r'sudo\s+-[A-Za-z]*n|sudo.*?NOPASSWD', 'Sudo override attempt'),
            (r'pkexec|gksudo|kdesudo', 'Privilege escalation tool'),
            (r'UAC|User.*?Account.*?Control', 'UAC reference'),
            (r'runas|ShellExecute.*?runas', 'Windows runas'),
            (r'fodhelper|eventvwr|computerdefaults', 'UAC override technique'),
        ]
        
        # Kernel technique patterns
        self.kernel_patterns = [
            (r'ioctl\s*\(', 'Kernel IOCTL call'),
            (r'/dev/|/proc/|/sys/', 'Kernel interface access'),
            (r'mmap\s*\(.*?MAP_FIXED', 'Fixed memory mapping'),
            (r'ptrace\s*\(', 'Process tracing'),
            (r'kernel.*?technique|kernel.*?vuln', 'Kernel technique reference'),
        ]
        
        # Unsafe file operations
        self.unsafe_file_patterns = [
            (r'symlink\s*\(|link\s*\(', 'Symlink creation'),
            (r'/tmp/[^/\s]+', 'Predictable temp file'),
            (r'mktemp\s*\(|tmpnam\s*\(', 'Unsafe temp file creation'),
            (r'chmod\s*\(.*?0777|chmod.*?777', 'Overly permissive permissions'),
            (r'chown\s*\(.*?0.*?0\)|chown.*?root', 'Ownership change to root'),
        ]
        
        # Privilege check patterns"""
        self.privilege_check_patterns = [
            (r'getuid|geteuid|getgid|getegid', 'UID/GID check'),
            (r'IsUserAnAdmin|CheckTokenMembership', 'Admin check (Windows)'),
            (r'if.*?root|if.*?uid.*?0', 'Root check'),
            (r'sudo\s+-l|sudo\s+--list', 'Sudo permission check'),
        ]
    
    def analyze_file(self, file_path):
        """Analyze a file for privilege escalation vulnerabilities"""
        try:
            # Only analyze source code files
            if not self._is_source_file(file_path):
                return None

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if file contains privilege escalation code
            if not self._has_privesc_code(content):
                return None

            results = {
                'file': str(file_path),
                'race_conditions': self._detect_race_conditions(content),
                'unsafe_privilege_drops': self._detect_unsafe_drops(content),
                'capability_issues': self._detect_capability_issues(content),
                'token_manipulation': self._detect_token_issues(content),
                'bypass_techniques': self._detect_bypass_techniques(content),
                'kernel_exploits': self._detect_kernel_exploits(content),
                'unsafe_file_ops': self._detect_unsafe_file_ops(content),
                'privilege_checks': self._detect_privilege_checks(content),
                'privesc_risk': 0,
                'severity': 'MEDIUM'
            }

            # Calculate privilege escalation risk and severity
            results['privesc_risk'] = self._calculate_privesc_risk(results)
            results['severity'] = self._calculate_severity(results)

            return results

        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}
    
    def _is_source_file(self, file_path):
        """Check if file is a source code file"""
        source_extensions = ['.py', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.pl', '.sh', '.ps1']
        return Path(file_path).suffix.lower() in source_extensions
    
    def _has_privesc_code(self, content):
        """Check if content has privilege escalation code"""
        keywords = [
            'setuid', 'setgid', 'sudo', 'root', 'admin', 'privilege',
            'escalat', 'token', 'capability', 'uac', 'kernel', 'technique'
        ]
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in keywords)
    
    def _detect_race_conditions(self, content):
        """Detect TOCTOU race conditions"""
        found_issues = []
        
        for pattern, description in self.race_condition_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_issues.append({
                        'issue': match.group()[:80],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_issues:
            return {'found': False, 'issues': []}
        
        return {
            'found': True,
            'issues': found_issues,
            'count': len(found_issues),
            'risk': 'HIGH',
            'explanation': 'TOCTOU race conditions allow privilege escalation exploitation'
        }
    
    def _detect_unsafe_drops(self, content):
        """Detect unsafe privilege drops"""
        found_issues = []
        
        for pattern, description in self.privilege_drop_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_issues.append({
                        'issue': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_issues:
            return {'found': False, 'issues': []}
        
        return {
            'found': True,
            'issues': found_issues,
            'count': len(found_issues),
            'risk': 'HIGH',
            'explanation': 'Unsafe privilege drops can be exploited to regain privileges'
        }
    
    def _detect_capability_issues(self, content):
        """Detect Linux capability issues"""
        found_issues = []
        
        for pattern, description in self.capability_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_issues.append({
                        'issue': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_issues:
            return {'found': False, 'issues': []}
        
        return {
            'found': True,
            'issues': found_issues,
            'count': len(found_issues),
            'risk': 'MEDIUM',
            'explanation': 'Capability manipulation can leak privileges'
        }
    
    def _detect_token_issues(self, content):
        """Detect Windows token manipulation issues"""
        found_issues = []
        
        for pattern, description in self.token_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_issues.append({
                        'issue': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_issues:
            return {'found': False, 'issues': []}
        
        return {
            'found': True,
            'issues': found_issues,
            'count': len(found_issues),
            'risk': 'HIGH',
            'explanation': 'Token manipulation errors can be exploited by defenders'
        }
    
    def _detect_bypass_techniques(self, content):
        """Detect sudo/UAC override techniques"""
        found_techniques = []
        
        for pattern, description in self.bypass_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_techniques.append({
                        'technique': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'MEDIUM'
                    })
        
        if not found_techniques:
            return {'found': False, 'techniques': []}
        
        return {
            'found': True,
            'techniques': found_techniques,
            'count': len(found_techniques),
            'risk': 'MEDIUM',
            'explanation': 'override techniques may have stability or detection issues'
        }
    
    def _detect_kernel_exploits(self, content):
        """Detect kernel technique patterns"""
        found_exploits = []
        
        for pattern, description in self.kernel_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_exploits.append({
                        'technique': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'CRITICAL'
                    })
        
        if not found_exploits:
            return {'found': False, 'exploits': []}
        
        return {
            'found': True,
            'exploits': found_exploits,
            'count': len(found_exploits),
            'risk': 'CRITICAL',
            'explanation': 'Kernel exploits can cause system crashes and are highly detectable'
        }
    
    def _detect_unsafe_file_ops(self, content):
        """Detect unsafe file operations"""
        found_ops = []
        
        for pattern, description in self.unsafe_file_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches[:5]:
                    line_num = content[:match.start()].count('\n') + 1
                    found_ops.append({
                        'operation': match.group()[:50],
                        'type': description,
                        'line': line_num,
                        'risk': 'HIGH'
                    })
        
        if not found_ops:
            return {'found': False, 'operations': []}
        
        return {
            'found': True,
            'operations': found_ops,
            'count': len(found_ops),
            'risk': 'HIGH',
            'explanation': 'Unsafe file operations create race condition vulnerabilities'
        }
    
    def _detect_privilege_checks(self, content):
        """Detect privilege checking code"""
        found_checks = []
        
        for pattern, description in self.privilege_check_patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                line_num = content[:matches[0].start()].count('\n') + 1
                found_checks.append({
                    'check': description,
                    'count': len(matches),
                    'line': line_num,
                    'risk': 'LOW'
                })
        
        if not found_checks:
            return {'found': False, 'checks': []}
        
        return {
            'found': True,
            'checks': found_checks,
            'count': len(found_checks),
            'risk': 'LOW',
            'explanation': 'Privilege checks present (good practice)'
        }
    
    def _calculate_privesc_risk(self, results):
        """Calculate privilege escalation risk (0-100)"""
        risk = 0
        
        # Race conditions (30 points)
        if results['race_conditions']['found']:
            risk += min(30, results['race_conditions']['count'] * 10)
        
        # Unsafe privilege drops (25 points)
        if results['unsafe_privilege_drops']['found']:
            risk += min(25, results['unsafe_privilege_drops']['count'] * 10)
        
        # Token manipulation (20 points)
        if results['token_manipulation']['found']:
            risk += min(20, results['token_manipulation']['count'] * 7)
        
        # Unsafe file operations (15 points)
        if results['unsafe_file_ops']['found']:
            risk += min(15, results['unsafe_file_ops']['count'] * 5)
        
        # Kernel exploits (10 points)
        if results['kernel_exploits']['found']:
            risk += min(10, results['kernel_exploits']['count'] * 5)
        
        # Reduce risk if privilege checks present (up to 10 points)
        if results['privilege_checks']['found']:
            risk -= min(10, results['privilege_checks']['count'] * 3)
        
        return max(0, min(100, risk))
    
    def _calculate_severity(self, results):
        """Calculate overall severity"""
        risk = results['privesc_risk']
        
        if risk >= 70:
            return 'CRITICAL'
        elif risk >= 50:
            return 'HIGH'
        elif risk >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'

def analyze_directory_for_privesc(directory):
    """Analyze a directory for privilege escalation vulnerabilities"""
    analyzer = PrivilegeEscalationAnalyzer()
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
        logger.info("Usage: python3 privilege_escalation_analyzer.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    logger.info(f"🔍 Analyzing {directory} for privilege escalation vulnerabilities...")
    
    results = analyze_directory_for_privesc(directory)
    
    logger.info(f"\n📊 Found {len(results)} files with privilege escalation code")
    
    for result in results:
        if 'error' in result:
            continue
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📄 File: {result['file']}")
        logger.info(f"⚠️  Severity: {result['severity']}")
        logger.info(f"🎯 Privesc Risk: {result['privesc_risk']}/100")
        
        if result['race_conditions']['found']:
            logger.info(f"  ⚡ Race Conditions: {result['race_conditions']['count']} found")
        
        if result['unsafe_privilege_drops']['found']:
            logger.info(f"  🔓 Unsafe Privilege Drops: {result['unsafe_privilege_drops']['count']} found")
        
        if result['token_manipulation']['found']:
            logger.info(f"  🎫 Token Manipulation: {result['token_manipulation']['count']} found")

