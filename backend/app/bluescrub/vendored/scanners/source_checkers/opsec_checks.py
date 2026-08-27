"""OPSEC and detectability checks: attribution, evasion, exploitation patterns

Mixin methods inherited by SimpleSecurityScanner.
"""

import re


class OpsecChecksMixin:
    """OPSEC and detectability checks: attribution, evasion, exploitation patterns"""
    def _check_etw_amsi_bypass(self, filepath, content):
        """Check for ETW/AMSI bypass patterns — high detection risk"""
        patterns = [
            (r'AmsiScanBuffer', 'AMSI bypass — AmsiScanBuffer hook/patch'),
            (r'amsi\.dll', 'AMSI DLL reference'),
            (r'AmsiInitialize', 'AMSI initialization hook'),
            (r'AmsiOpenSession', 'AMSI session hook'),
            (r'EtwEventWrite', 'ETW event write hook/patch'),
            (r'NtTraceEvent', 'ETW NtTraceEvent bypass'),
            (r'ntdll!EtwEventWrite', 'ETW bypass via ntdll patch'),
            (r'patch.*?amsi', 'AMSI patching pattern'),
            (r'patch.*?etw', 'ETW patching pattern'),
            (r'CLR_ETW', 'CLR ETW provider manipulation'),
            (r'SetWindowsHookEx.*?WH_', 'Windows hook injection (detectable)'),
            (r'NtProtectVirtualMemory.*?PAGE_EXECUTE_READWRITE', 'RWX memory — high detection signal'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['ETW/AMSI Bypass'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'CRITICAL'
                })
                self.issues_found += 1

    def _check_syscall_vs_api(self, filepath, content):
        """Distinguish direct syscalls from API calls — detection risk assessment"""
        api_patterns = [
            (r'(?:Nt|Zw)(?:CreateFile|OpenProcess|WriteVirtualMemory|AllocateVirtualMemory|ProtectVirtualMemory|MapViewOfSection|CreateThread|QueueApcThread)', 'Direct NT syscall (lower detection)'),
            (r'(?:Create|Open)Process(?:A|W)?\s*\(', 'Win32 API call (higher detection — hooked by EDR)'),
            (r'VirtualAlloc(?:Ex)?\s*\(', 'Win32 VirtualAlloc (hooked by EDR)'),
            (r'WriteProcessMemory\s*\(', 'Win32 WriteProcessMemory (highly monitored)'),
            (r'CreateRemoteThread(?:Ex)?\s*\(', 'Win32 CreateRemoteThread (highly monitored)'),
            (r'LoadLibrary(?:A|W|Ex)?\s*\(', 'Win32 LoadLibrary (monitored)'),
            (r'GetProcAddress\s*\(', 'Win32 GetProcAddress (API resolution — monitored)'),
            (r'syscall\s*\(', 'Direct syscall invocation'),
            (r'int\s+0x2e', 'Direct int 0x2e syscall (x86)'),
            (r'sysenter', 'sysenter instruction'),
        ]
        lines = content.split('\n')
        for pattern, desc in api_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                severity = 'HIGH' if 'hooked' in desc or 'monitored' in desc else 'MEDIUM'
                self.findings['Syscall vs API Detection'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': severity
                })
                self.issues_found += 1

    # ===== ATTRIBUTION CHECKS =====

    def _check_timezone_locale_leakage(self, filepath, content):
        """Check for timezone/locale information that could reveal operator location"""
        patterns = [
            (r'timezone\s*=\s*["\'][^"\']+["\']', 'Hardcoded timezone string'),
            (r'(?:TZ|TIMEZONE)\s*=\s*["\'][^"\']+["\']', 'Timezone environment variable'),
            (r'locale\s*=\s*["\'][a-z]{2}_[A-Z]{2}', 'Hardcoded locale (attribution risk)'),
            (r'(?:LC_ALL|LC_CTYPE|LANG)\s*=\s*["\'][^"\']+', 'Locale environment variable'),
            (r'setlocale\s*\(\s*\w+\s*,\s*["\'][^"\']+', 'setlocale call with specific locale'),
            (r'(?:Asia|Europe|America|Africa|Pacific|Atlantic)/\w+', 'IANA timezone identifier'),
            (r'(?:pytz|dateutil)\.timezone', 'Python timezone library usage'),
            (r'time\.timezone\b', 'System timezone access'),
            (r'GetTimeZoneInformation', 'Windows timezone API'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Timezone/Locale Leakage'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'MEDIUM'
                })
                self.issues_found += 1

    def _check_build_env_leakage(self, filepath, content):
        """Check for build environment paths and PDB paths that reveal developer info"""
        patterns = [
            (r'[A-Z]:\\\\Users\\\\[^\\]+', 'Windows user profile path (reveals username)'),
            (r'/home/[a-zA-Z0-9_]+/', 'Linux home directory path (reveals username)'),
            (r'/Users/[a-zA-Z0-9_]+/', 'macOS home directory path (reveals username)'),
            (r'\.pdb\b', 'PDB debug symbol reference (attribution risk)'),
            (r'DWARF', 'DWARF debug info reference'),
            (r'__COMPILATION_TIME__', 'Compilation time macro'),
            (r'__DATE__', 'Build date macro (timestamp leakage)'),
            (r'__TIME__', 'Build time macro (timestamp leakage)'),
            (r'__TIMESTAMP__', 'Build timestamp macro'),
            (r'BuildMachine\s*=', 'Build machine name'),
            (r'COMPUTERNAME|HOSTNAME|USERNAME', 'Environment variable leaking host/user info'),
            (r'os\.getlogin\(\)', 'Python getlogin() — reveals operator username'),
            (r'getenv\(\s*["\']USER', 'Getting USER environment variable'),
            (r'socket\.gethostname\(\)', 'Getting hostname — attribution risk'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Build Environment Leakage'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_unicode_homoglyphs(self, filepath, content):
        """Check for Unicode homoglyphs that could be stylometric fingerprints"""
        homoglyph_ranges = [
            (r'[\u0400-\u04ff]', 'Cyrillic character (homoglyph risk)'),
            (r'[\u0370-\u03ff]', 'Greek character (homoglyph risk)'),
            (r'[\u2000-\u206f]', 'General punctuation (invisible/special chars)'),
            (r'[\u200b-\u200f]', 'Zero-width character (steganographic fingerprint)'),
            (r'[\u2028-\u2029]', 'Line/paragraph separator (unusual whitespace)'),
            (r'[\u00a0]', 'Non-breaking space (stylometric fingerprint)'),
            (r'[\ufeff]', 'BOM character (encoding fingerprint)'),
            (r'[\u202a-\u202e]', 'Bi-directional text control (Trojan Source)'),
        ]
        lines = content.split('\n')
        for pattern, desc in homoglyph_ranges:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Unicode Homoglyphs'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'MEDIUM'
                })
                self.issues_found += 1

    # ===== OPSEC CHECKS =====

    def _check_dns_tunneling(self, filepath, content):
        """Check for DNS tunneling patterns"""
        patterns = [
            (r'dns\.resolver\.resolve\s*\(.*?TXT', 'DNS TXT query (common tunneling channel)'),
            (r'dnslib\.|dnspython', 'DNS library import (potential tunneling)'),
            (r'base64.*?\.encode.*?\..*?dns|dns.*?base64', 'Base64 + DNS (tunneling pattern)'),
            (r'nslookup|dig\s+', 'DNS lookup tool invocation'),
            (r'subdomain.*?encode|encode.*?subdomain', 'Subdomain encoding (DNS exfil)'),
            (r'\.arpa\b', 'Reverse DNS lookup'),
            (r'iodine|dnscat|dns2tcp', 'Known DNS tunneling tool reference'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['DNS Tunneling'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_timestamp_stomping(self, filepath, content):
        """Check for timestamp manipulation patterns"""
        patterns = [
            (r'os\.utime\s*\(', 'os.utime() — timestamp modification'),
            (r'SetFileTime', 'Windows SetFileTime API (timestamp stomping)'),
            (r'touch\s+-[trd]', 'touch with timestamp flag'),
            (r'futimens|utimensat', 'POSIX timestamp modification syscall'),
            (r'NtSetInformationFile.*?FileBasicInformation', 'NT timestamp stomping'),
            (r'\$SI|\$STANDARD_INFORMATION', 'NTFS $SI attribute manipulation'),
            (r'timestomp', 'Metasploit timestomp reference'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Timestamp Stomping'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_log_evasion(self, filepath, content):
        """Check for log evasion / event log clearing patterns"""
        patterns = [
            (r'ClearEventLog', 'Windows ClearEventLog API'),
            (r'wevtutil\s+cl', 'wevtutil clear-log command'),
            (r'Remove-EventLog', 'PowerShell Remove-EventLog'),
            (r'Clear-EventLog', 'PowerShell Clear-EventLog'),
            (r'del\s+.*?\.evtx', 'Deleting Windows event log files'),
            (r'rm\s+.*?/var/log/', 'Deleting Linux log files'),
            (r'truncate.*?/var/log/', 'Truncating Linux log files'),
            (r'history\s*-c|HISTSIZE\s*=\s*0|unset\s+HISTFILE', 'Shell history evasion'),
            (r'ELFCleaner|logcleaner|log_cleaner', 'Log cleaner tool reference'),
            (r'auditctl\s+-D', 'Audit rule deletion'),
            (r'systemctl\s+stop\s+.*?(?:syslog|rsyslog|auditd)', 'Stopping logging service'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Log Evasion'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_process_injection_classification(self, filepath, content):
        """Classify process injection techniques by detection risk"""
        patterns = [
            (r'CreateRemoteThread', 'Classic injection — HIGHEST detection risk'),
            (r'NtCreateThreadEx', 'NT thread creation — HIGH detection risk'),
            (r'RtlCreateUserThread', 'Undocumented thread creation — MEDIUM detection'),
            (r'QueueUserAPC|NtQueueApcThread', 'APC injection — MEDIUM detection'),
            (r'SetThreadContext|NtSetContextThread', 'Thread hijacking — MEDIUM detection'),
            (r'NtMapViewOfSection', 'Section mapping injection — LOWER detection'),
            (r'NtUnmapViewOfSection.*?NtMapViewOfSection', 'Process hollowing — HIGH detection'),
            (r'SetWindowLongPtr.*?WndProc', 'Window procedure hooking — MEDIUM detection'),
            (r'AtomBombing|GlobalAddAtom', 'AtomBombing injection — LOWER detection'),
            (r'EarlyBird|NtResumeThread', 'Early Bird injection — LOWER detection'),
            (r'EnumWindows.*?callback|EnumDisplayMonitors.*?callback', 'Callback injection — LOWER detection'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                severity = 'CRITICAL' if 'HIGHEST' in desc else ('HIGH' if 'HIGH' in desc else 'MEDIUM')
                self.findings['Process Injection'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': severity
                })
                self.issues_found += 1

    def _check_cleanup_routines(self, filepath, content):
        """Check for cleanup/self-deletion routines"""
        patterns = [
            (r'os\.remove\s*\(\s*__file__', 'Self-deletion via os.remove(__file__)'),
            (r'os\.unlink\s*\(\s*sys\.argv\[0\]', 'Self-deletion via sys.argv[0]'),
            (r'DeleteFile.*?argv\[0\]', 'Windows self-deletion'),
            (r'MoveFileEx.*?MOVEFILE_DELAY_UNTIL_REBOOT', 'Delayed self-deletion on reboot'),
            (r'shred\s+-[uzf]', 'Secure file shredding'),
            (r'cipher\s+/w:', 'Windows free-space wiping'),
            (r'SecureZeroMemory|RtlZeroMemory|memset.*?0.*?sizeof', 'Secure memory wiping'),
            (r'VirtualFree|HeapFree.*?sensitive|secret', 'Freeing sensitive memory'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Cleanup Routines'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'MEDIUM'
                })
                self.issues_found += 1

    # ===== EXPLOITATION ANALYSIS CHECKS =====

    def _check_stack_pivot(self, filepath, content):
        """Check for stack pivot gadgets and techniques"""
        patterns = [
            (r'xchg\s+(?:e|r)sp', 'Stack pivot via xchg esp/rsp'),
            (r'mov\s+(?:e|r)sp\s*,', 'Stack pivot via mov esp/rsp'),
            (r'leave\s*;\s*ret', 'Stack pivot via leave;ret gadget'),
            (r'add\s+(?:e|r)sp\s*,\s*(?:0x[0-9a-fA-F]+|[0-9]+)', 'Stack adjustment (potential pivot)'),
            (r'sub\s+(?:e|r)sp\s*,\s*(?:0x[0-9a-fA-F]+|[0-9]+)', 'Stack frame manipulation'),
            (r'pivot|stack_pivot|stackpivot', 'Stack pivot reference'),
            (r'VirtualProtect.*?PAGE_EXECUTE_READWRITE', 'RWX via VirtualProtect (ROP target)'),
            (r'mprotect\s*\(.*?PROT_EXEC', 'mprotect with PROT_EXEC (ROP target)'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Stack Pivot'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'HIGH'
                })
                self.issues_found += 1

    def _check_kernel_exploit_patterns(self, filepath, content):
        """Check for kernel exploitation patterns"""
        patterns = [
            (r'DeviceIoControl\s*\(', 'DeviceIoControl — kernel driver interaction'),
            (r'NtDeviceIoControlFile', 'NT DeviceIoControl syscall'),
            (r'\\\\\\\\\.\\\\', 'Device path prefix (driver access)'),
            (r'IOCTL_|CTL_CODE', 'IOCTL code definition/usage'),
            (r'MmMapIoSpace|MmMapLockedPages', 'Kernel memory mapping'),
            (r'ExAllocatePool|ExFreePool', 'Kernel pool allocation'),
            (r'IoCreateDevice|IoCreateSymbolicLink', 'Kernel device creation'),
            (r'SePrivilegeCheck|SeSinglePrivilegeCheck', 'Kernel privilege check'),
            (r'token.*?privilege|privilege.*?token', 'Token privilege manipulation'),
            (r'KPROCESS|EPROCESS|PEPROCESS', 'Kernel process structure reference'),
            (r'PsLookupProcessByProcessId', 'Kernel process lookup'),
            (r'/dev/mem|/dev/kmem', 'Direct kernel memory access (Linux)'),
            (r'kexploit|kernel_exploit|kernelexploit', 'Kernel exploit reference'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Kernel Exploit Pattern'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'CRITICAL'
                })
                self.issues_found += 1

    def _check_sandbox_escape(self, filepath, content):
        """Check for sandbox escape patterns"""
        patterns = [
            (r'WinExec\s*\(|ShellExecute(?:A|W|Ex)', 'Shell execution (sandbox escape vector)'),
            (r'CreateProcess(?:A|W)?\s*\(.*?CREATE_NO_WINDOW', 'Hidden process creation'),
            (r'COM\s*object|CoCreateInstance', 'COM object instantiation (sandbox escape)'),
            (r'IFileOperation', 'IFileOperation COM (UAC bypass / sandbox escape)'),
            (r'CMSTPLUA|CMSTP', 'CMSTP bypass technique'),
            (r'fodhelper|eventvwr|sdclt|computerdefaults', 'Known UAC bypass binary'),
            (r'wmic\s+process\s+call\s+create', 'WMIC process creation'),
            (r'mshta\s+|mshta\.exe', 'MSHTA execution (sandbox escape)'),
            (r'rundll32.*?javascript|rundll32.*?vbscript', 'Rundll32 script execution'),
            (r'regsvr32\s+/s\s+/n\s+/u', 'Regsvr32 AppLocker bypass'),
            (r'chrome.*?--no-sandbox|--disable-web-security', 'Browser sandbox disable flag'),
            (r'sandbox.*?escape|escape.*?sandbox|breakout', 'Sandbox escape reference'),
        ]
        lines = content.split('\n')
        for pattern, desc in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                if self._is_in_string_or_comment(content, match.start()):
                    continue
                code_snippet = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
                self.findings['Sandbox Escape'].append({
                    'file': filepath, 'line': line_num, 'code': code_snippet,
                    'description': desc, 'severity': 'CRITICAL'
                })
                self.issues_found += 1

