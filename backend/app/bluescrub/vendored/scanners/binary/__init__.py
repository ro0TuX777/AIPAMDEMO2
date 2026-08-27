"""Composed BinaryAnalyzer built from format-specific mixins.

Mixins live in sibling modules:
- ``primitives``  – hashing, entropy, strings, disassembly, LIEF
- ``pe``          – PE/DOS analysis
- ``elf``         – ELF analysis
- ``macho``       – Mach-O analysis
- ``capa``        – CAPA CLI + Radare2/Ghidra wrappers
"""

import os
import shutil
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .primitives import PrimitivesMixin, CAPSTONE_AVAILABLE, LIEF_AVAILABLE
from .pe import PEMixin, PEFILE_AVAILABLE
from .elf import ELFMixin
from .macho import MachOMixin
from .capa import CapaMixin, ADVANCED_AVAILABLE

try:
    from elftools.elf.elffile import ELFFile  # noqa: F401
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False

try:
    from advanced_binary_analyzer import check_installation
except ImportError:
    check_installation = None

CAPA_CLI_AVAILABLE = shutil.which('capa') is not None


class BinaryAnalyzer(PrimitivesMixin, PEMixin, ELFMixin, MachOMixin, CapaMixin):
    """Comprehensive binary file analyzer.

    Inherits format-specific analysis from mixin classes and adds
    orchestration (``analyze_file``, ``analyze_directory``),
    severity scoring, and issue generation.
    """

    # ── class constants ────────────────────────────────────────────────

    MAGIC_BYTES = {
        b'MZ': 'PE/DOS Executable (Windows)',
        b'\x7fELF': 'ELF Executable (Linux/Unix)',
        b'\xfe\xed\xfa\xce': 'Mach-O 32-bit (macOS)',
        b'\xfe\xed\xfa\xcf': 'Mach-O 64-bit (macOS)',
        b'\xca\xfe\xba\xbe': 'Mach-O Universal Binary (macOS)',
        b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit Little Endian (macOS)',
        b'\xce\xfa\xed\xfe': 'Mach-O 32-bit Little Endian (macOS)',
        b'PK\x03\x04': 'ZIP Archive',
        b'\x1f\x8b': 'GZIP Archive',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x89PNG': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF8': 'GIF Image',
        b'%PDF': 'PDF Document',
    }

    SUSPICIOUS_WIN_APIS = {
        'critical': [
            'VirtualAllocEx', 'VirtualProtectEx',
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx',
            'WriteProcessMemory', 'ReadProcessMemory',
            'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
            'WinExec', 'NtUnmapViewOfSection',
        ],
        'high': [
            'VirtualAlloc', 'VirtualProtect', 'OpenProcess',
            'CreateProcess', 'CreateProcessA', 'CreateProcessW',
            'LoadLibrary', 'LoadLibraryA', 'LoadLibraryW',
            'GetProcAddress',
            'RegSetValue', 'RegCreateKey', 'RegOpenKey', 'RegDeleteKey',
            'CreateService', 'StartService', 'OpenService',
            'SetWindowsHook', 'SetWindowsHookEx',
            'InternetOpen', 'InternetConnect', 'HttpOpenRequest',
            'URLDownloadToFile', 'socket', 'connect', 'send', 'recv',
            'WSAStartup', 'WSASocket', 'bind', 'listen', 'accept',
        ],
        'medium': [
            'CreateFile', 'DeleteFile',
            'CopyFile', 'MoveFile', 'CreateDirectory',
            'GetSystemDirectory', 'GetWindowsDirectory', 'GetTempPath',
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        ]
    }

    _API_DESCRIPTIONS = {
        'VirtualAlloc':           'allocates executable memory — used for shellcode injection',
        'VirtualAllocEx':         'allocates memory in another process — classic injection primitive',
        'VirtualProtect':         'changes memory protection flags — enables W+X for code injection',
        'VirtualProtectEx':       'changes memory protection in another process — injection primitive',
        'CreateRemoteThread':     'creates a thread in another process — primary injection technique',
        'CreateRemoteThreadEx':   'creates a thread in another process — injection technique',
        'NtCreateThreadEx':       'low-level thread creation in another process — stealthy injection',
        'WriteProcessMemory':     'writes into another process — injection payload delivery',
        'ReadProcessMemory':      'reads from another process — credential/memory dumping',
        'NtUnmapViewOfSection':   'unmaps process memory — process hollowing technique',
        'OpenProcess':            'opens a handle to another process — needed for injection',
        'GetProcAddress':         'resolves API at runtime — often used to hide import intent',
        'LoadLibrary':            'loads DLL at runtime — dynamic resolution of dependencies',
        'LoadLibraryA':           'loads DLL at runtime — dynamic resolution of dependencies',
        'LoadLibraryW':           'loads DLL at runtime — dynamic resolution of dependencies',
        'CreateProcess':          'spawns a new process — potential payload execution',
        'CreateProcessA':         'spawns a new process — potential payload execution',
        'CreateProcessW':         'spawns a new process — potential payload execution',
        'ShellExecute':           'executes a program — command execution vector',
        'ShellExecuteA':          'executes a program — command execution vector',
        'ShellExecuteW':          'executes a program — command execution vector',
        'WinExec':                'executes a command string — legacy command execution',
        'IsDebuggerPresent':      'checks for debugger — anti-analysis evasion',
        'CheckRemoteDebuggerPresent': 'checks for remote debugger — anti-analysis evasion',
        'RegSetValue':            'writes to Windows registry — potential persistence',
        'RegCreateKey':           'creates registry key — potential persistence or config storage',
        'CreateService':          'creates a Windows service — persistence mechanism',
        'StartService':           'starts a Windows service — persistence or execution',
        'SetWindowsHook':         'installs a hook procedure — keylogging or injection',
        'SetWindowsHookEx':       'installs a hook procedure — keylogging or injection',
        'InternetOpen':           'initializes WinInet — outbound network communication',
        'InternetConnect':        'connects to remote server — C2 or exfiltration',
        'URLDownloadToFile':      'downloads file from URL — dropper/downloader behavior',
    }

    SUSPICIOUS_LINUX_FUNCS = {
        'critical': [
            'execve', 'execl', 'execlp', 'execle', 'execv', 'execvp',
            'mmap', 'mprotect', 'ptrace', 'fork', 'clone',
            'dlopen', 'dlsym', 'system', 'popen',
        ],
        'high': [
            'socket', 'connect', 'bind', 'listen', 'accept',
            'send', 'recv', 'sendto', 'recvfrom',
            'open', 'read', 'write', 'unlink', 'chmod', 'chown',
        ],
        'medium': [
            'getenv', 'setenv', 'getuid', 'getpid', 'geteuid',
            'kill', 'signal', 'sigaction',
        ]
    }

    SHELLCODE_PATTERNS = [
        (b'\x31\xc0', 'xor eax, eax (null eax)'),
        (b'\x31\xdb', 'xor ebx, ebx (null ebx)'),
        (b'\x31\xc9', 'xor ecx, ecx (null ecx)'),
        (b'\x31\xd2', 'xor edx, edx (null edx)'),
        (b'\x50\x53\x51\x52', 'push eax/ebx/ecx/edx (save regs)'),
        (b'\xcd\x80', 'int 0x80 (Linux syscall)'),
        (b'\x0f\x05', 'syscall (x64 Linux)'),
        (b'\x0f\x34', 'sysenter (x86)'),
        (b'\xff\xd0', 'call eax'),
        (b'\xff\xd3', 'call ebx'),
        (b'\xff\xe0', 'jmp eax'),
        (b'\xff\xe4', 'jmp esp'),
        (b'\x68', 'push imm32 (common in shellcode)'),
        (b'\xe8\x00\x00\x00\x00', 'call $+5 (get EIP trick)'),
        (b'\xeb\xfe', 'jmp $-2 (infinite loop)'),
        (b'\x90\x90\x90\x90', 'NOP sled'),
        (b'\x48\x31\xc0', 'xor rax, rax (x64 null rax)'),
        (b'\x48\x31\xff', 'xor rdi, rdi (x64 null rdi)'),
        (b'\x48\x31\xf6', 'xor rsi, rsi (x64 null rsi)'),
        (b'\x48\x31\xd2', 'xor rdx, rdx (x64 null rdx)'),
    ]

    ARCHIVE_EXTENSIONS = {
        '.zip', '.7z', '.gz', '.tar', '.rar', '.bz2', '.xz', '.lz',
        '.lzma', '.cab', '.iso', '.dmg', '.pkg', '.deb', '.rpm',
        '.jar', '.war', '.ear', '.apk', '.ipa', '.tgz', '.tbz2',
        '.zipx', '.z', '.lz4', '.zst',
    }

    _ARCHIVE_MAGICS = {
        b'PK\x03\x04', b'\x1f\x8b', b'Rar!\x1a\x07',
        b'\x37\x7a\xbc\xaf', b'\x42\x5a\x68', b'\xfd\x37\x7a\x58',
    }

    _NOISE_IPS = {
        '127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.0.1',
        '192.168.1.1', '10.0.0.1', '169.254.169.254',
    }

    _BENIGN_SHELLCODE_DESCS = {
        'xor eax, eax', 'xor ebx, ebx', 'xor ecx, ecx', 'xor edx, edx',
        'xor esi, esi', 'xor edi, edi',
    }

    _LOW_VALUE_APIS = {
        'GetTickCount', 'QueryPerformanceCounter',
        'WriteFile', 'ReadFile', 'CreateFile',
        'GetModuleHandleA', 'GetModuleHandleW',
        'GetLastError', 'CloseHandle', 'Sleep',
        'GetSystemDirectory', 'GetWindowsDirectory',
        'GetTempPath', 'CreateDirectory',
        'CopyFile', 'MoveFile', 'DeleteFile',
    }


    # ── lifecycle ──────────────────────────────────────────────────────

    def __init__(self):
        self.findings = defaultdict(list)
        self.files_analyzed = 0
        self.total_issues = 0

    def get_capabilities(self):
        """Return available analysis capabilities."""
        caps = {
            'basic': True,
            'pe_analysis': PEFILE_AVAILABLE,
            'elf_analysis': PYELFTOOLS_AVAILABLE,
            'disassembly': CAPSTONE_AVAILABLE,
            'lief_analysis': LIEF_AVAILABLE,
            'capa': CAPA_CLI_AVAILABLE,
            'radare2': False,
            'ghidra': False,
        }
        if ADVANCED_AVAILABLE and check_installation is not None:
            try:
                status = check_installation()
                caps['radare2'] = status['radare2']['installed'] and status['radare2']['r2pipe']
                caps['ghidra'] = status['ghidra']['installed']
            except Exception:
                pass
        return caps

    # ── single-file orchestration ──────────────────────────────────────

    def analyze_file(self, file_path):
        """Analyze a single binary file."""
        file_path = Path(file_path)
        if not file_path.exists():
            return None

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            return {'file': str(file_path), 'error': str(e)}

        if len(content) < 16:
            return None

        result = {
            'file': str(file_path),
            'filename': file_path.name,
            'size': len(content),
            'hashes': self._calculate_hashes(content),
            'file_type': self._detect_file_type(content),
            'entropy': self._calculate_entropy(content),
            'strings': self._extract_strings(content),
            'shellcode_patterns': self._detect_shellcode_patterns(content),
            'suspicious_strings': self._find_suspicious_strings(content),
            'sections': [],
            'imports': [],
            'exports': [],
            'disassembly': [],
            'severity': 'LOW',
            'issues': [],
        }

        file_type = result['file_type']['type']

        if 'PE' in file_type and PEFILE_AVAILABLE:
            pe_info = self._analyze_pe(file_path, content)
            if pe_info:
                result.update(pe_info)
            result['imphash'] = self._calculate_imphash(file_path)
            result['rich_header'] = self._analyze_rich_header(content)
            result['section_anomalies'] = self._detect_section_anomalies(result.get('sections', []))
            result['overlay'] = self._detect_overlay(file_path, content)
            result['certificate'] = self._validate_certificate(file_path)
        elif 'ELF' in file_type and PYELFTOOLS_AVAILABLE:
            elf_info = self._analyze_elf(file_path)
            if elf_info:
                result.update(elf_info)
            result['section_anomalies'] = self._detect_section_anomalies(result.get('sections', []))
        elif 'Mach-O' in file_type:
            macho_info = self._analyze_macho(file_path, content)
            if macho_info:
                result.update(macho_info)

        result['section_entropy'] = self._per_section_entropy(content, result.get('sections', []))

        if LIEF_AVAILABLE:
            lief_info = self._analyze_with_lief(file_path)
            if lief_info:
                result['lief_analysis'] = lief_info

        if CAPSTONE_AVAILABLE and result.get('entry_point'):
            disasm = self._disassemble_section(content, result.get('entry_point', 0))
            if disasm:
                result['disassembly'] = disasm

        if ADVANCED_AVAILABLE:
            try:
                advanced_result = self._run_advanced_analysis(file_path)
                if advanced_result:
                    result['advanced_analysis'] = advanced_result
                    for issue in advanced_result.get('combined_issues', []):
                        result.setdefault('advanced_issues', []).append(issue)
            except Exception as e:
                result['advanced_analysis'] = {'error': str(e)}

        if CAPA_CLI_AVAILABLE and any(m in file_type for m in ('PE', 'ELF', 'Mach-O')):
            capa_result = self._run_capa_analysis(file_path)
            if capa_result:
                result['capa'] = capa_result

        result['severity'] = self._calculate_severity(result)
        result['issues'] = self._generate_issues(result)

        self.files_analyzed += 1
        self.total_issues += len(result['issues'])
        return result

    # ── severity scoring ───────────────────────────────────────────────

    def _calculate_severity(self, result):
        """Calculate overall severity of findings."""
        score = 0
        if result['entropy']['entropy'] >= 7.5:
            score += 30
        elif result['entropy']['entropy'] >= 7.0:
            score += 20

        if result['shellcode_patterns']['count'] >= 5:
            score += 30
        elif result['shellcode_patterns']['count'] >= 3:
            score += 20
        elif result['shellcode_patterns']['count'] >= 1:
            score += 10

        critical_strings = sum(1 for s in result['suspicious_strings'] if s['severity'] == 'CRITICAL')
        high_strings = sum(1 for s in result['suspicious_strings'] if s['severity'] == 'HIGH')
        score += critical_strings * 15 + high_strings * 10

        if result.get('suspicious_imports'):
            critical_imports = sum(1 for i in result['suspicious_imports'] if i['severity'] == 'CRITICAL')
            score += critical_imports * 10

        if result.get('suspicious_symbols'):
            critical_symbols = sum(1 for s in result['suspicious_symbols'] if s['severity'] == 'CRITICAL')
            score += critical_symbols * 10

        capa_matches = ((result.get('capa') or {}).get('summary') or {}).get('total_rule_matches', 0)
        if capa_matches >= 10:
            score += 20
        elif capa_matches >= 5:
            score += 15
        elif capa_matches >= 1:
            score += 8

        score += min(len(result.get('advanced_issues', [])) * 5, 15)

        if score >= 60:
            return 'CRITICAL'
        elif score >= 40:
            return 'HIGH'
        elif score >= 20:
            return 'MEDIUM'
        return 'LOW'

    # ── issue generation ───────────────────────────────────────────────

    def _generate_issues(self, result):
        """Generate list of OPSEC issues from analysis results."""
        issues = []

        # High entropy
        if result['entropy']['entropy'] >= 7.0:
            issues.append({
                'type': 'OPSEC: High Entropy Detection',
                'severity': 'HIGH',
                'offset': None,
                'description': (
                    f"Entropy {result['entropy']['entropy']:.2f}/8.0 — "
                    f"EDR/AV will flag as packed/encrypted"
                ),
                'recommendation': 'Add padding with normal code, use lower-entropy encoding, or embed in legitimate binary',
            })

        # Shellcode patterns
        if result['shellcode_patterns']['found']:
            for pattern in result['shellcode_patterns']['patterns'][:5]:
                desc_lower = pattern['description'].lower()
                if desc_lower in self._BENIGN_SHELLCODE_DESCS:
                    continue
                positions = pattern.get('positions', [])
                offset_hex = hex(positions[0]) if positions else None
                issues.append({
                    'type': 'OPSEC: Detectable Shellcode Pattern',
                    'severity': pattern['severity'],
                    'offset': offset_hex,
                    'description': f"Signature: {pattern['description']} at offset {offset_hex or '?'} — YARA/AV can match this",
                    'recommendation': 'Use polymorphic encoding, insert junk instructions, or obfuscate the pattern',
                })

        # Suspicious strings
        for s in result['suspicious_strings'][:10]:
            value = s['value'][:50]
            if s['type'] == 'ip_address' and value.strip() in self._NOISE_IPS:
                continue
            offset_hex = hex(s['offset']) if s.get('offset') is not None else None
            issues.append({
                'type': f"OPSEC: Extractable String ({s['type']})",
                'severity': s.get('severity', 'MEDIUM'),
                'offset': offset_hex,
                'description': f"Defenders can extract: {value}" + (f" (at offset {offset_hex})" if offset_hex else ""),
                'recommendation': 'Encrypt strings at rest, use runtime decryption, or obfuscate IOCs',
            })

        # Suspicious imports (PE)
        suspicious_imports = result.get('suspicious_imports', [])
        all_suspicious_names = {imp['function'] for imp in suspicious_imports}
        injection_combo = all_suspicious_names & {
            'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx',
        }
        has_injection_combo = len(injection_combo) >= 2

        for imp in suspicious_imports[:15]:
            func = imp['function']
            imp_severity = 'LOW' if func in self._LOW_VALUE_APIS else imp['severity']
            api_context = self._API_DESCRIPTIONS.get(func, 'EDR hooks this API for behavioral detection')

            if imp_severity == 'LOW':
                rationale = f"LOW — {func} is a common benign API. Flagged only because it appears alongside more suspicious imports."
            elif has_injection_combo and func in injection_combo:
                rationale = f"CRITICAL — {func} is part of a process injection API combination ({', '.join(sorted(injection_combo))})."
            elif imp_severity == 'CRITICAL':
                rationale = f"CRITICAL — {func} is a high-risk API with no legitimate use outside of exploit tooling."
            elif imp_severity == 'HIGH':
                rationale = f"HIGH — {func} is commonly monitored by EDR."
            else:
                rationale = None

            issue_dict = {
                'type': 'OPSEC: Monitored API Import',
                'severity': imp_severity,
                'offset': None,
                'description': f"{func} ({imp.get('dll', '?')}) — {api_context}",
                'recommendation': 'Use direct syscalls, dynamic resolution, or API unhooking to evade',
            }
            if rationale:
                issue_dict['severity_rationale'] = rationale
            issues.append(issue_dict)

        # Suspicious symbols (ELF)
        for sym in result.get('suspicious_symbols', [])[:10]:
            issues.append({
                'type': 'OPSEC: Monitored Function',
                'severity': sym['severity'],
                'offset': None,
                'description': f"{sym['function']} — Security tools monitor this function",
                'recommendation': 'Use inline syscalls or obfuscate function resolution',
            })

        # CAPA matches
        capa_summary = (result.get('capa') or {}).get('summary') or {}
        capa_matches = capa_summary.get('top_rule_matches', [])
        capa_severity = 'HIGH' if capa_summary.get('total_rule_matches', 0) >= 3 else 'MEDIUM'
        for match in capa_matches[:5]:
            issues.append({
                'type': 'OPSEC: CAPA Capability Match',
                'severity': capa_severity,
                'offset': None,
                'description': f"CAPA matched rule: {match.get('name')} ({match.get('namespace', 'unclassified')})",
                'recommendation': 'Review the matched behavior and reduce recognizable capability patterns where possible',
            })

        return issues

    # ── directory traversal ────────────────────────────────────────────

    def analyze_directory(self, directory):
        """Analyze all binary files in a directory."""
        import logging
        log = logging.getLogger(__name__)

        directory = Path(directory)
        results = []
        binary_extensions = {
            '.exe', '.dll', '.sys', '.bin', '.so', '.dylib',
            '.elf', '.o', '.obj', '.com', '.scr', '.drv',
            '.ocx', '.cpl', '.msi', '.dmp', '.raw',
        }

        log.info("Scanning directory for binaries: %s", directory)

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in {'__pycache__', '.git', 'node_modules', '.venv', 'venv'}]
            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix.lower()

                if ext in self.ARCHIVE_EXTENSIONS:
                    continue

                is_binary = ext in binary_extensions
                if not is_binary:
                    try:
                        with open(file_path, 'rb') as f:
                            header = f.read(16)
                        if any(header.startswith(m) for m in self._ARCHIVE_MAGICS):
                            continue
                        for magic in self.MAGIC_BYTES:
                            if header.startswith(magic):
                                is_binary = True
                                break
                    except Exception:
                        pass

                if is_binary:
                    result = self.analyze_file(file_path)
                    if result and 'error' not in result:
                        results.append(result)

        log.info("Analyzed %d binary files", len(results))
        return results

    # ── report generation ──────────────────────────────────────────────

    def generate_report(self, results):
        """Generate analysis report from a list of file results."""
        if not results:
            return {
                'timestamp': datetime.now().isoformat(),
                'files_analyzed': 0,
                'total_issues': 0,
                'findings': {},
                'summary': {'risk_level': 'NONE', 'risk_score': 0},
            }

        all_issues = []
        capa_rule_counter = Counter()
        capa_files_with_matches = 0
        total_capa_matches = 0

        for result in results:
            for issue in result.get('issues', []):
                issue['file'] = result['file']
                all_issues.append(issue)
            capa_summary = (result.get('capa') or {}).get('summary') or {}
            if capa_summary.get('total_rule_matches', 0) > 0:
                capa_files_with_matches += 1
            total_capa_matches += capa_summary.get('total_rule_matches', 0)
            for match in capa_summary.get('top_rule_matches', []):
                capa_rule_counter[(match.get('name'), match.get('namespace', 'unclassified'))] += 1

        severity_counts = {s: sum(1 for i in all_issues if i['severity'] == s) for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}

        risk_score = min(100, severity_counts['CRITICAL'] * 30 + severity_counts['HIGH'] * 15 + severity_counts['MEDIUM'] * 5 + severity_counts['LOW'])

        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        elif risk_score >= 10:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'

        return {
            'timestamp': datetime.now().isoformat(),
            'files_analyzed': len(results),
            'total_issues': len(all_issues),
            'severity_counts': severity_counts,
            'capabilities': self.get_capabilities(),
            'results': results,
            'issues': all_issues,
            'capa_summary': {
                'files_with_matches': capa_files_with_matches,
                'total_rule_matches': total_capa_matches,
                'top_rule_matches': [
                    {'name': name, 'namespace': ns, 'count': count}
                    for (name, ns), count in capa_rule_counter.most_common(10)
                ],
            },
            'summary': {'risk_level': risk_level, 'risk_score': risk_score},
        }


def analyze_binaries_in_directory(directory):
    """Convenience function to analyze binaries in a directory."""
    analyzer = BinaryAnalyzer()
    results = analyzer.analyze_directory(directory)
    return analyzer.generate_report(results)