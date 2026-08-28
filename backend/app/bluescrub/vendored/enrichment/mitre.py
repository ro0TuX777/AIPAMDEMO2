"""MITRE ATT&CK mapping for BlueScrub findings."""

MITRE_ATTACK_MAP = {
    # Binary/Shellcode Detection Vectors
    'High Entropy': {'technique': 'T1027', 'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
    'Entropy': {'technique': 'T1027', 'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
    'syscall': {'technique': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
    'int 0x80': {'technique': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
    'sysenter': {'technique': 'T1106', 'name': 'Native API', 'tactic': 'Execution'},
    'jmp esp': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'call eax': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'jmp eax': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'NOP sled': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'xor': {'technique': 'T1140', 'name': 'Deobfuscate/Decode Files', 'tactic': 'Defense Evasion'},
    'push imm32': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},

    # API-based Detection
    'VirtualAlloc': {'technique': 'T1055.001', 'name': 'Dynamic-link Library Injection', 'tactic': 'Defense Evasion'},
    'VirtualProtect': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'WriteProcessMemory': {'technique': 'T1055.001', 'name': 'Dynamic-link Library Injection', 'tactic': 'Defense Evasion'},
    'CreateRemoteThread': {'technique': 'T1055.001', 'name': 'Dynamic-link Library Injection', 'tactic': 'Defense Evasion'},
    'NtAllocateVirtualMemory': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'dlsym': {'technique': 'T1574.006', 'name': 'Dynamic Linker Hijacking', 'tactic': 'Defense Evasion'},
    'dlopen': {'technique': 'T1574.006', 'name': 'Dynamic Linker Hijacking', 'tactic': 'Defense Evasion'},
    'mmap': {'technique': 'T1055.009', 'name': 'Proc Memory', 'tactic': 'Defense Evasion'},
    'mprotect': {'technique': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
    'ptrace': {'technique': 'T1055.008', 'name': 'Ptrace System Calls', 'tactic': 'Defense Evasion'},
    'socket': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'connect': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},

    # Source Code Issues
    'Hardcoded IP': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'Hardcoded Password': {'technique': 'T1552.001', 'name': 'Credentials In Files', 'tactic': 'Credential Access'},
    'API Key': {'technique': 'T1552.001', 'name': 'Credentials In Files', 'tactic': 'Credential Access'},
    'Path Disclosure': {'technique': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
    'Debug': {'technique': 'T1497.001', 'name': 'System Checks', 'tactic': 'Defense Evasion'},
    'eval': {'technique': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
    'exec': {'technique': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
    'subprocess': {'technique': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},

    # Network Indicators
    'C2': {'technique': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'Beacon': {'technique': 'T1071.001', 'name': 'Web Protocols', 'tactic': 'Command and Control'},
    'DNS': {'technique': 'T1071.004', 'name': 'DNS', 'tactic': 'Command and Control'},

    # Forensic Artifacts
    'Registry': {'technique': 'T1112', 'name': 'Modify Registry', 'tactic': 'Defense Evasion'},
    'Persistence': {'technique': 'T1547', 'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
    'Log': {'technique': 'T1070', 'name': 'Indicator Removal', 'tactic': 'Defense Evasion'},
    'Temp File': {'technique': 'T1074.001', 'name': 'Local Data Staging', 'tactic': 'Collection'},

    # Anti-Analysis
    'Anti-Debug': {'technique': 'T1622', 'name': 'Debugger Evasion', 'tactic': 'Defense Evasion'},
    'VM Detection': {'technique': 'T1497.001', 'name': 'System Checks', 'tactic': 'Defense Evasion'},
    'Sandbox': {'technique': 'T1497.001', 'name': 'System Checks', 'tactic': 'Defense Evasion'},
}


def get_mitre_mapping(issue_text):
    """Map an issue description to MITRE ATT&CK technique."""
    issue_lower = issue_text.lower()
    for keyword, mapping in MITRE_ATTACK_MAP.items():
        if keyword.lower() in issue_lower:
            return mapping
    return None


def enrich_issues_with_mitre(issues):
    """Add MITRE ATT&CK mappings to issues list."""
    enriched = []
    for issue in issues:
        enriched_issue = issue.copy()
        desc = issue.get('description', '') + ' ' + issue.get('type', '')
        mitre = get_mitre_mapping(desc)
        if mitre:
            enriched_issue['mitre_attack'] = mitre
        enriched.append(enriched_issue)
    return enriched

