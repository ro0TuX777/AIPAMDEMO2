"""Canonical result schema helpers for BlueScrub scan outputs."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime

SCHEMA_VERSION = "1.0"
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# ---------------------------------------------------------------------------
# Rich category metadata – provides human-readable explanations for each
# finding category so that users can understand *what* the finding means,
# *why* it matters, and *what to do about it*.
# Keys are normalised to lower-case for lookup; the original casing is
# preserved in the finding itself.
# ---------------------------------------------------------------------------
CATEGORY_METADATA = {
    "anti analysis": {
        "description": "DETECTABILITY — Your code uses well-known anti-debugging, anti-VM, or sandbox-evasion techniques (e.g. ptrace, IsDebuggerPresent, VMware/VBox fingerprinting). While anti-analysis is expected in offensive tooling, the specific techniques used here are catalogued in AV/EDR signature databases and may actually *increase* detection risk rather than reduce it.",
        "why_high": "MEDIUM by default — anti-analysis is expected in exploit code, but using well-known techniques can backfire by triggering AV/EDR heuristics. Severity increases to HIGH only when the technique is trivially detectable (e.g. cleartext API calls, simple exit-on-detect patterns).",
        "recommendation": "Replace well-known checks with indirect methods (e.g. timing-based detection, CPUID leaf analysis, hardware-based checks). Use syscall stubs or dynamic resolution instead of calling known APIs directly. Remove any simple exit-on-detect patterns — they provide no real protection and are easy to patch out.",
        "mitre": "T1497",
    },
    "format_string": {
        "description": "VULNERABILITY — Your exploit contains uncontrolled format-string usage (printf-family, .format()). If the format string is derived from target data, your own exploit could crash mid-execution or be hijacked by a defender who controls the input.",
        "why_high": "HIGH because a format-string bug in your exploit can cause it to crash on the target, leaving forensic artifacts behind, or worse — allow the target to gain code execution against your tooling.",
        "recommendation": "Use explicit format specifiers everywhere. Validate all target-sourced data before passing it through formatting functions. Test your exploit against adversarial inputs.",
        "mitre": "T1203",
    },
    "memory safety": {
        "description": "VULNERABILITY — Your code has potential buffer overflows, use-after-free, or integer-overflow conditions. These bugs can cause your exploit to crash unpredictably, corrupt memory on the target, or be weaponised against you by a defender who reverse-engineers your tool.",
        "why_high": "HIGH because unreliable exploit code leaves crash dumps, core files, and event logs on the target — all of which are forensic gold for incident responders. A savvy defender could also exploit your bug to gain control of your implant.",
        "recommendation": "Add bounds checks on all buffer operations. Use safe integer arithmetic. Fuzz your exploit with different target configurations to ensure stability. Memory corruption in your tooling is an operational risk.",
        "mitre": "T1203",
    },
    "code similarity": {
        "description": "ATTRIBUTION — Your code shares significant structural patterns, function names, or logic with publicly known exploit frameworks (Metasploit, Cobalt Strike, Empire, etc.). Defenders and threat-intel teams actively fingerprint these similarities to attribute attacks.",
        "why_high": "HIGH because threat-intel vendors maintain code-similarity databases. If your tool matches a known framework, defenders can immediately classify your operation, predict your TTPs, and deploy targeted countermeasures.",
        "recommendation": "Rewrite shared logic from scratch — don't copy-paste from public repos. Rename all distinctive variables, functions, and class names. Change code structure and control flow to break similarity signatures.",
        "mitre": "T1588.002",
    },
    "forensic artifacts": {
        "description": "DETECTABILITY — Your code writes to disk, creates registry keys, drops temp files, or leaves other forensic traces that incident responders will find during post-compromise analysis. Every artifact is a breadcrumb leading back to your operation.",
        "why_high": "HIGH because forensic artifacts persist after your tool exits. IR teams will recover these traces to reconstruct your timeline, identify your tools, and potentially attribute the operation.",
        "recommendation": "Operate in-memory whenever possible. If you must touch disk, use self-deleting files, encrypt temp data, and clean up on exit. Avoid writing to well-monitored locations (e.g. %TEMP%, /tmp, registry Run keys).",
        "mitre": "T1070",
    },
    "privilege escalation": {
        "description": "DETECTABILITY — Your code uses privilege-escalation techniques (setuid, token manipulation, UAC bypass, kernel exploitation) that are heavily monitored by EDR products. These API calls and syscall patterns are high-priority detection targets.",
        "why_high": "HIGH because privilege escalation is one of the most monitored attack phases. EDR products have specialised detections for token theft, UAC bypass, and kernel exploits. Getting caught here often triggers immediate IR response.",
        "recommendation": "Use lesser-known escalation paths or LOLBins that blend with normal system activity. Avoid well-signatured techniques like named pipe impersonation or known UAC bypass binaries. Test against the target's EDR before deploying.",
        "mitre": "T1068",
    },
    "unsafe functions": {
        "description": "DETECTABILITY & VULNERABILITY — Your code calls functions that are both security-risky and commonly signatured (eval, exec, system, gets, strcpy). These are static-analysis low-hanging fruit that any automated scanner will flag, and they can also make your exploit unreliable.",
        "why_high": "HIGH because these function calls are trivial to detect via static analysis and YARA rules. They also introduce stability risks — a buffer overflow in your own tool is an operational failure.",
        "recommendation": "Replace with safer alternatives: use direct syscalls or API hashing instead of system(), dynamically resolve functions instead of static imports. For string operations, use length-bounded variants.",
        "mitre": "T1059",
    },
    "hardcoded secrets": {
        "description": "ATTRIBUTION & DETECTABILITY — Your code contains hard-coded credentials, API keys, C2 addresses, or tokens. If your tool is captured, these secrets are immediately exposed, compromising your infrastructure and potentially linking operations together.",
        "why_high": "HIGH because hard-coded secrets in a captured implant give defenders direct access to your C2 infrastructure, let them pivot to other operations using the same keys, and provide strong attribution evidence.",
        "recommendation": "Use encrypted configuration that's injected at deploy-time. Derive keys from target-specific data. Never embed C2 credentials, API keys, or infrastructure details in the binary. Rotate all credentials between engagements.",
        "mitre": "T1552.001",
    },
    "suspicious patterns": {
        "description": "DETECTABILITY — Your code contains patterns that EDR/AV engines specifically look for: shellcode stubs, process injection templates, DLL hollowing, reflective loading, or common obfuscation routines. These are signature magnets.",
        "why_high": "HIGH because these patterns match well-known YARA rules, heuristic detections, and behavioural signatures in every major security product. Using them without modification is almost guaranteed to trigger an alert.",
        "recommendation": "Rewrite injection and loading logic using novel techniques. Avoid textbook implementations — modify syscall patterns, use indirect execution methods, and break up recognisable byte sequences. Test against target AV/EDR before deployment.",
        "mitre": "T1055",
    },
    "source": {
        "description": "General source-code finding that may affect your tool's detectability, reliability, or operational security. Review the specific file and context for details.",
        "why_high": "Varies by finding — review the code context to assess whether this impacts detectability, exploit reliability, or attribution risk.",
        "recommendation": "Review the flagged code and assess whether it introduces detection risk, stability issues, or attribution markers. Fix accordingly.",
        "mitre": None,
    },
    "information disclosure": {
        "description": "ATTRIBUTION — Your code leaks operational details: file paths from your dev environment, build system info, usernames, debug strings, or error messages that reveal your tooling's internal structure to anyone who analyses the binary.",
        "why_high": "HIGH because leaked paths, usernames, and build artifacts are primary attribution vectors. Threat-intel teams routinely extract PDB paths, embedded strings, and error messages to fingerprint and track threat actors.",
        "recommendation": "Strip all debug symbols and PDB paths before deployment. Remove verbose error messages. Sanitise any strings that reference your development environment, username, or internal project names.",
        "mitre": "T1082",
    },
    "crypto vulnerabilities": {
        "description": "VULNERABILITY & DETECTABILITY — Your code uses weak crypto (MD5, SHA-1, DES, ECB mode, hard-coded IVs) or custom crypto implementations. Weak crypto makes your C2 comms interceptable and your encrypted payloads recoverable by defenders.",
        "why_high": "HIGH because weak encryption in your implant means defenders can decrypt your C2 traffic, recover your payloads, and understand your operational methods. Custom crypto is also a distinctive fingerprint for attribution.",
        "recommendation": "Use proven libraries with strong algorithms (AES-256-GCM, ChaCha20-Poly1305). Generate unique keys per engagement. Avoid custom crypto — it's both weak and fingerprintable.",
        "mitre": "T1600",
    },
    "supply chain": {
        "description": "VULNERABILITY — Your tooling pulls dependencies from external sources that could be compromised, typosquatted, or monitored. A poisoned dependency in your exploit chain could backdoor your own infrastructure or alert defenders.",
        "why_high": "HIGH because compromised dependencies can give third parties access to your tooling, implant source code, or C2 infrastructure. Defenders also monitor package registries for known offensive tool dependencies.",
        "recommendation": "Vendor all dependencies locally. Verify checksums against known-good copies. Avoid pulling packages at build-time from public registries — a compromised dependency poisons your entire operation.",
        "mitre": "T1195.001",
    },
    "opsec analysis": {
        "description": "ATTRIBUTION — Your code contains operational security failures: hard-coded C2 IPs, infrastructure hostnames, operator handles, timezone artifacts, or language-specific metadata that can be used to identify you or your team.",
        "why_high": "HIGH because OPSEC failures are the #1 way threat actors get attributed. A single hard-coded IP, timezone string, or language artifact can link your operation to previous campaigns or your real identity.",
        "recommendation": "Audit all strings and metadata for attribution markers. Remove hard-coded infrastructure references — use dynamic configuration. Scrub timezone data, language settings, and any PII. Use different infrastructure per engagement.",
        "mitre": "T1590",
    },
    # ===== PHASE 2 CATEGORIES =====
    "format string vulnerability": {
        "description": "VULNERABILITY — Your code passes user-controlled input directly as a format string to printf/sprintf-family functions. This enables arbitrary read/write primitives.",
        "why_high": "HIGH because format string bugs give attackers the ability to read/write arbitrary memory, leak stack data, or achieve RCE — and they're easy to exploit once found.",
        "recommendation": "Always use explicit format specifiers: printf(\"%s\", var) instead of printf(var). For Python, avoid .format() with unpacked user input and f-strings accessing dunder attributes.",
        "mitre": "T1203",
    },
    "integer overflow": {
        "description": "VULNERABILITY — Arithmetic operations on sizes/lengths without overflow guards. An integer overflow in a size calculation before malloc/memcpy leads to heap overflows.",
        "why_high": "HIGH because integer overflows in size calculations are a reliable exploit primitive — they bypass length checks and cause undersized allocations followed by overflows.",
        "recommendation": "Use safe integer arithmetic (e.g., __builtin_mul_overflow, SafeInt). Validate all size inputs before arithmetic. Use calloc instead of malloc+memset for zero-initialized allocations.",
        "mitre": "T1203",
    },
    "memory safety": {
        "description": "VULNERABILITY — Use-after-free, double-free, or dangling pointer patterns detected. These memory corruption bugs are the most common exploit primitives in modern software.",
        "why_high": "CRITICAL because UAF/double-free bugs give attackers control over memory layout and enable arbitrary code execution through heap manipulation.",
        "recommendation": "Set pointers to NULL after free(). Use ASAN/MSAN during development. Consider using smart pointers in C++ or memory-safe languages for critical components.",
        "mitre": "T1203",
    },
    "race condition": {
        "description": "VULNERABILITY — Time-of-check-to-time-of-use (TOCTOU) patterns or unprotected shared state. Race conditions create exploitable windows between security checks and resource use.",
        "why_high": "MEDIUM because TOCTOU races require precise timing but can bypass access controls, overwrite files, or escalate privileges when successfully exploited.",
        "recommendation": "Use atomic operations. Open files with O_EXCL|O_CREAT. Use fstat() on file descriptors instead of stat() on paths. Protect shared state with mutexes/locks.",
        "mitre": "T1068",
    },
    "deserialization sink": {
        "description": "VULNERABILITY — Unsafe deserialization of untrusted data (pickle, marshal, yaml.load, Java ObjectInputStream, .NET BinaryFormatter). These are direct RCE vectors.",
        "why_high": "CRITICAL because deserialization of untrusted data is almost always exploitable for remote code execution. Attackers craft serialized objects that execute arbitrary commands on load.",
        "recommendation": "Never deserialize untrusted data. Use yaml.safe_load() instead of yaml.load(). Avoid pickle for any network-received data. Use JSON or Protocol Buffers for data exchange.",
        "mitre": "T1059",
    },
    "etw/amsi bypass": {
        "description": "DETECTABILITY — Your code patches or hooks ETW/AMSI functions (AmsiScanBuffer, EtwEventWrite). These are the most heavily monitored evasion techniques by modern EDR.",
        "why_high": "CRITICAL because AMSI/ETW patches are signature #1 in every major EDR product. The act of patching these functions is itself a high-fidelity detection signal.",
        "recommendation": "Avoid direct AMSI/ETW patching — use hardware breakpoints, indirect syscalls, or unhooking via clean ntdll copies. Consider whether the bypass is even necessary for your engagement.",
        "mitre": "T1562.001",
    },
    "syscall vs api detection": {
        "description": "DETECTABILITY — Your code uses Win32 APIs that are hooked by EDR (CreateRemoteThread, VirtualAlloc, WriteProcessMemory) instead of direct NT syscalls.",
        "why_high": "HIGH because EDR products hook these APIs in usermode DLLs. Every call through the hooked API is visible to the EDR. Direct syscalls bypass this monitoring layer.",
        "recommendation": "Use direct syscalls (Nt*/Zw*) or syscall stubs for sensitive operations. Dynamically resolve API addresses. Consider using Hell's Gate / Halo's Gate for syscall number resolution.",
        "mitre": "T1106",
    },
    "timezone/locale leakage": {
        "description": "ATTRIBUTION — Your code contains timezone identifiers, locale strings, or regional settings that could reveal the operator's geographic location or language.",
        "why_high": "MEDIUM because timezone/locale artifacts have been used to attribute threat actors to specific countries. The Lazarus Group was partially attributed through Korean language artifacts.",
        "recommendation": "Remove all hardcoded timezone/locale strings. Use UTC exclusively. Strip locale metadata from binaries. Avoid system calls that reveal timezone (GetTimeZoneInformation, etc.).",
        "mitre": "T1614",
    },
    "build environment leakage": {
        "description": "ATTRIBUTION — Your code or binary contains build paths, PDB paths, usernames, hostnames, or compilation timestamps that reveal your development environment.",
        "why_high": "HIGH because PDB paths and build environment artifacts are primary attribution vectors. APT groups have been identified through unique build paths and compiler versions.",
        "recommendation": "Strip all debug symbols and PDB paths before deployment. Remove __DATE__/__TIME__ macros. Use a clean, dedicated build VM with no personal information. Randomize compilation timestamps.",
        "mitre": "T1588.002",
    },
    "unicode homoglyphs": {
        "description": "ATTRIBUTION — Your code contains Unicode homoglyphs, zero-width characters, or non-standard whitespace that create a unique stylometric fingerprint.",
        "why_high": "MEDIUM because invisible Unicode characters can be used as watermarks to track code distribution. Homoglyphs in identifiers may indicate the developer's native language/keyboard.",
        "recommendation": "Normalize all source files to ASCII or strict UTF-8. Remove zero-width characters and BOM markers. Use consistent quote styles and whitespace. Run a Unicode normalizer before distribution.",
        "mitre": "T1027",
    },
    "dns tunneling": {
        "description": "OPSEC — Your code implements DNS tunneling or uses DNS as a covert communication channel. DNS-based C2 is well-understood and monitored by enterprise security teams.",
        "why_high": "HIGH because DNS tunneling is detectable through query volume anomalies, unusual subdomain lengths, TXT record abuse, and entropy analysis of DNS queries.",
        "recommendation": "If DNS C2 is required, implement domain fronting or use legitimate cloud DNS APIs. Minimize query volume. Use short, low-entropy labels. Rotate domains frequently.",
        "mitre": "T1071.004",
    },
    "timestamp stomping": {
        "description": "OPSEC — Your code modifies file timestamps to blend in with legitimate system files. While useful for evasion, timestamp manipulation itself creates forensic artifacts.",
        "why_high": "HIGH because timestamp stomping can be detected by comparing $SI vs $FN timestamps in NTFS, or through USN journal analysis. The inconsistency itself is suspicious.",
        "recommendation": "If you stomp timestamps, also consider NTFS journal entries. Copy timestamps from legitimate nearby files rather than using round numbers. Be consistent with timezone offsets.",
        "mitre": "T1070.006",
    },
    "log evasion": {
        "description": "OPSEC — Your code clears event logs, deletes log files, or disables logging services. These actions are high-fidelity indicators of compromise.",
        "why_high": "HIGH because log clearing is one of the most commonly detected post-exploitation activities. SIEM systems specifically alert on event log clearing and audit policy changes.",
        "recommendation": "Instead of clearing logs, avoid generating detectable log entries in the first place. Use techniques that don't trigger audit events. If you must clear, be selective — clearing all logs is more suspicious.",
        "mitre": "T1070.001",
    },
    "process injection": {
        "description": "OPSEC — Your code uses process injection techniques (CreateRemoteThread, APC injection, process hollowing). Detection risk varies significantly by technique.",
        "why_high": "Severity varies by technique. Classic CreateRemoteThread is CRITICAL (every EDR detects it). Newer techniques like callback injection or Early Bird are MEDIUM (less monitored).",
        "recommendation": "Use modern injection techniques: module stomping, callback-based injection, or thread pool abuse. Avoid CreateRemoteThread entirely. Inject into processes that naturally allocate executable memory.",
        "mitre": "T1055",
    },
    "cleanup routines": {
        "description": "OPSEC — Your code implements self-deletion, memory wiping, or artifact cleanup routines. While good OPSEC practice, the cleanup code itself can be a detection signal.",
        "why_high": "MEDIUM because self-deletion and cleanup routines are normal in malware but unusual in legitimate software. EDR products flag self-deleting executables.",
        "recommendation": "Use delayed deletion (MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT) or bat/cmd file self-deletion. Wipe sensitive memory with SecureZeroMemory. Avoid obvious cleanup patterns.",
        "mitre": "T1070.004",
    },
    "stack pivot": {
        "description": "EXPLOITATION — Your code contains stack pivot gadgets or techniques for redirecting the stack pointer to attacker-controlled memory.",
        "why_high": "HIGH because stack pivots are essential for advanced exploitation but are fragile — they depend on specific memory layouts that change across OS versions and patches.",
        "recommendation": "Validate stack pivot gadgets against target OS versions. Use multiple pivot gadgets as fallbacks. Test against ASLR-enabled targets. Consider CFG/CET compatibility.",
        "mitre": "T1203",
    },
    "kernel exploit pattern": {
        "description": "EXPLOITATION — Your code interacts with kernel drivers, manipulates kernel structures, or performs privilege escalation through kernel exploitation.",
        "why_high": "CRITICAL because kernel exploits risk system crash (BSOD/panic) on failure and are heavily monitored. Kernel exploit code also tends to be highly version-specific.",
        "recommendation": "Version-check the target kernel before exploitation. Implement safe fallback on failure. Use kernel information leak primitives before attempting writes. Test on identical kernel versions.",
        "mitre": "T1068",
    },
    "sandbox escape": {
        "description": "EXPLOITATION — Your code attempts to escape sandboxes, bypass UAC, or break out of restricted execution environments.",
        "why_high": "CRITICAL because sandbox escapes are patched aggressively by vendors. Techniques like fodhelper, eventvwr, and CMSTP bypasses have short shelf lives and are quickly signatured.",
        "recommendation": "Verify the bypass works on the target OS version/patch level before use. Have multiple bypass techniques ready. Prefer living-off-the-land approaches over custom escape code.",
        "mitre": "T1548.002",
    },
    # ===== PHASE 1 SCANNER CATEGORIES =====
    "shellcode security": {
        "description": "DETECTABILITY & RELIABILITY — Your exploit contains raw shellcode (bytecode) with security issues: NULL bytes that break string-copy exploits, bad characters filtered by input validation, predictable byte patterns (NOP sleds, egg hunters) that AV/EDR signature-match, or low entropy that makes static detection trivial.",
        "why_high": "CRITICAL because shellcode flaws have a double impact: they make your exploit fail on target (NULL bytes, bad chars break the payload) AND make it detectable (predictable patterns and low entropy are signature magnets for AV/YARA).",
        "recommendation": "Encode or encrypt shellcode to remove NULL bytes and bad characters. Replace NOP sleds with random single-byte instructions. Use polymorphic or metamorphic encoding to increase entropy and break pattern signatures. Test against target input filters and AV engines.",
        "mitre": "T1059.006",
    },
    "exploit reliability": {
        "description": "RELIABILITY — Your exploit has stability and portability issues: hardcoded memory addresses that break under ASLR, version-specific offsets without fallback, race conditions, or missing error handling that causes crashes instead of clean failure.",
        "why_high": "HIGH because an unreliable exploit is worse than no exploit — it crashes the target, generates crash dumps and event logs (forensic evidence), alerts defenders, and potentially destabilises the target system. A failed exploit attempt is often more damaging to an operation than not attempting it at all.",
        "recommendation": "Use dynamic address resolution instead of hardcoded offsets. Implement version detection and offset tables. Add proper error handling so the exploit fails cleanly without crashing the target. Validate all target assumptions before triggering the exploit.",
        "mitre": "T1203",
    },
    "exploitation analysis": {
        "description": "DETECTABILITY & OPSEC — Your exploit code contains patterns associated with active exploitation: command injection vectors, code injection (eval/exec), stack pivots, ROP gadgets, or process injection logic. These patterns are high-priority targets for static analysis and EDR behavioural monitoring.",
        "why_high": "HIGH because exploitation patterns are catalogued by threat-intel vendors and AV signature databases. If your exploit code is captured, these patterns immediately classify it as an offensive tool and can be used to create detection rules for your entire toolkit.",
        "recommendation": "Obfuscate exploitation logic to break static-analysis signatures. Use indirect execution methods. Separate exploit delivery from payload execution. Minimize the exploitation footprint and clean up after successful exploitation.",
        "mitre": "T1203",
    },
    # ===== BINARY / OPSEC CATEGORIES =====
    "payload obfuscation": {
        "description": "DETECTABILITY — Your payload uses obfuscation techniques (packing, encoding, encryption) that are detectable by AV/EDR heuristics. While obfuscation hides the payload content, the obfuscation itself can be a detection signal.",
        "why_high": "HIGH because modern AV/EDR products specifically look for obfuscation artifacts (high entropy sections, known packer signatures, encoded shellcode patterns). Obfuscation that triggers heuristic alerts defeats its own purpose.",
        "recommendation": "Use custom obfuscation that avoids known packer signatures. Blend entropy with legitimate data sections. Test against target AV/EDR before deployment. Consider polymorphic or metamorphic techniques.",
        "mitre": "T1027",
    },
    "binary": {
        "description": "DETECTABILITY — Binary-level analysis detected suspicious characteristics in your compiled files: anomalous section names, import patterns, or structural indicators that AV/EDR products use for classification.",
        "why_high": "HIGH because binary-level indicators (suspicious imports, unusual PE sections, known tool signatures) are primary detection vectors for static analysis engines and threat-intel platforms.",
        "recommendation": "Review and clean binary metadata. Remove debug symbols and unnecessary imports. Use custom compilation settings to avoid common tool signatures. Test binaries against VirusTotal before deployment.",
        "mitre": "T1027.002",
    },
    "opsec: detectable shellcode pattern": {
        "description": "DETECTABILITY — Your binary contains byte sequences that match known shellcode signatures (NOP sleds, egg hunters, staged loaders, syscall stubs). AV/EDR products maintain databases of these patterns.",
        "why_high": "HIGH because shellcode pattern databases are extensively maintained by AV vendors. Even XOR-encoded shellcode can be detected by emulation-based scanners that decrypt and match at runtime.",
        "recommendation": "Use custom shellcode that avoids known byte patterns. Avoid common shellcode generators (msfvenom). Encode/encrypt with unique keys and custom schemes. Test against AV engines before deployment.",
        "mitre": "T1059.006",
    },
    "opsec: high entropy detection": {
        "description": "DETECTABILITY — Your binary contains high-entropy sections (>7.0/8.0) indicating packed, encrypted, or compressed data. High entropy is a primary heuristic trigger for AV/EDR static analysis.",
        "why_high": "HIGH because entropy analysis is one of the first checks performed by static AV engines. Sections with entropy >7.0 are almost always flagged for deeper inspection or outright blocked.",
        "recommendation": "Add padding with normal code/data to lower section entropy. Use lower-entropy encoding (base64 + dictionary substitution). Embed encrypted payloads within legitimate-looking data structures.",
        "mitre": "T1027.002",
    },
    "opsec: monitored api import": {
        "description": "DETECTABILITY — Your binary imports Win32 APIs that EDR products monitor. Import table analysis is zero-cost for defenders — suspicious APIs are flagged before the code even runs.",
        "why_high": None,  # severity rationale is per-finding, not per-category
        "recommendation": "Use dynamic API resolution (GetProcAddress/LdrGetProcedureAddress). Remove suspicious imports from the IAT. Consider direct syscalls for sensitive operations. Lazy-load APIs only when needed.",
        "mitre": "T1106",
    },
    "opsec: extractable string": {
        "description": "ATTRIBUTION & DETECTABILITY — Your binary contains extractable strings (URLs, IPs, domains, base64 blobs) that reveal operational infrastructure, C2 endpoints, or encoded payloads visible to anyone running 'strings' on your binary.",
        "why_high": "HIGH because string extraction is trivial and automated. Exposed C2 domains, IP addresses, and encoded payloads let defenders block your infrastructure, create IOCs, and attribute your operations.",
        "recommendation": "Encrypt all strings and decode at runtime. Use string stacking or character-by-character construction. Never embed C2 addresses in cleartext. Use domain fronting or dynamic DNS resolution.",
        "mitre": "T1027",
    },
}

# Alias map for OPSEC sub-categories with parameters to their parent entries
_CATEGORY_ALIASES = {
    "opsec: extractable string (base64_blob)": "opsec: extractable string",
    "opsec: extractable string (domain)": "opsec: extractable string",
    "opsec: extractable string (ip_address)": "opsec: extractable string",
    "opsec: extractable string (url)": "opsec: extractable string",
    "opsec: extractable string (email)": "opsec: extractable string",
    "opsec: extractable string (registry)": "opsec: extractable string",
    "opsec: extractable string (filepath)": "opsec: extractable string",
}


def _get_category_meta(category):
    """Look up rich metadata for a finding category (case-insensitive).

    Supports alias resolution for parameterized categories like
    'OPSEC: Extractable String (url)' → 'opsec: extractable string'.
    """
    key = category.lower().strip()
    result = CATEGORY_METADATA.get(key)
    if result is None:
        alias = _CATEGORY_ALIASES.get(key)
        if alias:
            result = CATEGORY_METADATA.get(alias)
    return result


def normalize_severity(value):
    """Normalize arbitrary severity text into a known level."""
    severity = str(value or "MEDIUM").upper()
    return severity if severity in _SEVERITIES else "MEDIUM"


def _make_finding_id(scanner, category, file_path, line_number, index):
    material = f"{scanner}|{category}|{file_path}|{line_number}|{index}"
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]


def _build_finding(scanner, category, issue, index):
    file_path = issue.get("file") or issue.get("file_path") or "N/A"
    line_number = issue.get("line") or issue.get("line_number") or issue.get("offset")
    recommendation = issue.get("recommended_fix") or issue.get("recommendation")
    description = issue.get("description") or issue.get("issue") or recommendation or issue.get("code") or category

    # If the description is just the category name repeated (no real info from
    # the scanner), substitute the rich category metadata instead.
    meta = _get_category_meta(category)
    if meta:
        if description == category or not description or description == issue.get("type"):
            description = meta["description"]
        if not recommendation:
            recommendation = meta.get("recommendation")

    evidence = {}
    for key in (
        "code",
        "count",
        "function",
        "category",
        "type",
        "mitre_attack",
        "recommended_fix",
        "recommendation",
    ):
        if issue.get(key) not in (None, ""):
            evidence[key] = issue.get(key)

    # Surface match/pattern as evidence.code when no code field exists
    if "code" not in evidence:
        match_str = issue.get("match") or issue.get("pattern")
        if match_str:
            evidence["code"] = str(match_str)[:500]

    # Inject MITRE ATT&CK mapping from metadata if not in the issue itself
    if meta and meta.get("mitre") and "mitre_attack" not in evidence:
        evidence["mitre_attack"] = meta["mitre"]

    # Add severity rationale — prefer per-finding rationale from the issue
    # over the generic category-level rationale from metadata.
    severity_rationale = issue.get("severity_rationale")
    if not severity_rationale and meta:
        severity_rationale = meta.get("why_high")

    # Top-level code/match for consumers that don't dig into evidence
    code_snippet = (
        evidence.get("code")
        or issue.get("code")
        or issue.get("match")
        or issue.get("pattern")
        or ""
    )

    return {
        "id": _make_finding_id(scanner, category, file_path, line_number, index),
        "scanner": scanner,
        "category": category,
        "severity": normalize_severity(issue.get("severity")),
        "title": issue.get("type") or category,
        "description": description,
        "recommendation": recommendation,
        "severity_rationale": severity_rationale,
        # Canonical names
        "file_path": file_path,
        "line_number": line_number,
        # Aliases — ensures any consumer looking for *either* naming
        # convention will find the data (templates use 'file'/'line',
        # the JS UI uses 'file_path'/'line_number', baseline comparison
        # uses 'file_path'/'line_number').
        "file": file_path,
        "line": line_number,
        # Code snippet surfaced at top level for quick access
        "match": code_snippet,
        "evidence": evidence,
        "raw_issue": issue,
    }


def _is_empty_finding(issue, category):
    """Return True if the issue carries no actionable content and should be
    suppressed rather than emitting a vague finding."""
    # A finding whose type/category is just 'source' or 'binary' with no
    # description, code, file, or recommendation is pure noise.
    noise_types = {"source", "binary", ""}
    desc = issue.get("description") or issue.get("issue") or ""
    code = issue.get("code") or issue.get("match") or ""
    file_ = issue.get("file") or issue.get("file_path") or "N/A"
    cat_lower = (category or "").lower().strip()

    if cat_lower in noise_types and not desc and not code and file_ == "N/A":
        return True
    # Suppress if the description is identical to the category name (no info added)
    if desc.lower().strip() == cat_lower and not code:
        return True
    return False


def normalize_source_findings(scan_results):
    """Normalize source-code findings into canonical finding objects."""
    normalized = []
    if not scan_results:
        return normalized

    for category, issues in scan_results.get("findings", {}).items():
        if not isinstance(issues, list):
            continue
        for index, issue in enumerate(issues):
            if isinstance(issue, dict):
                if _is_empty_finding(issue, category):
                    continue
                normalized.append(_build_finding("source_code", category, issue, index))
    return normalized


def normalize_binary_findings(binary_results):
    """Normalize binary-analysis findings into canonical finding objects."""
    normalized = []
    if not binary_results:
        return normalized

    for index, issue in enumerate(binary_results.get("issues", [])):
        if not isinstance(issue, dict):
            continue
        category = issue.get("type") or "Binary Analysis"
        normalized.append(_build_finding("binary_analysis", category, issue, index))
    return normalized


def summarize_findings(findings):
    """Create an aggregate summary over canonical findings."""
    severity_counts = {severity: 0 for severity in _SEVERITIES}
    scanner_counts = {}
    category_counts = {}

    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        severity_counts[severity] += 1

        scanner = finding.get("scanner", "unknown")
        scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        category = finding.get("category", "Uncategorized")
        category_counts[category] = category_counts.get(category, 0) + 1

    # Weighted severity contribution with logarithmic dampening so real malware
    # doesn't always saturate at 100/100.  Each severity bucket contributes a
    # base score per finding with diminishing returns:
    #   CRITICAL: 25 first, +5 log2(n) for extra
    #   HIGH:     12 first, +3 log2(n)
    #   MEDIUM:    4 first, +1 log2(n)
    #   LOW:       1 first, +0.3 log2(n)
    import math

    def _bucket_score(count, base, extra):
        if count <= 0:
            return 0
        return base + extra * math.log2(count) if count > 1 else base

    raw_score = (
        _bucket_score(severity_counts["CRITICAL"], 25, 5)
        + _bucket_score(severity_counts["HIGH"], 12, 3)
        + _bucket_score(severity_counts["MEDIUM"], 4, 1)
        + _bucket_score(severity_counts["LOW"], 1, 0.3)
    )
    risk_score = min(100, round(raw_score))

    if not findings:
        risk_level = "EXCELLENT"
    elif risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 55:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    elif risk_score >= 10:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "scanner_counts": scanner_counts,
        "category_counts": category_counts,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def build_tooling_payload(source_results=None, binary_results=None, dependency_results=None):
    """Build combined source/binary/dependency tooling metadata for UI and reports."""
    source_tooling = dict((source_results or {}).get("tooling") or {})
    binary_tooling = dict((binary_results or {}).get("tooling") or {})
    dependency_tooling = dict((dependency_results or {}).get("tooling") or {})
    binary_capabilities = binary_tooling.get("capabilities") or (binary_results or {}).get("capabilities") or {}
    dependency_summary = (dependency_results or {}).get("summary") or {}

    if binary_capabilities:
        binary_tooling["capabilities"] = binary_capabilities
        binary_tooling.setdefault(
            "enabled_capabilities",
            [name for name, enabled in binary_capabilities.items() if enabled],
        )
        binary_tooling.setdefault(
            "disabled_capabilities",
            [name for name, enabled in binary_capabilities.items() if not enabled],
        )
        binary_tooling.setdefault("scanner", "BinaryAnalyzer")

    if dependency_results:
        dependency_tooling.setdefault("scanner", (dependency_results or {}).get("scanner", "DependencyScanner"))
        dependency_tooling.setdefault("mode", (dependency_results or {}).get("mode", "offline_manifest_inventory"))
        dependency_tooling.setdefault("manifest_count", dependency_summary.get("total_dependency_files", 0))
        dependency_tooling.setdefault("package_count", dependency_summary.get("total_packages", 0))

    return {
        "source": source_tooling,
        "binary": binary_tooling,
        "dependency": dependency_tooling,
        "overview": {
            "source_mode": source_tooling.get("mode"),
            "source_scanner": source_tooling.get("scanner"),
            "source_scan_count": len(source_tooling.get("executed_scans", [])),
            "binary_enabled_capabilities": binary_tooling.get("enabled_capabilities", []),
            "dependency_manifest_count": dependency_tooling.get("manifest_count", 0),
            "dependency_languages": dependency_summary.get("languages_detected", []),
        },
    }


def _deduplicate_findings(source_findings, binary_findings):
    """Remove source-pipeline findings that overlap with binary analysis.

    When the binary analyzer already inspected a file (with much richer
    detail), redundant source-pipeline categories like payload-obfuscation
    and shellcode-security add noise.  Drop those source findings for any
    file that the binary analyzer already covers.
    """
    if not binary_findings:
        return source_findings

    binary_files = {
        os.path.basename(f.get("file_path") or "")
        for f in binary_findings
        if f.get("file_path")
    }
    if not binary_files:
        return source_findings

    # Categories from scanners whose work is subsumed by binary analysis
    redundant_categories = {
        "predictable pattern",
        "api sequence",
        "obfuscation technique",
        "weak obfuscation",
        "payload obfuscation",
        "shellcode detected",
        "null byte detected",
        "bad character",
        "encoding weakness",
        "alignment issue",
        "high signature risk",
        "api reference",
    }

    filtered = []
    for finding in source_findings:
        fname = os.path.basename(finding.get("file_path") or "")
        cat = (finding.get("category") or "").lower()
        # Only drop if the same file is covered by binary analysis AND
        # the category is one the binary analyzer handles better.
        if fname in binary_files and any(rc in cat for rc in redundant_categories):
            continue
        filtered.append(finding)
    return filtered


def build_scan_payload(project_name, directory, source_results=None, binary_results=None, dependency_results=None):
    """Build a schema-backed payload while preserving legacy keys."""
    source_findings = normalize_source_findings(source_results)
    binary_findings = normalize_binary_findings(binary_results)
    normalized_findings = _deduplicate_findings(source_findings, binary_findings)
    normalized_findings.extend(binary_findings)
    normalized_summary = summarize_findings(normalized_findings)
    tooling = build_tooling_payload(source_results, binary_results, dependency_results)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now().isoformat(),
        "target": project_name,
        "directory": directory,
        "files_scanned": (
            (source_results or {}).get("files_scanned", 0)
            + (binary_results or {}).get("files_analyzed", 0)
        ),
        "issues_found": normalized_summary["total_findings"],
        "findings": (source_results or {}).get("findings", {}),
        "summary": {
            "risk_score": normalized_summary["risk_score"],
            "risk_level": normalized_summary["risk_level"],
            "severity_counts": normalized_summary["severity_counts"],
        },
        "source_code": source_results,
        "binary": binary_results,
        "binary_analysis": binary_results,
        "dependency_inventory": dependency_results,
        "has_source": source_results is not None,
        "has_binary": bool(binary_results and binary_results.get("files_analyzed", 0) > 0),
        "has_dependency_inventory": bool(
            dependency_results and ((dependency_results.get("summary") or {}).get("total_dependency_files", 0) > 0)
        ),
        "normalized_findings": normalized_findings,
        "normalized_summary": normalized_summary,
        "tooling": tooling,
    }