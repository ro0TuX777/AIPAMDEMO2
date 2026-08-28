"""
Finding Exploders — convert per-file scanner results into granular findings.

Each ``explode_*`` function takes a ``file_path`` and a scanner result ``item``
dict, and returns a list of individual finding dicts.  These are pure functions
with no dependencies beyond their arguments.

Extracted from ``simple_scanner.py`` to keep that module under control.
"""


# ── Dispatcher ────────────────────────────────────────────────────────────────

_SCANNER_MAP = None  # populated lazily

def _get_scanner_map():
    global _SCANNER_MAP
    if _SCANNER_MAP is None:
        _SCANNER_MAP = {
            'shellcode_security': explode_shellcode,
            'exploit_reliability': explode_exploit_reliability,
            'anti_analysis': explode_anti_analysis,
            'payload_obfuscation': explode_payload_obfuscation,
            'code_similarity': explode_code_similarity,
            'forensic_artifacts': explode_forensic_artifacts,
            'privilege_escalation': explode_privilege_escalation,
            'metadata_leakage': explode_metadata_leakage,
            'network_security': explode_network_security,
        }
    return _SCANNER_MAP


def explode_rich_scanner_results(scan_name, raw_results):
    """Break per-file scanner dicts into individual sub-findings.

    Returns a list of finding dicts, or ``None`` if *scan_name* is not a
    recognised rich scanner (so the caller can fall through to a generic path).
    """
    if not isinstance(raw_results, list):
        return None
    handler = _get_scanner_map().get(scan_name)
    if handler is None:
        return None
    exploded = []
    for item in raw_results:
        if not isinstance(item, dict) or 'error' in item:
            continue
        file_path = item.get('file', 'N/A')
        exploded.extend(handler(file_path, item))
    return exploded


# ── Individual exploders ──────────────────────────────────────────────────────

def explode_shellcode(file_path, item):
    """Convert a single shellcode scanner result into granular findings."""
    subs = []
    severity = item.get('severity', 'MEDIUM')

    nb = item.get('null_bytes', {})
    if nb.get('found'):
        positions = nb.get('positions', [])[:5]
        pos_str = ', '.join(f'0x{p:04x}' for p in positions)
        subs.append({
            'file': file_path, 'severity': 'CRITICAL',
            'type': 'NULL Byte Detected',
            'description': (f"Found {nb.get('count', '?')} NULL bytes (0x00) at offsets [{pos_str}]. "
                            f"NULL bytes break string-copy exploit payloads (strcpy, gets, sprintf). "
                            f"The payload will be truncated at the first NULL, causing partial execution or crash."),
            'code': f"NULL bytes at: [{pos_str}] — {nb.get('explanation', '')}",
            'recommendation': ('Encode shellcode to eliminate NULL bytes (e.g. XOR, alpha-numeric, or custom encoder). '
                               'Verify encoded output contains no bad characters for the target input filter.'),
        })

    bc = item.get('bad_characters', {})
    if bc.get('found'):
        for bad in bc.get('bad_chars', [])[:5]:
            positions = bad.get('positions', [])[:3]
            pos_str = ', '.join(f'0x{p:04x}' for p in positions)
            subs.append({
                'file': file_path, 'severity': 'HIGH',
                'type': f"Bad Character {bad.get('char', '?')}",
                'description': (f"Bad character {bad.get('char', '?')} ({bad.get('description', '')}) "
                                f"found {bad.get('count', '?')} times at offsets [{pos_str}]. "
                                f"This byte is commonly filtered by input validation routines, "
                                f"which will corrupt or truncate your shellcode payload."),
                'code': f"{bad.get('char')} ({bad.get('description')}) × {bad.get('count')} at [{pos_str}]",
                'recommendation': ("Remove or encode this character. Test the shellcode against the "
                                   "target's exact input filter to identify all filtered bytes."),
            })

    pp = item.get('predictable_patterns', {})
    if pp.get('found'):
        for pat in pp.get('patterns', [])[:5]:
            positions = pat.get('positions', [])[:3]
            pos_str = ', '.join(f'0x{p:04x}' for p in positions)
            subs.append({
                'file': file_path, 'severity': 'HIGH',
                'type': f"Predictable Pattern: {pat.get('description', '?')}",
                'description': (f"Detected {pat.get('count', '?')} occurrence(s) of '{pat.get('description', '?')}' "
                                f"at offsets [{pos_str}]. Sample bytes: {pat.get('sample', 'N/A')}. "
                                f"AV/YARA signatures specifically match these byte sequences."),
                'code': f"{pat.get('description')}: {pat.get('sample', '')} at [{pos_str}]",
                'recommendation': ('Replace predictable byte patterns with equivalent random instructions. '
                                   'Use polymorphic encoding to vary the pattern on each generation.'),
            })

    apis = item.get('api_references', {})
    if apis.get('found'):
        for ref in apis.get('apis', [])[:5]:
            subs.append({
                'file': file_path, 'severity': 'MEDIUM',
                'type': f"API Reference: {ref.get('api', '?')}",
                'description': (f"Cleartext reference to '{ref.get('api', '?')}' detected in shellcode. "
                                f"String-based API references are trivially detectable by static analysis "
                                f"and allow defenders to identify shellcode capability."),
                'code': ref.get('api', ''),
                'recommendation': ('Use API hashing (e.g. ROR13, CRC32) instead of cleartext API names. '
                                   'Resolve APIs dynamically via PEB → LDR → InLoadOrderModuleList.'),
            })

    enc = item.get('encoding_analysis', {})
    for issue_text in enc.get('issues', []):
        subs.append({
            'file': file_path, 'severity': 'MEDIUM',
            'type': 'Encoding Weakness',
            'description': (f"{issue_text}. Weak or predictable encoding makes the shellcode "
                            f"detectable by emulation-based AV scanners that can decode and pattern-match."),
            'code': issue_text,
            'recommendation': ('Use a custom encoding scheme with a random key. Avoid single-byte XOR. '
                               'Consider AES-CTR or ChaCha20 with a runtime key derivation stub.'),
        })

    align = item.get('alignment_issues', {})
    for issue_text in align.get('issues', []):
        subs.append({
            'file': file_path, 'severity': 'MEDIUM',
            'type': 'Alignment Issue',
            'description': (f"{issue_text}. Stack misalignment causes SIGSEGV on x64 and "
                            f"certain SSE instructions, making the exploit unreliable."),
            'code': issue_text,
            'recommendation': ('Add alignment NOPs (or AND RSP, -16) before calling system APIs. '
                               'Ensure the stack is 16-byte aligned per the x64 ABI.'),
        })

    sig_risk = item.get('signature_risk', {})
    risk_level = sig_risk.get('risk', 'LOW')
    if risk_level in ('HIGH', 'CRITICAL'):
        subs.append({
            'file': file_path, 'severity': risk_level,
            'type': 'High Signature Risk',
            'description': (f"Overall signature detection risk is {risk_level} "
                            f"(score: {sig_risk.get('score', '?')}/100). "
                            f"This shellcode has a high probability of being detected by "
                            f"static AV/YARA signature scans."),
            'code': f"Signature risk: {risk_level} ({sig_risk.get('score', '?')}/100)",
            'recommendation': ('Apply multiple encoding layers, use metamorphic techniques, and '
                               'test against target AV before deployment.'),
        })

    # Fallback
    if not subs:
        subs.append({
            'file': file_path, 'severity': severity,
            'type': 'Shellcode Detected',
            'description': (f"File contains potential shellcode ({item.get('size', '?')} bytes, "
                            f"entropy: {item.get('entropy', {}).get('value', '?')}). "
                            f"Review for NULL bytes, bad characters, and detectable patterns."),
            'code': f"Size: {item.get('size', '?')} bytes, Entropy: {item.get('entropy', {}).get('value', '?')}",
        })
    return subs


def explode_exploit_reliability(file_path, item):
    """Convert a single exploit-reliability result into granular findings."""
    subs = []
    issues = item.get('issues', item.get('findings', []))
    if isinstance(issues, list):
        for issue in issues:
            if isinstance(issue, dict):
                issue.setdefault('file', file_path)
                subs.append(issue)
    if not subs:
        reliability = item.get('reliability_score', item.get('score'))
        error_handling = item.get('error_handling', {})
        cleanup = item.get('cleanup', {})
        parts = []
        if reliability is not None and reliability > 0:
            parts.append(f"Reliability score: {reliability}/100")
        if error_handling.get('found'):
            parts.append(f"error handling issues: {error_handling.get('count', '?')}")
        if cleanup.get('found') is False:
            parts.append("no post-exploitation cleanup")
        desc = '. '.join(parts) if parts else None
        if desc:
            subs.append({
                'file': file_path,
                'severity': item.get('severity', 'MEDIUM'),
                'type': 'Exploit Reliability',
                'description': desc,
                'recommendation': ('Add exception handling around exploit primitives. '
                                   'Implement cleanup routines to remove artifacts on failure.'),
            })
    return subs


def explode_anti_analysis(file_path, item):
    """Convert a single anti-analysis validator result into per-technique findings."""
    subs = []
    severity = item.get('severity', 'MEDIUM')

    technique_sections = [
        ('debugger_detection', 'Debugger Detection', 'techniques',
         'Anti-debugging check using a well-known API/technique. EDR products specifically signature these calls.',
         'Replace with indirect detection (timing side-channels, hardware breakpoint checks). '
         'Use syscall stubs instead of calling known APIs directly.'),
        ('vm_detection', 'VM Detection', 'techniques',
         'Virtual machine detection using a known fingerprinting method. Sandbox vendors actively patch against these checks.',
         'Use timing-based VM detection or CPUID leaf analysis instead of string/registry-based checks.'),
        ('sandbox_evasion', 'Sandbox Evasion', 'techniques',
         'Sandbox evasion technique that may be fingerprinted by automated analysis systems.',
         'Use environmental keying rather than generic sandbox detection. Combine multiple weak signals.'),
        ('anti_disassembly', 'Anti-Disassembly', 'techniques',
         'Anti-disassembly technique that slows but does not prevent static analysis.',
         'Combine with control-flow flattening and opaque predicates for better protection.'),
        ('environment_checks', 'Environment Check', 'checks',
         'Environment fingerprinting that could be used for sandbox detection or targeting.',
         'Ensure environment checks use indirect methods. Direct API calls are easily hooked.'),
    ]

    for section_key, label, items_key, desc_template, rec in technique_sections:
        section = item.get(section_key, {})
        if not section.get('found'):
            continue
        for tech in section.get(items_key, []):
            line = tech.get('line')
            technique_name = tech.get('type', tech.get('technique', label))
            subs.append({
                'file': file_path, 'line': line, 'severity': severity,
                'type': f'{label}: {technique_name}',
                'description': f"{desc_template} Technique: {technique_name}.",
                'code': tech.get('technique', tech.get('check', '')),
                'recommendation': rec,
            })

    weak = item.get('weak_techniques', {})
    if weak.get('found'):
        for w in weak.get('weaknesses', []):
            subs.append({
                'file': file_path, 'line': w.get('line'), 'severity': 'HIGH',
                'type': f"Weak Anti-Analysis: {w.get('type', '?')}",
                'description': (f"Weak anti-analysis pattern detected: {w.get('type', '?')}. "
                                f"This technique is trivially bypassed AND is a well-known signature."),
                'code': w.get('weakness', ''),
                'recommendation': ('Remove this check entirely or replace with a robust alternative.'),
            })

    if not subs:
        effectiveness = item.get('effectiveness_score', 0)
        if effectiveness and effectiveness > 0:
            subs.append({
                'file': file_path, 'severity': severity,
                'type': 'Anti-Analysis Code',
                'description': (f"File contains anti-analysis code (effectiveness: "
                                f"{effectiveness}/100). Review techniques for detectability risk."),
            })
    return subs



def explode_payload_obfuscation(file_path, item):
    """Convert a single payload-obfuscation result into granular findings."""
    subs = []
    severity = item.get('severity', 'MEDIUM')
    for technique in item.get('techniques', []):
        if isinstance(technique, dict):
            subs.append({
                'file': file_path,
                'severity': technique.get('severity', severity),
                'type': f"Obfuscation: {technique.get('type', '?')}",
                'description': technique.get('description', technique.get('type', '')),
                'code': technique.get('sample', ''),
                'line': technique.get('line'),
                'recommendation': technique.get('recommendation',
                    'Review obfuscation technique for OPSEC risk. '
                    'Ensure encoding is multi-layered and polymorphic.'),
            })
    if not subs and item.get('obfuscation_score', 0) > 0:
        subs.append({
            'file': file_path, 'severity': severity,
            'type': 'Payload Obfuscation',
            'description': (f"Obfuscation detected (score: {item.get('obfuscation_score', '?')}/100). "
                            f"Layers: {item.get('layers', '?')}."),
        })
    return subs


def explode_code_similarity(file_path, item):
    """Convert a code-similarity/attribution result into findings."""
    subs = []
    for match in item.get('matches', item.get('attributions', [])):
        if isinstance(match, dict):
            subs.append({
                'file': file_path,
                'severity': match.get('severity', 'HIGH'),
                'type': f"Code Attribution: {match.get('family', match.get('tool', '?'))}",
                'description': (f"Code similarity to known tool/malware: "
                                f"{match.get('family', match.get('tool', '?'))} "
                                f"(confidence: {match.get('confidence', '?')}%)."),
                'code': match.get('evidence', ''),
                'recommendation': ('Rewrite matched code sections. Unique implementations '
                                   'reduce attribution risk.'),
            })
    return subs


def explode_forensic_artifacts(file_path, item):
    """Convert forensic-artifact detector results into findings."""
    subs = []
    for artifact in item.get('artifacts', []):
        if isinstance(artifact, dict):
            subs.append({
                'file': file_path,
                'severity': artifact.get('severity', 'MEDIUM'),
                'type': f"Forensic Artifact: {artifact.get('type', '?')}",
                'description': artifact.get('description', ''),
                'code': artifact.get('evidence', ''),
                'line': artifact.get('line'),
                'recommendation': artifact.get('recommendation',
                    'Implement artifact cleanup or use techniques that avoid creating artifacts.'),
            })
    if not subs and item.get('artifact_score', 0) > 20:
        subs.append({
            'file': file_path, 'severity': item.get('severity', 'MEDIUM'),
            'type': 'Forensic Artifacts',
            'description': (f"Potential forensic artifacts detected "
                            f"(score: {item.get('artifact_score', '?')}/100)."),
        })
    return subs


def explode_privilege_escalation(file_path, item):
    """Convert privilege-escalation results into findings."""
    subs = []
    for vuln in item.get('vulnerabilities', item.get('findings', [])):
        if isinstance(vuln, dict):
            subs.append({
                'file': file_path,
                'severity': vuln.get('severity', 'HIGH'),
                'type': f"Privilege Escalation: {vuln.get('type', '?')}",
                'description': vuln.get('description', ''),
                'code': vuln.get('evidence', vuln.get('code', '')),
                'line': vuln.get('line'),
                'recommendation': vuln.get('recommendation',
                    'Review privilege escalation vector for reliability and stealth.'),
            })
    return subs


def explode_metadata_leakage(file_path, item):
    """Convert metadata-leakage results into findings."""
    subs = []
    for leak in item.get('leaks', item.get('findings', [])):
        if isinstance(leak, dict):
            subs.append({
                'file': file_path,
                'severity': leak.get('severity', 'MEDIUM'),
                'type': f"Metadata Leak: {leak.get('type', '?')}",
                'description': leak.get('description', ''),
                'code': leak.get('evidence', leak.get('value', '')),
                'line': leak.get('line'),
                'recommendation': ('Strip metadata before distribution. Use tools like '
                                   'mat2 (for documents) or exiftool (for images).'),
            })
    return subs


def explode_network_security(file_path, item):
    """Convert network-traffic analyzer results into findings."""
    subs = []
    for issue in item.get('issues', item.get('findings', [])):
        if isinstance(issue, dict):
            subs.append({
                'file': file_path,
                'severity': issue.get('severity', 'MEDIUM'),
                'type': f"Network: {issue.get('type', '?')}",
                'description': issue.get('description', ''),
                'code': issue.get('evidence', issue.get('code', '')),
                'line': issue.get('line'),
                'recommendation': issue.get('recommendation',
                    'Use encrypted channels and avoid hardcoded network indicators.'),
            })
    return subs