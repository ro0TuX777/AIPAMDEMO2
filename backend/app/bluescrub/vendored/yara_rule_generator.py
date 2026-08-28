"""
YARA Rule Generator for BlueScrub
Auto-generates YARA detection rules from scan findings so defenders
can deploy detection signatures based on discovered exploit patterns.
"""

import os
import re
import json
import hashlib
from datetime import datetime
from pathlib import Path


import logging

logger = logging.getLogger(__name__)
class YaraRuleGenerator:
    """Generates YARA rules from BlueScrub scan findings."""

    def __init__(self):
        self.rules = []
        self.rule_count = 0

    def generate_rules_from_findings(self, scan_results, project_name="BlueScrub_Scan"):
        """Generate YARA rules from scan result findings."""
        self.rules = []
        self.rule_count = 0
        timestamp = datetime.now().strftime("%Y-%m-%d")

        # Extract findings from all scan modules
        scans = scan_results.get('scans', {})

        # 1. Shellcode / bytecode patterns
        for result in scans.get('shellcode_security', []):
            self._rules_from_shellcode(result, project_name, timestamp)

        # 2. Exploit reliability findings
        for result in scans.get('exploit_reliability', []):
            self._rules_from_exploit(result, project_name, timestamp)

        # 3. Payload obfuscation findings
        for result in scans.get('payload_obfuscation', []):
            self._rules_from_obfuscation(result, project_name, timestamp)

        # 4. OPSEC analysis findings
        opsec = scans.get('opsec_analysis', {})
        if isinstance(opsec, dict) and opsec.get('findings'):
            self._rules_from_opsec(opsec, project_name, timestamp)

        # 5. Simple scanner findings (Phase 2 checks)
        simple = scans.get('simple_scanner', {})
        if isinstance(simple, dict):
            self._rules_from_simple_scanner(simple, project_name, timestamp)

        # 6. Binary analysis
        binary = scans.get('binary_analysis', {})
        if isinstance(binary, dict):
            self._rules_from_binary(binary, project_name, timestamp)

        return self.rules

    def _make_rule_name(self, prefix, suffix=""):
        """Create a valid YARA rule name."""
        self.rule_count += 1
        name = f"{prefix}_{suffix}_{self.rule_count}" if suffix else f"{prefix}_{self.rule_count}"
        # YARA rule names: alphanumeric + underscore, must start with letter
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if name[0].isdigit():
            name = "rule_" + name
        return name

    def _rules_from_shellcode(self, result, project, ts):
        """Generate rules from shellcode scan results."""
        file_path = result.get('file', 'unknown')
        patterns = result.get('shellcode_patterns', result.get('patterns', []))
        if not patterns:
            return
        strings_block = []
        for i, pat in enumerate(patterns[:10]):
            match_val = pat.get('match', pat.get('pattern', ''))
            if match_val and len(match_val) >= 4:
                safe = match_val.replace('\\', '\\\\').replace('"', '\\"')
                strings_block.append(f'        $s{i} = "{safe}"')
        if not strings_block:
            return
        rule_name = self._make_rule_name("shellcode_detected")
        rule = self._build_rule(
            rule_name, project, ts,
            f"Shellcode patterns from {os.path.basename(file_path)}",
            strings_block, "any of them",
            tags=["shellcode", "exploit"]
        )
        self.rules.append(rule)

    def _rules_from_exploit(self, result, project, ts):
        """Generate rules from exploit reliability analysis."""
        file_path = result.get('file', 'unknown')
        if result.get('error'):
            return
        strings_block = []
        idx = 0
        # Hardcoded addresses
        for addr in result.get('hardcoded_addresses', {}).get('addresses', [])[:5]:
            val = addr.get('address', addr.get('match', ''))
            if val:
                safe = val.replace('"', '\\"')
                strings_block.append(f'        $addr{idx} = "{safe}"')
                idx += 1
        # ROP gadgets
        for gad in result.get('rop_gadgets', {}).get('gadgets', [])[:5]:
            val = gad.get('match', gad.get('gadget', ''))
            if val and len(val) >= 3:
                safe = val.replace('"', '\\"')
                strings_block.append(f'        $rop{idx} = "{safe}" nocase')
                idx += 1
        # Stack pivots
        for piv in result.get('stack_pivots', {}).get('gadgets', [])[:3]:
            val = piv.get('match', '')
            if val:
                safe = val.replace('"', '\\"')
                strings_block.append(f'        $pivot{idx} = "{safe}" nocase')
                idx += 1
        if not strings_block:
            return
        rule_name = self._make_rule_name("exploit_code")
        rule = self._build_rule(
            rule_name, project, ts,
            f"Exploit patterns from {os.path.basename(file_path)}",
            strings_block, "2 of them",
            tags=["exploit", "reliability"]
        )
        self.rules.append(rule)

    def _rules_from_obfuscation(self, result, project, ts):
        """Generate rules from payload obfuscation findings."""
        file_path = result.get('file', 'unknown')
        techniques = result.get('techniques', result.get('obfuscation_techniques', []))
        # obfuscation_techniques may be a dict like {'found': bool, 'techniques': [...]}
        if isinstance(techniques, dict):
            techniques = techniques.get('techniques', [])
        if not techniques:
            return
        strings_block = []
        for i, tech in enumerate(techniques[:8]):
            indicator = tech.get('indicator', tech.get('match', ''))
            if indicator and len(indicator) >= 4:
                safe = indicator.replace('"', '\\"')
                strings_block.append(f'        $obf{i} = "{safe}" nocase')
        if not strings_block:
            return
        rule_name = self._make_rule_name("obfuscated_payload")
        rule = self._build_rule(
            rule_name, project, ts,
            f"Obfuscation patterns from {os.path.basename(file_path)}",
            strings_block, "2 of them",
            tags=["obfuscation", "evasion"]
        )
        self.rules.append(rule)

    def _rules_from_opsec(self, opsec_data, project, ts):
        """Generate rules from OPSEC analysis findings."""
        findings = opsec_data.get('findings', [])
        strings_block = []
        for i, finding in enumerate(findings[:10]):
            evidence = finding.get('evidence', finding.get('match', ''))
            if evidence and len(evidence) >= 4:
                safe = str(evidence).replace('"', '\\"')[:80]
                strings_block.append(f'        $opsec{i} = "{safe}" nocase')
        if not strings_block:
            return
        rule_name = self._make_rule_name("opsec_indicator")
        rule = self._build_rule(
            rule_name, project, ts,
            "OPSEC indicators found during scan",
            strings_block, "any of them",
            tags=["opsec", "attribution"]
        )
        self.rules.append(rule)

    def _rules_from_simple_scanner(self, simple_data, project, ts):
        """Generate rules from simple_scanner Phase 2 findings."""
        findings = simple_data.get('findings', [])
        category_groups = {}
        for f in findings:
            cat = f.get('category', 'unknown')
            category_groups.setdefault(cat, []).append(f)

        for cat, items in category_groups.items():
            strings_block = []
            for i, item in enumerate(items[:8]):
                evidence = item.get('evidence', item.get('match', item.get('detail', '')))
                if evidence and len(str(evidence)) >= 4:
                    safe = str(evidence).replace('"', '\\"').replace('\n', ' ')[:80]
                    strings_block.append(f'        $f{i} = "{safe}" nocase')
            if not strings_block:
                continue
            safe_cat = re.sub(r'[^a-zA-Z0-9]', '_', cat)
            rule_name = self._make_rule_name(f"finding_{safe_cat}")
            rule = self._build_rule(
                rule_name, project, ts,
                f"Detection for category: {cat}",
                strings_block, "any of them",
                tags=[safe_cat.lower()]
            )
            self.rules.append(rule)

    def _rules_from_binary(self, binary_data, project, ts):
        """Generate rules from binary analysis."""
        imphash = binary_data.get('imphash', {}).get('imphash', '')
        if imphash and imphash != 'no imports':
            rule_name = self._make_rule_name("binary_imphash")
            rule = self._build_rule(
                rule_name, project, ts,
                f"Binary identified by import hash: {imphash}",
                [f'        $imphash = "{imphash}"'],
                "any of them",
                tags=["binary", "attribution"],
                extra_meta=f'        imphash = "{imphash}"'
            )
            self.rules.append(rule)

        rich_hash = binary_data.get('rich_header', {}).get('rich_hash', '')
        if rich_hash:
            rule_name = self._make_rule_name("binary_richhash")
            rule = self._build_rule(
                rule_name, project, ts,
                f"Binary identified by Rich header hash: {rich_hash}",
                [f'        $rich = "{rich_hash}"'],
                "any of them",
                tags=["binary", "attribution"],
                extra_meta=f'        rich_hash = "{rich_hash}"'
            )
            self.rules.append(rule)

    def _build_rule(self, name, project, ts, description, strings_block, condition,
                    tags=None, extra_meta=""):
        """Build a complete YARA rule string."""
        tag_str = " : " + " ".join(tags) if tags else ""
        meta_lines = [
            f'        author = "BlueScrub Auto-Generator"',
            f'        date = "{ts}"',
            f'        project = "{project}"',
            f'        description = "{description}"',
        ]
        if extra_meta:
            meta_lines.append(extra_meta)

        rule = f"rule {name}{tag_str}\n{{\n"
        rule += "    meta:\n" + "\n".join(meta_lines) + "\n\n"
        rule += "    strings:\n" + "\n".join(strings_block) + "\n\n"
        rule += f"    condition:\n        {condition}\n}}\n"
        return rule

    def export_rules(self, output_path, scan_results=None, project_name="BlueScrub_Scan"):
        """Generate rules and write them to a .yar file."""
        if scan_results is not None:
            self.generate_rules_from_findings(scan_results, project_name)

        if not self.rules:
            return None

        header = (
            f"// BlueScrub YARA Rules — Auto-generated {datetime.now().isoformat()}\n"
            f"// Project: {project_name}\n"
            f"// Total rules: {len(self.rules)}\n\n"
        )

        content = header + "\n".join(self.rules)

        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return output_path


def generate_yara_from_scan(scan_results, output_dir, project_name="BlueScrub_Scan"):
    """Convenience function: generate YARA rules from scan results."""
    generator = YaraRuleGenerator()
    output_path = os.path.join(output_dir, f"{project_name}_detection_rules.yar")
    result_path = generator.export_rules(output_path, scan_results, project_name)
    if result_path:
        logger.info(f"   ✅ Generated {len(generator.rules)} YARA rules → {result_path}")
    else:
        logger.info("   ℹ️  No YARA rules generated (no actionable patterns found)")
    return result_path, len(generator.rules)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        logger.info("Usage: python3 yara_rule_generator.py <scan_results.json> [output_dir]")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        data = json.load(f)

    out_dir = sys.argv[2] if len(sys.argv) > 2 else '.'
    path, count = generate_yara_from_scan(data, out_dir)
    logger.info(f"Generated {count} YARA rules")

