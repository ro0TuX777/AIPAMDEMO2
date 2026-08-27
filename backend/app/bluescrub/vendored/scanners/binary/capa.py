"""CAPA + advanced analyzer mixin."""

import json
import subprocess

try:
    from advanced_binary_analyzer import AdvancedBinaryAnalyzer, check_installation
    ADVANCED_AVAILABLE = True
except ImportError:
    ADVANCED_AVAILABLE = False

CAPA_CLI_AVAILABLE = None  # resolved at runtime via shutil.which


class CapaMixin:
    """Wrappers for CAPA CLI and advanced (Radare2/Ghidra) analyzers."""

    def _run_advanced_analysis(self, file_path):
        """Run advanced analysis with Radare2/Ghidra if available"""
        if not ADVANCED_AVAILABLE:
            return None

        try:
            analyzer = AdvancedBinaryAnalyzer()
            caps = analyzer.get_capabilities()

            # Only run if at least one tool is available
            if caps.get('radare2') or caps.get('ghidra'):
                return analyzer.analyze(str(file_path), use_ghidra=False)  # Ghidra is slow, off by default
            return None
        except Exception as e:
            return {'error': str(e)}

    def _run_capa_analysis(self, file_path):
        """Run CAPA in JSON mode when available and summarize matches."""
        commands = [
            ['capa', '--json', str(file_path)],
            ['capa', '-j', str(file_path)],
        ]
        last_error = None

        for command in commands:
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
            except Exception as exc:
                last_error = str(exc)
                continue

            if completed.returncode != 0:
                last_error = (completed.stderr or completed.stdout or '').strip() or f'capa exited with {completed.returncode}'
                continue

            try:
                payload = json.loads(completed.stdout or '{}')
            except json.JSONDecodeError as exc:
                last_error = f'Failed to parse CAPA output: {exc}'
                continue

            rules = payload.get('rules') or {}
            rule_matches = []

            if isinstance(rules, dict):
                for rule_name, rule_data in rules.items():
                    meta = (rule_data or {}).get('meta') or {}
                    rule_matches.append({
                        'name': rule_name,
                        'namespace': meta.get('namespace', 'unclassified'),
                        'scope': meta.get('scope'),
                    })
            elif isinstance(rules, list):
                for rule_data in rules:
                    meta = (rule_data or {}).get('meta') or {}
                    rule_name = meta.get('name') or rule_data.get('name')
                    if rule_name:
                        rule_matches.append({
                            'name': rule_name,
                            'namespace': meta.get('namespace', 'unclassified'),
                            'scope': meta.get('scope'),
                        })

            top_rule_matches = [
                {
                    'name': match['name'],
                    'namespace': match.get('namespace', 'unclassified'),
                    'scope': match.get('scope'),
                }
                for match in rule_matches[:10]
            ]
            return {
                'available': True,
                'executed': True,
                'error': None,
                'summary': {
                    'total_rule_matches': len(rule_matches),
                    'top_rule_matches': top_rule_matches,
                },
            }

        return {
            'available': True,
            'executed': False,
            'error': last_error or 'Unable to execute CAPA',
            'summary': {
                'total_rule_matches': 0,
                'top_rule_matches': [],
            },
        }

