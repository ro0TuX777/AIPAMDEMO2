"""
CLI Tool Wrappers for BlueScrub
Extracted from defensive_security_scanner.py
Each function wraps an external security tool (Bandit, Semgrep, etc.)
"""

import os
import json

from backend.app.bluescrub.vendored.scanners.utils import run_command


import logging

logger = logging.getLogger(__name__)
def run_bandit_defensive(directory):
    """Run Bandit with focus on defensive security issues"""
    cmd = f'bandit -r "{directory}" -f json -ll --skip B101'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            return json.loads(result['stdout'])
        except json.JSONDecodeError:
            return {'error': 'Failed to parse Bandit JSON output'}
    return {'error': result.get('error', 'Bandit failed')}


def run_semgrep_defensive(directory):
    """Run Semgrep with FAST, focused rulesets for exploitation tool security"""
    priority_rulesets = [
        'p/owasp-top-ten', 'p/security-audit', 'p/secrets',
        'p/python', 'p/command-injection',
        'p/cryptography', 'p/deserialization',
    ]

    logger.info(f"🔍 Running {len(priority_rulesets)} priority Semgrep rulesets (optimized for speed)...")

    all_results = {'results': []}
    successful_rulesets = []
    failed_rulesets = []

    for i, ruleset in enumerate(priority_rulesets, 1):
        logger.info(f"  [{i}/{len(priority_rulesets)}] {ruleset}...")
        cmd = f'semgrep --config={ruleset} "{directory}" --json --quiet --timeout=30 --max-target-bytes=1MB'
        result = run_command(cmd, timeout=45)

        stdout = result.get('stdout', '')
        if stdout:
            try:
                data = json.loads(stdout)
                if 'results' in data and data['results']:
                    all_results['results'].extend(data['results'])
                    successful_rulesets.append(ruleset)
                    logger.info(f"    ✅ Found {len(data['results'])} issues")
                else:
                    logger.info(f"    ✅ No issues found")
                    successful_rulesets.append(ruleset)
                continue
            except json.JSONDecodeError:
                pass

        error_msg = result.get('error', result.get('stderr', '')[:120])
        failed_rulesets.append(f"{ruleset} (execution failed)")
        logger.info(f"    ❌ Execution failed: {error_msg[:80]}" if error_msg else f"    ❌ Execution failed")

    all_results['metadata'] = {
        'successful_rulesets': successful_rulesets,
        'failed_rulesets': failed_rulesets,
        'total_rulesets_attempted': len(priority_rulesets),
        'optimization': 'Fast mode - reduced rulesets for speed'
    }

    logger.info(f"🔍 Semgrep completed: {len(successful_rulesets)}/{len(priority_rulesets)} rulesets successful")
    return all_results


def run_safety_offline():
    """Run Safety in offline mode with local database only"""
    cmd = 'safety check --json --offline'
    result = run_command(cmd)
    if result['success']:
        try:
            return json.loads(result['stdout']) if result['stdout'] else []
        except json.JSONDecodeError:
            return []
    logger.info("⚠️ Safety offline mode not available - skipping to maintain OPSEC")
    return {'offline_mode': 'Safety requires internet connectivity - skipped for OPSEC'}


def run_eslint_security(directory):
    """Run ESLint with security plugins for JavaScript/TypeScript"""
    package_json_path = os.path.join(directory, 'package.json')
    if not os.path.exists(package_json_path):
        return {'error': 'No package.json found - skipping ESLint security scan'}
    cmd = f'cd "{directory}" && npx eslint . --ext .js,.ts,.jsx,.tsx --format json --config-file .eslintrc.security.js'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            return json.loads(result['stdout'])
        except json.JSONDecodeError:
            return {'error': 'Failed to parse ESLint JSON output'}
    return {'error': result.get('error', 'ESLint security scan failed')}


def run_gosec_security(directory):
    """Run Gosec for Go security scanning"""
    go_mod_path = os.path.join(directory, 'go.mod')
    go_files = []
    for root, dirs, files in os.walk(directory):
        go_files.extend([f for f in files if f.endswith('.go')])
    if not os.path.exists(go_mod_path) and not go_files:
        return {'error': 'No Go files found - skipping Gosec scan'}
    cmd = f'cd "{directory}" && gosec -fmt json ./...'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            return json.loads(result['stdout'])
        except json.JSONDecodeError:
            return {'error': 'Failed to parse Gosec JSON output'}
    return {'error': result.get('error', 'Gosec scan failed')}




def run_flawfinder_security(directory):
    """Run Flawfinder for C/C++ security scanning"""
    c_files = []
    for root, dirs, files in os.walk(directory):
        c_files.extend([f for f in files if f.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'))])
    if not c_files:
        return {'error': 'No C/C++ files found - skipping Flawfinder scan'}
    cmd = f'flawfinder --json "{directory}"'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            return json.loads(result['stdout'])
        except json.JSONDecodeError:
            return {'error': 'Failed to parse Flawfinder JSON output'}
    return {'error': result.get('error', 'Flawfinder scan failed')}


def run_cppcheck_security(directory):
    """Run Cppcheck for C/C++ security and quality issues"""
    c_files = []
    for root, dirs, files in os.walk(directory):
        c_files.extend([f for f in files if f.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'))])
    if not c_files:
        return {'error': 'No C/C++ files found - skipping Cppcheck scan'}
    cmd = f'cppcheck --enable=all --json "{directory}" 2>&1'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            json_output = result['stderr'] if result['stderr'] else result['stdout']
            return json.loads(json_output)
        except json.JSONDecodeError:
            return {'error': 'Failed to parse Cppcheck JSON output'}
    return {'error': result.get('error', 'Cppcheck scan failed')}


def run_gitleaks_secrets(directory):
    """Run GitLeaks for OFFLINE secrets detection (OPSEC-safe)"""
    cmd = f'gitleaks detect --source "{directory}" --report-format json --report-path /tmp/gitleaks_report.json --no-git --verbose'
    result = run_command(cmd)
    if result['success']:
        try:
            with open('/tmp/gitleaks_report.json', 'r') as f:
                data = json.load(f)
                logger.info(f"🔒 GitLeaks: Found {len(data)} potential secrets (offline analysis)")
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    return {'error': result.get('error', 'GitLeaks failed')}


def run_trufflehog_secrets(directory):
    """Run TruffleHog for OFFLINE secrets detection (OPSEC-safe)"""
    cmd = f'trufflehog filesystem "{directory}" --json --no-verification --no-update'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        secrets = []
        for line in result['stdout'].strip().split('\n'):
            if line.strip():
                try:
                    secrets.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        logger.info(f"🔒 TruffleHog: Found {len(secrets)} potential secrets (offline analysis)")
        return secrets
    return {'error': result.get('error', 'TruffleHog failed')}


def run_detect_secrets(directory):
    """Run detect-secrets for enterprise-grade secrets detection"""
    baseline_cmd = f'detect-secrets scan "{directory}" --baseline /tmp/secrets_baseline.json'
    baseline_result = run_command(baseline_cmd)
    if baseline_result['success']:
        try:
            with open('/tmp/secrets_baseline.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {'results': []}
    return {'error': baseline_result.get('error', 'detect-secrets failed')}


def run_trivy_offline(directory):
    """Run Trivy in offline mode for secrets and config scanning only"""
    cmd = f'trivy fs "{directory}" --format json --scanners secret,config --offline'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            return json.loads(result['stdout'])
        except json.JSONDecodeError:
            return {'error': 'Failed to parse Trivy JSON output'}
    logger.info("⚠️ Trivy offline mode not available - skipping vulnerability scanning to maintain OPSEC")
    return {'offline_mode': 'Trivy vulnerability scanning requires internet - using secrets/config only'}


def run_sonarqube_scan(directory):
    """Run SonarQube scanner for code quality and security"""
    cmd = f'sonar-scanner -Dsonar.projectKey=defensive_scan -Dsonar.sources="{directory}" -Dsonar.host.url=http://localhost:9000'
    result = run_command(cmd)
    if result['success']:
        return {'status': 'completed', 'message': 'SonarQube scan completed'}
    return {'error': result.get('error', 'SonarQube scan failed')}


def run_bearer_scan(directory):
    """Run Bearer for privacy and security analysis"""
    cmd = f'bearer scan "{directory}" --format json'
    result = run_command(cmd)
    if result['success'] and result['stdout']:
        try:
            return json.loads(result['stdout'])
        except json.JSONDecodeError:
            return {'error': 'Failed to parse Bearer JSON output'}
    return {'error': result.get('error', 'Bearer scan failed')}


def run_horusec_scan(directory):
    """Run Horusec for multi-language security analysis"""
    cmd = f'horusec start -p "{directory}" -o json -O /tmp/horusec_report.json'
    result = run_command(cmd)
    if result['success']:
        try:
            with open('/tmp/horusec_report.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {'error': 'Failed to read Horusec report'}
    return {'error': result.get('error', 'Horusec scan failed')}


def run_grype_scan(directory):
    """Run Grype for offline vulnerability scanning of filesystems.

    Grype scans package manifests (requirements.txt, package.json, go.mod,
    Cargo.toml, pom.xml, etc.) and matches discovered packages against a
    local vulnerability database.

    Offline mode
    ------------
    Grype caches its vulnerability DB after the first ``grype db update``.
    Once cached, it works fully offline — no network calls during the scan.
    Run ``grype db update`` once on a machine with internet, then the DB
    persists at ``~/.cache/grype/db/``.  Copy that directory to an air-gapped
    host if needed.

    Returns a dict with:
      - ``matches``  – list of CVE matches
      - ``source``   – scan metadata
      - ``summary``  – aggregated counts by severity
      - ``error``    – present only on failure
    """
    import shutil

    if not shutil.which("grype"):
        return {
            "available": False,
            "error": "grype is not installed — install from https://github.com/anchore/grype",
        }

    # ``dir:<path>`` tells Grype to scan a local directory (not a container image)
    cmd = f'grype dir:"{directory}" -o json --by-cve'
    result = run_command(cmd, timeout=300)

    # Grype exits 0 on success and also on "vulnerabilities found".
    # It exits non-zero only on hard errors.
    stdout = result.get("stdout", "")
    if not stdout:
        return {
            "available": True,
            "error": result.get("error") or result.get("stderr") or "Grype produced no output",
        }

    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return {"available": True, "error": "Failed to parse Grype JSON output"}

    matches = raw.get("matches") or []

    # Build a severity summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    for match in matches:
        vuln = match.get("vulnerability") or {}
        sev = vuln.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Normalise matches into a simpler list for the report
    vulnerabilities = []
    for match in matches:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        related = vuln.get("relatedVulnerabilities") or []
        cve_ids = [vuln.get("id", "")]
        cve_ids.extend(rv.get("id", "") for rv in related if rv.get("id", "").startswith("CVE-"))

        vulnerabilities.append({
            "id": vuln.get("id", ""),
            "severity": vuln.get("severity", "Unknown"),
            "package": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "language": artifact.get("language", ""),
            "type": artifact.get("type", ""),
            "fix_versions": vuln.get("fix", {}).get("versions") or [],
            "fix_state": vuln.get("fix", {}).get("state", ""),
            "description": vuln.get("description", ""),
            "data_source": vuln.get("dataSource", ""),
            "cve_ids": [c for c in cve_ids if c],
            "urls": vuln.get("urls") or [],
            "matched_by": (match.get("matchDetails") or [{}])[0].get("type", ""),
        })

    return {
        "available": True,
        "scanner": "grype",
        "mode": "offline_filesystem",
        "total_matches": len(matches),
        "severity_counts": severity_counts,
        "vulnerabilities": vulnerabilities,
        "source": raw.get("source") or {},
        "descriptor": raw.get("descriptor") or {},
        "db_status": raw.get("descriptor", {}).get("db", {}),
    }


# ── Checkov (IaC / Dockerfile / Kubernetes misconfiguration scanner) ──────


def run_checkov_scan(directory):
    """Run Checkov for Infrastructure-as-Code misconfiguration scanning.

    Scans Dockerfiles, Terraform, CloudFormation, Kubernetes manifests,
    Helm charts, and more.  Works fully offline — no API key required.

    Returns a dict with:
      - ``passed``   – number of passing checks
      - ``failed``   – number of failing checks
      - ``skipped``  – number of skipped checks
      - ``findings`` – list of failed checks with details
      - ``error``    – present only on failure
    """
    import shutil

    if not shutil.which("checkov"):
        return {
            "available": False,
            "error": "checkov is not installed — pip install checkov",
        }

    cmd = (
        f'checkov -d "{directory}" '
        f'--output json --compact --quiet '
        f'--skip-download '  # fully offline, no external calls
    )
    result = run_command(cmd, timeout=300)

    stdout = result.get("stdout", "")
    if not stdout:
        # Checkov may return nothing if no IaC files found
        return {
            "available": True,
            "scanner": "checkov",
            "no_iac_files": True,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "findings": [],
        }

    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return {"available": True, "error": "Failed to parse Checkov JSON output"}

    # Checkov returns a list when multiple frameworks are scanned
    if isinstance(raw, dict):
        raw = [raw]

    findings = []
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    for framework_result in raw:
        summary = framework_result.get("summary", {})
        total_passed += summary.get("passed", 0)
        total_failed += summary.get("failed", 0)
        total_skipped += summary.get("skipped", 0)

        for check in framework_result.get("results", {}).get("failed_checks", []):
            findings.append({
                "check_id": check.get("check_id", ""),
                "check_name": check.get("check_type", check.get("check_id", "")),
                "severity": check.get("severity", "MEDIUM"),
                "resource": check.get("resource", ""),
                "file": check.get("file_path", ""),
                "line_range": check.get("file_line_range", []),
                "guideline": check.get("guideline", ""),
                "check_class": check.get("check_class", ""),
                "framework": framework_result.get("check_type", ""),
            })

    return {
        "available": True,
        "scanner": "checkov",
        "passed": total_passed,
        "failed": total_failed,
        "skipped": total_skipped,
        "findings": findings,
    }


# ── Blint (Binary Linter — hardening & capability checks) ────────────────


def run_blint_scan(directory):
    """Run Blint for binary hardening and capability analysis.

    Checks ELF/PE/Mach-O executables for security properties:
    ASLR, NX/DEP, PIE, stack canaries, RELRO, code signing, etc.
    Works fully offline — pure Python, no network calls.

    Returns a dict with:
      - ``binaries_scanned`` – number of binaries analysed
      - ``findings``         – list of hardening issues
      - ``capabilities``     – list of detected capabilities per binary
      - ``error``            – present only on failure
    """
    import shutil, glob, tempfile

    if not shutil.which("blint"):
        return {
            "available": False,
            "error": "blint is not installed — pip install blint",
        }

    # blint outputs reports to a directory
    with tempfile.TemporaryDirectory(prefix="bluescrub_blint_") as tmpdir:
        cmd = f'blint -i "{directory}" -o "{tmpdir}" --no-banner --no-error'
        run_command(cmd, timeout=300)

        # blint produces JSON reports in the output dir
        report_files = glob.glob(os.path.join(tmpdir, "*.json"))
        if not report_files:
            return {
                "available": True,
                "scanner": "blint",
                "binaries_scanned": 0,
                "findings": [],
                "capabilities": [],
                "no_binaries": True,
            }

        findings = []
        capabilities = []
        binaries_scanned = 0

        for report_file in report_files:
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # blint review reports
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        binaries_scanned += 1
                        for review in entry.get("reviews", []):
                            findings.append({
                                "binary": entry.get("name", os.path.basename(report_file)),
                                "check": review.get("id", ""),
                                "title": review.get("title", ""),
                                "severity": review.get("severity", "medium"),
                                "description": review.get("description", ""),
                            })
                        for cap in entry.get("capabilities", []):
                            capabilities.append({
                                "binary": entry.get("name", ""),
                                "capability": cap.get("name", ""),
                                "description": cap.get("description", ""),
                            })
            elif isinstance(data, dict):
                binaries_scanned += 1
                for review in data.get("reviews", []):
                    findings.append({
                        "binary": data.get("name", os.path.basename(report_file)),
                        "check": review.get("id", ""),
                        "title": review.get("title", ""),
                        "severity": review.get("severity", "medium"),
                        "description": review.get("description", ""),
                    })
                for cap in data.get("capabilities", []):
                    capabilities.append({
                        "binary": data.get("name", ""),
                        "capability": cap.get("name", ""),
                        "description": cap.get("description", ""),
                    })

    return {
        "available": True,
        "scanner": "blint",
        "binaries_scanned": binaries_scanned,
        "findings": findings,
        "capabilities": capabilities,
    }


# ── YARA (rule-based malware / pattern scanning) ─────────────────────────

# Default directory for YARA rule files.  Users can drop ``.yar`` / ``.yara``
# files here, or set the env var to a custom location.
YARA_RULES_DIR = os.environ.get(
    "BLUESCRUB_YARA_RULES_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "yara_rules"),
)

# Extensions to scan with YARA (skip huge binaries / archives by default)
_YARA_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".c", ".cpp", ".h", ".go", ".rs", ".java",
    ".rb", ".php", ".sh", ".bat", ".ps1", ".pl", ".lua",
    ".exe", ".dll", ".so", ".dylib", ".elf", ".bin",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf",
}

_YARA_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB per file


def run_yara_scan(directory, rules_dir=None):
    """Scan files in *directory* against YARA rule files.

    Loads all ``.yar`` / ``.yara`` files from *rules_dir* (defaults to
    ``yara_rules/`` in the project root), compiles them, and matches
    against every eligible file in the target directory.

    Works fully offline — ``yara-python`` is a pure library with no
    network calls.

    Returns a dict with:
      - ``rules_loaded``   – number of YARA rules compiled
      - ``files_scanned``  – number of files checked
      - ``matches``        – list of match dicts
      - ``error``          – present only on failure
    """
    try:
        import yara  # type: ignore
    except ImportError:
        return {
            "available": False,
            "error": "yara-python is not installed — pip install yara-python",
        }

    rules_dir = rules_dir or YARA_RULES_DIR
    if not os.path.isdir(rules_dir):
        return {
            "available": True,
            "scanner": "yara",
            "rules_loaded": 0,
            "files_scanned": 0,
            "matches": [],
            "no_rules": True,
            "rules_dir": rules_dir,
        }

    # Discover and compile rule files
    rule_files = {}
    for fname in sorted(os.listdir(rules_dir)):
        if fname.lower().endswith((".yar", ".yara")):
            namespace = os.path.splitext(fname)[0]
            rule_files[namespace] = os.path.join(rules_dir, fname)

    if not rule_files:
        return {
            "available": True,
            "scanner": "yara",
            "rules_loaded": 0,
            "files_scanned": 0,
            "matches": [],
            "no_rules": True,
            "rules_dir": rules_dir,
        }

    try:
        compiled = yara.compile(filepaths=rule_files)
    except yara.SyntaxError as exc:
        return {"available": True, "error": f"YARA compilation error: {exc}"}

    # Walk directory and match
    matches_found = []
    files_scanned = 0

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _YARA_SCAN_EXTENSIONS:
                continue
            try:
                if os.path.getsize(fpath) > _YARA_MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            files_scanned += 1
            try:
                hits = compiled.match(fpath, timeout=30)
            except Exception:
                continue

            for hit in hits:
                matches_found.append({
                    "rule": hit.rule,
                    "namespace": hit.namespace,
                    "file": os.path.relpath(fpath, directory),
                    "tags": list(hit.tags),
                    "meta": dict(hit.meta) if hit.meta else {},
                    "strings_matched": len(hit.strings),
                })

    return {
        "available": True,
        "scanner": "yara",
        "rules_loaded": len(rule_files),
        "files_scanned": files_scanned,
        "total_matches": len(matches_found),
        "matches": matches_found,
    }