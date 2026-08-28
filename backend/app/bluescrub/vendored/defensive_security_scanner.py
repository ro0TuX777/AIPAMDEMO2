#!/usr/bin/env python3
"""
Enhanced Defensive Security Scanner for BlueScrub
Focuses on finding vulnerabilities in your own code that could be exploited
Rather than detecting malicious patterns, this identifies security weaknesses

Enhanced Features (100% Offline):
- Advanced secrets detection with custom patterns
- Information disclosure analysis
- Memory safety analysis
- Cryptographic vulnerability detection
- Supply chain security analysis
- Code quality and maintainability analysis

Phase 1 Enhancements (technique-Specific Security):
- bytecode security analysis (null bytes, bad chars, patterns)
- technique reliability analysis (ROP chains, ASLR bypasses)
- data obfuscation analysis (entropy, detection risk)
"""

import os
import sys
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import logging

logger = logging.getLogger(__name__)
# Import all standalone analyzers from the unified package
from backend.app.bluescrub.vendored.scanners.analyzers import (
    scan_directory_for_shellcode,
    analyze_directory_for_exploits,
    analyze_directory_for_payloads,
    analyze_directory_for_attribution,
    analyze_directory_for_metadata,
    analyze_directory_for_network,
    analyze_directory_for_anti_analysis,
    analyze_directory_for_artifacts,
    analyze_directory_for_privesc,
)

SHELLCODE_SCANNER_AVAILABLE = True
EXPLOIT_ANALYZER_AVAILABLE = True
PAYLOAD_ANALYZER_AVAILABLE = True
CODE_SIMILARITY_AVAILABLE = True
METADATA_SCANNER_AVAILABLE = True
NETWORK_ANALYZER_AVAILABLE = True
ANTI_ANALYSIS_AVAILABLE = True
FORENSIC_DETECTOR_AVAILABLE = True
PRIVESC_ANALYZER_AVAILABLE = True

# Import YARA Rule Generator
try:
    from backend.app.bluescrub.vendored.yara_rule_generator import generate_yara_from_scan
    YARA_GENERATOR_AVAILABLE = True
except ImportError:
    YARA_GENERATOR_AVAILABLE = False

SOURCE_CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc', '.cxx',
    '.h', '.hpp', '.go', '.rs', '.rb', '.php', '.cs', '.swift', '.kt', '.scala',
    '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.pl', '.pm', '.lua', '.r',
    '.html', '.css', '.scss', '.sass', '.vue', '.svelte',
}

SKIP_DIRS = {'analysis_results', 'dependency-check-report', '__pycache__',
             '.git', 'node_modules', '.venv', 'venv', '.tox'}


def has_source_files(directory, limit=5):
    """Fast check: does this directory contain any source code files?
    Returns as soon as `limit` source files are found (default 5 to be sure).
    """
    count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_CODE_EXTENSIONS:
                count += 1
                if count >= limit:
                    return True
    return count > 0


# Import run_command from shared utils (avoids circular import)
from backend.app.bluescrub.vendored.scanners.utils import run_command

# Import extracted scanner modules
from backend.app.bluescrub.vendored.scanners import (
    run_bandit_defensive,
    run_semgrep_defensive,
    run_safety_offline,
    run_eslint_security,
    run_gosec_security,
    run_flawfinder_security,
    run_cppcheck_security,
    run_gitleaks_secrets,
    run_trufflehog_secrets,
    run_detect_secrets,
    run_trivy_offline,
    run_sonarqube_scan,
    run_bearer_scan,
    run_horusec_scan,
    run_enhanced_secrets_detection,
    run_information_disclosure_analysis,
    run_memory_safety_analysis,
    run_crypto_vulnerability_analysis,
    run_supply_chain_analysis,
    run_opsec_analysis,
    run_exploitation_tool_analysis,
)


# --- All scanner functions below have been extracted to scanners/ package ---
# See scanners/tool_wrappers.py and scanners/custom_analyzers.py

def check_tool_availability():
    """Check which OFFLINE-ONLY security tools are available (OPSEC-compliant)"""
    tools = {
        # Core SAST tools (100% offline)
        'bandit': run_command('bandit --version')['success'],
        'semgrep': run_command('semgrep --version')['success'],
        'safety': run_command('safety --version')['success'],

        # Language-specific tools (100% offline)
        'gosec': run_command('gosec -version')['success'],
        'flawfinder': run_command('flawfinder --version')['success'],
        'cppcheck': run_command('cppcheck --version')['success'],

        # Secrets detection tools (100% offline)
        'gitleaks': run_command('gitleaks version')['success'],
        'trufflehog': run_command('trufflehog --help')['success'],  # TruffleHog doesn't have --version
        'detect-secrets': run_command('detect-secrets --version')['success'],

        # Binary analysis tools (100% offline)
        'yara': run_command('yara --version')['success'],
        'strings': run_command('which strings')['success'],  # Check if strings command exists
        'file': run_command('file --version')['success'],
        'objdump': run_command('objdump --version')['success'],
        'nm': run_command('nm --version')['success']
    }

    # REMOVED INTERNET-DEPENDENT TOOLS FOR OPSEC COMPLIANCE:
    # - 'eslint': May download plugins/rules from npm
    # - 'trivy': Requires internet for vulnerability database updates
    # - 'snyk': Requires online account and uploads code hashes
    # - 'sonar-scanner': Requires server connection
    # - 'bearer': May download rules/updates
    # - 'horusec': May download rule updates

    return tools

def analyze_defensive_security(directory):
    """Run comprehensive defensive security analysis with optimized performance"""
    start_time = datetime.now()
    logger.info("🛡️ Starting FAST Defensive Security Analysis...")
    logger.info("Focus: Finding vulnerabilities in YOUR code that could be exploited")
    logger.info("⚡ Optimized for speed while maintaining security coverage\n")

    # Check tool availability
    logger.info("📋 Checking available security tools...")
    available_tools = check_tool_availability()
    available_count = sum(1 for available in available_tools.values() if available)
    total_count = len(available_tools)
    logger.info(f"📊 Found {available_count}/{total_count} security tools available")

    for tool, available in available_tools.items():
        status = "✅" if available else "❌"
        logger.info(f"  {status} {tool}")
    logger.info("")
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'directory': directory,
        'available_tools': available_tools,
        'scans': {}
    }

    # ===== FAST PATH: detect if target has source code =====
    source_present = has_source_files(directory)
    if source_present:
        logger.info("📝 Source code detected — running full SAST suite")
    else:
        logger.info("⚡ No source code found — skipping SAST tools (Semgrep, Bandit, etc.) for speed")

    # Run Python security scans with progress tracking
    scan_step = 1
    total_steps = 7  # Approximate number of scan steps

    if source_present and available_tools['bandit']:
        logger.info(f"[{scan_step}/{total_steps}] 🐍 Running Bandit (Python Security)...")
        scan_step += 1
        results['scans']['bandit'] = run_bandit_defensive(directory)

    if source_present and available_tools['semgrep']:
        logger.info(f"[{scan_step}/{total_steps}] 🔍 Running Semgrep (Multi-language Security)...")
        scan_step += 1
        results['scans']['semgrep'] = run_semgrep_defensive(directory)

    if source_present and available_tools['safety']:
        logger.info(f"[{scan_step}/{total_steps}] 📦 Running Safety (Offline Python Dependencies)...")
        scan_step += 1
        results['scans']['safety'] = run_safety_offline()

    # Run language-specific scans (OFFLINE ONLY) — source-only tools
    if source_present and available_tools['gosec']:
        logger.info("🐹 Running Gosec (Go Security)...")
        results['scans']['gosec'] = run_gosec_security(directory)

    if source_present and available_tools['flawfinder']:
        logger.info("⚡ Running Flawfinder (C/C++ Security)...")
        results['scans']['flawfinder'] = run_flawfinder_security(directory)

    if source_present and available_tools['cppcheck']:
        logger.info("🔧 Running Cppcheck (C/C++ Quality & Security)...")
        results['scans']['cppcheck'] = run_cppcheck_security(directory)

    # Run OFFLINE secrets detection tools only
    if available_tools['gitleaks']:
        logger.info("🔑 Running GitLeaks (Offline Secrets Detection)...")
        results['scans']['gitleaks'] = run_gitleaks_secrets(directory)

    if available_tools['trufflehog']:
        logger.info("🐷 Running TruffleHog (Offline Deep Secrets Scanning)...")
        results['scans']['trufflehog'] = run_trufflehog_secrets(directory)

    if available_tools['detect-secrets']:
        logger.info("🕵️ Running detect-secrets (Offline Enterprise Secrets Detection)...")
        results['scans']['detect_secrets'] = run_detect_secrets(directory)

    # REMOVED INTERNET-DEPENDENT TOOLS FOR OPSEC COMPLIANCE:
    # ❌ ESLint - May download plugins/rules from npm
    # ❌ Trivy - Requires internet for vulnerability database updates
    # ❌ Snyk - Requires online account and uploads code hashes
    # ❌ SonarQube - Requires server connection
    # ❌ Bearer - May download rules/updates
    # ❌ Horusec - May download rule updates
    logger.info("🔒 OPSEC-compliant: Using only offline security tools (no internet connectivity)")

    # Run custom analyzers IN PARALLEL for speed
    logger.info("⚡ Running 7 custom analyzers in parallel...")
    custom_analyzers = {
        'enhanced_secrets': ('🔍 Enhanced Secrets Detection', run_enhanced_secrets_detection),
        'information_disclosure': ('📋 Information Disclosure', run_information_disclosure_analysis),
        'memory_safety': ('🛡️ Memory Safety', run_memory_safety_analysis),
        'crypto_vulnerabilities': ('🔐 Crypto Vulnerabilities', run_crypto_vulnerability_analysis),
        'supply_chain': ('📦 Supply Chain', run_supply_chain_analysis),
        'opsec_analysis': ('🎯 OPSEC Analysis', run_opsec_analysis),
        'exploitation_analysis': ('⚔️ Exploitation Tool Security', run_exploitation_tool_analysis),
    }

    with ThreadPoolExecutor(max_workers=min(7, os.cpu_count() or 4)) as executor:
        future_to_key = {
            executor.submit(fn, directory): key
            for key, (label, fn) in custom_analyzers.items()
        }
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            label = custom_analyzers[key][0]
            try:
                results['scans'][key] = future.result()
                logger.info(f"   ✅ {label} complete")
            except Exception as e:
                logger.info(f"   ⚠️ {label} error: {e}")
                results['scans'][key] = []

    # ===== PHASE 1: technique-SPECIFIC SECURITY ANALYSIS =====
    logger.info("\n🚀 Phase 1: technique-Specific Security Analysis")

    # bytecode Security Scanner
    if SHELLCODE_SCANNER_AVAILABLE:
        logger.info("🔍 Running bytecode Security Scanner...")
        try:
            shellcode_results = scan_directory_for_shellcode(directory)
            results['scans']['shellcode_security'] = shellcode_results
            logger.info(f"   ✅ Found {len(shellcode_results)} files with bytecode")
        except Exception as e:
            logger.info(f"   ⚠️  bytecode scanner error: {str(e)}")
            results['scans']['shellcode_security'] = []
    else:
        logger.info("⚠️  bytecode Security Scanner not available")
        results['scans']['shellcode_security'] = []

    # technique Reliability Analyzer
    if EXPLOIT_ANALYZER_AVAILABLE:
        logger.info("🎯 Running technique Reliability Analyzer...")
        try:
            exploit_results = analyze_directory_for_exploits(directory)
            results['scans']['exploit_reliability'] = exploit_results
            logger.info(f"   ✅ Found {len(exploit_results)} files with technique code")
        except Exception as e:
            logger.info(f"   ⚠️  technique analyzer error: {str(e)}")
            results['scans']['exploit_reliability'] = []
    else:
        logger.info("⚠️  technique Reliability Analyzer not available")
        results['scans']['exploit_reliability'] = []

    # data Obfuscation Analyzer
    if PAYLOAD_ANALYZER_AVAILABLE:
        logger.info("🔐 Running data Obfuscation Analyzer...")
        try:
            payload_results = analyze_directory_for_payloads(directory)
            results['scans']['payload_obfuscation'] = payload_results
            logger.info(f"   ✅ Found {len(payload_results)} files with data code")
        except Exception as e:
            logger.info(f"   ⚠️  data analyzer error: {str(e)}")
            results['scans']['payload_obfuscation'] = []
    else:
        logger.info("⚠️  data Obfuscation Analyzer not available")
        results['scans']['payload_obfuscation'] = []

    # ===== PHASE 2: OPSEC & ATTRIBUTION ANALYSIS =====
    logger.info("\n🔐 Phase 2: OPSEC & Attribution Analysis")

    # Code Similarity Detector
    if CODE_SIMILARITY_AVAILABLE:
        logger.info("🔍 Running Code Similarity Detector...")
        try:
            similarity_results = analyze_directory_for_attribution(directory)
            results['scans']['code_similarity'] = similarity_results
            logger.info(f"   ✅ Found {len(similarity_results)} files with attribution risks")
        except Exception as e:
            logger.info(f"   ⚠️  Code similarity detector error: {str(e)}")
            results['scans']['code_similarity'] = []
    else:
        logger.info("⚠️  Code Similarity Detector not available")
        results['scans']['code_similarity'] = []

    # Metadata Leakage Scanner
    if METADATA_SCANNER_AVAILABLE:
        logger.info("🔎 Running Metadata Leakage Scanner...")
        try:
            metadata_results = analyze_directory_for_metadata(directory)
            results['scans']['metadata_leakage'] = metadata_results
            logger.info(f"   ✅ Found {len(metadata_results)} files with metadata leakage")
        except Exception as e:
            logger.info(f"   ⚠️  Metadata scanner error: {str(e)}")
            results['scans']['metadata_leakage'] = []
    else:
        logger.info("⚠️  Metadata Leakage Scanner not available")
        results['scans']['metadata_leakage'] = []

    # Network Traffic Analyzer
    if NETWORK_ANALYZER_AVAILABLE:
        logger.info("🌐 Running Network Traffic Analyzer...")
        try:
            network_results = analyze_directory_for_network(directory)
            results['scans']['network_security'] = network_results
            logger.info(f"   ✅ Found {len(network_results)} files with network security issues")
        except Exception as e:
            logger.info(f"   ⚠️  Network analyzer error: {str(e)}")
            results['scans']['network_security'] = []
    else:
        logger.info("⚠️  Network Traffic Analyzer not available")
        results['scans']['network_security'] = []

    # ===== PHASE 3: ADVANCED SECURITY ANALYSIS =====
    logger.info("\n🛡️ Phase 3: Advanced Security Analysis")

    # Anti-Analysis Validator
    if ANTI_ANALYSIS_AVAILABLE:
        logger.info("🔍 Running Anti-Analysis Validator...")
        try:
            anti_analysis_results = analyze_directory_for_anti_analysis(directory)
            results['scans']['anti_analysis'] = anti_analysis_results
            logger.info(f"   ✅ Found {len(anti_analysis_results)} files with anti-analysis code")
        except Exception as e:
            logger.info(f"   ⚠️  Anti-analysis validator error: {str(e)}")
            results['scans']['anti_analysis'] = []
    else:
        logger.info("⚠️  Anti-Analysis Validator not available")
        results['scans']['anti_analysis'] = []

    # Forensic Artifact Detector
    if FORENSIC_DETECTOR_AVAILABLE:
        logger.info("🔎 Running Forensic Artifact Detector...")
        try:
            forensic_results = analyze_directory_for_artifacts(directory)
            results['scans']['forensic_artifacts'] = forensic_results
            logger.info(f"   ✅ Found {len(forensic_results)} files creating forensic artifacts")
        except Exception as e:
            logger.info(f"   ⚠️  Forensic detector error: {str(e)}")
            results['scans']['forensic_artifacts'] = []
    else:
        logger.info("⚠️  Forensic Artifact Detector not available")
        results['scans']['forensic_artifacts'] = []

    # Privilege Escalation Analyzer
    if PRIVESC_ANALYZER_AVAILABLE:
        logger.info("⚡ Running Privilege Escalation Analyzer...")
        try:
            privesc_results = analyze_directory_for_privesc(directory)
            results['scans']['privilege_escalation'] = privesc_results
            logger.info(f"   ✅ Found {len(privesc_results)} files with privilege escalation code")
        except Exception as e:
            logger.info(f"   ⚠️  Privilege escalation analyzer error: {str(e)}")
            results['scans']['privilege_escalation'] = []
    else:
        logger.info("⚠️  Privilege Escalation Analyzer not available")
        results['scans']['privilege_escalation'] = []

    # ===== PHASE 4: YARA RULE GENERATION =====
    if YARA_GENERATOR_AVAILABLE:
        logger.info("\n📐 Phase 4: YARA Rule Generation")
        try:
            output_dir = os.path.join(directory, 'analysis_results')
            os.makedirs(output_dir, exist_ok=True)
            yara_path, yara_count = generate_yara_from_scan(
                results, output_dir, os.path.basename(directory)
            )
            results['yara_rules'] = {'path': yara_path, 'count': yara_count}
        except Exception as e:
            logger.info(f"   ⚠️  YARA generation error: {str(e)}")
            results['yara_rules'] = {'error': str(e)}
    else:
        logger.info("⚠️  YARA Rule Generator not available")

    # Calculate execution time
    end_time = datetime.now()
    execution_time = (end_time - start_time).total_seconds()
    results['execution_time'] = execution_time

    logger.info(f"\n🎉 Enhanced Defensive Security Analysis Complete!")
    logger.info(f"⏱️ Total execution time: {execution_time:.2f} seconds")
    logger.info(f"📊 Analysis results ready for report generation")

    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        logger.info("Usage: python defensive_security_scanner.py <directory> <project_name> [mode]")
        logger.info("  mode: 'combined_scan' to output JSON for merging with other scanners")
        sys.exit(1)

    directory = sys.argv[1]
    project_name = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else 'normal'

    if not os.path.exists(directory):
        logger.info(f"Error: Directory '{directory}' does not exist")
        sys.exit(1)

    # Run defensive security analysis
    results = analyze_defensive_security(directory)

    # If combined_scan mode, output JSON for merging
    if mode == 'combined_scan':
        logger.info(json.dumps(results))
        sys.exit(0)

    # Generate Enhanced report
    logger.info("\n📊 Generating Enhanced Defensive Security Report...")

    from comprehensive_report_generator import generate_comprehensive_report

    target_results_dir = os.path.join(directory, 'analysis_results')
    os.makedirs(target_results_dir, exist_ok=True)
    report_path = os.path.join(target_results_dir, f'{project_name}_defensive_security_report.html')

    html_content = generate_comprehensive_report(results)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    logger.info(f"🛡️ Defensive Security Analysis complete!")
    logger.info(f"📄 Report saved to: {report_path}")
