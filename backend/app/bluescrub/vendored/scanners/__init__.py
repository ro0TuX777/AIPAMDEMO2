"""
BlueScrub Security Scanners Package
Extracted from defensive_security_scanner.py for modularity.
"""

from backend.app.bluescrub.vendored.scanners.custom_analyzers import (
    run_enhanced_secrets_detection,
    run_information_disclosure_analysis,
    run_memory_safety_analysis,
    run_crypto_vulnerability_analysis,
    run_supply_chain_analysis,
    run_opsec_analysis,
    run_exploitation_tool_analysis,
)

from backend.app.bluescrub.vendored.scanners.tool_wrappers import (
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
    run_grype_scan,
    run_checkov_scan,
    run_blint_scan,
    run_yara_scan,
)

__all__ = [
    'run_enhanced_secrets_detection',
    'run_information_disclosure_analysis',
    'run_memory_safety_analysis',
    'run_crypto_vulnerability_analysis',
    'run_supply_chain_analysis',
    'run_opsec_analysis',
    'run_exploitation_tool_analysis',
    'run_bandit_defensive',
    'run_semgrep_defensive',
    'run_safety_offline',
    'run_eslint_security',
    'run_gosec_security',
    'run_flawfinder_security',
    'run_cppcheck_security',
    'run_gitleaks_secrets',
    'run_trufflehog_secrets',
    'run_detect_secrets',
    'run_trivy_offline',
    'run_sonarqube_scan',
    'run_bearer_scan',
    'run_horusec_scan',
    'run_grype_scan',
    'run_checkov_scan',
    'run_blint_scan',
    'run_yara_scan',
]

