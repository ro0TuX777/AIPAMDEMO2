"""
BlueScrub Analyzers Package
All pattern-based security analyzers, each inheriting from BaseAnalyzer.
Also re-exports the 3 standalone class-based analyzers for a unified namespace.
"""

from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.opsec import OpsecAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.exploitation import ExploitationToolAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.secrets import SecretsAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.disclosure import InformationDisclosureAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.memory_safety import MemorySafetyAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.crypto import CryptoVulnerabilityAnalyzer
from backend.app.bluescrub.vendored.scanners.analyzers.supply_chain import SupplyChainAnalyzer

# Standalone class-based analyzers (now co-located in this package).
from backend.app.bluescrub.vendored.scanners.analyzers.exploit_reliability_analyzer import ExploitReliabilityAnalyzer, analyze_directory_for_exploits
from backend.app.bluescrub.vendored.scanners.analyzers.metadata_leakage_scanner import MetadataLeakageScanner, analyze_directory_for_metadata
from backend.app.bluescrub.vendored.scanners.analyzers.network_traffic_analyzer import NetworkTrafficAnalyzer, analyze_directory_for_network
from backend.app.bluescrub.vendored.scanners.analyzers.forensic_artifact_detector import ForensicArtifactDetector, analyze_directory_for_artifacts
from backend.app.bluescrub.vendored.scanners.analyzers.payload_obfuscation_analyzer import PayloadObfuscationAnalyzer, analyze_directory_for_payloads
from backend.app.bluescrub.vendored.scanners.analyzers.privilege_escalation_analyzer import PrivilegeEscalationAnalyzer, analyze_directory_for_privesc
from backend.app.bluescrub.vendored.scanners.analyzers.shellcode_security_scanner import ShellcodeSecurityScanner, scan_directory_for_shellcode
from backend.app.bluescrub.vendored.scanners.analyzers.code_similarity_detector import CodeSimilarityDetector, analyze_directory_for_attribution
from backend.app.bluescrub.vendored.scanners.analyzers.anti_analysis_validator import AntiAnalysisValidator, analyze_directory_for_anti_analysis

# Convenience wrappers — same signature as the old functional API so that
# ``defensive_security_scanner.py`` and ``scanners/__init__.py`` keep working.

def run_opsec_analysis(directory):
    return OpsecAnalyzer().run(directory)

def run_exploitation_tool_analysis(directory):
    return ExploitationToolAnalyzer().run(directory)

def run_enhanced_secrets_detection(directory):
    return SecretsAnalyzer().run(directory)

def run_information_disclosure_analysis(directory):
    return InformationDisclosureAnalyzer().run(directory)

def run_memory_safety_analysis(directory):
    return MemorySafetyAnalyzer().run(directory)

def run_crypto_vulnerability_analysis(directory):
    return CryptoVulnerabilityAnalyzer().run(directory)

def run_supply_chain_analysis(directory):
    return SupplyChainAnalyzer().run(directory)

__all__ = [
    'BaseAnalyzer',
    # Pattern-based analyzers (BaseAnalyzer subclasses)
    'OpsecAnalyzer',
    'ExploitationToolAnalyzer',
    'SecretsAnalyzer',
    'InformationDisclosureAnalyzer',
    'MemorySafetyAnalyzer',
    'CryptoVulnerabilityAnalyzer',
    'SupplyChainAnalyzer',
    # Standalone class-based analyzers
    'ExploitReliabilityAnalyzer',
    'MetadataLeakageScanner',
    'NetworkTrafficAnalyzer',
    'ForensicArtifactDetector',
    'PayloadObfuscationAnalyzer',
    'PrivilegeEscalationAnalyzer',
    'ShellcodeSecurityScanner',
    'CodeSimilarityDetector',
    'AntiAnalysisValidator',
    # Functional API
    'analyze_directory_for_exploits',
    'analyze_directory_for_metadata',
    'analyze_directory_for_network',
    'analyze_directory_for_artifacts',
    'analyze_directory_for_payloads',
    'analyze_directory_for_privesc',
    'scan_directory_for_shellcode',
    'analyze_directory_for_attribution',
    'analyze_directory_for_anti_analysis',
    'run_opsec_analysis',
    'run_exploitation_tool_analysis',
    'run_enhanced_secrets_detection',
    'run_information_disclosure_analysis',
    'run_memory_safety_analysis',
    'run_crypto_vulnerability_analysis',
    'run_supply_chain_analysis',
]

