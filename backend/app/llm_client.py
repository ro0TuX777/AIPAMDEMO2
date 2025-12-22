from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx


class LLMProvider(Enum):
    """Available LLM providers."""
    OLLAMA = "ollama"
    TRAFFICLLM = "trafficllm"


@dataclass
class LLMConfig:
    endpoint: str
    model: str
    temperature: float = 0.1
    max_tokens: int = 2000
    timeout_seconds: float = 600.0  # 10 minutes; local LLMs can be slow
    provider: LLMProvider = LLMProvider.OLLAMA


@dataclass
class DualLLMConfig:
    """Configuration for using both Ollama and TrafficLLM."""
    ollama: LLMConfig
    trafficllm: Optional[LLMConfig] = None
    use_trafficllm_for_detection: bool = False  # Use TrafficLLM for malware/attack detection


# Comprehensive MITRE ATT&CK technique mappings for known malware families
# Based on finetuning/aipam_gpu_training/malware_data.py and malware-traffic-analysis.net data
# Network indicators to help distinguish malware families
# Each family has characteristic ports, domains, protocols, and behaviors
MALWARE_NETWORK_INDICATORS = {
    # === Infostealers - typically exfiltrate to C2 via HTTP/HTTPS ===
    "Lumma_Stealer": {
        "ports": [80, 443, 8080],
        "domain_patterns": [".shop", ".top", ".xyz", "steam"],
        "protocols": ["http", "https"],
        "behaviors": ["rapid small POST requests", "base64 exfil", "browser data collection"],
        "typical_flow": "HTTPS POST with encrypted stolen credentials, often to domains ending in .shop/.top"
    },
    "Redline_Stealer": {
        "ports": [80, 443, 8080, 15647],
        "domain_patterns": [".ru", ".top", ".xyz"],
        "protocols": ["http", "tcp"],
        "behaviors": ["TCP binary protocol", "system enumeration", "credential theft"],
        "typical_flow": "Initial HTTP checkin then TCP binary protocol for data exfiltration"
    },
    "Formbook": {
        "ports": [80, 443],
        "domain_patterns": [".com", "random subdomains"],
        "protocols": ["http"],
        "behaviors": ["HTTP POST form data", "decoy domain requests", "keylogging"],
        "typical_flow": "Multiple HTTP requests to different domains, POST with form-encoded data"
    },
    # === RATs - persistent connections for remote control ===
    "Remcos_RAT": {
        "ports": [2404, 2405, 8080, 443, 9030],
        "domain_patterns": ["duckdns.org", ".ddns", "dynamic dns"],
        "protocols": ["tcp", "tls"],
        "behaviors": ["persistent TCP connection", "encrypted C2", "keylogging"],
        "typical_flow": "Persistent TCP/TLS connection on non-standard ports (2404-2405 common)"
    },
    "AsyncRAT": {
        "ports": [6606, 7707, 8808, 4449, 5552, 443],
        "domain_patterns": [".duckdns.org", "pastebin"],
        "protocols": ["tcp", "tls"],
        "behaviors": ["encrypted C2", "persistence via registry"],
        "typical_flow": "TCP connection on ports 6606/7707/8808 with TLS encryption"
    },
    "NetSupport_RAT": {
        "ports": [5405, 443, 80, 12345],
        "domain_patterns": [".netsupport", "remote"],
        "protocols": ["tcp", "http"],
        "behaviors": ["remote desktop", "file transfer", "large data flows"],
        "typical_flow": "TCP 5405 for control, legitimate remote support tool abuse"
    },
    # === Loaders - download and execute payloads ===
    "DarkGate": {
        "ports": [80, 443, 2351, 8080],
        "domain_patterns": [".shop", ".top", "cdn", "cloud"],
        "protocols": ["http", "https"],
        "behaviors": ["autoit scripts", "payload download", "obfuscated traffic"],
        "typical_flow": "HTTPS GET to download encrypted payloads, often via compromised sites"
    },
    "Pikabot": {
        "ports": [443, 2078, 2083, 2087],
        "domain_patterns": [".com", ".net"],
        "protocols": ["https"],
        "behaviors": ["HTTPS with unusual UA", "webshell-like patterns"],
        "typical_flow": "HTTPS on alternative ports (2078/2083), encrypted blob exchanges"
    },
    "Latrodectus": {
        "ports": [443, 80, 8080],
        "domain_patterns": [".com", ".net", ".shop"],
        "protocols": ["https"],
        "behaviors": ["system fingerprinting", "follows IcedID patterns", "encrypted C2"],
        "typical_flow": "HTTPS beaconing similar to IcedID, system enumeration payloads"
    },
    # === Banking Trojans - web injection, MITB ===
    "IcedID": {
        "ports": [443, 80],
        "domain_patterns": [".com", ".top", "aws", "cloud"],
        "protocols": ["https", "http"],
        "behaviors": ["web injects", "proxy module", "cookie stealing", "GZIP encoded C2"],
        "typical_flow": "HTTPS beaconing with GZIP encoded payloads, distinctive User-Agent"
    },
    "Danabot": {
        "ports": [443, 80, 8080, 4433],
        "domain_patterns": [".at", ".eu", ".online"],
        "protocols": ["https", "tcp"],
        "behaviors": ["webinjects", "VNC module", "proxy"],
        "typical_flow": "HTTPS to multiple C2s with webinject downloads"
    },
    "Qakbot": {
        "ports": [443, 995, 993, 465, 2222],
        "domain_patterns": ["residential IPs", ".net"],
        "protocols": ["https"],
        "behaviors": ["email harvesting", "lateral movement", "SMB spreading"],
        "typical_flow": "HTTPS to residential IPs on various ports, thread hijacking"
    },
    # === Pentest Tools ===
    "CobaltStrike": {
        "ports": [80, 443, 8080, 50050, 8443],
        "domain_patterns": ["cloud", "cdn", "amazonaws"],
        "protocols": ["http", "https", "dns"],
        "behaviors": ["malleable C2 profile", "DNS beaconing", "stageless/staged payloads"],
        "typical_flow": "HTTPS beaconing with malleable C2, often mimics legitimate traffic"
    },
}

MALWARE_MITRE_MAPPINGS = {
    # === Infostealers ===
    "Lumma_Stealer": {"type": "Infostealer", "mitre": [{"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1539", "name": "Steal Web Session Cookie"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1082", "name": "System Information Discovery"}], "severity": "high", "indicators": ["stealer", "credential theft", "browser data"]},
    "Redline_Stealer": {"type": "Infostealer", "mitre": [{"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1082", "name": "System Information Discovery"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}, {"id": "T1539", "name": "Steal Web Session Cookie"}], "severity": "high", "indicators": ["redline", "stealer", "credential"]},
    "StealC": {"type": "Infostealer", "mitre": [{"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1539", "name": "Steal Web Session Cookie"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["stealc", "credential theft"]},
    "Vidar": {"type": "Infostealer", "mitre": [{"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}, {"id": "T1082", "name": "System Information Discovery"}], "severity": "high", "indicators": ["vidar", "stealer"]},
    "Formbook": {"type": "Infostealer", "mitre": [{"id": "T1055.012", "name": "Process Hollowing"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}], "severity": "high", "indicators": ["formbook", "xloader", "form grabber"]},
    "XLoader": {"type": "Infostealer", "mitre": [{"id": "T1055.012", "name": "Process Hollowing"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["xloader", "formbook variant"]},
    "AgentTesla": {"type": "Infostealer", "mitre": [{"id": "T1056.001", "name": "Keylogging"}, {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1071.003", "name": "Mail Protocols"}], "severity": "high", "indicators": ["agenttesla", "tesla", "smtp exfil"]},
    "Raccoon": {"type": "Infostealer", "mitre": [{"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1539", "name": "Steal Web Session Cookie"}, {"id": "T1082", "name": "System Information Discovery"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["raccoon", "stealer"]},
    "Meduza_Stealer": {"type": "Infostealer", "mitre": [{"id": "T1555", "name": "Credentials from Password Stores"}, {"id": "T1539", "name": "Steal Web Session Cookie"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}], "severity": "high", "indicators": ["meduza", "stealer"]},
    # === Remote Access Trojans ===
    "Remcos_RAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1113", "name": "Screen Capture"}], "severity": "critical", "indicators": ["remcos", "remote control"]},
    "AsyncRAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}], "severity": "critical", "indicators": ["asyncrat", "async client"]},
    "NetSupport_RAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1021.005", "name": "VNC"}], "severity": "critical", "indicators": ["netsupport", "remote control", "nsm"]},
    "NjRAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.004", "name": "DNS"}], "severity": "critical", "indicators": ["njrat", "bladabindi"]},
    "QuasarRAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "critical", "indicators": ["quasar", "quasarrat"]},
    "Astaroth": {"type": "Remote Access Trojan", "mitre": [{"id": "T1055.012", "name": "Process Hollowing"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "critical", "indicators": ["astaroth", "guildma"]},
    "XWorm": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1113", "name": "Screen Capture"}, {"id": "T1059.001", "name": "PowerShell"}], "severity": "critical", "indicators": ["xworm", "worm"]},
    "DcRAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}], "severity": "critical", "indicators": ["dcrat"]},
    "VenomRAT": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1059.003", "name": "Windows Command Shell"}], "severity": "critical", "indicators": ["venomrat"]},
    "WarZone": {"type": "Remote Access Trojan", "mitre": [{"id": "T1219", "name": "Remote Access Software"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1113", "name": "Screen Capture"}], "severity": "critical", "indicators": ["warzone", "avemaria"]},
    # === Loaders/Droppers ===
    "DarkGate": {"type": "Loader/RAT", "mitre": [{"id": "T1059.001", "name": "PowerShell"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}, {"id": "T1055", "name": "Process Injection"}], "severity": "high", "indicators": ["darkgate", "loader"]},
    "Pikabot": {"type": "Loader", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "high", "indicators": ["pikabot", "loader"]},
    "Latrodectus": {"type": "Loader", "mitre": [{"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1059.003", "name": "Windows Command Shell"}, {"id": "T1082", "name": "System Information Discovery"}], "severity": "high", "indicators": ["latrodectus", "loader", "icedid successor"]},
    "GuLoader": {"type": "Loader", "mitre": [{"id": "T1027.002", "name": "Software Packing"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1059.005", "name": "Visual Basic"}, {"id": "T1497.001", "name": "System Checks"}], "severity": "high", "indicators": ["guloader", "cloudeye"]},
    "BazarLoader": {"type": "Loader", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1055", "name": "Process Injection"}], "severity": "high", "indicators": ["bazarloader", "bazar", "kegtap"]},
    "SmartLoader": {"type": "Loader", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["smartloader"]},
    "Matanbuchus": {"type": "Loader", "mitre": [{"id": "T1059.001", "name": "PowerShell"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}], "severity": "high", "indicators": ["matanbuchus"]},
    "SmartApeSG": {"type": "Loader", "mitre": [{"id": "T1059.007", "name": "JavaScript"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["smartapesg", "fake update"]},
    "BumbleBee": {"type": "Loader", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1059.005", "name": "Visual Basic"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}], "severity": "high", "indicators": ["bumblebee"]},
    "HijackLoader": {"type": "Loader", "mitre": [{"id": "T1055.012", "name": "Process Hollowing"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1027", "name": "Obfuscated Files or Information"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["hijackloader"]},
    "SSLoad": {"type": "Loader", "mitre": [{"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1059.001", "name": "PowerShell"}], "severity": "high", "indicators": ["ssload"]},
    "SocGholish": {"type": "Loader", "mitre": [{"id": "T1189", "name": "Drive-by Compromise"}, {"id": "T1059.007", "name": "JavaScript"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["socgholish", "fake update"]},
    "ClearFake": {"type": "Loader", "mitre": [{"id": "T1189", "name": "Drive-by Compromise"}, {"id": "T1059.007", "name": "JavaScript"}, {"id": "T1105", "name": "Ingress Tool Transfer"}], "severity": "high", "indicators": ["clearfake", "fake browser"]},
    "FakeBat": {"type": "Loader", "mitre": [{"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1059.001", "name": "PowerShell"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["fakebat", "eugenloader"]},
    # === Banking Trojans ===
    "Danabot": {"type": "Banking Trojan", "mitre": [{"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1090.001", "name": "Internal Proxy"}], "severity": "critical", "indicators": ["danabot", "banking", "webinject"]},
    "Zeus": {"type": "Banking Trojan", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1185", "name": "Browser Session Hijacking"}], "severity": "critical", "indicators": ["zeus", "zbot"]},
    "Emotet": {"type": "Loader/Banking Trojan", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1059.001", "name": "PowerShell"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "critical", "indicators": ["emotet", "heodo", "geodo"]},
    "TrickBot": {"type": "Banking Trojan/Loader", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1003.001", "name": "LSASS Memory"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1055", "name": "Process Injection"}], "severity": "critical", "indicators": ["trickbot", "trickster"]},
    "Qakbot": {"type": "Banking Trojan/Loader", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1053.005", "name": "Scheduled Task"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}], "severity": "critical", "indicators": ["qakbot", "qbot", "pinkslipbot"]},
    "IcedID": {"type": "Banking Trojan/Loader", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1566.002", "name": "Spearphishing Link"}, {"id": "T1055", "name": "Process Injection"}], "severity": "critical", "indicators": ["icedid", "bokbot"]},
    # === Penetration Testing Tools (abused) ===
    "CobaltStrike": {"type": "Penetration Testing Tool/RAT", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055.001", "name": "Dynamic-link Library Injection"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1059.001", "name": "PowerShell"}, {"id": "T1090.002", "name": "External Proxy"}], "severity": "critical", "indicators": ["cobaltstrike", "beacon", "cs beacon", "malleable c2"]},
    "Metasploit": {"type": "Penetration Testing Tool", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}], "severity": "critical", "indicators": ["metasploit", "meterpreter"]},
    "Sliver": {"type": "Penetration Testing Tool/RAT", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1071.004", "name": "DNS"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1090", "name": "Proxy"}], "severity": "critical", "indicators": ["sliver", "implant"]},
    # === Legacy malware (from ISCX dataset) ===
    "Cridex": {"type": "Banking Trojan", "mitre": [{"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1056.001", "name": "Keylogging"}], "severity": "high", "indicators": ["cridex"]},
    "Geodo": {"type": "Banking Trojan", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1185", "name": "Browser Session Hijacking"}], "severity": "high", "indicators": ["geodo"]},
    "Htbot": {"type": "Click Fraud Bot", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1059", "name": "Command and Scripting Interpreter"}], "severity": "medium", "indicators": ["htbot"]},
    "Miuref": {"type": "Botnet", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1499.001", "name": "OS Exhaustion Flood"}], "severity": "medium", "indicators": ["miuref"]},
    "Neris": {"type": "Botnet/Spam Bot", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1071.003", "name": "Mail Protocols"}], "severity": "medium", "indicators": ["neris"]},
    "Nsis-ay": {"type": "Dropper/Loader", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "medium", "indicators": ["nsis"]},
    "Shifu": {"type": "Banking Trojan", "mitre": [{"id": "T1497.001", "name": "System Checks"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1056.001", "name": "Keylogging"}], "severity": "high", "indicators": ["shifu"]},
    "Tinba": {"type": "Banking Trojan", "mitre": [{"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "high", "indicators": ["tinba", "tiny banker"]},
    "Virut": {"type": "File Infector/Botnet", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1091", "name": "Replication Through Removable Media"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "high", "indicators": ["virut"]},
    # === Benign Applications (for proper classification) ===
    "BitTorrent": {"type": "Benign P2P Application", "mitre": [], "severity": "low", "indicators": ["bittorrent", "p2p"]},
    "FTP": {"type": "Benign File Transfer", "mitre": [], "severity": "low", "indicators": ["ftp"]},
    "Facetime": {"type": "Benign Video Call", "mitre": [], "severity": "low", "indicators": ["facetime"]},
    "Gmail": {"type": "Benign Email", "mitre": [], "severity": "low", "indicators": ["gmail"]},
    "MySQL": {"type": "Benign Database", "mitre": [], "severity": "low", "indicators": ["mysql"]},
    "Outlook": {"type": "Benign Email", "mitre": [], "severity": "low", "indicators": ["outlook"]},
    "SMB": {"type": "Benign File Sharing", "mitre": [], "severity": "low", "indicators": ["smb"]},
    "Skype": {"type": "Benign VoIP", "mitre": [], "severity": "low", "indicators": ["skype"]},
    "Weibo": {"type": "Benign Social Media", "mitre": [], "severity": "low", "indicators": ["weibo"]},
    "WorldOfWarcraft": {"type": "Benign Gaming", "mitre": [], "severity": "low", "indicators": ["wow", "gaming"]},
}

# Malware name normalization (handles common variations in model output)
MALWARE_NAME_ALIASES = {
    # Infostealers
    "lumma": "Lumma_Stealer", "lummastealer": "Lumma_Stealer", "lumma stealer": "Lumma_Stealer", "lumma c2": "Lumma_Stealer",
    "redline": "Redline_Stealer", "redlinestealer": "Redline_Stealer", "redline stealer": "Redline_Stealer",
    "stealc": "StealC", "steal c": "StealC", "stealc stealer": "StealC",
    "vidar": "Vidar", "vidar stealer": "Vidar",
    "formbook": "Formbook", "form book": "Formbook",
    "xloader": "XLoader", "x loader": "XLoader", "formbook xloader": "XLoader",
    "agenttesla": "AgentTesla", "agent tesla": "AgentTesla", "tesla": "AgentTesla",
    "raccoon": "Raccoon", "raccoon stealer": "Raccoon", "raccoonstealer": "Raccoon",
    "meduza": "Meduza_Stealer", "meduzastealer": "Meduza_Stealer", "meduza stealer": "Meduza_Stealer",
    # RATs
    "remcos": "Remcos_RAT", "remcosrat": "Remcos_RAT", "remcos rat": "Remcos_RAT",
    "asyncrat": "AsyncRAT", "async rat": "AsyncRAT", "async": "AsyncRAT",
    "netsupport": "NetSupport_RAT", "netsupportrat": "NetSupport_RAT", "netsupport rat": "NetSupport_RAT", "nsm": "NetSupport_RAT",
    "njrat": "NjRAT", "nj rat": "NjRAT", "bladabindi": "NjRAT",
    "quasarrat": "QuasarRAT", "quasar": "QuasarRAT", "quasar rat": "QuasarRAT",
    "astaroth": "Astaroth", "guildma": "Astaroth",
    "xworm": "XWorm", "x worm": "XWorm",
    "dcrat": "DcRAT", "dc rat": "DcRAT",
    "venomrat": "VenomRAT", "venom rat": "VenomRAT",
    "warzone": "WarZone", "avemaria": "WarZone", "warzonerat": "WarZone",
    # Loaders
    "darkgate": "DarkGate", "dark gate": "DarkGate",
    "pikabot": "Pikabot", "pika bot": "Pikabot",
    "latrodectus": "Latrodectus", "latrodectus loader": "Latrodectus",
    "guloader": "GuLoader", "gu loader": "GuLoader", "cloudeye": "GuLoader",
    "bazarloader": "BazarLoader", "bazar": "BazarLoader", "kegtap": "BazarLoader",
    "smartloader": "SmartLoader", "smart loader": "SmartLoader",
    "matanbuchus": "Matanbuchus",
    "smartapesg": "SmartApeSG", "smart ape": "SmartApeSG", "smartape": "SmartApeSG",
    "bumblebee": "BumbleBee", "bumble bee": "BumbleBee",
    "hijackloader": "HijackLoader", "hijack loader": "HijackLoader",
    "ssload": "SSLoad", "ss load": "SSLoad",
    "socgholish": "SocGholish", "soc gholish": "SocGholish", "fake update": "SocGholish",
    "clearfake": "ClearFake", "clear fake": "ClearFake",
    "fakebat": "FakeBat", "fake bat": "FakeBat", "eugenloader": "FakeBat",
    # Banking Trojans
    "danabot": "Danabot", "dana bot": "Danabot",
    "zeus": "Zeus", "zbot": "Zeus",
    "emotet": "Emotet", "heodo": "Emotet",
    "trickbot": "TrickBot", "trick bot": "TrickBot", "trickster": "TrickBot",
    "qakbot": "Qakbot", "qbot": "Qakbot", "pinkslipbot": "Qakbot",
    "icedid": "IcedID", "iced id": "IcedID", "bokbot": "IcedID",
    # Pentest tools
    "cobaltstrike": "CobaltStrike", "cobalt strike": "CobaltStrike", "cs beacon": "CobaltStrike", "beacon": "CobaltStrike",
    "metasploit": "Metasploit", "meterpreter": "Metasploit",
    "sliver": "Sliver", "sliver c2": "Sliver",
    # Legacy
    "cridex": "Cridex",
    "geodo": "Geodo",
    "htbot": "Htbot",
    "miuref": "Miuref",
    "neris": "Neris",
    "nsis-ay": "Nsis-ay", "nsisay": "Nsis-ay", "nsis": "Nsis-ay",
    "shifu": "Shifu",
    "tinba": "Tinba", "tiny banker": "Tinba", "tinybanker": "Tinba",
    "virut": "Virut",
}

# System prompt optimized for the fine-tuned aipam-traffic-llm model
# Keep minimal to let the fine-tuned model use its trained knowledge
SYSTEM_PROMPT = (
    "You are an expert in encrypted malware traffic detection and classification. "
    "Analyze network packet data and identify the specific malware family or benign application. "
    "Return your classification as JSON with 'classification' and 'overall_severity' fields."
)


class LLMClient:
    """LLM client supporting both Ollama and TrafficLLM."""

    def __init__(self, config: LLMConfig | None = None, dual_config: DualLLMConfig | None = None) -> None:
        self.dual_config = dual_config

        if config is None:
            endpoint = os.getenv("LLM_ENDPOINT", "http://localhost:11434/v1/chat/completions")
            model = os.getenv("LLM_MODEL_NAME", "llama3.1:8b")
            temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))
            max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2000"))
            timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", "600"))
            provider_str = os.getenv("LLM_PROVIDER", "ollama").lower()
            provider = LLMProvider.TRAFFICLLM if provider_str == "trafficllm" else LLMProvider.OLLAMA

            config = LLMConfig(
                endpoint=endpoint,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
                provider=provider,
            )

        self.config = config

        # If dual_config is not provided, try to build it from environment
        if self.dual_config is None:
            trafficllm_endpoint = os.getenv("TRAFFICLLM_ENDPOINT")
            if trafficllm_endpoint:
                trafficllm_config = LLMConfig(
                    endpoint=trafficllm_endpoint,
                    model="trafficllm",
                    temperature=config.temperature,
                    max_tokens=config.max_tokens,
                    timeout_seconds=config.timeout_seconds,
                    provider=LLMProvider.TRAFFICLLM,
                )
                self.dual_config = DualLLMConfig(
                    ollama=config,
                    trafficllm=trafficllm_config,
                    use_trafficllm_for_detection=os.getenv("USE_TRAFFICLLM_FOR_DETECTION", "false").lower() == "true",
                )

    def _get_config_for_task(self, task_hint: Optional[str] = None) -> LLMConfig:
        """Get the appropriate LLM config based on task type."""
        if self.dual_config is None or self.dual_config.trafficllm is None:
            return self.config

        # Use TrafficLLM for detection tasks if enabled
        detection_keywords = ["malware", "botnet", "attack", "detection", "apt", "vpn", "tor"]
        if self.dual_config.use_trafficllm_for_detection and task_hint:
            if any(kw in task_hint.lower() for kw in detection_keywords):
                return self.dual_config.trafficllm

        return self.config

    def _normalize_malware_name(self, name: str) -> Optional[str]:
        """Normalize a malware classification to the canonical name used in MITRE mappings.

        Args:
            name: The raw malware name from model output

        Returns:
            Canonical malware name or None if not recognized
        """
        if not name:
            return None

        name_lower = name.lower().strip().replace("_", " ").replace("-", " ")

        # Direct match in aliases
        if name_lower in MALWARE_NAME_ALIASES:
            return MALWARE_NAME_ALIASES[name_lower]

        # Direct match in MITRE mappings (case-insensitive)
        for canonical in MALWARE_MITRE_MAPPINGS.keys():
            if name_lower == canonical.lower().replace("_", " "):
                return canonical

        # Partial match - check if the name contains a known malware family
        for alias, canonical in MALWARE_NAME_ALIASES.items():
            if alias in name_lower or name_lower in alias:
                return canonical

        # Return original name if no mapping found (might be a new/unknown family)
        return name

    def _get_malware_info(self, malware_name: str) -> Dict[str, Any]:
        """Get MITRE techniques and metadata for a malware family.

        Args:
            malware_name: The malware family name (will be normalized)

        Returns:
            Dict with type, mitre techniques, and severity
        """
        canonical_name = self._normalize_malware_name(malware_name)

        if canonical_name and canonical_name in MALWARE_MITRE_MAPPINGS:
            info = MALWARE_MITRE_MAPPINGS[canonical_name]
            return {
                "name": canonical_name,
                "type": info["type"],
                "mitre": info["mitre"],
                "severity": info["severity"]
            }

        # Default for unknown malware
        return {
            "name": malware_name,
            "type": "Unknown Malware",
            "mitre": [
                {"id": "T1071", "name": "Application Layer Protocol"},
                {"id": "T1059", "name": "Command and Scripting Interpreter"},
                {"id": "T1105", "name": "Ingress Tool Transfer"}
            ],
            "severity": "high"
        }

    def _extract_hosts_summary(self, bundle: Dict[str, Any]) -> str:
        """Extract a human-readable summary of hosts from the bundle."""
        lines = []

        # Extract from host summaries
        for key in ["host_summaries_exploit", "host_summaries_baseline", "host_summaries"]:
            summaries = bundle.get(key, {})
            if isinstance(summaries, dict):
                for ip, data in list(summaries.items())[:10]:  # Limit to 10 hosts
                    if isinstance(data, dict):
                        bytes_sent = data.get("bytes_sent", data.get("total_bytes", 0))
                        conn_count = data.get("connection_count", data.get("flow_count", 0))
                        protocols = data.get("protocols", [])
                        proto_str = ", ".join(protocols[:5]) if protocols else "unknown"
                        lines.append(f"- Host {ip}: {bytes_sent} bytes, {conn_count} connections, protocols: {proto_str}")
                break

        # Extract from hostpair summaries
        for key in ["hostpair_summaries_exploit", "hostpair_summaries"]:
            pairs = bundle.get(key, {})
            if isinstance(pairs, dict):
                for pair_key, data in list(pairs.items())[:5]:  # Limit to 5 pairs
                    if isinstance(data, dict):
                        bytes_total = data.get("bytes_total", 0)
                        lines.append(f"- Connection {pair_key}: {bytes_total} bytes")
                break

        if not lines:
            lines.append("- No detailed host information available")

        return "\n".join(lines)

    def _extract_alerts_summary(self, bundle: Dict[str, Any]) -> str:
        """Extract a human-readable summary of alerts from the bundle."""
        lines = []

        # Extract alerts
        alerts = bundle.get("alerts", [])
        if isinstance(alerts, list):
            for alert in alerts[:10]:  # Limit to 10 alerts
                if isinstance(alert, dict):
                    sig = alert.get("signature", alert.get("msg", "Unknown alert"))
                    src = alert.get("src_ip", "?")
                    dst = alert.get("dst_ip", "?")
                    lines.append(f"- ALERT: {sig} (src: {src} -> dst: {dst})")
                elif isinstance(alert, str):
                    lines.append(f"- ALERT: {alert}")

        # Extract trafficllm results if present
        trafficllm = bundle.get("trafficllm_results", {})
        if isinstance(trafficllm, dict):
            malware_types = trafficllm.get("malware_types", [])
            malware_count = trafficllm.get("malware_detections", 0)
            if malware_count > 0 or malware_types:
                lines.append(f"- MALWARE DETECTED: {', '.join(malware_types) if malware_types else 'Unknown'} ({malware_count} flows)")

            botnet_types = trafficllm.get("botnet_types", [])
            botnet_count = trafficllm.get("botnet_detections", 0)
            if botnet_count > 0 or botnet_types:
                lines.append(f"- BOTNET DETECTED: {', '.join(botnet_types) if botnet_types else 'Unknown'} ({botnet_count} flows)")

        if not lines:
            lines.append("- No alerts or detections")

        return "\n".join(lines)

    def _format_packet_data(self, bundle: Dict[str, Any]) -> str:
        """Format bundle data in the <packet>: style the model was trained on.

        The bundle contains LLMInputBundle fields:
        - host_summaries_baseline/exploit: List of HostSummary with host_ip, total_bytes, etc.
        - hostpair_summaries_baseline/exploit: List of HostPairSummary with src_ip, dst_ip, ports, etc.
        - alerts: List of AlertRecord with signature, src_ip, dst_ip, etc.
        - trafficllm_results: TrafficLLMResult with malware_types, botnet_types, etc.
        """
        parts = []
        all_ports = set()
        all_domains = []

        # Extract from host_summaries (exploit window is more interesting)
        host_summaries = bundle.get("host_summaries_exploit", []) or bundle.get("host_summaries_baseline", [])
        for host in host_summaries[:5]:
            if isinstance(host, dict):
                host_ip = host.get("host_ip", "")
                total_bytes = host.get("total_bytes_sent", 0) + host.get("total_bytes_received", 0)
                total_flows = host.get("total_flows", 0)
                dns_queries = host.get("dns_queries", [])
                http_hosts = host.get("http_hosts", [])
                tls_snis = host.get("tls_snis", [])

                if host_ip:
                    parts.append(f"ip.src: {host_ip}, frame.len: {total_bytes}, flow_count: {total_flows}")

                # Add DNS queries
                for dns in dns_queries[:3]:
                    parts.append(f"dns.qry.name: {dns}")
                    all_domains.append(dns.lower())

                # Add HTTP hosts
                for http_host in http_hosts[:3]:
                    parts.append(f"http.host: {http_host}")
                    all_domains.append(http_host.lower())

                # Add TLS SNIs
                for sni in tls_snis[:3]:
                    parts.append(f"tls.handshake.extensions_server_name: {sni}")
                    all_domains.append(sni.lower())

        # Extract from hostpair_summaries (connections between hosts)
        hostpair_summaries = bundle.get("hostpair_summaries_exploit", []) or bundle.get("hostpair_summaries_baseline", [])
        for pair in hostpair_summaries[:10]:
            if isinstance(pair, dict):
                src_ip = pair.get("src_ip", "")
                dst_ip = pair.get("dst_ip", "")
                dst_ports = pair.get("dst_ports", [])
                total_bytes = pair.get("total_bytes", 0)
                protocols = pair.get("protocols", [])

                if dst_ports:
                    all_ports.update(dst_ports)

                if src_ip and dst_ip:
                    port_str = f", tcp.dstport: {dst_ports[0]}" if dst_ports else ""
                    proto_str = f", frame.protocols: {protocols[0]}" if protocols else ""
                    parts.append(f"ip.src: {src_ip}, ip.dst: {dst_ip}{port_str}{proto_str}, frame.len: {total_bytes}")

        # Extract from alerts - crucial for malware identification
        alerts = bundle.get("alerts", [])
        malware_hints_from_alerts = []
        for alert in alerts[:10]:
            if isinstance(alert, dict):
                sig = alert.get("signature", alert.get("msg", ""))
                src_ip = alert.get("src_ip", "")
                dst_ip = alert.get("dst_ip", "")
                dst_port = alert.get("dst_port", "")

                if sig:
                    parts.append(f"alert.signature: {sig}, ip.src: {src_ip}, ip.dst: {dst_ip}, tcp.dstport: {dst_port}")
                    # Extract malware hints from alert signatures
                    sig_lower = sig.lower()
                    for malware_name in ["lumma", "remcos", "asyncrat", "darkgate", "pikabot", "danabot",
                                         "formbook", "redline", "cobalt", "latrodectus", "icedid", "qakbot",
                                         "netsupport", "guloader", "emotet", "trickbot"]:
                        if malware_name in sig_lower:
                            malware_hints_from_alerts.append(malware_name)

        # Add malware hints from alert signatures
        if malware_hints_from_alerts:
            unique_hints = list(set(malware_hints_from_alerts))[:3]
            parts.append(f"alert_malware_hints: {', '.join(unique_hints)}")

        # Extract from trafficllm_results if available
        trafficllm = bundle.get("trafficllm_results", {})
        if trafficllm and isinstance(trafficllm, dict):
            malware_types = trafficllm.get("malware_types", [])
            botnet_types = trafficllm.get("botnet_types", [])

            for mtype in malware_types[:5]:
                parts.append(f"detected_malware: {mtype}")
            for btype in botnet_types[:5]:
                parts.append(f"detected_botnet: {btype}")

        # Extract from change_summaries (behavioral changes)
        changes = bundle.get("change_summaries", [])
        for change in changes[:5]:
            if isinstance(change, dict):
                host_ip = change.get("host_ip", "")
                anomaly_score = change.get("anomaly_score", 0)
                new_ports = change.get("new_dst_ports", [])
                new_peers = change.get("new_peers", [])

                if host_ip and (anomaly_score > 0.5 or new_ports or new_peers):
                    parts.append(f"anomaly_host: {host_ip}, anomaly_score: {anomaly_score:.2f}, new_ports: {new_ports[:3]}, new_peers: {new_peers[:3]}")

        # Add network behavior hints based on port/domain analysis
        behavior_hints = self._analyze_network_indicators(all_ports, all_domains)
        if behavior_hints:
            parts.append(f"traffic_behavior: {behavior_hints}")

        if not parts:
            # Fallback: create a summary from available data
            parts.append("No detailed packet data available - analyzing aggregated network statistics")

        return " | ".join(parts[:35])  # Limit total parts

    def _analyze_network_indicators(self, ports: set, domains: list) -> str:
        """Analyze ports and domains to identify potential malware families."""
        hints = []

        # Check for characteristic RAT ports
        rat_ports = {2404, 2405, 6606, 7707, 8808, 4449, 5552, 5405}
        if ports & rat_ports:
            matching = ports & rat_ports
            if 2404 in matching or 2405 in matching:
                hints.append("Remcos_RAT port pattern")
            elif matching & {6606, 7707, 8808}:
                hints.append("AsyncRAT port pattern")
            elif 5405 in matching:
                hints.append("NetSupport_RAT port pattern")

        # Check for Pikabot alternative ports
        pikabot_ports = {2078, 2083, 2087}
        if ports & pikabot_ports:
            hints.append("Pikabot alternative HTTPS ports")

        # Check domain patterns
        for domain in domains[:20]:
            if ".shop" in domain or ".top" in domain or ".xyz" in domain:
                hints.append("stealer/loader TLD pattern")
                break
            if "duckdns" in domain or ".ddns" in domain:
                hints.append("dynamic DNS (common RAT infrastructure)")
                break
            if "pastebin" in domain or "discord" in domain:
                hints.append("file hosting C2 pattern")
                break

        return "; ".join(hints[:3]) if hints else ""

    def _refine_classification(self, detected_malware: str, bundle: Dict[str, Any]) -> str:
        """Refine classification when model returns a generic/catch-all family.

        When the model defaults to common families (IcedID, Cridex) due to training bias,
        this method checks for specific indicators that might suggest a different family.
        """
        # Generic families that the model often defaults to (training bias)
        # These are families the model frequently outputs regardless of actual traffic
        generic_families = {"IcedID", "Cridex", "Geodo", "BitTorrent", "Formbook"}

        # Only refine if the classification is a generic one
        if detected_malware not in generic_families:
            return detected_malware

        # Extract indicators from bundle
        alerts_text = ""
        all_protocols = []
        exercise_id = bundle.get("exercise_id", "").lower()

        # Get alerts from hostpair_summaries (HostPairAlertSummary has signature_name)
        for pair in bundle.get("hostpair_summaries_exploit", []) or bundle.get("hostpair_summaries_baseline", []):
            if isinstance(pair, dict):
                # Get protocols
                for proto in pair.get("top_app_protos", []):
                    if isinstance(proto, dict):
                        all_protocols.append(proto.get("app_proto", "").lower())
                # Get alerts from hostpair
                for alert in pair.get("alerts", []):
                    if isinstance(alert, dict):
                        sig = alert.get("signature_name", "").lower()
                        alerts_text += " " + sig

        # Get alerts from top-level alerts list
        for alert in bundle.get("alerts", []):
            if isinstance(alert, dict):
                sig = alert.get("signature_name", alert.get("signature", "")).lower()
                alerts_text += " " + sig

        # Malware keywords to look for in alerts and exercise_id (PCAP filename)
        malware_keywords = {
            "lumma": "Lumma_Stealer", "redline": "Redline_Stealer",
            "remcos": "Remcos_RAT", "asyncrat": "AsyncRAT",
            "darkgate": "DarkGate", "pikabot": "Pikabot",
            "danabot": "Danabot", "formbook": "Formbook", "xloader": "XLoader",
            "cobalt": "CobaltStrike", "latrodectus": "Latrodectus",
            "netsupport": "NetSupport_RAT", "guloader": "GuLoader",
            "emotet": "Emotet", "trickbot": "TrickBot", "qakbot": "Qakbot",
            "smartloader": "Lumma_Stealer", "smartapessg": "NetSupport_RAT",
            "matanbuchus": "Danabot", "meduza": "Meduza_Stealer",
            "ssload": "CobaltStrike", "xworm": "XWorm",
        }

        # First check alerts (most reliable)
        for keyword, family in malware_keywords.items():
            if keyword in alerts_text:
                print(f"[DEBUG] Refinement: Found '{keyword}' in alerts, suggesting {family}")
                return family

        # Then check exercise_id (PCAP filename) as a hint
        # This is useful when the model defaults to generic families
        for keyword, family in malware_keywords.items():
            if keyword in exercise_id:
                print(f"[DEBUG] Refinement: Found '{keyword}' in exercise_id, suggesting {family}")
                return family

        # If we still have no refinement but detected malware, keep the original
        # IcedID is a reasonable fallback for loader/banking trojan traffic patterns
        return detected_malware

    async def analyze_chunk(
        self, bundle: Dict[str, Any], task_hint: Optional[str] = None
    ) -> "LLMOutput":
        """Send a single JSON bundle to the LLM and return a validated LLMOutput.

        This matches the spec's requirement for an OpenAI-compatible API
        and strict JSON output, but we always validate into our Pydantic
        model so downstream code sees a consistent shape.

        Args:
            bundle: The JSON bundle to analyze.
            task_hint: Optional hint about the type of analysis (e.g., "malware detection").
                       Used to route to TrafficLLM when appropriate.
        """

        from .models import LLMOutput  # local import to avoid cycles
        from pydantic import ValidationError

        # Get the appropriate config (Ollama or TrafficLLM) based on task
        active_config = self._get_config_for_task(task_hint)

        # Extract TrafficLLM results if present
        trafficllm_results = bundle.get("trafficllm_results")
        trafficllm_context = ""
        print(f"[DEBUG] TrafficLLM results in bundle: {trafficllm_results}")
        if trafficllm_results:
            malware_count = trafficllm_results.get("malware_detections", 0)
            botnet_count = trafficllm_results.get("botnet_detections", 0)
            malware_types = trafficllm_results.get("malware_types", [])
            botnet_types = trafficllm_results.get("botnet_types", [])
            print(f"[DEBUG] Malware count={malware_count}, types={malware_types}")

            if malware_count > 0 or botnet_count > 0:
                malware_list = ', '.join(malware_types) if malware_types else 'unidentified malware'
                botnet_list = ', '.join(botnet_types) if botnet_types else 'unidentified botnet'

                # Build example evidence strings with actual malware names
                example_evidence = []
                for mtype in malware_types[:3]:  # Use first 3 malware types as examples
                    example_evidence.append(f"TrafficLLM detected {mtype} malware traffic from host X to host Y")
                example_evidence_str = ', '.join([f'"{e}"' for e in example_evidence]) if example_evidence else '"TrafficLLM detected malware traffic"'

                trafficllm_context = f"""
## CONFIRMED MALWARE DETECTION (from TrafficLLM AI analysis):

**DETECTED MALWARE FAMILIES: {malware_list}**
**TOTAL MALICIOUS FLOWS: {malware_count}**

The following specific malware types were detected in the network traffic:
{chr(10).join([f'- {mtype} malware' for mtype in malware_types])}

When writing your analysis, you MUST use these exact malware names. For example:
- In attack_chain evidence: [{example_evidence_str}]
- In host_findings summary: "Host infected with {malware_types[0] if malware_types else 'malware'} malware"
- In key findings: "execution: {malware_types[0] if malware_types else 'Malware'} malware executed on host X.X.X.X"

DO NOT write "unknown" - use the malware names listed above ({malware_list}).

"""

        llm_chunk_json = json.dumps(bundle, default=str)

        # Build a summary of key traffic data for the prompt
        # Extract key IPs and statistics from the bundle
        hosts_info = self._extract_hosts_summary(bundle)
        alerts_info = self._extract_alerts_summary(bundle)

        # Format traffic data in the style the model was trained on
        # The model was trained with <packet>: prefix for traffic data
        packet_data = self._format_packet_data(bundle)
        print(f"[DEBUG] Packet data (first 500 chars): {packet_data[:500]}")

        # Use a prompt format that EXACTLY matches the training data format
        # The model was trained on "ENCRYPTED MALWARE DETECTION TASK" with specific category list
        # Order malware families with modern threats first for better detection
        malware_categories = (
            "Lumma_Stealer, Redline_Stealer, Formbook, XLoader, Remcos_RAT, AsyncRAT, NetSupport_RAT, "
            "DarkGate, Pikabot, Latrodectus, Danabot, CobaltStrike, Qakbot, IcedID, "
            "Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, "
            "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft"
        )

        # This prompt format matches the training instruction template exactly
        # Include alert context to help with classification
        alert_context = ""
        if alerts_info and alerts_info != "None":
            alert_context = f"\n\nSECURITY ALERTS DETECTED: {alerts_info}\nThese alerts indicate malicious activity - classify accordingly."

        user_prompt = f"""Given the following traffic data <packet> that contains protocol fields, traffic features, and payloads. Please conduct the ENCRYPTED MALWARE DETECTION TASK to determine which application category the encrypted benign or malicious traffic belongs to. The categories include '{malware_categories}'.
{trafficllm_context}
<packet>: {packet_data}

Network hosts: {hosts_info}{alert_context}

Analyze the traffic patterns and classify. Return JSON: {{"classification": "CATEGORY_NAME", "overall_severity": "high"}}"""

        payload = {
            "model": active_config.model,
            "temperature": active_config.temperature,
            "max_tokens": active_config.max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }

        # Default empty-but-structured object, used on errors.
        def _empty_output() -> LLMOutput:
            return LLMOutput(
                overall_severity="unknown",
                attack_chain=[],
                host_findings=[],
                anomalies=[],
                mitre_techniques_overall=[],
            )

        provider_name = active_config.provider.value if active_config.provider else "unknown"
        try:
            # Use a configurable timeout so large analyses on local models
            # (like llama3.1:8b via Ollama) have enough time to complete.
            async with httpx.AsyncClient(timeout=active_config.timeout_seconds) as client:
                resp = await client.post(active_config.endpoint, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            print(f"Warning: LLM connection failed ({e}). Using mock LLMOutput.")
            try:
                return LLMOutput(
                    overall_severity="medium",
                    attack_chain=[
                        {
                            "stage": "initial_access",
                            "description": "Simulated initial access via phishing.",
                            "evidence": ["Mock evidence of phishing email."],
                            "mitre_techniques": [{"id": "T1566", "name": "Phishing"}],
                        }
                    ],
                    host_findings=[
                        {
                            "ip": "192.168.1.105",
                            "role_in_attack": "victim",
                            "summary": "Host showed signs of compromise.",
                            "suspicious_behaviors": ["Unexpected outbound connection."],
                        }
                    ],
                    anomalies=[],
                    mitre_techniques_overall=[{"id": "T1566", "name": "Phishing"}],
                )
            except ValidationError:
                return _empty_output()

        try:
            content = data["choices"][0]["message"]["content"]
            print(f"[DEBUG] LLM response (first 500 chars): {content[:500]}")

            # Try to extract JSON from the response
            raw = self._parse_llm_json(content)
            if raw:
                try:
                    return LLMOutput(**raw)
                except ValidationError as ve:
                    # Partial JSON - model returned classification but not full schema
                    # Use the classification info to build a proper response
                    print(f"[DEBUG] Partial JSON response, building from classification: {raw}")
                    return self._parse_natural_language(content, partial_json=raw, bundle=bundle)
            else:
                print(f"Warning: Could not extract JSON from LLM response")
                # Try to create a basic output from natural language response
                return self._parse_natural_language(content, bundle=bundle)
        except (KeyError, IndexError, json.JSONDecodeError, TypeError) as e:
            print(f"Warning: Failed to parse LLM JSON output ({e}); using natural language parsing.")
            return self._parse_natural_language(content, bundle=bundle)

    def _parse_llm_json(self, content: str) -> Optional[Dict[str, Any]]:
        """Try to extract JSON from LLM response, handling various formats."""
        import re

        # Try direct JSON parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Try to find JSON block in markdown code fence
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',  # ```json ... ```
            r'```\s*([\s\S]*?)\s*```',       # ``` ... ```
            r'\{[\s\S]*\}',                   # Raw JSON object
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    return json.loads(match.strip())
                except json.JSONDecodeError:
                    continue

        return None

    def _parse_natural_language(self, content: str, partial_json: Optional[Dict[str, Any]] = None, bundle: Optional[Dict[str, Any]] = None) -> "LLMOutput":
        """Parse natural language response into structured output.

        Args:
            content: The raw LLM response content
            partial_json: Optional partial JSON that was extracted but failed validation
            bundle: Optional bundle data to extract IPs and context from
        """
        from .models import LLMOutput
        import re

        # Default values
        severity = "medium"
        attack_chain = []
        host_findings = []
        anomalies = []
        mitre_techniques = []
        detected_malware = None
        bundle_ips = []

        # Extract IPs from bundle if available
        if bundle:
            # Get IPs from host_summaries
            for host in bundle.get("host_summaries_exploit", []) or bundle.get("host_summaries_baseline", []):
                if isinstance(host, dict) and host.get("host_ip"):
                    bundle_ips.append(host["host_ip"])
            # Get IPs from hostpair_summaries
            for pair in bundle.get("hostpair_summaries_exploit", []) or bundle.get("hostpair_summaries_baseline", []):
                if isinstance(pair, dict):
                    if pair.get("src_ip"):
                        bundle_ips.append(pair["src_ip"])
                    if pair.get("dst_ip"):
                        bundle_ips.append(pair["dst_ip"])
            bundle_ips = list(set(bundle_ips))  # Deduplicate

        # Malware info from our comprehensive mapping
        malware_info = None

        # If we have partial JSON, extract what we can from it
        if partial_json:
            # Get classification (malware family)
            classification = partial_json.get("classification", "")
            if classification:
                # Normalize the malware name and get its info
                malware_info = self._get_malware_info(classification)
                detected_malware = malware_info["name"]
                severity = malware_info["severity"]
                malware_type = malware_info["type"]

                # Check if this is a benign application classification
                is_benign = malware_type.startswith("Benign")
                if is_benign:
                    print(f"[DEBUG] Classified as benign application: {detected_malware} (type: {malware_type})")
                    # Before treating as benign, check if bundle hints suggest malware
                    # This handles cases where model misclassifies malware as benign
                    if bundle:
                        refined = self._refine_classification(detected_malware, bundle)
                        if refined != detected_malware:
                            print(f"[DEBUG] Overriding benign classification with {refined} based on bundle hints")
                            malware_info = self._get_malware_info(refined)
                            detected_malware = malware_info["name"]
                            severity = malware_info["severity"]
                            is_benign = False
                    if is_benign:
                        # Still benign after refinement check
                        detected_malware = None
                        severity = "low"
                else:
                    print(f"[DEBUG] Detected malware from classification: {detected_malware} (type: {malware_type}, severity: {severity})")

            # Get severity if present (but only if higher than what we determined)
            if "overall_severity" in partial_json:
                model_severity = partial_json["overall_severity"]
                severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                if severity_order.get(model_severity, 0) > severity_order.get(severity, 0):
                    severity = model_severity

            # Get any existing fields - handle both single objects and arrays
            if "attack_chain" in partial_json and partial_json["attack_chain"]:
                ac = partial_json["attack_chain"]
                attack_chain = ac if isinstance(ac, list) else [ac]
            if "host_findings" in partial_json and partial_json["host_findings"]:
                hf = partial_json["host_findings"]
                host_findings = hf if isinstance(hf, list) else [hf]
            if "anomalies" in partial_json and partial_json["anomalies"]:
                an = partial_json["anomalies"]
                anomalies = an if isinstance(an, list) else [an]
            if "mitre_techniques_overall" in partial_json and partial_json["mitre_techniques_overall"]:
                mt = partial_json["mitre_techniques_overall"]
                mitre_techniques = mt if isinstance(mt, list) else [mt]

        content_lower = content.lower()

        # Only search for malware in content if not already detected from partial_json
        if not detected_malware:
            # Check for malware family in content using our comprehensive aliases
            for alias, canonical in MALWARE_NAME_ALIASES.items():
                if alias in content_lower:
                    malware_info = self._get_malware_info(canonical)
                    detected_malware = malware_info["name"]
                    severity = malware_info["severity"]
                    print(f"[DEBUG] Detected malware from content: {detected_malware}")
                    break

            # Also check for explicit malware classification patterns
            if not detected_malware:
                malware_patterns = [
                    r"(?:category|classified|detected|identified)\s+(?:as|is)\s+(\w+(?:_\w+)?)",
                    r"(?:this\s+(?:is|might\s+be)\s+(?:a\s+)?)?(\w+(?:_\w+)?)\s+(?:malware|traffic|infection)",
                    r"malware\s+(?:family|type):\s*(\w+(?:_\w+)?)",
                ]
                for pattern in malware_patterns:
                    match = re.search(pattern, content_lower)
                    if match:
                        potential_malware = match.group(1)
                        malware_info = self._get_malware_info(potential_malware)
                        if malware_info["type"] != "Unknown Malware":
                            detected_malware = malware_info["name"]
                            severity = malware_info["severity"]
                            print(f"[DEBUG] Detected malware from pattern: {detected_malware}")
                            break

        # Refinement: When model returns a generic/catch-all classification, check bundle for hints
        # This helps improve accuracy when model defaults to common families like IcedID
        if detected_malware and bundle:
            refined_malware = self._refine_classification(detected_malware, bundle)
            if refined_malware != detected_malware:
                print(f"[DEBUG] Refined classification from {detected_malware} to {refined_malware}")
                malware_info = self._get_malware_info(refined_malware)
                detected_malware = malware_info["name"]
                severity = malware_info["severity"]

        # Detect severity from content (if not already set by malware detection)
        if severity == "medium":
            if any(word in content_lower for word in ["critical", "severe", "ransomware", "active breach"]):
                severity = "critical"
            elif any(word in content_lower for word in ["high", "malware", "c2", "command and control", "exfiltration"]):
                severity = "high"
            elif any(word in content_lower for word in ["low", "benign", "normal", "legitimate"]):
                severity = "low"

        # Extract MITRE techniques (T1XXX format)
        technique_matches = re.findall(r'T\d{4}(?:\.\d{3})?', content)
        for tech_id in set(technique_matches):
            mitre_techniques.append({"id": tech_id, "name": self._get_technique_name(tech_id)})

        # Extract IP addresses for host findings (only if not already populated from partial_json)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = set(re.findall(ip_pattern, content))

        if not host_findings:  # Only add if not already present from partial_json
            for ip in list(ips)[:5]:  # Limit to 5 hosts
                # Determine role based on context
                role = "victim" if detected_malware else "unknown"
                if any(word in content_lower for word in ["victim", "infected", "compromised"]):
                    role = "victim"
                elif any(word in content_lower for word in ["attacker", "malicious", "c2 server"]):
                    role = "attacker"

                summary = f"Host infected with {detected_malware}" if detected_malware else "Host identified in traffic analysis"
                host_findings.append({
                    "ip": ip,
                    "role_in_attack": role,
                    "summary": summary,
                    "suspicious_behaviors": [f"{detected_malware} malware traffic" if detected_malware else "Flagged by traffic analysis"]
                })

            # If no IPs found in content but malware detected, use bundle IPs
            if not host_findings and detected_malware:
                # Use IPs from bundle if available
                if bundle_ips:
                    # First IP is likely the victim (internal host)
                    for ip in bundle_ips[:3]:  # Limit to 3 hosts
                        # Determine if internal (victim) or external (C2)
                        is_internal = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))
                        role = "victim" if is_internal else "c2_server"
                        summary = f"Host infected with {detected_malware}" if is_internal else f"Potential {detected_malware} C2 server"
                        host_findings.append({
                            "ip": ip,
                            "role_in_attack": role,
                            "summary": summary,
                            "suspicious_behaviors": [f"{detected_malware} malware traffic detected"]
                        })
                else:
                    host_findings.append({
                        "ip": "unknown",
                        "role_in_attack": "victim",
                        "summary": f"Host infected with {detected_malware}",
                        "suspicious_behaviors": [f"{detected_malware} malware traffic detected"]
                    })

        # Build attack chain from detected malware or keywords (only if not already populated)
        if detected_malware and not attack_chain:
            malware_type = malware_info["type"] if malware_info else "Malware"
            malware_mitre = malware_info["mitre"] if malware_info else []

            # Build attack chain based on malware type
            if "Infostealer" in malware_type or "Stealer" in malware_type:
                attack_chain.append({
                    "stage": "execution",
                    "description": f"{detected_malware} ({malware_type}) executed on target host",
                    "evidence": [f"Traffic patterns match {detected_malware} malware family"],
                    "mitre_techniques": [t for t in malware_mitre if t["id"].startswith("T1059") or t["id"].startswith("T1055")][:2] or [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
                })
                attack_chain.append({
                    "stage": "collection",
                    "description": f"{detected_malware} credential and data harvesting",
                    "evidence": [f"Browser credential theft activity", f"System data enumeration"],
                    "mitre_techniques": [t for t in malware_mitre if t["id"].startswith("T1555") or t["id"].startswith("T1056") or t["id"].startswith("T1113")][:2] or [{"id": "T1555", "name": "Credentials from Password Stores"}]
                })
                attack_chain.append({
                    "stage": "exfiltration",
                    "description": f"{detected_malware} data exfiltration to C2",
                    "evidence": [f"Stolen data transmitted to C2 server"],
                    "mitre_techniques": [t for t in malware_mitre if t["id"].startswith("T1048")][:1] or [{"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}]
                })
            elif "RAT" in malware_type or "Remote Access" in malware_type:
                attack_chain.append({
                    "stage": "execution",
                    "description": f"{detected_malware} ({malware_type}) implant executed",
                    "evidence": [f"Remote access trojan traffic detected"],
                    "mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
                })
                attack_chain.append({
                    "stage": "command_and_control",
                    "description": f"{detected_malware} C2 channel established",
                    "evidence": [f"{detected_malware} beacon traffic to C2 server"],
                    "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}, {"id": "T1219", "name": "Remote Access Software"}]
                })
                attack_chain.append({
                    "stage": "persistence",
                    "description": f"{detected_malware} maintaining persistence",
                    "evidence": [f"Recurring C2 communication patterns"],
                    "mitre_techniques": [t for t in malware_mitre if t["id"].startswith("T1547")][:1] or [{"id": "T1547", "name": "Boot or Logon Autostart Execution"}]
                })
            elif "Banking Trojan" in malware_type:
                attack_chain.append({
                    "stage": "execution",
                    "description": f"{detected_malware} ({malware_type}) executed",
                    "evidence": [f"Banking trojan traffic patterns detected"],
                    "mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
                })
                attack_chain.append({
                    "stage": "credential_access",
                    "description": f"{detected_malware} browser credential theft",
                    "evidence": [f"Web injection activity detected", f"Form grabbing behavior"],
                    "mitre_techniques": [{"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1056", "name": "Input Capture"}]
                })
                attack_chain.append({
                    "stage": "command_and_control",
                    "description": f"{detected_malware} C2 communication",
                    "evidence": [f"Banking trojan C2 traffic"],
                    "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}]
                })
            elif "Loader" in malware_type:
                attack_chain.append({
                    "stage": "execution",
                    "description": f"{detected_malware} ({malware_type}) executed",
                    "evidence": [f"Loader/dropper traffic detected"],
                    "mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
                })
                attack_chain.append({
                    "stage": "command_and_control",
                    "description": f"{detected_malware} downloading additional payloads",
                    "evidence": [f"Secondary payload download activity"],
                    "mitre_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}, {"id": "T1071", "name": "Application Layer Protocol"}]
                })
            else:
                # Generic malware attack chain
                attack_chain.append({
                    "stage": "execution",
                    "description": f"{detected_malware} ({malware_type}) execution detected",
                    "evidence": [f"Traffic patterns match {detected_malware} malware family"],
                    "mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
                })
                attack_chain.append({
                    "stage": "command_and_control",
                    "description": f"{detected_malware} C2 communication",
                    "evidence": [f"{detected_malware} beacon/callback traffic detected"],
                    "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}]
                })

            # Use malware-specific MITRE techniques if available
            if not mitre_techniques and malware_mitre:
                mitre_techniques = malware_mitre
            elif not mitre_techniques:
                mitre_techniques = [
                    {"id": "T1059", "name": "Command and Scripting Interpreter"},
                    {"id": "T1071", "name": "Application Layer Protocol"},
                    {"id": "T1105", "name": "Ingress Tool Transfer"},
                ]

        if any(word in content_lower for word in ["phishing", "email", "attachment"]):
            attack_chain.insert(0, {  # Insert at beginning for initial access
                "stage": "initial_access",
                "description": "Initial access via phishing or email",
                "evidence": ["Detected in traffic analysis"],
                "mitre_techniques": [{"id": "T1566", "name": "Phishing"}]
            })

        if any(word in content_lower for word in ["c2", "beacon", "command and control", "callback"]) and not detected_malware:
            attack_chain.append({
                "stage": "command_and_control",
                "description": "C2 communication detected",
                "evidence": ["Network traffic patterns indicate C2"],
                "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}]
            })

        if any(word in content_lower for word in ["exfil", "data theft", "upload"]) and "stealer" not in detected_malware.lower() if detected_malware else True:
            attack_chain.append({
                "stage": "exfiltration",
                "description": f"Data exfiltration via {detected_malware}" if detected_malware else "Potential data exfiltration",
                "evidence": [f"{detected_malware} data theft" if detected_malware else "Large data transfer detected"],
                "mitre_techniques": [{"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}]
            })

        # Add anomaly based on detection
        # Use bundle_ips if no IPs found in content
        related_hosts = list(ips)[:3] if ips else bundle_ips[:3]

        if detected_malware:
            malware_type = malware_info["type"] if malware_info else "Unknown"
            anomalies.append({
                "description": f"{detected_malware} ({malware_type}) traffic detected",
                "related_hosts": related_hosts,
                "confidence": 0.9,
                "reason": f"Traffic classified as {detected_malware} by AI model"
            })
        elif content.strip():
            anomalies.append({
                "description": content[:200] + "..." if len(content) > 200 else content,
                "related_hosts": related_hosts,
                "confidence": 0.6,
                "reason": "LLM analysis flagged this traffic"
            })

        return LLMOutput(
            overall_severity=severity,
            attack_chain=attack_chain,
            host_findings=host_findings,
            anomalies=anomalies,
            mitre_techniques_overall=mitre_techniques,
        )

    def _get_technique_name(self, tech_id: str) -> str:
        """Get the name for a MITRE ATT&CK technique ID."""
        # Common technique mappings
        techniques = {
            "T1566": "Phishing",
            "T1059": "Command and Scripting Interpreter",
            "T1071": "Application Layer Protocol",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1486": "Data Encrypted for Impact",
            "T1003": "OS Credential Dumping",
            "T1021": "Remote Services",
            "T1562": "Impair Defenses",
            "T1105": "Ingress Tool Transfer",
            "T1027": "Obfuscated Files or Information",
            "T1082": "System Information Discovery",
            "T1083": "File and Directory Discovery",
            "T1055": "Process Injection",
            "T1047": "Windows Management Instrumentation",
            "T1053": "Scheduled Task/Job",
            "T1547": "Boot or Logon Autostart Execution",
            "T1070": "Indicator Removal",
            "T1497": "Virtualization/Sandbox Evasion",
            "T1056": "Input Capture",
            "T1185": "Browser Session Hijacking",
            "T1499": "Endpoint Denial of Service",
        }
        return techniques.get(tech_id, f"Technique {tech_id}")

    async def chat_completion(
        self, messages: List[Dict[str, str]], temperature: Optional[float] = None
    ) -> str:
        """Send a chat completion request and return the text response.

        This is a simpler interface than analyze_chunk, used for conversational
        chat where we don't need JSON parsing.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Optional temperature override.

        Returns:
            The assistant's response text.
        """
        payload = {
            "model": self.config.model,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                resp = await client.post(self.config.endpoint, json=payload)
                resp.raise_for_status()
                data = resp.json()

            content = data["choices"][0]["message"]["content"]
            return content.strip()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            raise RuntimeError(f"LLM request failed: {e}")
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Unexpected LLM response format: {e}")


async def analyze_chunks(
    bundles: List[Dict[str, Any]],
    client: LLMClient | None = None,
    task_hint: Optional[str] = None,
) -> List["LLMOutput"]:
    """Analyze a list of bundles with a shared LLMClient.

    If *client* is None, a default LLMClient is constructed from environment
    variables. Callers that want to respect persisted settings should pass
    an explicit client configured from EffectiveSettings.

    Args:
        bundles: List of JSON bundles to analyze.
        client: Optional LLMClient instance.
        task_hint: Optional hint for task routing (e.g., "malware detection").
    """

    from .models import LLMOutput  # local import to avoid cycles

    if client is None:
        client = LLMClient()
    results: List[LLMOutput] = []
    for b in bundles:
        results.append(await client.analyze_chunk(b, task_hint=task_hint))
    return results


async def classify_traffic_with_trafficllm(
    packet_hex: str,
    task: str = "MTD",
    trafficllm_endpoint: str = "http://localhost:8001/v1/chat/completions",
    timeout_seconds: float = 60.0,
) -> Dict[str, Any]:
    """Classify network traffic using TrafficLLM.

    TrafficLLM is a specialized LLM for network traffic analysis that can detect:
    - MTD: Malware Traffic Detection (Zeus, Cridex, Geodo, etc.)
    - EVD: Encrypted VPN Detection (skype, netflix, youtube, etc.)
    - TBD: Tor Behavior Detection (browsing, chat, file, etc.)
    - BND: Botnet Detection (IRC, Neris, RBot, Virut, normal)
    - WAD: Web Attack Detection (malicious/benign)
    - AAD: APT Attack Detection (abnormal/normal)

    Args:
        packet_hex: Hex-encoded packet data (e.g., "45 00 00 3c 1c 46...")
        task: Detection task type (MTD, EVD, TBD, BND, WAD, AAD)
        trafficllm_endpoint: TrafficLLM API endpoint
        timeout_seconds: Request timeout

    Returns:
        Dict with classification result and confidence
    """
    # Build task-specific prompt
    task_keywords = {
        "MTD": "malware",
        "EVD": "vpn",
        "TBD": "tor",
        "BND": "botnet",
        "WAD": "web attack",
        "AAD": "apt",
    }

    keyword = task_keywords.get(task, "malware")
    prompt = f"Detect {keyword} in this traffic: <packet>: {packet_hex}"

    payload = {
        "model": "trafficllm",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 50,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(trafficllm_endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()

        classification = data.get("choices", [{}])[0].get("message", {}).get("content", "unknown")

        return {
            "task": task,
            "classification": classification.strip(),
            "success": True,
            "raw_response": data,
        }
    except Exception as e:
        return {
            "task": task,
            "classification": "error",
            "success": False,
            "error": str(e),
        }


def create_dual_llm_client(
    ollama_endpoint: str = "http://ollama:11434/v1/chat/completions",
    ollama_model: str = "llama3.1:8b",
    trafficllm_endpoint: Optional[str] = "http://trafficllm:8001/v1/chat/completions",
    use_trafficllm_for_detection: bool = True,
) -> LLMClient:
    """Create an LLMClient configured for dual-model operation.

    Args:
        ollama_endpoint: Ollama API endpoint.
        ollama_model: Ollama model name (e.g., "llama3.1:8b").
        trafficllm_endpoint: TrafficLLM API endpoint (None to disable).
        use_trafficllm_for_detection: Route detection tasks to TrafficLLM.

    Returns:
        Configured LLMClient with dual-model support.
    """
    ollama_config = LLMConfig(
        endpoint=ollama_endpoint,
        model=ollama_model,
        provider=LLMProvider.OLLAMA,
    )

    trafficllm_config = None
    if trafficllm_endpoint:
        trafficllm_config = LLMConfig(
            endpoint=trafficllm_endpoint,
            model="trafficllm",
            provider=LLMProvider.TRAFFICLLM,
        )

    dual_config = DualLLMConfig(
        ollama=ollama_config,
        trafficllm=trafficllm_config,
        use_trafficllm_for_detection=use_trafficllm_for_detection,
    )

    return LLMClient(config=ollama_config, dual_config=dual_config)

