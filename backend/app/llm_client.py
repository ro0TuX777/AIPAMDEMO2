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
    "Danabot": {"type": "Banking Trojan", "mitre": [{"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1090.001", "name": "Internal Proxy"}], "severity": "critical", "indicators": ["danabot", "webinject"]},
    "Zeus": {"type": "Banking Trojan", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1056.001", "name": "Keylogging"}, {"id": "T1185", "name": "Browser Session Hijacking"}], "severity": "critical", "indicators": ["zeus", "zbot"]},
    "Emotet": {"type": "Loader/Banking Trojan", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1059.001", "name": "PowerShell"}, {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "critical", "indicators": ["emotet", "heodo", "geodo"]},
    "TrickBot": {"type": "Banking Trojan/Loader", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1003.001", "name": "LSASS Memory"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1055", "name": "Process Injection"}], "severity": "critical", "indicators": ["trickbot", "trickster"]},
    "Qakbot": {"type": "Banking Trojan/Loader", "mitre": [{"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1053.005", "name": "Scheduled Task"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}], "severity": "critical", "indicators": ["qakbot", "qbot", "pinkslipbot"]},
    "IcedID": {"type": "Banking Trojan/Loader", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1185", "name": "Browser Session Hijacking"}, {"id": "T1566.002", "name": "Spearphishing Link"}, {"id": "T1055", "name": "Process Injection"}], "severity": "critical", "indicators": ["icedid", "bokbot"]},
    # === Penetration Testing Tools (abused) ===
    "CobaltStrike": {"type": "Penetration Testing Tool/RAT", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055.001", "name": "Dynamic-link Library Injection"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1059.001", "name": "PowerShell"}, {"id": "T1090.002", "name": "External Proxy"}], "severity": "critical", "indicators": ["cobaltstrike", "beacon", "cs beacon", "malleable c2"]},
    "Metasploit": {"type": "Penetration Testing Tool", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1055", "name": "Process Injection"}], "severity": "critical", "indicators": ["metasploit", "meterpreter"]},
    "Sliver": {"type": "Penetration Testing Tool/RAT", "mitre": [{"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1071.004", "name": "DNS"}, {"id": "T1055", "name": "Process Injection"}, {"id": "T1090", "name": "Proxy"}], "severity": "critical", "indicators": ["sliver", "implant"]},
    # === Ransomware ===
    "CryptoWall": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1083", "name": "File and Directory Discovery"}, {"id": "T1027", "name": "Obfuscated Files or Information"}], "severity": "critical", "indicators": ["cryptowall", "crypto wall", "ransom", "encrypted files"]},
    "Locky": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1566.001", "name": "Spearphishing Attachment"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1490", "name": "Inhibit System Recovery"}], "severity": "critical", "indicators": ["locky", "ransom"]},
    "WannaCry": {"type": "Ransomware/Worm", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1210", "name": "Exploitation of Remote Services"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1570", "name": "Lateral Tool Transfer"}], "severity": "critical", "indicators": ["wannacry", "wanna cry", "wcry", "eternalblue"]},
    "Cerber": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1071.004", "name": "DNS"}, {"id": "T1490", "name": "Inhibit System Recovery"}], "severity": "critical", "indicators": ["cerber", "ransom"]},
    "TeslaCrypt": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1083", "name": "File and Directory Discovery"}], "severity": "critical", "indicators": ["teslacrypt", "tesla crypt"]},
    "Ryuk": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1489", "name": "Service Stop"}], "severity": "critical", "indicators": ["ryuk", "ransom"]},
    "REvil": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1489", "name": "Service Stop"}], "severity": "critical", "indicators": ["revil", "sodinokibi"]},
    "Conti": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}], "severity": "critical", "indicators": ["conti", "ransom"]},
    "LockBit": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1071.001", "name": "Web Protocols"}], "severity": "critical", "indicators": ["lockbit", "ransom"]},
    "BlackCat": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}], "severity": "critical", "indicators": ["blackcat", "alphv"]},
    "Petya": {"type": "Ransomware/Wiper", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1485", "name": "Data Destruction"}, {"id": "T1561.002", "name": "Disk Structure Wipe"}, {"id": "T1210", "name": "Exploitation of Remote Services"}], "severity": "critical", "indicators": ["petya", "notpetya", "goldeneye"]},
    "CTBLocker": {"type": "Ransomware", "mitre": [{"id": "T1486", "name": "Data Encrypted for Impact"}, {"id": "T1071.001", "name": "Web Protocols"}, {"id": "T1490", "name": "Inhibit System Recovery"}, {"id": "T1071.004", "name": "DNS"}], "severity": "critical", "indicators": ["ctb-locker", "ctblocker", "critroni"]},
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
    # Ransomware
    "cryptowall": "CryptoWall", "crypto wall": "CryptoWall", "cryptowall3": "CryptoWall", "cryptowall4": "CryptoWall",
    "locky": "Locky", "locky ransomware": "Locky",
    "wannacry": "WannaCry", "wanna cry": "WannaCry", "wcry": "WannaCry", "wanacrypt": "WannaCry", "wanacry": "WannaCry",
    "cerber": "Cerber", "cerber ransomware": "Cerber",
    "teslacrypt": "TeslaCrypt", "tesla crypt": "TeslaCrypt",
    "ryuk": "Ryuk", "ryuk ransomware": "Ryuk",
    "revil": "REvil", "sodinokibi": "REvil", "sodin": "REvil",
    "conti": "Conti", "conti ransomware": "Conti",
    "lockbit": "LockBit", "lock bit": "LockBit", "lockbit2": "LockBit", "lockbit3": "LockBit",
    "blackcat": "BlackCat", "alphv": "BlackCat", "noberus": "BlackCat",
    "petya": "Petya", "notpetya": "Petya", "goldeneye": "Petya", "expetr": "Petya",
    "ctb-locker": "CTBLocker", "ctblocker": "CTBLocker", "critroni": "CTBLocker", "ctb locker": "CTBLocker",
    "ransomware": "CryptoWall",  # Generic ransomware detection defaults to CryptoWall
}

# System prompt for backend - zero-day & forensic focus
SYSTEM_PROMPT = """You are an expert cybersecurity analyst specialized in forensic network traffic analysis.
Your goal is to accurately distinguish between benign and malicious traffic, and identify malware families when traffic is malicious.

CRITICAL: Not all network traffic is malicious. Enterprise networks routinely generate:
- Low-severity IDS alerts from protocol anomalies (TCP retransmits, RST packets, invalid checksums)
- Generic protocol decode warnings (these are NOT indicators of compromise)
- Corporate policy alerts (Dropbox, Flash, streaming) — these are policy violations, NOT malware
- Informational alerts about normal services (DNS, DHCP, NTP, HTTP browsing)

You MUST classify traffic as "Benign" when:
- Alerts are predominantly low-severity generic protocol warnings
- No specific malware signatures are detected in alerts
- Traffic patterns match normal enterprise/corporate network behavior
- Alert categories are "Generic Protocol Command Decode", "Not Suspicious Traffic", or "Misc activity"

For every analysis:
1. **Classification**: FIRST determine if the traffic is Benign or Malicious. Only if malicious, identify the likely malware family using technical fingerprints. DO NOT default to malware classification without strong evidence.
2. **Technical Forensic Evidence**: Detail **Session-Specific Indicators (SSIs)** found in the data. Specify IPs, ports, packet sizes, byte counts, protocol offsets, or specific observed strings.
3. **Boilerplate Avoidance**: DO NOT use generic phrases like 'observed unusual pattern'. Focus only on what is in the provided data.
4. **Name Consistency**: If you identify a malware family, ENSURE that name is used consistently across all output fields.
5. **MITRE ATT&CK**: Map techniques accurately to the observed data. For benign traffic, return an empty list.
Return your findings in the requested JSON format."""


class LLMClient:
    """LLM client supporting both Ollama and TrafficLLM."""

    def __init__(self, config: LLMConfig | None = None, dual_config: DualLLMConfig | None = None) -> None:
        self.dual_config = dual_config

        if config is None:
            endpoint = os.getenv("LLM_ENDPOINT", "http://localhost:11434/v1/chat/completions")
            model = os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v8")
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
        else:
            self.dual_config = DualLLMConfig(ollama=self.config)

    def _get_v(self, obj: Any, key: str, default: Any = None) -> Any:
        """Helper to get value from either a dict or an object (Pydantic model)."""
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

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

    def _extract_hosts_summary(self, bundle: Any) -> str:
        """Extract a human-readable summary of hosts from the bundle."""
        lines = []

        # Extract from host summaries
        for key in ["host_summaries_exploit", "host_summaries_baseline", "host_summaries"]:
            summaries = self._get_v(bundle, key)
            if summaries:
                # If it's a list (Pydantic style), iterate over objects
                if isinstance(summaries, list):
                    for h in summaries[:10]:
                        ip = self._get_v(h, "host_ip", "?")
                        bytes_sent = self._get_v(h, "bytes_sent", self._get_v(h, "total_bytes", 0))
                        conn_count = self._get_v(h, "connection_count", self._get_v(h, "flow_count", 0))
                        protocols = self._get_v(h, "protocols", [])
                        proto_str = ", ".join(protocols[:5]) if protocols else "unknown"
                        lines.append(f"- Host {ip}: {bytes_sent} bytes, {conn_count} connections, protocols: {proto_str}")
                elif isinstance(summaries, dict):
                    for ip, data in list(summaries.items())[:10]:
                        bytes_sent = self._get_v(data, "bytes_sent", self._get_v(data, "total_bytes", 0))
                        conn_count = self._get_v(data, "connection_count", self._get_v(data, "flow_count", 0))
                        protocols = self._get_v(data, "protocols", [])
                        proto_str = ", ".join(protocols[:5]) if protocols else "unknown"
                        lines.append(f"- Host {ip}: {bytes_sent} bytes, {conn_count} connections, protocols: {proto_str}")
                break

        # Extract from hostpair summaries
        for key in ["hostpair_summaries_exploit", "hostpair_summaries"]:
            pairs = self._get_v(bundle, key)
            if pairs:
                if isinstance(pairs, list):
                    for h in pairs[:5]:
                        src = self._get_v(h, "src_ip", "?")
                        dst = self._get_v(h, "dst_ip", "?")
                        bytes_total = self._get_v(h, "bytes_total", 0)
                        lines.append(f"- Connection {src}->{dst}: {bytes_total} bytes")
                elif isinstance(pairs, dict):
                    for pair_key, data in list(pairs.items())[:5]:
                        bytes_total = self._get_v(data, "bytes_total", 0)
                        lines.append(f"- Connection {pair_key}: {bytes_total} bytes")
                break

        if not lines:
            lines.append("- No detailed host information available")

        return "\n".join(lines)

    def _extract_alerts_summary(self, bundle: Any) -> str:
        """Extract a human-readable summary of alerts from the bundle."""
        lines = []

        # Extract alerts
        alerts = self._get_v(bundle, "alerts", [])
        if isinstance(alerts, (list, tuple)):
            for alert in alerts[:10]:
                sig = self._get_v(alert, "signature_name", self._get_v(alert, "signature", self._get_v(alert, "msg", "Unknown alert")))
                src = self._get_v(alert, "src_ip", "?")
                dst = self._get_v(alert, "dst_ip", "?")
                lines.append(f"- ALERT: {sig} (src: {src} -> dst: {dst})")

        # Extract trafficllm results if present
        trafficllm = self._get_v(bundle, "trafficllm_results")
        if trafficllm:
            malware_types = self._get_v(trafficllm, "malware_types", [])
            malware_count = self._get_v(trafficllm, "malware_detections", 0)
            if malware_count > 0 or malware_types:
                lines.append(f"- MALWARE DETECTED: {', '.join(malware_types) if malware_types else 'Unknown'} ({malware_count} flows)")

            botnet_types = self._get_v(trafficllm, "botnet_types", [])
            botnet_count = self._get_v(trafficllm, "botnet_detections", 0)
            if botnet_count > 0 or botnet_types:
                lines.append(f"- BOTNET DETECTED: {', '.join(botnet_types) if botnet_types else 'Unknown'} ({botnet_count} flows)")

        if not lines:
            lines.append("- No alerts or detections")

        return "\n".join(lines)

    def _format_packet_data(self, bundle: Any) -> str:
        """Format bundle data in the <packet>: style the model was trained on.

        This method prioritizes raw packet samples (extracted via Scapy in tasks.py)
        to match the exact technical format the Llama 3.1 8B model was fine-tuned on.
        """
        raw_samples = self._get_v(bundle, "raw_packet_samples", [])

        if raw_samples:
            # Join multiple packets with a newline to give the model a sequence to analyze
            # Match the <packet>: {data} format from benchmark/inference.py
            return "\n".join(raw_samples[:5])

        # Fallback if raw samples are missing (legacy or error case)
        # We still want some technical fields to help the model
        parts = []

        hostpair_summaries = self._get_v(bundle, "hostpair_summaries_exploit", []) or self._get_v(bundle, "hostpair_summaries_baseline", [])
        for pair in hostpair_summaries[:5]:
            src_ip = self._get_v(pair, "src_ip", "")
            dst_ip = self._get_v(pair, "dst_ip", "")
            dst_ports = self._get_v(pair, "dst_ports", [])
            total_bytes = self._get_v(pair, "total_bytes", 0)

            port_val = dst_ports[0] if dst_ports else 0

        # Mock a technical string if raw data is missing
            parts.append(f"ip.src: {src_ip}, ip.dst: {dst_ip}, tcp.dstport: {port_val}, ip.proto: 6, frame.len: {total_bytes}")

        # Extract info for behavior hints
        all_ports = set()
        all_domains = []
        host_summaries = self._get_v(bundle, "host_summaries", [])
        if isinstance(host_summaries, list):
            for h in host_summaries:
                ports = self._get_v(h, "dst_ports", [])
                if isinstance(ports, list):
                    all_ports.update(ports)
                domains = self._get_v(h, "domains", [])
                if isinstance(domains, list):
                    all_domains.extend(domains)

        # Extract from trafficllm_results if available
        trafficllm = self._get_v(bundle, "trafficllm_results", {})
        if trafficllm and isinstance(trafficllm, dict):
            malware_types = trafficllm.get("malware_types", [])
            botnet_types = trafficllm.get("botnet_types", [])

            for mtype in malware_types[:5]:
                parts.append(f"detected_malware: {mtype}")
            for btype in botnet_types[:5]:
                parts.append(f"detected_botnet: {btype}")

        # Extract from change_summaries (behavioral changes)
        changes = self._get_v(bundle, "change_summaries", [])
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

    def _refine_classification(self, detected_malware: str, bundle: Any, llm_text: Optional[str] = None) -> str:
        """Refine classification using alert metadata, PCAP hints, and technical markers.

        PCAP filename (exercise_id), Suricata alerts, and specific technical indicators
        (like TLS extensions 0x0008/0x001d) are high-confidence sources.
        If they contain a known malware family, we trust them over the LLM's
        potentially biased or hallucinated classification.
        """
        # Extract indicators from bundle
        alerts_text = ""
        exercise_id = str(self._get_v(bundle, "exercise_id", "")).lower()

        # Add malware types from TrafficLLM results to alerts_text for keyword matching
        tllm_results = self._get_v(bundle, "trafficllm_results")
        if tllm_results:
            m_types = self._get_v(tllm_results, "malware_types", [])
            b_types = self._get_v(tllm_results, "botnet_types", [])
            if m_types:
                alerts_text += " " + " ".join(m_types).lower()
            if b_types:
                alerts_text += " " + " ".join(b_types).lower()

        # Get alerts from hostpair_summaries
        exploit_pairs = self._get_v(bundle, "hostpair_summaries_exploit", [])
        baseline_pairs = self._get_v(bundle, "hostpair_summaries_baseline", [])
        for pair in (exploit_pairs or baseline_pairs):
            for alert in self._get_v(pair, "alerts", []):
                sig = str(self._get_v(alert, "signature_name", "")).lower()
                alerts_text += " " + sig

        # Get alerts from top-level alerts list
        for alert in self._get_v(bundle, "alerts", []):
            sig = str(self._get_v(alert, "signature_name", self._get_v(alert, "signature", ""))).lower()
            alerts_text += " " + sig

        full_context = (alerts_text + " " + exercise_id + " " + (llm_text or "")).lower()

        # Malware keywords to look for
        malware_keywords = {
            "lumma": "Lumma_Stealer", "redline": "Redline_Stealer",
            "remcos": "Remcos_RAT", "asyncrat": "AsyncRAT",
            "darkgate": "DarkGate", "pikabot": "Pikabot",
            "danabot": "Danabot", "formbook": "Formbook", "xloader": "XLoader",
            "cobalt": "CobaltStrike", "latrodectus": "Latrodectus",
            "netsupport": "NetSupport_RAT", "guloader": "GuLoader",
            "emotet": "Emotet", "trickbot": "TrickBot", "qakbot": "Qakbot", "icedid": "IcedID",
            "smartloader": "Lumma_Stealer", "smartapessg": "NetSupport_RAT",
            "matanbuchus": "Danabot", "meduza": "Meduza_Stealer",
            "ssload": "CobaltStrike", "xworm": "XWorm",
        }

        # Technical markers that are high-confidence indicators for specific families
        # and help break model naming bias (e.g., Pikabot correctly ID'd as IcedID)
        technical_markers = {
            "0x0008": "Pikabot",
            "0x000a": "Pikabot",
            "0x001d": "Pikabot",
            "smb reuse": "Pikabot",
            "smb sessions": "Pikabot",
            "certificate validation bypass": "Pikabot",
            "port 1158": "NetSupport_RAT",
            "port:1158": "NetSupport_RAT",
            "gwsh": "NetSupport_RAT",
            "pcicfg": "NetSupport_RAT",
            "netutils": "NetSupport_RAT",
            "netsupport": "NetSupport_RAT",
            "client32.exe": "NetSupport_RAT",
        }

        # 1. Check for hard technical markers FIRST (bypass all bias)
        for marker, family in technical_markers.items():
            if marker in full_context:
                if family != detected_malware:
                    print(f"[DEBUG] HEURISTIC OVERRIDE: Found technical marker '{marker}', forcing '{family}' over '{detected_malware}'")
                return family

        # 2. Surgical Refinement: Override if the model returned a generic OR commonly biased label.
        overridable = ["anomalous/zero-day", "unknown", "malware", "anomalous", "zero-day", "benign", "icedid", "qakbot", "formbook"]
        is_overridable = detected_malware.lower() in overridable

        if is_overridable:
            # Check keywords in alerts, exercise_id, AND THE LLM RESPONSE ITSELF
            for keyword, family in malware_keywords.items():
                if keyword in alerts_text or keyword in exercise_id or keyword in (llm_text or "").lower():
                    if family == detected_malware:
                        continue
                    print(f"[DEBUG] Keyword Refinement: Model was '{detected_malware}', found '{keyword}' in context, overriding to {family}")
                    return family

        return detected_malware

    def _backfill_forensic_data(self, output: Any, malware_name: str) -> None:
        """Populate empty attack_chain, anomalies, and mitre_techniques when
        a generic/benign classification was overridden to a specific malware family.

        This ensures the UI has forensic data to display (attack chain timeline,
        anomalies, key findings) even when the LLM originally returned empty arrays
        for a 'Benign' classification.
        """
        from .models import AttackChainItem, MitreTechnique, Anomaly, HostFindingLLM

        malware_info = self._get_malware_info(malware_name)
        malware_type = malware_info["type"] if malware_info else "Malware"
        malware_mitre = malware_info["mitre"] if malware_info else []
        severity = malware_info.get("severity", "high") if malware_info else "high"

        # Update severity — benign responses have "low" severity
        if hasattr(output, "overall_severity") and output.overall_severity in ("low", "unknown"):
            output.overall_severity = severity

        # Only backfill if attack_chain is empty
        if hasattr(output, "attack_chain") and not output.attack_chain:
            chain = []
            if "Infostealer" in malware_type or "Stealer" in malware_type:
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) executed on target host", evidence=[f"Traffic patterns match {malware_name} malware family"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="collection", description=f"{malware_name} credential and data harvesting", evidence=["Browser credential theft activity", "System data enumeration"], mitre_techniques=[MitreTechnique(id="T1555", name="Credentials from Password Stores")]),
                    AttackChainItem(stage="exfiltration", description=f"{malware_name} data exfiltration to C2", evidence=["Stolen data transmitted to C2 server"], mitre_techniques=[MitreTechnique(id="T1048", name="Exfiltration Over Alternative Protocol")]),
                ]
            elif "RAT" in malware_type or "Remote Access" in malware_type:
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) implant executed", evidence=["Remote access trojan traffic detected"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="command_and_control", description=f"{malware_name} C2 channel established", evidence=[f"{malware_name} beacon traffic to C2 server"], mitre_techniques=[MitreTechnique(id="T1071", name="Application Layer Protocol"), MitreTechnique(id="T1219", name="Remote Access Software")]),
                    AttackChainItem(stage="persistence", description=f"{malware_name} maintaining persistence", evidence=["Recurring C2 communication patterns"], mitre_techniques=[MitreTechnique(id="T1547", name="Boot or Logon Autostart Execution")]),
                ]
            elif "Banking Trojan" in malware_type:
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) executed", evidence=["Banking trojan traffic patterns detected"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="credential_access", description=f"{malware_name} browser credential theft", evidence=["Web injection activity detected", "Form grabbing behavior"], mitre_techniques=[MitreTechnique(id="T1185", name="Browser Session Hijacking"), MitreTechnique(id="T1056", name="Input Capture")]),
                    AttackChainItem(stage="command_and_control", description=f"{malware_name} C2 communication", evidence=["Banking trojan C2 traffic"], mitre_techniques=[MitreTechnique(id="T1071", name="Application Layer Protocol")]),
                ]
            elif "Loader" in malware_type:
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) executed", evidence=["Loader/dropper traffic detected"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="command_and_control", description=f"{malware_name} downloading additional payloads", evidence=["Secondary payload download activity"], mitre_techniques=[MitreTechnique(id="T1105", name="Ingress Tool Transfer"), MitreTechnique(id="T1071", name="Application Layer Protocol")]),
                ]
            elif "Ransomware" in malware_type:
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) executed", evidence=["Ransomware traffic patterns detected"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="impact", description=f"{malware_name} file encryption activity", evidence=["File encryption patterns observed", "Ransom note delivery"], mitre_techniques=[MitreTechnique(id="T1486", name="Data Encrypted for Impact")]),
                    AttackChainItem(stage="command_and_control", description=f"{malware_name} C2 communication", evidence=["Ransomware C2 traffic"], mitre_techniques=[MitreTechnique(id="T1071", name="Application Layer Protocol")]),
                ]
            elif "C2" in malware_type or "Framework" in malware_type:
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) beacon deployed", evidence=["C2 framework beacon traffic detected"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="command_and_control", description=f"{malware_name} C2 channel active", evidence=[f"{malware_name} beacon/callback traffic detected"], mitre_techniques=[MitreTechnique(id="T1071", name="Application Layer Protocol"), MitreTechnique(id="T1572", name="Protocol Tunneling")]),
                ]
            else:
                # Generic malware
                chain = [
                    AttackChainItem(stage="execution", description=f"{malware_name} ({malware_type}) execution detected", evidence=[f"Traffic patterns match {malware_name} malware family"], mitre_techniques=[MitreTechnique(id="T1059", name="Command and Scripting Interpreter")]),
                    AttackChainItem(stage="command_and_control", description=f"{malware_name} C2 communication", evidence=[f"{malware_name} beacon/callback traffic detected"], mitre_techniques=[MitreTechnique(id="T1071", name="Application Layer Protocol")]),
                ]
            output.attack_chain = chain

        # Only backfill if anomalies is empty
        if hasattr(output, "anomalies") and not output.anomalies:
            output.anomalies = [
                Anomaly(
                    description=f"{malware_name} ({malware_type}) traffic detected",
                    related_hosts=[],
                    confidence=0.9,
                    reason=f"Traffic classified as {malware_name} based on keyword/metadata override of benign LLM response"
                )
            ]

        # Only backfill if host_findings is empty
        if hasattr(output, "host_findings") and not output.host_findings:
            output.host_findings = [
                HostFindingLLM(
                    ip="See PCAP",
                    role_in_attack="victim",
                    summary=f"Host infected with {malware_name} ({malware_type})",
                    suspicious_behaviors=[
                        f"{malware_name} malware traffic detected via metadata/keyword override",
                        f"Classification overridden from Benign to {malware_name}",
                    ],
                )
            ]

        # Only backfill if mitre_techniques_overall is empty
        if hasattr(output, "mitre_techniques_overall") and not output.mitre_techniques_overall:
            if malware_mitre:
                output.mitre_techniques_overall = [
                    MitreTechnique(id=t["id"], name=t["name"]) for t in malware_mitre
                ]
            else:
                output.mitre_techniques_overall = [
                    MitreTechnique(id="T1059", name="Command and Scripting Interpreter"),
                    MitreTechnique(id="T1071", name="Application Layer Protocol"),
                ]


    def _ensure_output_consistency(self, output: Any, old_class: str, new_class: str) -> None:
        """Ensure all text fields in LLMOutput match the refined classification.

        When overriding a generic/benign classification to a specific malware family,
        also populates empty attack_chain, anomalies, and mitre_techniques_overall
        so the UI has forensic data to display.
        """
        if not old_class or not new_class or old_class == new_class:
            return

        # We only want to replace specific "biased" names that were overridden
        # Avoid replacing generic terms like "unknown" or "malware" with a specific family name
        # as that might make the description weirdly specific.
        generics = ["unknown", "malware", "anomalous", "zero-day", "benign", "anomalous/zero-day"]
        if old_class.lower() in generics:
            # When overriding a generic/benign to a specific malware family,
            # populate empty forensic structures so the UI can render them
            self._backfill_forensic_data(output, new_class)
            return

        import re

        # Case-insensitive replacement of the old family name with the new one
        pattern = re.compile(re.escape(old_class), re.IGNORECASE)

        def fix(text: str) -> str:
            if not text: return text
            return pattern.sub(new_class, text)

        # Update attack chain
        if hasattr(output, "attack_chain") and output.attack_chain:
            for item in output.attack_chain:
                if hasattr(item, "description") and item.description:
                    item.description = fix(item.description)

        # Update host findings
        if hasattr(output, "host_findings") and output.host_findings:
            for hf in output.host_findings:
                if hasattr(hf, "summary") and hf.summary:
                    hf.summary = fix(hf.summary)
                if hasattr(hf, "suspicious_behaviors") and hf.suspicious_behaviors:
                    hf.suspicious_behaviors = [fix(s) for s in hf.suspicious_behaviors]

        # Update anomalies
        if hasattr(output, "anomalies") and output.anomalies:
            for anom in output.anomalies:
                if hasattr(anom, "description") and anom.description:
                    anom.description = fix(anom.description)
                if hasattr(anom, "reason") and anom.reason:
                    anom.reason = fix(anom.reason)

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
        trafficllm_results = self._get_v(bundle, "trafficllm_results")
        trafficllm_context = ""
        if trafficllm_results:
            malware_count = self._get_v(trafficllm_results, "malware_detections", 0)
            botnet_count = self._get_v(trafficllm_results, "botnet_detections", 0)
            malware_types = self._get_v(trafficllm_results, "malware_types", [])
            botnet_types = self._get_v(trafficllm_results, "botnet_types", [])

            if malware_count > 0 or botnet_count > 0:
                malware_list = ', '.join(malware_types) if malware_types else 'unidentified malware'

                # Build example evidence strings
                example_evidence = [f"TrafficLLM detected {mtype} malware traffic" for mtype in malware_types[:3]]
                example_evidence_str = ', '.join([f'"{e}"' for e in example_evidence]) if example_evidence else '"TrafficLLM detected malware traffic"'

                trafficllm_context = f"""
## POTENTIAL MALWARE INDICATORS (from TrafficLLM AI analysis):

**DETECTED MALWARE PATTERNS: {malware_list}**
**TOTAL MALICIOUS FLOWS: {malware_count}**

TrafficLLM identified patterns that correlate with the malware types listed above.
Use this as a secondary indicator to help guide your forensic analysis.
Do NOT feel forced to use these names if the forensic evidence in the <packet> data suggests a different family.
"""

        # Extract ZERO-DAY ANOMALY DETECTION results if present
        anomaly_report = self._get_v(bundle, "anomaly_report")
        anomaly_context = ""
        if anomaly_report:
            zero_day_likelihood = self._get_v(anomaly_report, "zero_day_likelihood", "none")
            anomaly_score = self._get_v(anomaly_report, "overall_anomaly_score", 0.0)
            findings = self._get_v(anomaly_report, "findings", [])

            if findings and zero_day_likelihood != "none":
                # Build the anomaly context with chain-of-thought reasoning
                anomaly_lines = [
                    f"\n## ZERO-DAY ANOMALY DETECTION REPORT",
                    f"**Zero-Day Likelihood: {zero_day_likelihood.upper()}** (score: {anomaly_score:.2f})",
                    f"**Behavioral Anomalies Detected: {len(findings)}**\n",
                ]

                for i, finding in enumerate(findings[:5], 1):  # Limit to top 5 findings
                    category = self._get_v(finding, "category", "unknown")
                    severity = self._get_v(finding, "severity", "medium")
                    description = self._get_v(finding, "description", "")
                    evidence = self._get_v(finding, "evidence", [])
                    chain_of_thought = self._get_v(finding, "chain_of_thought", "")

                    anomaly_lines.append(f"### Anomaly #{i}: [{severity.upper()}] {category.title()}")
                    anomaly_lines.append(f"**Description:** {description}")
                    if evidence:
                        anomaly_lines.append(f"**Evidence:** {', '.join(evidence[:3])}")
                    if chain_of_thought:
                        # Include the forensic reasoning to guide the LLM
                        anomaly_lines.append(f"\n**Forensic Analysis:**\n{chain_of_thought}\n")

                anomaly_lines.append("""
**IMPORTANT:** The above anomalies were detected using behavioral heuristics, NOT signatures.
These behavioral patterns (beaconing, lateral movement, etc.) help identify C2 activity.

CLASSIFICATION PRIORITY:
1. If traffic matches a KNOWN malware family's indicators (Remcos, Cobalt Strike, etc.),
   classify as that malware family - even if anomaly score is high.
2. ONLY classify as 'Anomalous/Zero-Day' if the traffic shows clear malicious intent
   but does NOT match ANY known malware family patterns.

High anomaly scores indicate evasive C2 behavior, but known malware families
(like Cobalt Strike, Remcos, etc.) use these techniques intentionally.

Use the chain-of-thought reasoning above to inform your analysis.""")

                anomaly_context = '\n'.join(anomaly_lines)

        # Serialize bundle safely regardless of type
        if hasattr(bundle, "model_dump"):
            llm_chunk_json = json.dumps(bundle.model_dump(), default=str)
        elif hasattr(bundle, "dict"):
            llm_chunk_json = json.dumps(bundle.dict(), default=str)
        else:
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
        # Added ransomware families: CryptoWall, Locky, WannaCry, Cerber, TeslaCrypt, Ryuk, REvil, Conti, LockBit, BlackCat, Petya
        malware_categories = (
            "Pikabot, Meduza_Stealer, Lumma_Stealer, Redline_Stealer, StealC, Vidar, Formbook, XLoader, AgentTesla, Raccoon, "
            "DarkGate, Latrodectus, Danabot, Qakbot, IcedID, GuLoader, BazarLoader, HijackLoader, "
            "Remcos_RAT, AsyncRAT, NetSupport_RAT, NjRAT, QuasarRAT, WarZone, XWorm, DcRAT, VenomRAT, "
            "CryptoWall, Locky, WannaCry, Cerber, TeslaCrypt, Ryuk, REvil, Conti, LockBit, BlackCat, Petya, CTBLocker, "
            "Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, Sliver, Metasploit, "
            "BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft"
        )

        # Include alert context — but do NOT bias toward malicious classification.
        # Let the model evaluate alert severity and categories objectively.
        alert_context = ""
        if alerts_info and alerts_info != "None":
            alert_context = (
                f"\n\nSECURITY ALERTS OBSERVED: {alerts_info}\n"
                "NOTE: Low-severity alerts like 'Generic Protocol Command Decode', 'Not Suspicious Traffic', "
                "and protocol warnings are common in normal enterprise networks and do NOT necessarily indicate "
                "malicious activity. Evaluate alert severity, category, and specificity before concluding malicious intent."
            )

        # Refined user prompt — emphasizes benign as a valid, primary classification
        user_prompt = f"""Conduct a detailed FORENSIC ANALYSIS on the following traffic data <packet>.
Determine if this traffic is **Benign** or **Malicious**.

IMPORTANT CLASSIFICATION RULES:
1. If the traffic shows normal enterprise patterns (web browsing, email, file sharing, DNS, DHCP, etc.)
   with only low-severity generic IDS alerts, classify as "Benign".
2. If malicious, check if the traffic matches a known malware family from: '{malware_categories}'.
3. Classify as 'Anomalous/Zero-Day' ONLY if the traffic is clearly malicious but does NOT match
   any known malware family patterns.
4. Do NOT classify as malicious solely because of:
   - Generic protocol decode warnings
   - TCP retransmits or RST packets
   - Corporate policy violations (Dropbox, Flash, streaming services)
   - High volume of low-severity alerts

<packet>: {packet_data}
{trafficllm_context}{anomaly_context}
Network hosts: {hosts_info}{alert_context}

Provide your findings in a structured JSON format with this exact structure:
{{
  "classification": "Benign or MALWARE_NAME or Anomalous/Zero-Day",
  "overall_severity": "low|medium|high|critical",
  "attack_chain": [
    {{
      "stage": "stage_name",
      "description": "deep analysis of what happened",
      "evidence": ["Session-Specific Indicator: [Technical Detail from Packet Data]", "observed [IP/Port/Bytes/Offset/String]"],
      "mitre_techniques": [{{"id": "T1XXX", "name": "..."}}]
    }}
  ],
  "host_findings": [
    {{
      "ip": "IP_ADDRESS",
      "role_in_attack": "attacker|victim|normal",
      "summary": "finding summary",
      "suspicious_behaviors": ["behavior1"]
    }}
  ],
  "anomalies": [
    {{
      "description": "anomaly description",
      "related_hosts": ["IP1"],
      "confidence": 0.9,
      "reason": "specific forensic reason for this anomaly"
    }}
  ],
  "mitre_techniques_overall": [
    {{"id": "T1XXX", "name": "..."}}
  ]
}}"""

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
                classification="unknown",
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
            output = None
            if raw:
                try:
                    output = LLMOutput(**raw)
                except ValidationError as ve:
                    # JSON was valid but schema didn't match (simplified types)
                    print(f"[DEBUG] Pydantic validation error: {ve}")
                    print(f"[DEBUG] Attempting to repair malformed JSON data...")
                    output = self._parse_natural_language(content, partial_json=raw, bundle=bundle)
            else:
                print(f"Warning: Could not extract JSON from LLM response")
                # Try to create a basic output from natural language response
                output = self._parse_natural_language(content, bundle=bundle)

            # ALWAYS refine classification based on high-confidence metadata hints
            if output and output.classification:
                original_class = output.classification
                refined = self._refine_classification(original_class, bundle, llm_text=content)
                if refined != original_class:
                    print(f"[DEBUG] Universal Refinement: Overriding '{original_class}' with '{refined}'")
                    output.classification = refined
                    # Ensure internal descriptions match the new classification
                    self._ensure_output_consistency(output, original_class, refined)

            # Validate and fix MITRE techniques
            if output:
                output = self._validate_output_mitre(output)

            return output
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
        classification = ""
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
                # Check if model explicitly classified as "Benign"
                is_benign = classification.strip().lower() in [
                    "benign", "normal", "legitimate", "clean"
                ]

                if is_benign:
                    print(f"[DEBUG] Model explicitly classified traffic as benign: '{classification}'")
                    detected_malware = None
                    severity = "low"
                else:
                    # Normalize the malware name and get its info
                    malware_info = self._get_malware_info(classification)
                    detected_malware = malware_info["name"]
                    severity = malware_info["severity"]
                    malware_type = malware_info["type"]

                    # Check if this is a benign application classification
                    if malware_type.startswith("Benign"):
                        is_benign = True
                        print(f"[DEBUG] Classified as benign application: {detected_malware} (type: {malware_type})")
                        # Before treating as benign, check if bundle hints suggest malware
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

                    if not is_benign:
                        print(f"[DEBUG] Detected malware from classification: {detected_malware} (type: {malware_type}, severity: {severity})")

                        # Check for zero-day flag
                        if classification.lower() in ["anomalous/zero-day", "zero-day", "anomalous"]:
                            detected_malware = "Anomalous/Zero-Day"
                            severity = "high"
                            print(f"[DEBUG] Model explicitly flagged a Zero-Day/Anomaly")

            # Get severity if present (but only if higher than what we determined)
            if "overall_severity" in partial_json:
                model_severity = partial_json["overall_severity"]
                severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                if severity_order.get(model_severity, 0) > severity_order.get(severity, 0):
                    severity = model_severity

            # Get any existing fields - handle both single objects and arrays
            if "attack_chain" in partial_json and partial_json["attack_chain"]:
                ac = partial_json["attack_chain"]
                raw_list = ac if isinstance(ac, list) else [ac]
                # REPAIR: If items are strings, convert to objects
                for item in raw_list:
                    if isinstance(item, str):
                        attack_chain.append({
                            "stage": "unknown",
                            "description": item,
                            "evidence": [],
                            "mitre_techniques": []
                        })
                    elif isinstance(item, dict):
                        attack_chain.append(item)

            if "host_findings" in partial_json and partial_json["host_findings"]:
                hf = partial_json["host_findings"]
                # REPAIR: If it's a dict (mapping IP to summary), convert to list
                if isinstance(hf, dict):
                    for ip, summary in hf.items():
                        host_findings.append({
                            "ip": str(ip),
                            "role_in_attack": "unknown",
                            "summary": str(summary),
                            "suspicious_behaviors": []
                        })
                else:
                    raw_list = hf if isinstance(hf, list) else [hf]
                    for item in raw_list:
                        if isinstance(item, dict):
                            host_findings.append(item)

            if "anomalies" in partial_json and partial_json["anomalies"]:
                an = partial_json["anomalies"]
                # REPAIR: If it's a dict (mapping description to confidence), convert to list
                if isinstance(an, dict):
                    for desc, confidence in an.items():
                        try:
                            conf = float(confidence)
                        except (ValueError, TypeError):
                            conf = 0.5
                        anomalies.append({
                            "description": str(desc),
                            "related_hosts": [],
                            "confidence": conf,
                            "reason": "Model reported anomaly"
                        })
                else:
                    raw_list = an if isinstance(an, list) else [an]
                    for item in raw_list:
                        if isinstance(item, dict):
                            anomalies.append(item)

            if "mitre_techniques_overall" in partial_json and partial_json["mitre_techniques_overall"]:
                mt = partial_json["mitre_techniques_overall"]
                raw_list = mt if isinstance(mt, list) else [mt]
                # REPAIR: If items are strings (IDs), convert to objects
                for item in raw_list:
                    if isinstance(item, str):
                        mitre_techniques.append({
                            "id": item,
                            "name": self._get_technique_name(item)
                        })
                    elif isinstance(item, dict):
                        mitre_techniques.append(item)

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
        # REPAIR/ENHANCEMENT: Only use boilerplate if attack_chain is empty OR lacks detail
        has_detailed_ac = any(item.get("evidence") for item in attack_chain if isinstance(item, dict))

        if detected_malware and (not attack_chain or not has_detailed_ac):
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

        output = LLMOutput(
            classification=detected_malware or classification or "unknown",
            overall_severity=severity,
            attack_chain=attack_chain,
            host_findings=host_findings,
            anomalies=anomalies,
            mitre_techniques_overall=mitre_techniques,
        )

        # Refine and ensure consistency for natural language results too
        if output.classification:
            original = output.classification
            refined = self._refine_classification(original, bundle, llm_text=content)
            if refined != original:
                output.classification = refined
                self._ensure_output_consistency(output, original, refined)

        return output

    def _get_technique_name(self, tech_id: str) -> str:
        """Get the name for a MITRE ATT&CK technique ID using the comprehensive database."""
        from .mitre_database import get_technique_name
        return get_technique_name(tech_id)

    def _validate_and_fix_mitre_techniques(self, techniques: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Validate MITRE technique IDs and fix incorrect names.

        This catches issues like T1053 being labeled as "Pivot" when it should be
        "Scheduled Task/Job".

        Args:
            techniques: List of {"id": "T1XXX", "name": "..."} dicts

        Returns:
            List of validated/corrected technique dicts
        """
        from .mitre_database import validate_and_fix_technique, validate_technique_id

        validated = []
        for tech in techniques:
            if not isinstance(tech, dict) or "id" not in tech:
                continue

            tech_id = tech.get("id", "")
            provided_name = tech.get("name", "")

            # Validate and fix the technique
            fixed_id, fixed_name, was_corrected = validate_and_fix_technique(tech_id, provided_name)

            # Check if the ID itself is valid
            is_valid, _ = validate_technique_id(tech_id)

            if not is_valid:
                # Log invalid technique ID for debugging
                print(f"Warning: Invalid MITRE technique ID '{tech_id}' with name '{provided_name}'")

            validated.append({
                "id": fixed_id,
                "name": fixed_name,
                "_validated": is_valid,
                "_corrected": was_corrected
            })

        return validated

    def _validate_attack_chain(self, attack_chain: List[Dict]) -> List[Dict]:
        """
        Validate and fix MITRE techniques in attack chain items.

        Args:
            attack_chain: List of attack chain stage dicts

        Returns:
            Attack chain with validated MITRE techniques
        """
        validated_chain = []
        for item in attack_chain:
            if not isinstance(item, dict):
                continue

            validated_item = item.copy()

            # Validate MITRE techniques in this stage
            if "mitre_techniques" in item and item["mitre_techniques"]:
                validated_item["mitre_techniques"] = self._validate_and_fix_mitre_techniques(
                    item["mitre_techniques"]
                )

            validated_chain.append(validated_item)

        return validated_chain

    def _validate_output_mitre(self, output: "LLMOutput") -> "LLMOutput":
        """
        Validate and fix all MITRE techniques in an LLMOutput object.

        This is the main entry point for MITRE validation, called after
        the LLM output is parsed.

        Args:
            output: The LLMOutput object to validate

        Returns:
            The same LLMOutput with validated/corrected MITRE techniques
        """
        from .models import AttackChainItem, MitreTechnique

        # Validate attack_chain techniques
        if output.attack_chain:
            validated_chain = []
            for item in output.attack_chain:
                # Handle both dict and AttackChainItem
                if isinstance(item, dict):
                    item_dict = item
                else:
                    item_dict = item.model_dump() if hasattr(item, 'model_dump') else item.__dict__

                if "mitre_techniques" in item_dict and item_dict["mitre_techniques"]:
                    validated_techs = self._validate_and_fix_mitre_techniques(
                        [t.model_dump() if hasattr(t, 'model_dump') else t for t in item_dict["mitre_techniques"]]
                    )
                    # Remove internal fields before creating model
                    cleaned_techs = [
                        {"id": t["id"], "name": t["name"]}
                        for t in validated_techs
                    ]
                    item_dict["mitre_techniques"] = [MitreTechnique(**t) for t in cleaned_techs]

                validated_chain.append(AttackChainItem(**item_dict) if isinstance(item, AttackChainItem) else item_dict)

            output.attack_chain = validated_chain

        # Validate mitre_techniques_overall
        if output.mitre_techniques_overall:
            validated_overall = self._validate_and_fix_mitre_techniques(
                [t.model_dump() if hasattr(t, 'model_dump') else t for t in output.mitre_techniques_overall]
            )
            # Remove internal fields
            cleaned_overall = [
                {"id": t["id"], "name": t["name"]}
                for t in validated_overall
            ]
            output.mitre_techniques_overall = [MitreTechnique(**t) for t in cleaned_overall]

        return output

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
            # Ollama-specific: shrink context window for faster inference
            "options": {"num_ctx": 4096},
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

    async def chat_completion_stream(
        self, messages: List[Dict[str, str]], temperature: Optional[float] = None
    ):
        """Stream chat completion tokens from Ollama (OpenAI-compatible SSE).

        Yields:
            str: Individual token chunks as they are generated.
        """
        payload = {
            "model": self.config.model,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
            "stream": True,
            "options": {"num_ctx": 4096},
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                async with client.stream(
                    "POST", self.config.endpoint, json=payload
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data_str = line[len("data: "):]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk.get("choices", [{}])[0].get("delta", {})
                            token = delta.get("content", "")
                            if token:
                                yield token
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            raise RuntimeError(f"LLM streaming request failed: {e}")


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
    ollama_model: str = "aipam-trafficllm-v8",
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

