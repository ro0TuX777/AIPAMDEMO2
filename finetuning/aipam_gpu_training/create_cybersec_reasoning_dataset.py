#!/usr/bin/env python3
"""
Create cybersecurity reasoning training dataset for fine-tuning Llama 3.1 8B.

This generates Q&A pairs for:
1. MITRE ATT&CK technique explanations
2. Malware family analysis
3. Attack chain reasoning
4. Incident response recommendations
"""

import json
import random
from pathlib import Path

# Import extended data
from mitre_data import MITRE_TECHNIQUES
from malware_data import MALWARE_FAMILIES
from scenarios_data import ATTACK_SCENARIOS, QUESTION_TEMPLATES

# Additional inline MITRE for backwards compat (merged with imported)
MITRE_TECHNIQUES_INLINE = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "examples": ["PowerShell scripts", "bash commands", "Python scripts", "Windows Command Shell"],
        "detection": "Monitor process execution, command-line arguments, and script block logging",
        "mitigation": "Disable or restrict scripting, use application whitelisting"
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection by blending in with normal traffic.",
        "examples": ["HTTP/HTTPS C2", "DNS tunneling", "SMTP for exfiltration"],
        "detection": "Analyze network traffic for anomalous patterns, unusual user agents, beacon behavior",
        "mitigation": "Network intrusion prevention, SSL inspection, DNS filtering"
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access", 
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "examples": ["Spearphishing attachments", "malicious links", "credential harvesting"],
        "detection": "Email gateway filtering, user reporting, attachment analysis",
        "mitigation": "User training, email filtering, sandbox detonation"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "examples": ["Ransomware encryption", "file locking", "MBR encryption"],
        "detection": "Monitor for mass file modifications, known ransomware signatures",
        "mitigation": "Backups, endpoint protection, network segmentation"
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service specifically designed for remote access.",
        "examples": ["RDP", "SSH", "SMB/Windows Admin Shares", "VNC"],
        "detection": "Monitor authentication logs, unusual login times/locations",
        "mitigation": "MFA, network segmentation, privileged access management"
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login information.",
        "examples": ["LSASS memory dump", "SAM database", "DCSync", "Mimikatz"],
        "detection": "Monitor for LSASS access, credential dumping tools",
        "mitigation": "Credential guard, LSA protection, limit credential exposure"
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than existing C2.",
        "examples": ["DNS exfiltration", "FTP uploads", "cloud storage upload"],
        "detection": "Monitor for unusual outbound protocols, large data transfers",
        "mitigation": "DLP solutions, egress filtering, network monitoring"
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable or modify security tools to avoid detection.",
        "examples": ["Disable AV", "stop logging", "firewall modification", "EDR tampering"],
        "detection": "Monitor security tool status, audit log gaps",
        "mitigation": "Tamper protection, centralized logging, integrity monitoring"
    },
}

# Malware families with detailed analysis
MALWARE_FAMILIES = {
    "Zeus": {
        "type": "Banking Trojan",
        "first_seen": "2007",
        "behavior": "Steals banking credentials via form grabbing and keylogging. Uses web injects to modify banking pages.",
        "c2": "HTTP-based C2 with encrypted config files. Uses domain generation algorithms (DGA).",
        "indicators": ["Hooks browser APIs", "Injects into explorer.exe", "Creates mutex ZonesCacheCounterMutex"],
        "mitre_techniques": ["T1059", "T1071", "T1056", "T1185"]
    },
    "Emotet": {
        "type": "Loader/Banking Trojan",
        "first_seen": "2014",
        "behavior": "Initially banking trojan, evolved to malware loader. Spreads via malspam with malicious attachments.",
        "c2": "HTTPS with encrypted payloads. Multiple C2 servers for redundancy.",
        "indicators": ["Spawns rundll32.exe", "Creates scheduled tasks", "Uses PowerShell for downloads"],
        "mitre_techniques": ["T1566", "T1059.001", "T1547", "T1071"]
    },
    "Neris": {
        "type": "Botnet/Spam Bot",
        "first_seen": "2008",
        "behavior": "Part of the Neris botnet. Sends spam and participates in DDoS attacks.",
        "c2": "IRC-based C2 communication. Receives commands for spam campaigns.",
        "indicators": ["IRC traffic on non-standard ports", "High volume SMTP connections", "Credential theft"],
        "mitre_techniques": ["T1071", "T1499", "T1003"]
    },
    "Shifu": {
        "type": "Banking Trojan",
        "first_seen": "2015",
        "behavior": "Sophisticated banking trojan targeting Japanese banks. Uses anti-analysis and evasion techniques.",
        "c2": "HTTPS with certificate pinning. Tor fallback for resilience.",
        "indicators": ["Sandbox detection", "VM detection", "Targets specific banking software"],
        "mitre_techniques": ["T1497", "T1071", "T1185", "T1056"]
    },
    "Htbot": {
        "type": "Click Fraud Bot",
        "first_seen": "2013",
        "behavior": "Generates fraudulent ad clicks. Often bundled with other malware.",
        "c2": "HTTP-based C2 for receiving click fraud campaigns.",
        "indicators": ["Browser automation", "Hidden browser instances", "Unusual HTTP patterns"],
        "mitre_techniques": ["T1071", "T1059"]
    },
}

# Attack scenarios for chain reasoning
ATTACK_SCENARIOS = [
    {
        "scenario": "Banking trojan infection via phishing",
        "indicators": ["Phishing email with Excel attachment", "PowerShell execution", "Zeus malware detected", "C2 beaconing to suspicious domain"],
        "attack_chain": [
            ("T1566.001", "Spearphishing attachment delivered via email"),
            ("T1204.002", "User executed malicious Excel macro"),
            ("T1059.001", "PowerShell downloaded and executed Zeus payload"),
            ("T1071.001", "Zeus established C2 channel over HTTPS"),
            ("T1056.001", "Keylogger captured banking credentials"),
        ],
        "severity": "critical",
        "recommendations": ["Isolate affected host", "Reset user credentials", "Block C2 domains", "Scan for lateral movement"]
    },
    {
        "scenario": "Ransomware attack with lateral movement",
        "indicators": ["Initial RDP brute force", "Credential dumping detected", "SMB lateral movement", "Mass file encryption"],
        "attack_chain": [
            ("T1110.001", "RDP brute force gained initial access"),
            ("T1003.001", "LSASS credential dumping with Mimikatz"),
            ("T1021.002", "Lateral movement via SMB/Admin shares"),
            ("T1486", "Ransomware encrypted files across network"),
        ],
        "severity": "critical",
        "recommendations": ["Isolate network segment", "Restore from backups", "Reset all domain credentials", "Enable MFA on RDP"]
    },
]

def format_llama_prompt(system: str, user: str, assistant: str) -> str:
    """Format as Llama 3.1 instruct format."""
    return f"""<|start_header_id|>system<|end_header_id|>

{system}<|eot_id|><|start_header_id|>user<|end_header_id|>

{user}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

{assistant}<|eot_id|>"""

SYSTEM_PROMPT = """You are a cybersecurity analyst expert specializing in network traffic analysis, malware detection, and incident response. You have deep knowledge of MITRE ATT&CK framework, malware families, and attack patterns. Provide detailed, actionable analysis."""

def generate_mitre_qa():
    """Generate Q&A pairs for MITRE ATT&CK techniques."""
    samples = []

    for tech_id, tech in MITRE_TECHNIQUES.items():
        # Explanation question
        q1 = f"What is MITRE ATT&CK technique {tech_id} ({tech['name']})? How do attackers use it?"
        examples = tech.get('examples', [])
        examples_str = ', '.join(examples) if examples else 'various methods'
        a1 = f"""{tech_id} - {tech['name']} is a {tech['tactic']} technique. {tech['description']}

Common examples include: {examples_str}.

**Detection:** {tech['detection']}

**Mitigation:** {tech['mitigation']}"""
        samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q1, a1)})

        # Detection question
        q2 = f"How do I detect {tech['name']} ({tech_id}) attacks in my network?"
        a2 = f"""To detect {tech['name']} ({tech_id}) attacks:

**Detection Approach:** {tech['detection']}

**Indicators to Monitor:**
- Look for: {examples_str}
- This technique is used in the {tech['tactic']} phase of an attack

**Recommended Mitigations:** {tech['mitigation']}"""
        samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q2, a2)})

    return samples

def generate_malware_qa():
    """Generate Q&A pairs for malware analysis."""
    samples = []

    for name, malware in MALWARE_FAMILIES.items():
        # Handle both 'mitre' and 'mitre_techniques' keys
        mitre_techs = malware.get('mitre', malware.get('mitre_techniques', []))

        # Analysis question
        q1 = f"My network detected {name} malware. What should I know about it?"
        a1 = f"""{name} is a {malware['type']} first seen in {malware['first_seen']}.

**Behavior:** {malware['behavior']}

**C2 Communication:** {malware['c2']}

**Key Indicators:**
{chr(10).join(f'- {ind}' for ind in malware['indicators'])}

**Associated MITRE Techniques:** {', '.join(mitre_techs)}

**Immediate Actions:**
1. Isolate the infected host from the network
2. Capture memory and disk forensics
3. Block known C2 indicators
4. Check for lateral movement to other hosts"""
        samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q1, a1)})

        # IOC question
        q2 = f"What are the indicators of compromise (IOCs) for {name}?"
        a2 = f"""{name} ({malware['type']}) IOCs:

**Behavioral Indicators:**
{chr(10).join(f'- {ind}' for ind in malware['indicators'])}

**Network Indicators:**
{malware['c2']}

**MITRE ATT&CK Mapping:**
{chr(10).join(f'- {t}' for t in mitre_techs)}"""
        samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q2, a2)})

    return samples

def generate_scenario_qa():
    """Generate Q&A pairs for attack scenario analysis with variations."""
    samples = []

    for scenario in ATTACK_SCENARIOS:
        indicators_text = ', '.join(scenario['indicators'])
        chain_text = '\n'.join(f"{i+1}. **{t[0]}**: {t[1]}" for i, t in enumerate(scenario['attack_chain']))
        recommendations_text = '\n'.join(f"- {r}" for r in scenario['recommendations'])

        response = f"""This appears to be a **{scenario['scenario']}** attack. Severity: **{scenario['severity'].upper()}**

**Attack Chain Analysis:**
{chain_text}

**Immediate Recommendations:**
{recommendations_text}

This is a serious incident requiring immediate response."""

        # Generate multiple question variations
        for template in QUESTION_TEMPLATES.get('scenario', []):
            q = template.format(indicators=indicators_text)
            samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q, response)})

    return samples

def generate_mitre_variations():
    """Generate additional MITRE Q&A variations."""
    samples = []

    for tech_id, tech in MITRE_TECHNIQUES.items():
        examples = tech.get('examples', [])
        examples_str = ', '.join(examples) if examples else 'various methods'

        # Explanation variations
        explanation = f"""{tech_id} - {tech['name']} is a {tech['tactic']} technique. {tech['description']}

Common examples include: {examples_str}.

**Detection:** {tech['detection']}

**Mitigation:** {tech['mitigation']}"""

        for template in QUESTION_TEMPLATES.get('mitre_explain', [])[1:]:  # Skip first (already used)
            q = template.format(id=tech_id, name=tech['name'])
            samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q, explanation)})

        # Detection variations
        detection_response = f"""To detect {tech['name']} ({tech_id}) attacks:

**Detection Approach:** {tech['detection']}

**Indicators to Monitor:**
- Look for: {examples_str}
- This technique is used in the {tech['tactic']} phase

**Recommended Mitigations:** {tech['mitigation']}"""

        for template in QUESTION_TEMPLATES.get('mitre_detect', [])[1:]:
            q = template.format(id=tech_id, name=tech['name'])
            samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q, detection_response)})

    return samples

def generate_malware_variations():
    """Generate additional malware Q&A variations."""
    samples = []

    for name, malware in MALWARE_FAMILIES.items():
        mitre_techs = malware.get('mitre', malware.get('mitre_techniques', []))

        info_response = f"""{name} is a {malware['type']} first seen in {malware['first_seen']}.

**Behavior:** {malware['behavior']}

**C2 Communication:** {malware['c2']}

**Key Indicators:**
{chr(10).join(f'- {ind}' for ind in malware['indicators'])}

**Associated MITRE Techniques:** {', '.join(mitre_techs)}

**Immediate Actions:**
1. Isolate the infected host
2. Capture forensic evidence
3. Block C2 indicators
4. Check for lateral movement"""

        for template in QUESTION_TEMPLATES.get('malware_info', [])[1:]:
            q = template.format(name=name)
            samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q, info_response)})

        ioc_response = f"""{name} ({malware['type']}) IOCs:

**Behavioral Indicators:**
{chr(10).join(f'- {ind}' for ind in malware['indicators'])}

**Network Indicators:**
{malware['c2']}

**MITRE ATT&CK Mapping:**
{chr(10).join(f'- {t}' for t in mitre_techs)}"""

        for template in QUESTION_TEMPLATES.get('malware_ioc', [])[1:]:
            q = template.format(name=name)
            samples.append({"text": format_llama_prompt(SYSTEM_PROMPT, q, ioc_response)})

    return samples

def main():
    output_dir = Path("data")
    output_dir.mkdir(exist_ok=True)

    print("Generating cybersecurity reasoning dataset...")

    all_samples = []
    all_samples.extend(generate_mitre_qa())
    all_samples.extend(generate_malware_qa())
    all_samples.extend(generate_scenario_qa())
    all_samples.extend(generate_mitre_variations())
    all_samples.extend(generate_malware_variations())

    # Shuffle and split
    random.seed(42)
    random.shuffle(all_samples)

    split_idx = int(len(all_samples) * 0.9)
    train_samples = all_samples[:split_idx]
    valid_samples = all_samples[split_idx:]

    # Save
    train_file = output_dir / "cybersec_train.jsonl"
    valid_file = output_dir / "cybersec_valid.jsonl"

    with open(train_file, 'w') as f:
        for sample in train_samples:
            f.write(json.dumps(sample) + '\n')

    with open(valid_file, 'w') as f:
        for sample in valid_samples:
            f.write(json.dumps(sample) + '\n')

    print(f"Created {len(train_samples)} training samples: {train_file}")
    print(f"Created {len(valid_samples)} validation samples: {valid_file}")
    print(f"Total samples: {len(all_samples)}")
    print("\nTo train, run: python train_cuda.py")

if __name__ == "__main__":
    main()

