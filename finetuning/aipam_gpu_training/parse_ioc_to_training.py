#!/usr/bin/env python3
"""
Parse malware-traffic IOC files and generate training data for fine-tuning.
"""

import os
import json
import re
from pathlib import Path

# MITRE ATT&CK mappings for common malware families and techniques
MALWARE_MITRE_MAPPING = {
    "vidar": {"techniques": ["T1055", "T1082", "T1083", "T1005"], "tactic": "Collection", "description": "Vidar is an information stealer that collects browser data, cryptocurrency wallets, and system information."},
    "venom rat": {"techniques": ["T1219", "T1071", "T1105"], "tactic": "Command and Control", "description": "Venom RAT is a remote access trojan providing persistent backdoor access with keylogging and screen capture."},
    "remcos rat": {"techniques": ["T1219", "T1056.001", "T1113"], "tactic": "Command and Control", "description": "Remcos RAT is a commercial remote access tool abused for keylogging, screenshots, and remote control."},
    "guloader": {"techniques": ["T1027", "T1140", "T1055"], "tactic": "Defense Evasion", "description": "GuLoader is a shellcode-based downloader using cloud services to retrieve encrypted payloads."},
    "astaroth": {"techniques": ["T1059.001", "T1218.005", "T1055"], "tactic": "Execution", "description": "Astaroth/Guildma is a Latin American banking trojan using LOLBins and process injection."},
    "guildma": {"techniques": ["T1059.001", "T1218.005", "T1055"], "tactic": "Execution", "description": "Guildma is a Brazilian banking trojan targeting financial institutions via phishing."},
    "masslogger": {"techniques": ["T1056.001", "T1555", "T1552.001"], "tactic": "Credential Access", "description": "MassLogger is a credential stealer targeting browsers, email clients, and FTP applications."},
    "stealc": {"techniques": ["T1555", "T1539", "T1005"], "tactic": "Credential Access", "description": "StealC is an information stealer targeting browser credentials, crypto wallets, and sensitive files."},
    "netsupport rat": {"techniques": ["T1219", "T1105", "T1071"], "tactic": "Command and Control", "description": "NetSupport RAT is legitimate remote admin software abused for unauthorized access."},
    "lumma stealer": {"techniques": ["T1555", "T1539", "T1005", "T1082"], "tactic": "Credential Access", "description": "Lumma Stealer targets browser data, crypto wallets, and 2FA extensions, often via fake software."},
    "kongtuke": {"techniques": ["T1189", "T1059.007", "T1027"], "tactic": "Initial Access", "description": "KongTuke is a traffic distribution system using compromised websites to deliver malware."},
    "smartapesg": {"techniques": ["T1189", "T1204.002", "T1059.007"], "tactic": "Initial Access", "description": "SmartApeSG injects malicious scripts into compromised sites to deliver fake browser updates."},
    "clickfix": {"techniques": ["T1204.002", "T1059.001", "T1027"], "tactic": "Execution", "description": "ClickFix uses fake CAPTCHA pages to trick users into running malicious PowerShell commands."},
    "clearfake": {"techniques": ["T1189", "T1204.002", "T1059.001"], "tactic": "Initial Access", "description": "ClearFake injects fake browser update prompts into compromised websites."},
}

DELIVERY_MITRE = {
    "email": {"technique": "T1566.001", "name": "Spearphishing Attachment"},
    "zip": {"technique": "T1566.001", "name": "Spearphishing Attachment"},
    "vhd": {"technique": "T1553.005", "name": "Mark-of-the-Web Bypass"},
    "iso": {"technique": "T1553.005", "name": "Mark-of-the-Web Bypass"},
    "lnk": {"technique": "T1204.002", "name": "Malicious File"},
    "webdav": {"technique": "T1187", "name": "Forced Authentication"},
    "drive-by": {"technique": "T1189", "name": "Drive-by Compromise"},
}


def parse_ioc_file(filepath):
    """Parse a single IOC file and extract structured information."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    filename = os.path.basename(filepath)
    date_match = re.match(r'(\d{4}-\d{2}-\d{2})', filename)
    date = date_match.group(1) if date_match else "Unknown"

    # Extract malware name from filename
    malware_names = []
    for malware in MALWARE_MITRE_MAPPING.keys():
        if malware.replace(" ", "-").lower() in filename.lower() or malware.replace(" ", "").lower() in filename.lower():
            malware_names.append(malware)

    # Also check content for malware names
    content_lower = content.lower()
    for malware in MALWARE_MITRE_MAPPING.keys():
        if malware in content_lower and malware not in malware_names:
            malware_names.append(malware)

    # Extract IOCs
    sha256_hashes = re.findall(r'SHA256[^:]*:\s*([a-fA-F0-9]{64})', content)
    urls = re.findall(r'hxxps?\[:\]//[^\s<>"]+', content)
    ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(?:port\s*(\d+))?', content)
    domains = re.findall(r'([a-zA-Z0-9][-a-zA-Z0-9]*\[?\.\]?[a-zA-Z]{2,}(?:\[?\.\]?[a-zA-Z]{2,})*)', content)

    # Extract infection chain
    infection_chain = None
    chain_match = re.search(r'INFECTION CHAIN[^:]*:(.*?)(?=\n\n|\n[A-Z])', content, re.DOTALL | re.IGNORECASE)
    if chain_match:
        infection_chain = chain_match.group(1).strip()

    # Extract C2 information
    c2_info = []
    c2_section = re.search(r'C2[^:]*:(.*?)(?=\n\n[A-Z]|\Z)', content, re.DOTALL | re.IGNORECASE)
    if c2_section:
        c2_info = re.findall(r'[-•]\s*(.+)', c2_section.group(1))

    return {
        "date": date,
        "filename": filename,
        "malware_names": malware_names,
        "sha256_hashes": sha256_hashes[:5],  # Limit to 5
        "urls": urls[:10],
        "ips": [(ip, port) for ip, port in ips if ip not in ["0", "1", "2"]][:5],
        "infection_chain": infection_chain,
        "c2_info": c2_info[:5],
        "raw_content": content
    }


def generate_training_samples(parsed_data):
    """Generate Q&A training samples from parsed IOC data."""
    samples = []

    for malware in parsed_data["malware_names"]:
        malware_info = MALWARE_MITRE_MAPPING.get(malware, {})
        techniques = malware_info.get("techniques", [])
        tactic = malware_info.get("tactic", "Unknown")
        description = malware_info.get("description", "")

        # Sample 1: What is this malware?
        samples.append({
            "instruction": f"What is {malware.title()} malware and what MITRE ATT&CK techniques does it use?",
            "output": f"{malware.title()} - {description}\n\nMITRE ATT&CK Techniques: {', '.join(techniques)}\nPrimary Tactic: {tactic}\n\nDetection: Monitor for suspicious process behavior, network connections to known C2 infrastructure, and credential access attempts.\n\nMitigation: Implement application whitelisting, enable credential protection, and block known malicious domains."
        })

        # Sample 2: IOC-specific question
        if parsed_data["sha256_hashes"]:
            samples.append({
                "instruction": f"What are the file indicators (hashes) associated with {malware.title()}?",
                "output": f"Known SHA256 hashes for {malware.title()} samples:\n\n" + "\n".join([f"- {h}" for h in parsed_data["sha256_hashes"]]) + f"\n\nThese hashes can be used for threat hunting and blocking. Add them to your EDR/AV blocklists and search historical logs for matches."
            })

        # Sample 3: Network indicators
        if parsed_data["urls"] or parsed_data["c2_info"]:
            network_iocs = parsed_data["urls"][:5] + parsed_data["c2_info"][:3]
            samples.append({
                "instruction": f"What network indicators should I look for to detect {malware.title()} activity?",
                "output": f"Network indicators for {malware.title()}:\n\n" + "\n".join([f"- {url}" for url in network_iocs]) + f"\n\nDetection recommendations:\n- Add these to DNS sinkhole/blocklist\n- Create Suricata/Snort rules for these domains\n- Monitor for beaconing patterns to these IPs\n- Check proxy logs for connections to these URLs"
            })

        # Sample 4: Infection chain
        if parsed_data["infection_chain"]:
            samples.append({
                "instruction": f"How does {malware.title()} infect systems? What is the infection chain?",
                "output": f"Infection chain for {malware.title()}:\n\n{parsed_data['infection_chain']}\n\nMITRE ATT&CK Mapping:\n- Initial Access: T1566 (Phishing)\n- Execution: T1204 (User Execution)\n\nPrevention:\n- User awareness training on phishing\n- Block macro execution in Office documents\n- Implement email attachment filtering"
            })

    return samples




def main():
    """Main function to parse all IOC files and generate training data."""
    ioc_dir = Path(__file__).parent / "malware-traffic-indicators"
    output_file = Path(__file__).parent / "ioc_training_data.json"

    all_samples = []

    # Parse all IOC files
    for ioc_file in sorted(ioc_dir.glob("*.txt")):
        if ioc_file.name in ["LICENSE", "README.md"]:
            continue

        print(f"Parsing: {ioc_file.name}")
        parsed = parse_ioc_file(ioc_file)
        samples = generate_training_samples(parsed)
        all_samples.extend(samples)
        print(f"  -> Generated {len(samples)} samples")

    # Add general technique questions
    general_samples = [
        {
            "instruction": "What is a drive-by compromise attack?",
            "output": "Drive-by Compromise (MITRE T1189) is an initial access technique where attackers compromise websites to deliver malware to visitors.\n\nExamples: SmartApeSG, KongTuke, ClearFake inject malicious JavaScript into compromised sites.\n\nDetection:\n- Monitor for unexpected JavaScript execution\n- Block known malicious domains\n- Use browser isolation\n\nMitigation: Keep browsers updated, use ad blockers, implement web filtering."
        },
        {
            "instruction": "What is ClickFix and how does it work?",
            "output": "ClickFix is a social engineering technique using fake CAPTCHA or verification pages to trick users into running malicious commands.\n\nMITRE ATT&CK: T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell)\n\nInfection chain:\n1. User visits compromised/malicious site\n2. Fake CAPTCHA appears requiring 'verification'\n3. User is instructed to press Win+R and paste a command\n4. PowerShell downloads and executes malware (often Lumma Stealer, StealC)\n\nDetection: Monitor for PowerShell execution from user prompts, suspicious clipboard activity."
        },
        {
            "instruction": "How do attackers use VHD files to bypass security?",
            "output": "VHD (Virtual Hard Disk) files are used to bypass Mark-of-the-Web (MOTW) security.\n\nMITRE ATT&CK: T1553.005 (Mark-of-the-Web Bypass)\n\nTechnique:\n1. Malicious file packaged inside VHD/ISO container\n2. When mounted, files inside don't have MOTW flag\n3. Windows doesn't show security warnings for these files\n4. User executes payload without SmartScreen warning\n\nExamples: Venom RAT, Remcos RAT delivered via email with VHD attachments.\n\nMitigation: Block VHD/ISO files at email gateway, monitor for mounted virtual disks."
        },
        {
            "instruction": "What are common indicators of RAT (Remote Access Trojan) activity?",
            "output": "Common RAT indicators:\n\nNetwork:\n- Persistent outbound connections to unusual ports\n- TLS traffic to non-standard ports (e.g., 4444, 5555, 9090)\n- Beaconing patterns (regular interval connections)\n- DNS queries to DGA domains\n\nHost:\n- Unexpected processes with network connections\n- Registry persistence mechanisms\n- Scheduled tasks for persistence\n- Keylogger artifacts (keyboard hooks)\n\nExamples: Remcos RAT (port 9090), Venom RAT (port 55016), NetSupport RAT\n\nMITRE: T1219 (Remote Access Software), T1071 (Application Layer Protocol)"
        },
        {
            "instruction": "How do information stealers exfiltrate data?",
            "output": "Information stealers exfiltrate data using several methods:\n\nMITRE ATT&CK:\n- T1041 (Exfiltration Over C2 Channel)\n- T1567 (Exfiltration Over Web Service)\n- T1048 (Exfiltration Over Alternative Protocol)\n\nCommon techniques:\n1. HTTP POST to C2 server (Lumma, StealC, Vidar)\n2. Telegram bot API for exfil\n3. Discord webhooks\n4. Email (SMTP) exfiltration\n\nData targeted:\n- Browser credentials and cookies\n- Cryptocurrency wallets\n- 2FA authenticator data\n- System information\n\nDetection: Monitor for large outbound data transfers, connections to known stealer C2 infrastructure."
        },
    ]
    all_samples.extend(general_samples)

    # Save to JSON
    with open(output_file, 'w') as f:
        json.dump(all_samples, f, indent=2)

    print(f"\nTotal samples generated: {len(all_samples)}")
    print(f"Saved to: {output_file}")

    return all_samples


if __name__ == "__main__":
    main()
