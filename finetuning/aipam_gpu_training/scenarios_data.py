"""Attack scenarios for training dataset."""

ATTACK_SCENARIOS = [
    {"scenario": "Banking trojan infection via phishing", "indicators": ["Phishing email with Excel attachment", "PowerShell execution", "Zeus malware detected", "C2 beaconing to suspicious domain"], "attack_chain": [("T1566.001", "Spearphishing attachment delivered via email"), ("T1204.002", "User executed malicious Excel macro"), ("T1059.001", "PowerShell downloaded and executed Zeus payload"), ("T1071.001", "Zeus established C2 channel over HTTPS"), ("T1056.001", "Keylogger captured banking credentials")], "severity": "critical", "recommendations": ["Isolate affected host", "Reset user credentials", "Block C2 domains", "Scan for lateral movement"]},
    {"scenario": "Ransomware attack with lateral movement", "indicators": ["Initial RDP brute force", "Credential dumping detected", "SMB lateral movement", "Mass file encryption"], "attack_chain": [("T1110.001", "RDP brute force gained initial access"), ("T1003.001", "LSASS credential dumping with Mimikatz"), ("T1021.002", "Lateral movement via SMB/Admin shares"), ("T1486", "Ransomware encrypted files across network")], "severity": "critical", "recommendations": ["Isolate network segment", "Restore from backups", "Reset all domain credentials", "Enable MFA on RDP"]},
    {"scenario": "APT data exfiltration campaign", "indicators": ["Spearphishing with PDF exploit", "Cobalt Strike beacon detected", "Internal reconnaissance observed", "Large outbound data transfer to cloud storage"], "attack_chain": [("T1566.001", "Spearphishing with weaponized PDF"), ("T1055", "Process injection to establish persistence"), ("T1087", "Account and group discovery"), ("T1083", "File and directory discovery"), ("T1048.003", "Data exfiltration to cloud storage")], "severity": "critical", "recommendations": ["Engage incident response team", "Preserve forensic evidence", "Block exfiltration channels", "Conduct full network sweep"]},
    {"scenario": "Supply chain compromise", "indicators": ["Legitimate software update mechanism", "Unsigned DLL loaded", "Unusual network connections from trusted application"], "attack_chain": [("T1195.002", "Compromised software supply chain"), ("T1574.002", "DLL side-loading"), ("T1071.001", "C2 via HTTPS to legitimate-looking domain")], "severity": "high", "recommendations": ["Verify software integrity", "Block C2 domains", "Contact software vendor", "Check for persistence mechanisms"]},
    {"scenario": "Emotet/TrickBot infection chain", "indicators": ["Malspam with macro document", "Emotet C2 communication", "TrickBot module download", "LDAP enumeration detected"], "attack_chain": [("T1566.001", "Malspam delivered Word document"), ("T1204.002", "User enabled macros"), ("T1059.001", "PowerShell dropped Emotet"), ("T1105", "TrickBot downloaded as secondary payload"), ("T1087.002", "Domain account enumeration")], "severity": "high", "recommendations": ["Block macro execution", "Isolate infected hosts", "Reset exposed credentials", "Monitor for ransomware deployment"]},
    {"scenario": "Cryptomining malware infection", "indicators": ["High CPU usage", "Connections to mining pool", "Unknown process running", "PowerShell execution from Office application"], "attack_chain": [("T1566.001", "Malicious Office document delivered"), ("T1059.001", "PowerShell executed miner payload"), ("T1496", "Resource hijacking for cryptocurrency mining")], "severity": "medium", "recommendations": ["Terminate mining process", "Block mining pool connections", "Remove malware", "Patch entry vector"]},
    {"scenario": "BEC wire fraud attempt", "indicators": ["Spoofed executive email", "Urgent wire transfer request", "Reply-to different domain", "Similar domain registration"], "attack_chain": [("T1566.002", "Phishing link to credential harvesting"), ("T1078", "Compromised email account access"), ("T1534", "Internal spearphishing for wire fraud")], "severity": "high", "recommendations": ["Verify transfer requests out-of-band", "Enable email authentication (DMARC)", "User security awareness", "Monitor for account compromise"]},
    {"scenario": "Insider threat data theft", "indicators": ["After-hours access", "Large file downloads", "USB device connected", "Access to sensitive directories"], "attack_chain": [("T1078", "Legitimate credentials used"), ("T1083", "Sensitive file discovery"), ("T1052", "Exfiltration over USB device")], "severity": "high", "recommendations": ["Disable user account", "Preserve forensic evidence", "DLP policy review", "HR/Legal involvement"]},
    {"scenario": "Web server compromise", "indicators": ["SQL injection attempts", "Web shell uploaded", "Reverse shell connection", "Database dump detected"], "attack_chain": [("T1190", "Exploit public-facing application (SQLi)"), ("T1505.003", "Web shell persistence"), ("T1059.004", "Reverse shell via bash"), ("T1005", "Database data collection")], "severity": "critical", "recommendations": ["Isolate web server", "Patch vulnerability", "Rotate database credentials", "Check for data exfiltration"]},
    {"scenario": "Active Directory compromise", "indicators": ["DCSync attack detected", "Golden ticket usage", "Abnormal Kerberos traffic", "Domain admin account compromise"], "attack_chain": [("T1003.006", "DCSync credential extraction"), ("T1558.001", "Golden ticket creation"), ("T1078.002", "Domain admin account abuse")], "severity": "critical", "recommendations": ["Reset krbtgt password twice", "Reset all privileged accounts", "Investigate initial compromise", "Rebuild affected DCs"]},
    {"scenario": "VPN credential theft", "indicators": ["Phishing page mimicking VPN portal", "SSL certificate mismatch", "Credential submission to external server"], "attack_chain": [("T1566.002", "Phishing link sent to employees"), ("T1056.002", "Fake VPN portal captured credentials"), ("T1078", "VPN access with stolen credentials")], "severity": "high", "recommendations": ["Reset exposed credentials", "Enable MFA on VPN", "Block phishing domain", "User awareness training"]},
    {"scenario": "IoT botnet recruitment", "indicators": ["Telnet brute force", "Mirai-like payload detected", "Outbound DDoS traffic", "Infected IoT device"], "attack_chain": [("T1110.001", "Default credential exploitation"), ("T1059.004", "Shell commands to download bot"), ("T1499.002", "DDoS participation")], "severity": "medium", "recommendations": ["Isolate IoT device", "Change default credentials", "Segment IoT network", "Update firmware"]},
    {"scenario": "Credential stuffing attack", "indicators": ["High volume failed logins", "Distributed source IPs", "Known compromised credentials", "Account takeovers detected"], "attack_chain": [("T1110.004", "Credential stuffing from breached databases"), ("T1078.004", "Successful account compromise")], "severity": "high", "recommendations": ["Enable account lockout", "Deploy MFA", "Check for credential reuse", "Monitor for fraud"]},
    {"scenario": "DNS tunneling for C2", "indicators": ["Unusual DNS query volume", "Long subdomain strings", "DNS TXT record responses", "Single IP making excessive queries"], "attack_chain": [("T1071.004", "DNS tunneling for command and control"), ("T1048.003", "Data exfiltration via DNS")], "severity": "high", "recommendations": ["Block suspicious DNS queries", "Implement DNS filtering", "Investigate source host", "Check for malware"]},
    {"scenario": "Lateral movement via PsExec", "indicators": ["PsExec service installation", "SMB connections to multiple hosts", "ADMIN$ share access", "Sequential host compromise"], "attack_chain": [("T1021.002", "SMB/Windows Admin Shares"), ("T1569.002", "PsExec service execution"), ("T1078.002", "Domain account abuse")], "severity": "high", "recommendations": ["Disable admin shares", "Reset compromised credentials", "Enable Windows Firewall", "Deploy EDR"]},
]

# Additional question templates for variation
QUESTION_TEMPLATES = {
    "mitre_explain": [
        "What is MITRE ATT&CK technique {id} ({name})? How do attackers use it?",
        "Explain the {name} technique ({id}) from MITRE ATT&CK.",
        "Can you describe {id} - {name} and how it's used in attacks?",
        "Tell me about MITRE technique {id}.",
    ],
    "mitre_detect": [
        "How do I detect {name} ({id}) attacks in my network?",
        "What are the detection strategies for {id} ({name})?",
        "How can I identify if {id} technique is being used against us?",
        "What indicators should I look for to detect {name}?",
    ],
    "malware_info": [
        "My network detected {name} malware. What should I know about it?",
        "We found {name} on our systems. What is it and what does it do?",
        "Tell me about the {name} malware family.",
        "What are the characteristics of {name} malware?",
    ],
    "malware_ioc": [
        "What are the indicators of compromise (IOCs) for {name}?",
        "How can I identify {name} infections in my network?",
        "What should I look for to detect {name}?",
        "List the IOCs associated with {name}.",
    ],
    "scenario": [
        "I observed the following in my network: {indicators}. What's happening?",
        "We detected: {indicators}. Can you analyze this incident?",
        "Our SIEM alerted on: {indicators}. What does this mean?",
        "Help me understand this attack: {indicators}",
    ],
}

