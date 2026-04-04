#!/usr/bin/env python3
"""Generate realistic E2E test data for AIPAM telemetry fusion.

Produces three files in tests/e2e_data/:
  1. attack_traffic.pcap        — minimal valid PCAP with C2-like network flows
  2. sysmon_during_bundle.zip   — Sysmon JSON logs (phase: during)
  3. windows_evtx_before.json   — Windows Security EVTX-exported JSON (phase: before)

All share overlapping IPs/hostnames for cross-correlation.
"""

import json
import struct
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT_DIR = Path(__file__).parent / "e2e_data"

# ── Shared scenario constants ──
WORKSTATION = "WORKSTATION-07"
DOMAIN = "ACME"
ATTACKER_IP = "198.51.100.42"   # external C2 server
VICTIM_IP = "192.168.10.25"     # internal workstation
DC_IP = "192.168.10.1"          # domain controller
USERNAME = "t.analyst"
BASE_TIME = datetime(2026, 3, 28, 9, 0, 0, tzinfo=timezone.utc)


def _ts(offset_min: int) -> str:
    return (BASE_TIME + timedelta(minutes=offset_min)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ─────────────────────────────────────────────────────────────────────
# 1. Minimal valid PCAP
# ─────────────────────────────────────────────────────────────────────
def _build_pcap() -> bytes:
    """Build a minimal libpcap file with a few synthetic TCP packets."""
    # Global header: magic, v2.4, GMT, snaplen=65535, linktype=ETHERNET(1)
    ghdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def _pkt(src_ip: str, dst_ip: str, dst_port: int, ts_offset_min: int, payload: bytes = b"") -> bytes:
        ts = BASE_TIME + timedelta(minutes=ts_offset_min)
        ts_sec = int(ts.timestamp())
        ts_usec = 0
        src = bytes(int(o) for o in src_ip.split("."))
        dst = bytes(int(o) for o in dst_ip.split("."))
        # Ethernet(14) + IP(20) + TCP(20) + payload
        ip_total = 20 + 20 + len(payload)
        eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"  # dst mac, src mac, IPv4
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total, 0, 0, 64, 6, 0, src, dst)
        tcp = struct.pack(">HHIIBBHHH", 49200, dst_port, 0, 0, 0x50, 0x02, 8192, 0, 0)
        frame = eth + ip + tcp + payload
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        return pkt_hdr + frame

    pkts = b""
    # C2 beaconing: victim → attacker on 443 (during phase)
    for i in range(5):
        pkts += _pkt(VICTIM_IP, ATTACKER_IP, 443, 10 + i * 2, b"GET /beacon HTTP/1.1\r\n")
    # Lateral movement: victim → DC on 445/SMB (during phase)
    pkts += _pkt(VICTIM_IP, DC_IP, 445, 20, b"\x00\x00\x00\x45SMB")
    # DNS exfil: victim → attacker on 53
    pkts += _pkt(VICTIM_IP, ATTACKER_IP, 53, 25, b"\x00\x00\x01\x00")

    return ghdr + pkts


# ─────────────────────────────────────────────────────────────────────
# 2. Sysmon JSON logs (zipped) — "during" phase
# ─────────────────────────────────────────────────────────────────────
def _build_sysmon() -> list[dict]:
    proc_guid = "{ACME0007-c2c2-0328-aaaa-beefcafe0001}"
    events = [
        # Process Create — suspicious PowerShell download cradle
        {"EventID": 1, "TimeCreated": _ts(8), "Computer": WORKSTATION,
         "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Provider": "Microsoft-Windows-Sysmon",
         "EventData": {
             "ProcessGuid": proc_guid, "ProcessId": "6120",
             "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
             "User": f"{DOMAIN}\\{USERNAME}",
             "ParentImage": "C:\\Windows\\explorer.exe",
             "ParentCommandLine": "C:\\Windows\\explorer.exe",
             "Hashes": "SHA256=deadbeef01234567890abcdef01234567890abcdef01234567890abcdef0123",
         }},
        # Network Connect — C2 callback
        {"EventID": 3, "TimeCreated": _ts(10), "Computer": WORKSTATION,
         "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Provider": "Microsoft-Windows-Sysmon",
         "EventData": {
             "ProcessGuid": proc_guid, "ProcessId": "6120",
             "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "User": f"{DOMAIN}\\{USERNAME}",
             "Protocol": "tcp", "SourceIp": VICTIM_IP, "SourcePort": "49200",
             "DestinationIp": ATTACKER_IP, "DestinationPort": "443",
             "DestinationHostname": "c2.evil-corp.example",
         }},
        # File Create — dropped payload
        {"EventID": 11, "TimeCreated": _ts(12), "Computer": WORKSTATION,
         "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Provider": "Microsoft-Windows-Sysmon",
         "EventData": {
             "ProcessGuid": proc_guid, "ProcessId": "6120",
             "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "TargetFilename": "C:\\Users\\t.analyst\\AppData\\Local\\Temp\\payload.dll",
             "Hashes": "SHA256=cafebabe01234567890abcdef01234567890abcdef01234567890abcdef0123",
         }},
        # DNS Query — C2 domain
        {"EventID": 22, "TimeCreated": _ts(9), "Computer": WORKSTATION,
         "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Provider": "Microsoft-Windows-Sysmon",
         "EventData": {
             "ProcessGuid": proc_guid, "ProcessId": "6120",
             "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "QueryName": "c2.evil-corp.example", "QueryResults": ATTACKER_IP,
         }},
        # Registry modification — persistence
        {"EventID": 13, "TimeCreated": _ts(15), "Computer": WORKSTATION,
         "Channel": "Microsoft-Windows-Sysmon/Operational",
         "Provider": "Microsoft-Windows-Sysmon",
         "EventData": {
             "ProcessGuid": proc_guid, "ProcessId": "6120",
             "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateSvc",
             "Details": "C:\\Users\\t.analyst\\AppData\\Local\\Temp\\payload.dll",
         }},
    ]
    return events


# ─────────────────────────────────────────────────────────────────────
# 3. Windows Security EVTX JSON — "before" phase (pre-compromise)
# ─────────────────────────────────────────────────────────────────────
def _build_evtx_security() -> list[dict]:
    events = [
        # Successful logon — attacker's initial RDP session
        {"EventID": 4624, "TimeCreated": _ts(-30), "Computer": WORKSTATION,
         "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
         "EventData": {
             "TargetUserName": USERNAME, "TargetDomainName": DOMAIN,
             "LogonType": "10",  # RemoteInteractive (RDP)
             "IpAddress": "203.0.113.77", "IpPort": "54210",
             "WorkstationName": "EXT-LAPTOP",
             "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate",
         }},
        # Failed logon attempts — brute force before success
        {"EventID": 4625, "TimeCreated": _ts(-35), "Computer": WORKSTATION,
         "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
         "EventData": {
             "TargetUserName": "administrator", "TargetDomainName": DOMAIN,
             "LogonType": "10", "IpAddress": "203.0.113.77", "IpPort": "54180",
             "FailureReason": "%%2313", "Status": "0xc000006d", "SubStatus": "0xc000006a",
         }},
        {"EventID": 4625, "TimeCreated": _ts(-34), "Computer": WORKSTATION,
         "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
         "EventData": {
             "TargetUserName": "admin", "TargetDomainName": DOMAIN,
             "LogonType": "10", "IpAddress": "203.0.113.77", "IpPort": "54185",
             "FailureReason": "%%2313", "Status": "0xc000006d", "SubStatus": "0xc000006a",
         }},
        {"EventID": 4625, "TimeCreated": _ts(-33), "Computer": WORKSTATION,
         "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
         "EventData": {
             "TargetUserName": USERNAME, "TargetDomainName": DOMAIN,
             "LogonType": "10", "IpAddress": "203.0.113.77", "IpPort": "54190",
             "FailureReason": "%%2313", "Status": "0xc000006d", "SubStatus": "0xc000006a",
         }},
        # Special privilege assigned to new logon
        {"EventID": 4672, "TimeCreated": _ts(-29), "Computer": WORKSTATION,
         "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
         "EventData": {
             "SubjectUserName": USERNAME, "SubjectDomainName": DOMAIN,
             "PrivilegeList": "SeDebugPrivilege\n\t\t\tSeImpersonatePrivilege",
         }},
        # Process creation (pre-Sysmon — older event)
        {"EventID": 4688, "TimeCreated": _ts(-25), "Computer": WORKSTATION,
         "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
         "EventData": {
             "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
             "SubjectUserName": USERNAME, "SubjectDomainName": DOMAIN,
             "CommandLine": "whoami /all",
             "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
         }},
    ]
    return events


# ─────────────────────────────────────────────────────────────────────
# Main — generate all files
# ─────────────────────────────────────────────────────────────────────
def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. PCAP
    pcap_path = OUT_DIR / "attack_traffic.pcap"
    pcap_path.write_bytes(_build_pcap())
    print(f"✅ {pcap_path}  ({pcap_path.stat().st_size:,} bytes)")

    # 2. Sysmon ZIP (during phase)
    sysmon_data = json.dumps(_build_sysmon(), indent=2)
    zip_path = OUT_DIR / "sysmon_during_bundle.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sample_sysmon.json", sysmon_data)
    print(f"✅ {zip_path}  ({zip_path.stat().st_size:,} bytes)")

    # 3. Raw EVTX JSON (before phase) — note: filename has "evtx" so parser detects it
    evtx_path = OUT_DIR / "windows_evtx_before.json"
    evtx_path.write_text(json.dumps(_build_evtx_security(), indent=2))
    print(f"✅ {evtx_path}  ({evtx_path.stat().st_size:,} bytes)")

    print(f"\n📁 All files in: {OUT_DIR.resolve()}")
    print("\n📋 Upload plan:")
    print(f"   PCAP:    {pcap_path.name}          → label: 'during'")
    print(f"   Bundle:  {zip_path.name}  → label: 'during'  (Sysmon logs)")
    print(f"   Raw log: {evtx_path.name} → label: 'before'  (EVTX security events)")


if __name__ == "__main__":
    main()

