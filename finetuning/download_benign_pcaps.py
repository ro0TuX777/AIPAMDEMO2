#!/usr/bin/env python3
"""
Download benign/normal network traffic PCAPs from public sources.

Sources:
1. Wireshark SampleCaptures - various normal protocol traffic
2. Stratosphere IPS IoT-23 - benign IoT traffic
3. CIC datasets - normal traffic samples

This data will help balance the training dataset which is currently
biased toward malware traffic.
"""

import os
import requests
import gzip
import shutil
from pathlib import Path
from urllib.parse import urlparse, unquote
import time

# Output directory
OUTPUT_DIR = Path("finetuning/data/raw/benign")

# Wireshark sample captures - normal protocol traffic (not malware/attack related)
WIRESHARK_SAMPLES = [
    # HTTP/Web traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap",
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http_gzip.cap",
    # DNS traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap",
    # DHCP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap",
    # FTP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ftp.pcap",
    # SMTP/Email traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smtp.pcap",
    # NTP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ntp.pcap",
    # SNMP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/snmp_usm.pcap",
    # SSH traffic (encrypted)
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ssh-session.pcap",
    # Telnet traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/telnet-raw.pcap",
    # RDP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/rdp.pcap",
    # LDAP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ldap-controls-dirsync-01.cap",
    # SIP/VoIP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/sip-rtp-opus-hybrid.pcap",
    # Kerberos traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/krb5-with-keytab.pcap",
    # NFS traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/nfsv3.pcap.gz",
    # SMB traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smb-on-windows-10.pcapng",
    # IMAP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/imap.cap",
    # MySQL traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mysql_complete.pcap",
    # PostgreSQL traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/postgres.pcap",
    # RADIUS traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/radius_localhost.pcapng",
    # OSPF/Routing
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ospf.cap",
    # BGP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/bgp.pcap",
    # ARP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp-storm.pcap",
    # ICMP traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/icmp.pcap",
    # TLS/SSL traffic
    "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/tls12-dsb.pcapng",
]

# IoT-23 Benign captures (from Stratosphere IPS)
IOT23_BENIGN = [
    # These are benign IoT device traffic captures
    "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/2019-01-09-14-55-36-192.168.1.196.pcap",
    "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-5-1/2019-01-10-17-22-20-192.168.1.132.pcap",
    "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/2019-01-11-17-21-05-192.168.1.200.pcap",
]

# Other normal traffic samples
OTHER_SAMPLES = []

def download_file(url: str, output_dir: Path, category: str = "general") -> bool:
    """Download a single file with retry logic."""
    try:
        # Parse filename from URL
        parsed = urlparse(url)
        filename = unquote(os.path.basename(parsed.path))
        
        # Create category subdirectory
        cat_dir = output_dir / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = cat_dir / filename
        
        # Skip if already exists
        if output_path.exists():
            print(f"  [SKIP] {filename} already exists")
            return True
        
        print(f"  Downloading {filename}...", end=" ", flush=True)
        
        headers = {'User-Agent': 'Mozilla/5.0 (AIPAM Training Data Collector)'}
        response = requests.get(url, headers=headers, timeout=60, stream=True)
        response.raise_for_status()
        
        # Save file
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Decompress if gzipped
        if filename.endswith('.gz'):
            decompressed = output_path.with_suffix('')
            with gzip.open(output_path, 'rb') as f_in:
                with open(decompressed, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(output_path)
            print(f"✓ ({decompressed.stat().st_size / 1024:.1f} KB)")
        else:
            print(f"✓ ({output_path.stat().st_size / 1024:.1f} KB)")
        
        return True
        
    except Exception as e:
        print(f"✗ {e}")
        return False


def main():
    print("=" * 60)
    print("AIPAM Benign PCAP Downloader")
    print("=" * 60)
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    success = 0
    failed = 0
    
    # Download Wireshark samples
    print(f"\n📥 Downloading Wireshark samples ({len(WIRESHARK_SAMPLES)} files)...")
    for url in WIRESHARK_SAMPLES:
        if download_file(url, OUTPUT_DIR, "wireshark"):
            success += 1
        else:
            failed += 1
        time.sleep(0.5)  # Be nice to servers
    
    # Download IoT-23 benign samples
    print(f"\n📥 Downloading IoT-23 benign samples ({len(IOT23_BENIGN)} files)...")
    for url in IOT23_BENIGN:
        if download_file(url, OUTPUT_DIR, "iot23-benign"):
            success += 1
        else:
            failed += 1
        time.sleep(0.5)

    # Download other samples
    if OTHER_SAMPLES:
        print(f"\n📥 Downloading other samples ({len(OTHER_SAMPLES)} files)...")
        for url in OTHER_SAMPLES:
            if download_file(url, OUTPUT_DIR, "enterprise"):
                success += 1
            else:
                failed += 1
            time.sleep(0.5)

    print(f"\n{'=' * 60}")
    print(f"✅ Downloaded: {success}")
    print(f"❌ Failed: {failed}")
    print(f"📁 Output: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()

