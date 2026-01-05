#!/usr/bin/env python3
"""
Download PCAP files from malware-traffic-analysis.net for TrafficLLM training.
"""

import os
import re
import requests
import zipfile
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import subprocess
import time
import argparse

# Password format for malware-traffic-analysis.net zip files
# Format: infected_YYYYMMDD (e.g., infected_20240610 for June 10, 2024)
def get_zip_password(filename):
    """Extract date from filename and return password."""
    import re
    # Look for date pattern YYYY-MM-DD in filename
    match = re.search(r'(\d{4})-(\d{2})-(\d{2})', filename)
    if match:
        year, month, day = match.groups()
        return f"infected_{year}{month}{day}"
    # Fallback to old password
    return "infected"

# Base URL
BASE_URL = "https://www.malware-traffic-analysis.net"

# Malware families we want to train on - comprehensive list
TARGET_MALWARE = {
    # Infostealers
    "lumma": "Lumma_Stealer",
    "stealc": "StealC",
    "vidar": "Vidar",
    "redline": "Redline_Stealer",
    "raccoon": "Raccoon",
    "meduza": "Meduza_Stealer",
    # RATs
    "remcos": "Remcos_RAT",
    "netsupport": "NetSupport_RAT",
    "asyncrat": "AsyncRAT",
    "njrat": "NjRAT",
    "quasar": "QuasarRAT",
    "dcrat": "DcRAT",
    "xworm": "XWorm",
    "warzone": "WarZone",
    "venomrat": "VenomRAT",
    # Loaders
    "darkgate": "DarkGate",
    "pikabot": "Pikabot",
    "latrodectus": "Latrodectus",
    "guloader": "GuLoader",
    "bazarloader": "BazarLoader",
    "bumblebee": "BumbleBee",
    "hijackloader": "HijackLoader",
    "ssload": "SSLoad",
    "socgholish": "SocGholish",
    "matanbuchus": "Matanbuchus",
    "smartloader": "SmartLoader",
    # Banking Trojans
    "danabot": "Danabot",
    "emotet": "Emotet",
    "trickbot": "TrickBot",
    "qakbot": "Qakbot",
    "qbot": "Qakbot",
    "icedid": "IcedID",
    "bokbot": "IcedID",
    "ursnif": "Ursnif",
    "gozi": "Ursnif",
    # Infostealers/Formgrabbers
    "formbook": "Formbook",
    "xloader": "XLoader",
    "agent tesla": "AgentTesla",
    "agenttesla": "AgentTesla",
    "astaroth": "Astaroth",
    "guildma": "Astaroth",
    # Pentest/C2
    "cobalt strike": "CobaltStrike",
    "cobaltstrike": "CobaltStrike",
    "sliver": "Sliver",
    "metasploit": "Metasploit",
    "havoc": "Havoc",
    "brute ratel": "BruteRatel",
    # Ransomware precursors
    "conti": "Conti",
    "lockbit": "LockBit",
    "blackcat": "BlackCat",
    "alphv": "BlackCat",
    "royal": "Royal",
    "akira": "Akira",
}

# Years to download from
YEARS = ["2025", "2024", "2023", "2022", "2021", "2020"]

# Output directory for training data
# We target the modern ingestion subdirectories specifically
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "modern")

def get_pcap_links(year="2024"):
    """Get links to blog posts from the index page."""
    url = f"{BASE_URL}/{year}/index.html"
    print(f"Fetching index from {url}...")
    
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find all links in the page
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        text = a.get_text().lower()
        
        # Check if it matches our target malware
        for keyword, label in TARGET_MALWARE.items():
            if keyword in text:
                full_url = urljoin(url, href)
                links.append((full_url, label, text))
                break
    
    return links

def download_pcap_from_post(post_url, malware_label):
    """Download PCAP zip from a blog post."""
    print(f"\nFetching {post_url}...")
    response = requests.get(post_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find PCAP zip links
    pcap_links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if '.pcap.zip' in href.lower():
            full_url = urljoin(post_url, href)
            pcap_links.append(full_url)
    
    if not pcap_links:
        print(f"  No PCAP found in {post_url}")
        return None
    
    # Download first PCAP
    pcap_url = pcap_links[0]
    filename = pcap_url.split('/')[-1]
    
    # Create output directory
    malware_dir = os.path.join(OUTPUT_DIR, malware_label)
    os.makedirs(malware_dir, exist_ok=True)
    
    zip_path = os.path.join(malware_dir, filename)
    
    print(f"  Downloading {filename}...")
    response = requests.get(pcap_url)
    with open(zip_path, 'wb') as f:
        f.write(response.content)
    
    # Extract with password
    pcap_path = extract_pcap(zip_path, malware_dir)
    return pcap_path

def extract_pcap(zip_path, output_dir):
    """Extract PCAP from password-protected zip."""
    # Get password based on filename date
    zip_filename = os.path.basename(zip_path)
    password = get_zip_password(zip_filename)
    print(f"  Using password: {password}")

    try:
        # Use Python zipfile with password
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Try extraction with password
            for name in zf.namelist():
                if name.endswith('.pcap') or name.endswith('.pcap.gz'):
                    zf.extract(name, output_dir, pwd=password.encode())
                    pcap_path = os.path.join(output_dir, name)
                    print(f"  Extracted: {name}")
                    os.remove(zip_path)  # Clean up zip
                    return pcap_path

        print(f"  No PCAP found in zip")

    except zipfile.BadZipFile:
        print(f"  Bad zip file (may need different extraction)")
    except RuntimeError as e:
        if "password" in str(e).lower():
            print(f"  Python zipfile can't handle encryption, trying unzip...")
            # Try unzip command as fallback (handles AES encryption)
            try:
                cmd = f'unzip -P "{password}" -o "{zip_path}" -d "{output_dir}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    os.remove(zip_path)
                    for f in os.listdir(output_dir):
                        if f.endswith('.pcap'):
                            print(f"  Extracted with unzip: {f}")
                            return os.path.join(output_dir, f)
                else:
                    print(f"  unzip failed: {result.stderr}")
            except Exception as ex:
                print(f"  unzip error: {ex}")
        else:
            print(f"  Error: {e}")
    except Exception as e:
        print(f"  Error extracting: {e}")

    return None

def get_existing_pcaps():
    """Get list of already downloaded PCAPs to avoid duplicates."""
    existing = set()
    if os.path.exists(OUTPUT_DIR):
        for malware_dir in os.listdir(OUTPUT_DIR):
            dir_path = os.path.join(OUTPUT_DIR, malware_dir)
            if os.path.isdir(dir_path):
                for f in os.listdir(dir_path):
                    if f.endswith('.pcap'):
                        # Extract date from filename (e.g., 2024-03-19)
                        existing.add(f.split('.')[0] if '-' in f else f)
    return existing

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Download PCAPs from malware-traffic-analysis.net')
    parser.add_argument('--years', nargs='+', default=YEARS, help='Years to download from')
    parser.add_argument('--limit', type=int, default=None, help='Max PCAPs per year (None=all)')
    parser.add_argument('--skip-existing', action='store_true', default=True, help='Skip already downloaded')
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    existing = get_existing_pcaps() if args.skip_existing else set()
    print(f"Found {len(existing)} existing PCAPs")

    all_downloaded = []

    for year in args.years:
        print(f"\n{'='*50}")
        print(f"Processing year {year}")
        print(f"{'='*50}")

        posts = get_pcap_links(year)
        print(f"Found {len(posts)} relevant posts for {year}")

        # Apply limit if specified
        posts_to_process = posts[:args.limit] if args.limit else posts

        for url, label, _ in posts_to_process:
            # Check if already downloaded (by date in filename)
            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', url)
            if date_match and args.skip_existing:
                date_str = date_match.group(1)
                if any(date_str in e for e in existing):
                    print(f"  Skipping {url} (already have PCAP from {date_str})")
                    continue

            pcap = download_pcap_from_post(url, label)
            if pcap:
                all_downloaded.append((pcap, label))
                # Add delay to be nice to the server
                time.sleep(1)

    # Summary by malware family
    print(f"\n{'='*50}")
    print(f"=== Downloaded {len(all_downloaded)} new PCAPs ===")
    print(f"{'='*50}")

    from collections import Counter
    family_counts = Counter(label for _, label in all_downloaded)
    for family, count in sorted(family_counts.items()):
        print(f"  {family}: {count}")

    # Total count including existing
    total_pcaps = len(list(p for p in os.listdir(OUTPUT_DIR)
                          if os.path.isdir(os.path.join(OUTPUT_DIR, p))))
    print(f"\nTotal malware families with PCAPs: {total_pcaps}")

if __name__ == "__main__":
    main()

