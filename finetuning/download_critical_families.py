#!/usr/bin/env python3
"""
Download PCAPs for critical/underrepresented malware families.
Targets: XWorm, XLoader, RigEK, Raccoon, GuLoader, Meduza_Stealer, SocGholish, StealC
"""

import os
import re
import requests
import zipfile
import subprocess
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin

BASE_URL = "https://www.malware-traffic-analysis.net"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "data", "raw", "modern")

# Critical families that need more samples
CRITICAL_FAMILIES = {
    # Most critical (< 300 samples)
    "xworm": "XWorm",
    "x-worm": "XWorm",
    "xloader": "XLoader",
    "x-loader": "XLoader",
    "rig ek": "RigEK",
    "rig exploit": "RigEK",
    "rigek": "RigEK",
    "raccoon": "Raccoon",
    # Low (300-500 samples)
    "guloader": "GuLoader",
    "gu-loader": "GuLoader",
    "meduza": "Meduza_Stealer",
    "socgholish": "SocGholish",
    "soc gholish": "SocGholish",
    "stealc": "StealC",
    "steal-c": "StealC",
    "sliver": "Sliver",
}

YEARS = ["2025", "2024", "2023", "2022"]

def get_zip_password(filename):
    """Extract date from filename and return password."""
    match = re.search(r'(\d{4})-(\d{2})-(\d{2})', filename)
    if match:
        year, month, day = match.groups()
        return f"infected_{year}{month}{day}"
    return "infected"

def get_pcap_links(year):
    """Get links to blog posts from the index page."""
    url = f"{BASE_URL}/{year}/index.html"
    print(f"Fetching index from {url}...")
    
    try:
        response = requests.get(url, timeout=30)
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return []
    
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        text = a.get_text().lower()
        
        for keyword, label in CRITICAL_FAMILIES.items():
            if keyword in text:
                full_url = urljoin(url, href)
                links.append((full_url, label, text))
                break
    
    return links

def download_pcap_from_post(post_url, malware_label):
    """Download PCAP zip from a blog post."""
    print(f"\n  Fetching {post_url}...")
    try:
        response = requests.get(post_url, timeout=30)
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(f"    Error: {e}")
        return None
    
    pcap_links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if '.pcap.zip' in href.lower():
            full_url = urljoin(post_url, href)
            pcap_links.append(full_url)
    
    if not pcap_links:
        print(f"    No PCAP found")
        return None
    
    pcap_url = pcap_links[0]
    filename = pcap_url.split('/')[-1]
    
    malware_dir = os.path.join(OUTPUT_DIR, malware_label)
    os.makedirs(malware_dir, exist_ok=True)
    
    # Check if already exists
    pcap_name = filename.replace('.zip', '')
    if os.path.exists(os.path.join(malware_dir, pcap_name)):
        print(f"    Already have {pcap_name}")
        return None
    
    zip_path = os.path.join(malware_dir, filename)
    
    print(f"    Downloading {filename}...")
    try:
        response = requests.get(pcap_url, timeout=60)
        with open(zip_path, 'wb') as f:
            f.write(response.content)
    except Exception as e:
        print(f"    Download error: {e}")
        return None
    
    return extract_pcap(zip_path, malware_dir)

def extract_pcap(zip_path, output_dir):
    """Extract PCAP from password-protected zip."""
    password = get_zip_password(os.path.basename(zip_path))
    
    try:
        # Try unzip command (handles AES encryption better)
        cmd = f'unzip -P "{password}" -o "{zip_path}" -d "{output_dir}" 2>/dev/null'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            os.remove(zip_path)
            for f in os.listdir(output_dir):
                if f.endswith('.pcap'):
                    print(f"    ✓ Extracted: {f}")
                    return os.path.join(output_dir, f)
    except Exception as e:
        print(f"    Extract error: {e}")
    
    # Cleanup failed zip
    if os.path.exists(zip_path):
        os.remove(zip_path)
    return None

def main():
    print("=" * 60)
    print("Downloading PCAPs for Critical Families")
    print("=" * 60)
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    downloaded = []
    
    for year in YEARS:
        print(f"\n{'='*40}")
        print(f"Year: {year}")
        print(f"{'='*40}")
        
        posts = get_pcap_links(year)
        print(f"Found {len(posts)} relevant posts")
        
        for url, label, _ in posts:
            pcap = download_pcap_from_post(url, label)
            if pcap:
                downloaded.append((pcap, label))
            time.sleep(0.5)  # Be nice to the server
    
    print(f"\n{'='*60}")
    print(f"Downloaded {len(downloaded)} new PCAPs")
    print("=" * 60)
    
    from collections import Counter
    counts = Counter(label for _, label in downloaded)
    for family, count in sorted(counts.items()):
        print(f"  {family}: {count}")

if __name__ == "__main__":
    main()

