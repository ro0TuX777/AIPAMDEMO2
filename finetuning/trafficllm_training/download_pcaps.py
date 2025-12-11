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

# Common password for malware-traffic-analysis.net zip files
ZIP_PASSWORD = "infected"

# Base URL
BASE_URL = "https://www.malware-traffic-analysis.net"

# Malware families we want to train on (matching our IOC data)
TARGET_MALWARE = {
    "lumma": "Lumma_Stealer",
    "remcos": "Remcos_RAT",
    "stealc": "StealC",
    "netsupport": "NetSupport_RAT",
    "asyncrat": "AsyncRAT",
    "darkgate": "DarkGate",
    "astaroth": "Astaroth",
    "guildma": "Astaroth",
    "formbook": "Formbook",
    "xloader": "XLoader",
    "vidar": "Vidar",
    "redline": "Redline_Stealer",
    "agent tesla": "AgentTesla",
    "cobalt strike": "CobaltStrike",
    "pikabot": "Pikabot",
    "danabot": "Danabot",
    "latrodectus": "Latrodectus",
    "guloader": "GuLoader",
}

# Output directory
OUTPUT_DIR = "pcaps"

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
    try:
        # Use Python zipfile with password
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Try extraction with password
            for name in zf.namelist():
                if name.endswith('.pcap') or name.endswith('.pcap.gz'):
                    zf.extract(name, output_dir, pwd=ZIP_PASSWORD.encode())
                    pcap_path = os.path.join(output_dir, name)
                    print(f"  Extracted: {name}")
                    os.remove(zip_path)  # Clean up zip
                    return pcap_path

        print(f"  No PCAP found in zip")

    except zipfile.BadZipFile:
        print(f"  Bad zip file (may need different extraction)")
    except RuntimeError as e:
        if "password" in str(e).lower():
            print(f"  Wrong password or encryption not supported by Python zipfile")
            # Try unzip command as fallback
            try:
                cmd = f'unzip -P {ZIP_PASSWORD} -o "{zip_path}" -d "{output_dir}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    os.remove(zip_path)
                    for f in os.listdir(output_dir):
                        if f.endswith('.pcap'):
                            return os.path.join(output_dir, f)
            except:
                pass
        else:
            print(f"  Error: {e}")
    except Exception as e:
        print(f"  Error extracting: {e}")

    return None

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Get links from 2024
    posts = get_pcap_links("2024")
    print(f"\nFound {len(posts)} relevant posts")
    
    # Download PCAPs
    downloaded = []
    for url, label, title in posts[:20]:  # Limit to 20 for now
        pcap = download_pcap_from_post(url, label)
        if pcap:
            downloaded.append((pcap, label))
    
    print(f"\n=== Downloaded {len(downloaded)} PCAPs ===")
    for pcap, label in downloaded:
        print(f"  {label}: {pcap}")

if __name__ == "__main__":
    main()

