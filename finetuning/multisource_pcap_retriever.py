#!/usr/bin/env python3
"""
AIPAM Multisource PCAP Retriever

Automates the collection of labeled forensic PCAPs from:
1. Malware-Traffic-Analysis.net (MTA)
2. Triage (triagemalware.com)
3. Any.Run (any.run)

Targets: data/raw/modern/{Family}/
"""

import os
import re
import sys
import json
import time
import requests
import zipfile
import subprocess
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# --- Configuration ---
# Target directory for ingestion
BASE_OUTPUT_DIR = Path(__file__).parent.parent / "data" / "raw" / "modern"

# API Keys (should be set via environment variables)
TRIAGE_API_KEY = os.getenv("TRIAGE_API_KEY")
ANY_RUN_API_KEY = os.getenv("ANY_RUN_API_KEY")

# Mapping family names to our internal labels
FAMILY_MAPPING = {
    "lumma": "Lumma_Stealer",
    "stealc": "StealC",
    "pikabot": "Pikabot",
    "netsupport": "NetSupport_RAT",
    "redline": "Redline_Stealer",
    "meduza": "Meduza_Stealer",
    "remcos": "Remcos_RAT",
    "darkgate": "DarkGate",
    "agenttesla": "AgentTesla",
    "vidar": "Vidar_Stealer",
}

# --- Module: Malware-Traffic-Analysis (MTA) ---
# (Integrated from existing download_pcaps.py)

def get_mta_zip_password(filename):
    match = re.search(r'(\d{4})-(\d{2})-(\d{2})', filename)
    if match:
        year, month, day = match.groups()
        return f"infected_{year}{month}{day}"
    return "infected"

def download_from_mta(year="2025", limit=5):
    print(f"\n--- [MTA] Fetching {year} samples ---")
    base_url = "https://www.malware-traffic-analysis.net"
    index_url = f"{base_url}/{year}/index.html"
    
    try:
        resp = requests.get(index_url, timeout=30)
        soup = BeautifulSoup(resp.text, 'html.parser')
    except Exception as e:
        print(f"Error fetching MTA index: {e}")
        return

    post_links = []
    for a in soup.find_all('a', href=True):
        text = a.get_text().lower()
        for family in FAMILY_MAPPING.keys():
            if family in text:
                post_links.append((urljoin(index_url, a['href']), FAMILY_MAPPING[family]))
                break
    
    for post_url, label in post_links[:limit]:
        print(f"Processing MTA Post: {post_url}")
        resp = requests.get(post_url, timeout=30)
        post_soup = BeautifulSoup(resp.text, 'html.parser')
        
        target_dir = BASE_OUTPUT_DIR / label
        target_dir.mkdir(parents=True, exist_ok=True)
        
        for a in post_soup.find_all('a', href=True):
            if '.pcap.zip' in a['href'].lower():
                zip_url = urljoin(post_url, a['href'])
                zip_name = zip_url.split('/')[-1]
                zip_path = target_dir / zip_name
                
                print(f"  Downloading: {zip_name}")
                zresp = requests.get(zip_url)
                with open(zip_path, 'wb') as f:
                    f.write(zresp.content)
                
                # Extract
                password = get_mta_zip_password(zip_name)
                try:
                    with zipfile.ZipFile(zip_path) as zf:
                        for name in zf.namelist():
                            if name.endswith('.pcap'):
                                zf.extract(name, target_dir, pwd=password.encode())
                                print(f"  ✓ Extracted: {name}")
                    zip_path.unlink()
                except Exception as e:
                    print(f"  ❌ Extraction failed: {e}. Trying system unzip...")
                    subprocess.run(f'unzip -P "{password}" -o "{zip_path}" -d "{target_dir}"', shell=True)
                    if zip_path.exists(): zip_path.unlink()
                break

# --- Module: Triage (triagemalware.com) ---

def download_from_triage(family="pikabot", limit=5):
    if not TRIAGE_API_KEY:
        print("\n--- [Triage] Skipped (No TRIAGE_API_KEY) ---")
        return

    print(f"\n--- [Triage] Fetching {family} samples ---")
    headers = {"Authorization": f"Bearer {TRIAGE_API_KEY}"}
    search_url = f"https://tria.ge/api/v0/search?query=family:{family}"
    
    try:
        resp = requests.get(search_url, headers=headers)
        data = resp.json()
        
        label = FAMILY_MAPPING.get(family, family)
        target_dir = BASE_OUTPUT_DIR / label
        target_dir.mkdir(parents=True, exist_ok=True)

        for sample in data.get("data", [])[:limit]:
            sample_id = sample["id"]
            # Assume first behavioral task for PCAP
            pcap_url = f"https://tria.ge/api/v0/samples/{sample_id}/behavioral1/dump.pcap"
            filename = f"triage_{sample_id}.pcap"
            pcap_path = target_dir / filename
            
            print(f"  Downloading: {filename}")
            presp = requests.get(pcap_url, headers=headers)
            if presp.status_code == 200:
                with open(pcap_path, 'wb') as f:
                    f.write(presp.content)
                print(f"  ✓ Saved to {label}/")
            else:
                print(f"  ❌ Failed to download PCAP (Status: {presp.status_code})")
                
    except Exception as e:
        print(f"Error in Triage retrieval: {e}")

# --- Module: Any.Run ---

def download_from_anyrun(family="pikabot", limit=5):
    if not ANY_RUN_API_KEY:
        print("\n--- [Any.Run] Skipped (No ANY_RUN_API_KEY) ---")
        return

    print(f"\n--- [Any.Run] Fetching {family} samples ---")
    headers = {"Authorization": f"API-Key {ANY_RUN_API_KEY}"}
    query_url = "https://api.any.run/v1/ti/submissions/query"
    
    try:
        resp = requests.post(query_url, headers=headers, json={"query": family})
        data = resp.json()
        
        label = FAMILY_MAPPING.get(family, family)
        target_dir = BASE_OUTPUT_DIR / label
        target_dir.mkdir(parents=True, exist_ok=True)

        for task in data.get("data", [])[:limit]:
            task_id = task["uuid"]
            pcap_url = f"https://api.any.run/v1/analysis/{task_id}/pcap"
            filename = f"anyrun_{task_id}.pcap"
            pcap_path = target_dir / filename
            
            print(f"  Downloading: {filename}")
            presp = requests.get(pcap_url, headers=headers)
            if presp.status_code == 200:
                with open(pcap_path, 'wb') as f:
                    f.write(presp.content)
                print(f"  ✓ Saved to {label}/")
            else:
                print(f"  ❌ Failed to download PCAP (Status: {presp.status_code})")
    
    except Exception as e:
        print(f"Error in Any.Run retrieval: {e}")

# --- Main Logic ---

def main():
    print("=" * 60)
    print("AIPAM Multisource Forensic Retriever")
    print("=" * 60)
    
    BASE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Run MTA (Public)
    download_from_mta(year="2025", limit=10)
    download_from_mta(year="2024", limit=10)

    # 2. Run API-based sources for each mapping
    for family in FAMILY_MAPPING.keys():
        download_from_triage(family=family, limit=2)
        download_from_anyrun(family=family, limit=2)

    print("\n" + "=" * 60)
    print("Retrieval Complete!")
    print(f"Check directories in: {BASE_OUTPUT_DIR}")
    print("=" * 60)

if __name__ == "__main__":
    main()
