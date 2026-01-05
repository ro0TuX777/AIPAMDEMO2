#!/usr/bin/env python3
"""
Download PCAP files for AIPAM v2 benchmarking.

Downloads PCAPs that were NOT used in training:
- Older PCAPs (2013-2019) 
- Recent late 2024 PCAPs not in training set
"""

import os
import re
import json
import requests
import zipfile
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import subprocess
import time
import argparse
from pathlib import Path
from datetime import datetime

# Base URL
BASE_URL = "https://www.malware-traffic-analysis.net"

# Output directory for benchmark PCAPs
OUTPUT_DIR = Path(__file__).parent / "benchmark_pcaps"

# Malware families - same as training to test generalization
TARGET_MALWARE = {
    # Infostealers
    "lumma": "Lumma_Stealer", "stealc": "StealC", "vidar": "Vidar",
    "redline": "Redline_Stealer", "raccoon": "Raccoon", "meduza": "Meduza_Stealer",
    # RATs
    "remcos": "Remcos_RAT", "netsupport": "NetSupport_RAT", "asyncrat": "AsyncRAT",
    "njrat": "NjRAT", "quasar": "QuasarRAT", "dcrat": "DcRAT",
    "xworm": "XWorm", "warzone": "WarZone", "venomrat": "VenomRAT",
    # Loaders
    "darkgate": "DarkGate", "pikabot": "Pikabot", "latrodectus": "Latrodectus",
    "guloader": "GuLoader", "bazarloader": "BazarLoader", "bumblebee": "BumbleBee",
    "hijackloader": "HijackLoader", "ssload": "SSLoad", "socgholish": "SocGholish",
    "matanbuchus": "Matanbuchus", "smartloader": "SmartLoader",
    # Banking Trojans
    "danabot": "Danabot", "emotet": "Emotet", "trickbot": "TrickBot",
    "qakbot": "Qakbot", "qbot": "Qakbot", "icedid": "IcedID", "bokbot": "IcedID",
    "ursnif": "Ursnif", "gozi": "Ursnif",
    # Older malware families (common in 2013-2019)
    "dridex": "Dridex", "hancitor": "Hancitor", "pony": "Pony",
    "zeus": "Zeus", "zbot": "Zeus", "kovter": "Kovter", "locky": "Locky",
    "cerber": "Cerber", "jaff": "Jaff", "vawtrak": "Vawtrak",
    "necurs": "Necurs", "nymaim": "Nymaim", "rig": "RigEK",
    "magnitude": "MagnitudeEK", "neutrino": "NeutrinoEK", "angler": "AnglerEK",
    "ransomware": "Ransomware", "cryptowall": "CryptoWall", "teslacrypt": "TeslaCrypt",
    # Infostealers/Formgrabbers
    "formbook": "Formbook", "xloader": "XLoader", "agent tesla": "AgentTesla",
    "agenttesla": "AgentTesla", "astaroth": "Astaroth", "guildma": "Astaroth",
    # C2/Pentest
    "cobalt strike": "CobaltStrike", "cobaltstrike": "CobaltStrike",
    "sliver": "Sliver", "metasploit": "Metasploit", "havoc": "Havoc",
}

def get_zip_password(filename):
    """Extract date from filename and return password."""
    match = re.search(r'(\d{4})-(\d{2})-(\d{2})', filename)
    if match:
        year, month, day = match.groups()
        return f"infected_{year}{month}{day}"
    return "infected"


def load_training_dates():
    """Load dates of PCAPs used in training to avoid them."""
    manifest_path = Path(__file__).parent / "manifests" / "training_manifest.json"
    if manifest_path.exists():
        with open(manifest_path) as f:
            data = json.load(f)
        return {s["date"] for s in data["samples"]}
    return set()


def get_pcap_links(year):
    """Get links to blog posts from the index page."""
    url = f"{BASE_URL}/{year}/index.html"
    print(f"Fetching index from {url}...")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return []
        
    soup = BeautifulSoup(response.text, 'html.parser')
    
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        text = a.get_text().lower()
        
        for keyword, label in TARGET_MALWARE.items():
            if keyword in text:
                full_url = urljoin(url, href)
                links.append((full_url, label, text))
                break
    
    return links


def download_pcap_from_post(post_url, malware_label, output_dir):
    """Download PCAP zip from a blog post."""
    print(f"\nFetching {post_url}...")
    try:
        response = requests.get(post_url, timeout=30)
    except Exception as e:
        print(f"  Error: {e}")
        return None
        
    soup = BeautifulSoup(response.text, 'html.parser')
    
    pcap_links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if '.pcap.zip' in href.lower():
            full_url = urljoin(post_url, href)
            pcap_links.append(full_url)
    
    if not pcap_links:
        print(f"  No PCAP found")
        return None
    
    pcap_url = pcap_links[0]
    filename = pcap_url.split('/')[-1]
    
    malware_dir = output_dir / malware_label
    malware_dir.mkdir(parents=True, exist_ok=True)
    
    zip_path = malware_dir / filename
    
    print(f"  Downloading {filename}...")
    try:
        response = requests.get(pcap_url, timeout=60)
        with open(zip_path, 'wb') as f:
            f.write(response.content)
    except Exception as e:
        print(f"  Download error: {e}")
        return None
    
    return extract_pcap(zip_path, malware_dir)


def extract_pcap(zip_path, output_dir):
    """Extract PCAP from password-protected zip."""
    password = get_zip_password(zip_path.name)
    print(f"  Using password: {password}")

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.pcap') or name.endswith('.pcap.gz'):
                    zf.extract(name, output_dir, pwd=password.encode())
                    pcap_path = output_dir / name
                    print(f"  Extracted: {name}")
                    zip_path.unlink()
                    return pcap_path
        print(f"  No PCAP in zip")
    except RuntimeError as e:
        if "password" in str(e).lower():
            print(f"  Trying unzip command...")
            try:
                cmd = f'unzip -P "{password}" -o "{zip_path}" -d "{output_dir}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    zip_path.unlink()
                    for f in output_dir.iterdir():
                        if f.suffix == '.pcap':
                            print(f"  Extracted: {f.name}")
                            return f
            except Exception as ex:
                print(f"  unzip error: {ex}")
    except Exception as e:
        print(f"  Error: {e}")
    return None


def main():
    parser = argparse.ArgumentParser(description='Download benchmark PCAPs')
    parser.add_argument('--old-years', nargs='+', default=['2019', '2018', '2017', '2016', '2015'],
                        help='Older years to download (pre-training)')
    parser.add_argument('--new-years', nargs='+', default=['2024'],
                        help='New years for recent samples')
    parser.add_argument('--limit-per-year', type=int, default=30,
                        help='Max PCAPs per year')
    parser.add_argument('--skip-training-dates', action='store_true', default=True,
                        help='Skip dates used in training')
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    training_dates = load_training_dates() if args.skip_training_dates else set()
    print(f"Loaded {len(training_dates)} training dates to skip")

    downloaded = {"old": [], "new": []}

    # Download older PCAPs (benchmark set)
    print(f"\n{'='*60}")
    print("DOWNLOADING OLDER PCAPs (2015-2019) FOR BENCHMARK")
    print(f"{'='*60}")

    for year in args.old_years:
        print(f"\n--- Year {year} ---")
        posts = get_pcap_links(year)
        print(f"Found {len(posts)} relevant posts")

        count = 0
        for url, label, _ in posts:
            if count >= args.limit_per_year:
                break

            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', url)
            if date_match:
                date_str = date_match.group(1)
                if date_str in training_dates:
                    print(f"  Skipping {date_str} (in training set)")
                    continue

            pcap = download_pcap_from_post(url, label, OUTPUT_DIR / "old")
            if pcap:
                downloaded["old"].append((str(pcap), label))
                count += 1
                time.sleep(1)

    # Download recent PCAPs not in training
    print(f"\n{'='*60}")
    print("DOWNLOADING RECENT PCAPs (late 2024) FOR BENCHMARK")
    print(f"{'='*60}")

    for year in args.new_years:
        print(f"\n--- Year {year} ---")
        posts = get_pcap_links(year)
        print(f"Found {len(posts)} relevant posts")

        count = 0
        for url, label, _ in posts:
            if count >= args.limit_per_year:
                break

            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', url)
            if date_match:
                date_str = date_match.group(1)
                if date_str in training_dates:
                    print(f"  Skipping {date_str} (in training set)")
                    continue

            pcap = download_pcap_from_post(url, label, OUTPUT_DIR / "new")
            if pcap:
                downloaded["new"].append((str(pcap), label))
                count += 1
                time.sleep(1)

    # Generate benchmark manifest
    print(f"\n{'='*60}")
    print("GENERATING BENCHMARK MANIFEST")
    print(f"{'='*60}")

    manifest = {
        "description": "Benchmark set for AIPAM v2 - held-out samples not in training",
        "created": datetime.now().isoformat(),
        "composition": {
            "old_samples": len(downloaded["old"]),
            "new_samples": len(downloaded["new"])
        },
        "samples": []
    }

    for pcap_path, label in downloaded["old"]:
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', pcap_path)
        manifest["samples"].append({
            "pcap": pcap_path,
            "label": label,
            "date": date_match.group(1) if date_match else "unknown",
            "set": "benchmark_old"
        })

    for pcap_path, label in downloaded["new"]:
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})', pcap_path)
        manifest["samples"].append({
            "pcap": pcap_path,
            "label": label,
            "date": date_match.group(1) if date_match else "unknown",
            "set": "benchmark_new"
        })

    manifest_path = Path(__file__).parent / "manifests" / "benchmark_manifest.json"
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\nSaved manifest to {manifest_path}")

    # Summary
    print(f"\n{'='*60}")
    print("DOWNLOAD SUMMARY")
    print(f"{'='*60}")
    print(f"Old PCAPs (2015-2019): {len(downloaded['old'])}")
    print(f"New PCAPs (late 2024): {len(downloaded['new'])}")
    print(f"Total benchmark samples: {len(downloaded['old']) + len(downloaded['new'])}")

    from collections import Counter
    all_labels = [label for _, label in downloaded["old"] + downloaded["new"]]
    print(f"\nBy malware family:")
    for family, count in sorted(Counter(all_labels).items(), key=lambda x: -x[1]):
        print(f"  {family}: {count}")


if __name__ == "__main__":
    main()

