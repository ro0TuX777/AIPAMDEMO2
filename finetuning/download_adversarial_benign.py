#!/usr/bin/env python3
"""
Download adversarial benign PCAPs for AIPAM v4 training.
These samples help reduce model bias and improve zero-day precision.
"""

import os
import requests
from pathlib import Path

# Targeted PCAPs that look suspicious but are benign
ADVERSARIAL_SAMPLES = {
    "DNS_Normal": [
        "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/dns/dns.pcap"
    ],
    "SMB_Transfer": [
        "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/smb/smb2.pcap"
    ],
    "HTTP_Benign": [
        "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/http/big-get.pcap",
        "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/http/post.pcap",
        "https://raw.githubusercontent.com/zeek/zeek/master/testing/btest/Traces/http/get.pcap"
    ]
}

OUTPUT_DIR = Path("data/raw/adversarial_benign")

def download_file(url, category):
    category_dir = OUTPUT_DIR / category
    category_dir.mkdir(parents=True, exist_ok=True)
    
    filename = url.split('/')[-1]
    if '?' in filename:
        filename = filename.split('&target=')[-1].split('&')[0]
    
    output_path = category_dir / filename
    
    if output_path.exists():
        print(f"  ✓ {filename} already exists")
        return
    
    print(f"  Downloading {filename}...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        with open(output_path, 'wb') as f:
            f.write(response.content)
        print(f"  ✓ Saved to {output_path}")
    except Exception as e:
        print(f"  ✗ Failed to download {url}: {e}")

def main():
    print("=" * 60)
    print("AIPAM Adversarial Benign Data Downloader")
    print("=" * 60)
    
    for category, urls in ADVERSARIAL_SAMPLES.items():
        print(f"\nProcessing category: {category}")
        for url in urls:
            download_file(url, category)
    
    print("\n" + "=" * 60)
    print("Download complete.")
    print("Next step: Run 'python process_training_data.py' to ingest these.")

if __name__ == "__main__":
    main()
