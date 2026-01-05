#!/usr/bin/env python3
"""
Verify Ingestion Labels: Modern Malware Consistency Check

This script checks the folders in data/raw/modern/ against the 
hardened LABEL_MAPPING in process_training_data.py.
"""

import os
import sys
from pathlib import Path

# Add backend to path for importing AIPAM modules
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

try:
    from process_training_data import LABEL_MAPPING
except ImportError:
    print("Error: Could not import LABEL_MAPPING from process_training_data.py")
    sys.exit(1)

def main():
    print("=" * 60)
    print("AIPAM Ingestion Label Validator")
    print("=" * 60)

    modern_raw_dir = Path("data/raw/modern")
    
    if not modern_raw_dir.exists():
        print(f"Directory not found: {modern_raw_dir}")
        print("Please run 'mkdir -p data/raw/modern' first.")
        return

    subdirs = [d.name for d in modern_raw_dir.iterdir() if d.is_dir()]
    
    if not subdirs:
        print("No subdirectories found in data/raw/modern/.")
        print("Drop your labeled PCAP folders there (e.g., Pikabot/, Lumma/).")
        return

    print(f"Checking {len(subdirs)} folders...")
    
    success_count = 0
    fail_count = 0

    for folder in subdirs:
        # Check if the folder name (label) is in our mapping
        if folder in LABEL_MAPPING:
            target = LABEL_MAPPING[folder]
            if target == folder:
                print(f"✅ [PROTECTED] {folder} -> {target}")
                success_count += 1
            elif target == "malware":
                 print(f"⚠️  [MERGING]   {folder} -> generic 'malware' (Is this intended?)")
                 fail_count += 1
            else:
                print(f"✅ [MAPPING]   {folder} -> {target}")
                success_count += 1
        else:
            print(f"❌ [UNKNOWN]   {folder} -> Not in LABEL_MAPPING! (Will be treated as folder name)")
            fail_count += 1

    print("\n" + "=" * 60)
    if fail_count == 0:
        print(f"SUCCESS: All {success_count} folders are correctly mapped.")
        print("You are ready to run 'python process_training_data.py'.")
    else:
        print(f"CAUTION: Found {fail_count} inconsistencies.")
        print("Please update LABEL_MAPPING in process_training_data.py if these are new families.")
    print("=" * 60)

if __name__ == "__main__":
    main()
