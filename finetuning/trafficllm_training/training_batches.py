#!/usr/bin/env python3
"""
Training batch definitions for malware families.
Organizes 40 malware families into logical training batches.
"""

# Training Batch Definitions
TRAINING_BATCHES = {
    "batch1_banking_trojans": {
        "description": "Banking Trojans & Financial Malware",
        "families": [
            "IcedID",      # 74 samples
            "Qakbot",      # 59 samples
            "Emotet",      # 42 samples
            "TrickBot",    # 21 samples
            "Ursnif",      # 24 samples
            "Dridex",      # 14 samples
            "ZLoader",     # 8 samples
            "Danabot",     # 4 samples
        ],
        "priority": 1,
        "estimated_samples": 246,
    },
    
    "batch2_infostealers": {
        "description": "Information Stealers & Credential Harvesters",
        "families": [
            "Formbook",        # 34 samples
            "Lumma_Stealer",   # 13 samples
            "AgentTesla",      # 7 samples
            "StealC",          # 6 samples
            "LokiBot",         # 3 samples
            "Raccoon",         # 3 samples
            "SnakeKeylogger",  # 2 samples
            "Redline_Stealer", # 2 samples
            "Rhadamanthys",    # 2 samples
            "XLoader",         # 1 sample
            "Meduza_Stealer",  # 1 sample
            "AZORult",         # 1 sample
        ],
        "priority": 2,
        "estimated_samples": 75,
    },
    
    "batch3_loaders": {
        "description": "Malware Loaders & Droppers",
        "families": [
            "Hancitor",      # 24 samples
            "BazarLoader",   # 19 samples
            "Pikabot",       # 11 samples
            "DarkGate",      # 11 samples
            "BumbleBee",     # 8 samples
            "Matanbuchus",   # 6 samples
            "GootLoader",    # 5 samples
            "SSLoad",        # 3 samples
            "GuLoader",      # 3 samples
            "SocGholish",    # 2 samples
            "Latrodectus",   # 2 samples
            "SmokeLoader",   # 1 sample
        ],
        "priority": 3,
        "estimated_samples": 95,
    },
    
    "batch4_rats_c2": {
        "description": "Remote Access Trojans & C2 Frameworks",
        "families": [
            "CobaltStrike",   # 17 samples
            "Remcos_RAT",     # 6 samples
            "NetSupport_RAT", # 3 samples
            "Sliver",         # 2 samples
            "AsyncRAT",       # 1 sample
            "XWorm",          # 1 sample
        ],
        "priority": 4,
        "estimated_samples": 30,
    },
    
    "batch5_regional_other": {
        "description": "Regional Malware & Exploit Kits",
        "families": [
            "Astaroth",    # 10 samples (Brazilian banking trojan)
            "RigEK",       # 2 samples (Exploit Kit)
        ],
        "priority": 5,
        "estimated_samples": 12,
    },
}

# Family to batch mapping for quick lookup
FAMILY_TO_BATCH = {}
for batch_name, batch_info in TRAINING_BATCHES.items():
    for family in batch_info["families"]:
        FAMILY_TO_BATCH[family] = batch_name

# All families list
ALL_FAMILIES = list(FAMILY_TO_BATCH.keys())

def get_batch_for_family(family: str) -> str:
    """Get the batch name for a given malware family."""
    return FAMILY_TO_BATCH.get(family, "unknown")

def get_families_in_batch(batch_name: str) -> list:
    """Get all families in a specific batch."""
    return TRAINING_BATCHES.get(batch_name, {}).get("families", [])

def print_batch_summary():
    """Print summary of all training batches."""
    print("=" * 60)
    print("TRAINING BATCH SUMMARY")
    print("=" * 60)
    
    total_samples = 0
    for batch_name, batch_info in TRAINING_BATCHES.items():
        print(f"\n{batch_name}:")
        print(f"  Description: {batch_info['description']}")
        print(f"  Priority: {batch_info['priority']}")
        print(f"  Families ({len(batch_info['families'])}): {', '.join(batch_info['families'])}")
        print(f"  Estimated Samples: {batch_info['estimated_samples']}")
        total_samples += batch_info['estimated_samples']
    
    print(f"\n{'=' * 60}")
    print(f"Total Families: {len(ALL_FAMILIES)}")
    print(f"Total Estimated Samples: {total_samples}")
    print("=" * 60)

if __name__ == "__main__":
    print_batch_summary()

