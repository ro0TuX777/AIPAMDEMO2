#!/usr/bin/env python3
"""
AIPAM Benchmark Inference Module

Standalone inference for running the fine-tuned model on PCAP files.
Supports both direct LoRA loading and Ollama-based inference.
"""

import os
import sys
import json
import argparse
import binascii
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.run(["pip", "install", "scapy", "-q"])
    from scapy.all import rdpcap, IP, TCP, UDP

import httpx


@dataclass
class InferenceConfig:
    """Configuration for inference."""
    endpoint: str = "http://localhost:11434/v1/chat/completions"
    model: str = "aipam-trafficllm-v4"  # Fine-tuned model name in Ollama
    temperature: float = 0.1
    max_tokens: int = 100
    timeout_seconds: float = 120.0


# Malware categories - MUST MATCH EXACT training format from preprocess_pcaps.py
# This is the exact string used in training data generation
MALWARE_CATEGORIES = [
    "BitTorrent", "FTP", "Facetime", "Gmail", "MySQL", "Outlook", "SMB",
    "Skype", "Weibo", "WorldOfWarcraft", "Cridex", "Geodo", "Htbot",
    "Miuref", "Neris", "Nsis-ay", "Shifu", "Tinba", "Virut", "Zeus",
    "IcedID", "Qakbot", "Emotet", "TrickBot", "Formbook", "CobaltStrike",
    "BazarLoader", "DarkGate", "Ursnif", "Pikabot", "BumbleBee", "Matanbuchus",
    "Astaroth", "AgentTesla", "Lumma_Stealer", "Danabot", "SSLoad",
    "Remcos_RAT", "Sliver", "Latrodectus", "NetSupport_RAT", "Redline_Stealer",
    "SocGholish", "Raccoon", "Meduza_Stealer", "GuLoader", "AsyncRAT"
]

# Additional categories for parsing responses (not in prompt, but model might output)
EXTRA_CATEGORIES_FOR_PARSING = [
    "Hancitor", "RigEK", "AnglerEK", "Cerber", "Locky", "Necurs", "StealC",
    "NeutrinoEK", "Nymaim", "Pony", "Dridex", "XWorm", "XLoader", "Vawtrak"
]

# System prompt for inference - zero-day & forensic focus
SYSTEM_PROMPT = """You are an expert cybersecurity analyst specialized in forensic network traffic analysis and zero-day threat hunting.
Your goal is to identify both known malware families and novel, anomalous malicious activities.
For every packet or flow analyzed, provide:
1. **Classification**: The likely malware family, benign category, or 'Anomalous/Zero-Day' if it shows malicious intent without matching a known signature.
2. **Confidence**: Your level of certainty.
3. **Forensic Evidence**: Specific indicators (e.g., non-standard protocol state, high-entropy fields, unusual TLS extensions, novel obfuscation).
4. **Zero-Day Indicators**: Explicitly flag any behavior that suggests a novel exploit or unreported C2 pattern.
5. **MITRE ATT&CK Mapping**: Relevant techniques and tactics.
6. **Contextual Analysis**: Its place in the attack chain (e.g., Initial Access, C2)."""

# Instruction template for zero-day investigation
INSTRUCTION_TEMPLATE = """Conduct a detailed ZERO-DAY FORENSIC ANALYSIS on the following traffic data <packet>.
Determine if this traffic is Benign or Malicious. 

If malicious:
1. Check if it matches any known category: '{categories}'.
2. If it displays malicious intent (e.g., exploit patterns, C2 behavior) but does NOT match a known category, classify it as 'Anomalous/Zero-Day'.

Provide your findings in a structured format:
- CLASSIFICATION: [Category Name or 'Anomalous/Zero-Day']
- REASONING: [Detailed forensic evidence, anomaly justification, and MITRE mappings]

<packet>: {packet_data}"""

# Build a set of known categories for extraction (case-insensitive)
# Include both training categories and extra categories for response parsing
ALL_CATEGORIES_FOR_PARSING = MALWARE_CATEGORIES + EXTRA_CATEGORIES_FOR_PARSING
KNOWN_CATEGORIES_LOWER = {cat.lower(): cat for cat in ALL_CATEGORIES_FOR_PARSING}
# Add common variations and aliases
KNOWN_CATEGORIES_LOWER.update({
    "botnet": "Botnet",
    "ransomware": "Ransomware",
    "trojan": "Trojan",
    "malware": "Malware",
    "benign": "Benign",
    "unknown": "unknown",
    # Common aliases
    "rig_ek": "RigEK",
    "rig ek": "RigEK",
    "angler_ek": "AnglerEK",
    "angler ek": "AnglerEK",
    "neutrino_ek": "NeutrinoEK",
    "neutrino ek": "NeutrinoEK",
    "lumma": "Lumma_Stealer",
    "stealc": "StealC",
    "steal_c": "StealC",
    "xworm": "XWorm",
    "x_worm": "XWorm",
    "xloader": "XLoader",
    "x_loader": "XLoader",
})


def extract_classification(content: str) -> str:
    """Extract the malware classification from model response.

    Handles various response formats:
    - Single word: "Emotet"
    - Verbose: "This might be a Malware traffic packet. The category is likely to be recognized as Pikabot."
    - Sentence: "The traffic appears to be Emotet malware."
    """
    if not content:
        return "unknown"

    content_lower = content.lower()

    # First, check if the entire response is just a category name
    content_clean = content.strip().strip('."\',:;')
    if content_clean.lower() in KNOWN_CATEGORIES_LOWER:
        return KNOWN_CATEGORIES_LOWER[content_clean.lower()]

    # Look for known categories in the response
    found_categories = []
    for cat_lower, cat_original in KNOWN_CATEGORIES_LOWER.items():
        # Skip generic terms when looking for specific families
        if cat_lower in ["botnet", "ransomware", "trojan", "malware", "benign", "unknown"]:
            continue
        # Check for word boundary matches
        import re
        pattern = r'\b' + re.escape(cat_lower) + r'\b'
        if re.search(pattern, content_lower):
            found_categories.append(cat_original)

    if found_categories:
        # Return the first specific category found
        return found_categories[0]

    # Check for generic categories as fallback
    for generic in ["botnet", "ransomware", "trojan", "malware"]:
        if generic in content_lower:
            return KNOWN_CATEGORIES_LOWER[generic]

    # Check for error/invalid responses
    error_phrases = ["not a valid", "cannot", "unable", "error", "invalid", "i'm afraid"]
    if any(phrase in content_lower for phrase in error_phrases):
        return "unknown"

    # Last resort: return first word if it looks like a category
    first_word = content.split()[0].strip('."\',:;') if content.split() else "unknown"
    # Only return first word if it's capitalized (likely a category name)
    if first_word and first_word[0].isupper() and len(first_word) > 2:
        return first_word
    return "unknown"


def extract_packet_features(pcap_path: str, max_packets: int = 50) -> List[str]:
    """Extract packet features from a PCAP file using Scapy.

    IMPORTANT: This function now matches the training data format from
    finetuning/trafficllm_training/preprocess_pcaps.py to ensure consistency.

    Args:
        pcap_path: Path to the PCAP file
        max_packets: Maximum number of packets to extract

    Returns:
        List of packet feature strings in the training format
    """
    packets_data = []
    MAX_PACKET_LENGTH = 1024  # Match training

    try:
        # Read packets - match training approach (read more, filter to max_packets)
        pkts = rdpcap(pcap_path, count=max_packets * 3)

        extracted_count = 0
        for pkt in pkts:
            if extracted_count >= max_packets:
                break

            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            fields = []

            # IP layer fields - match training format
            fields.append(f"ip.version: {ip.version}")
            fields.append(f"ip.len: {ip.len}")
            fields.append(f"ip.ttl: {ip.ttl}")
            fields.append(f"ip.proto: {ip.proto}")
            fields.append(f"ip.src: {ip.src}")
            fields.append(f"ip.dst: {ip.dst}")

            # TCP layer - MUST MATCH training format from preprocess_pcaps.py
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                fields.append(f"tcp.srcport: {tcp.sport}")
                fields.append(f"tcp.dstport: {tcp.dport}")
                fields.append(f"tcp.seq: {tcp.seq}")
                fields.append(f"tcp.ack: {tcp.ack}")  # CRITICAL: was missing, required for training format match
                fields.append(f"tcp.flags: {tcp.flags}")
                fields.append(f"tcp.window: {tcp.window}")

                # Payload
                if tcp.payload:
                    payload_bytes = bytes(tcp.payload)[:256]
                    payload_hex = binascii.hexlify(payload_bytes).decode()[:512]
                    fields.append(f"tcp.payload: {payload_hex}")

            # UDP layer
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                fields.append(f"udp.srcport: {udp.sport}")
                fields.append(f"udp.dstport: {udp.dport}")
                fields.append(f"udp.len: {udp.len}")

                if udp.payload:
                    payload_bytes = bytes(udp.payload)[:256]
                    payload_hex = binascii.hexlify(payload_bytes).decode()[:512]
                    fields.append(f"udp.payload: {payload_hex}")
            else:
                continue  # Skip non-TCP/UDP packets (match training)

            packet_str = ", ".join(fields)
            if len(packet_str) < MAX_PACKET_LENGTH:  # Match training limit
                packets_data.append(packet_str)
                extracted_count += 1

    except Exception as e:
        print(f"Error reading PCAP {pcap_path}: {e}")

    return packets_data


def format_prompt(packet_data: str) -> str:
    """Format packet data into the prompt template."""
    categories = ", ".join(MALWARE_CATEGORIES)
    return INSTRUCTION_TEMPLATE.format(categories=categories, packet_data=packet_data)


async def run_inference_ollama(
    packet_data: str,
    config: InferenceConfig
) -> Tuple[str, float]:
    """Run inference using Ollama API.
    
    Returns:
        Tuple of (classification, confidence)
    """
    prompt = format_prompt(packet_data)
    
    payload = {
        "model": config.model,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }
    
    try:
        async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
            resp = await client.post(config.endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
            
        content = data["choices"][0]["message"]["content"].strip()

        # Extract classification from response
        classification = extract_classification(content)

        return classification, 1.0  # Confidence placeholder
        
    except Exception as e:
        print(f"Inference error: {e}")
        return "error", 0.0


def run_inference_sync(packet_data: str, config: InferenceConfig) -> Tuple[str, float]:
    """Synchronous wrapper for inference."""
    import asyncio
    return asyncio.run(run_inference_ollama(packet_data, config))


def analyze_pcap(
    pcap_path: str,
    config: Optional[InferenceConfig] = None,
    num_packets: int = 10,
    aggregate: bool = True
) -> Dict:
    """Analyze a PCAP file and return classification results.

    Args:
        pcap_path: Path to the PCAP file
        config: Inference configuration (uses defaults if None)
        num_packets: Number of packets to analyze
        aggregate: If True, aggregate results; if False, return per-packet

    Returns:
        Dict with classification results
    """
    if config is None:
        config = InferenceConfig()

    # Extract packet features
    packets = extract_packet_features(pcap_path, max_packets=num_packets)

    if not packets:
        return {
            "pcap": pcap_path,
            "status": "error",
            "error": "No valid packets extracted",
            "classification": "unknown",
            "confidence": 0.0
        }

    results = []
    for i, packet_data in enumerate(packets):
        classification, confidence = run_inference_sync(packet_data, config)
        results.append({
            "packet_index": i,
            "classification": classification,
            "confidence": confidence
        })

    if aggregate:
        # Aggregate by majority vote
        from collections import Counter
        classifications = [r["classification"] for r in results]
        vote_counts = Counter(classifications)
        top_classification, top_count = vote_counts.most_common(1)[0]

        return {
            "pcap": pcap_path,
            "status": "success",
            "classification": top_classification,
            "confidence": top_count / len(results),
            "vote_distribution": dict(vote_counts),
            "packets_analyzed": len(results)
        }
    else:
        return {
            "pcap": pcap_path,
            "status": "success",
            "per_packet_results": results,
            "packets_analyzed": len(results)
        }


def main():
    """CLI entry point for inference."""
    parser = argparse.ArgumentParser(description="AIPAM Benchmark Inference")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--model", default="aipam-trafficllm-v4", help="Ollama model name")
    parser.add_argument("--endpoint", default="http://localhost:11434/v1/chat/completions")
    parser.add_argument("--packets", type=int, default=10, help="Number of packets to analyze")
    parser.add_argument("--no-aggregate", action="store_true", help="Return per-packet results")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    config = InferenceConfig(
        endpoint=args.endpoint,
        model=args.model
    )

    result = analyze_pcap(
        args.pcap,
        config=config,
        num_packets=args.packets,
        aggregate=not args.no_aggregate
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nPCAP: {result['pcap']}")
        print(f"Status: {result['status']}")
        if result['status'] == 'success':
            print(f"Classification: {result['classification']}")
            print(f"Confidence: {result.get('confidence', 'N/A'):.2%}")
            if 'vote_distribution' in result:
                print(f"Vote Distribution: {result['vote_distribution']}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")


if __name__ == "__main__":
    main()

