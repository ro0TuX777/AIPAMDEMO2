#!/usr/bin/env python3
"""
AIPAM Benchmark Evaluation Script

Runs batch evaluation on a benchmark dataset and calculates metrics.
"""

import os
import sys
import json
import argparse
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from inference import InferenceConfig, analyze_pcap, MALWARE_CATEGORIES


@dataclass
class BenchmarkResult:
    """Results for a single benchmark sample."""
    pcap_path: str
    ground_truth: str
    prediction: str
    confidence: float
    is_correct: bool
    is_malicious_correct: bool  # Correct on malicious vs benign
    inference_time: float
    error: Optional[str] = None


@dataclass
class BenchmarkReport:
    """Aggregated benchmark report."""
    timestamp: str
    model_name: str
    total_samples: int
    correct: int
    accuracy: float
    malicious_detection_accuracy: float  # Binary: malicious vs benign
    type_accuracy: float = 0.0  # Accuracy on malware type (Loader, Stealer, RAT, etc.)
    precision_per_family: Dict[str, float] = field(default_factory=dict)
    recall_per_family: Dict[str, float] = field(default_factory=dict)
    f1_per_family: Dict[str, float] = field(default_factory=dict)
    confusion_matrix: Dict[str, Dict[str, int]] = field(default_factory=dict)
    type_confusion_matrix: Dict[str, Dict[str, int]] = field(default_factory=dict)
    avg_inference_time: float = 0.0
    results: List[BenchmarkResult] = field(default_factory=list)


# Malware family to type mapping - for type-level accuracy
FAMILY_TO_TYPE = {
    # Infostealers
    "AgentTesla": "Infostealer",
    "Lumma_Stealer": "Infostealer",
    "Redline_Stealer": "Infostealer",
    "Meduza_Stealer": "Infostealer",
    "StealC": "Infostealer",
    "Formbook": "Infostealer",
    "XLoader": "Infostealer",
    "Raccoon": "Infostealer",

    # Loaders
    "BazarLoader": "Loader",
    "GuLoader": "Loader",
    "Pikabot": "Loader",
    "Latrodectus": "Loader",
    "Matanbuchus": "Loader",
    "SocGholish": "Loader",
    "SSLoad": "Loader",
    "DarkGate": "Loader",
    "BumbleBee": "Loader",
    "SmartApeSG": "Loader",

    # RATs
    "AsyncRAT": "RAT",
    "Remcos_RAT": "RAT",
    "NetSupport_RAT": "RAT",
    "XWorm": "RAT",
    "NanoCore": "RAT",

    # Banking Trojans
    "IcedID": "Banking_Trojan",
    "Danabot": "Banking_Trojan",
    "Ursnif": "Banking_Trojan",
    "Astaroth": "Banking_Trojan",
    "Emotet": "Banking_Trojan",
    "Qakbot": "Banking_Trojan",
    "TrickBot": "Banking_Trojan",
    "Zeus": "Banking_Trojan",
    "Cridex": "Banking_Trojan",

    # C2 Frameworks
    "CobaltStrike": "C2_Framework",
    "Sliver": "C2_Framework",

    # Exploit Kits
    "RigEK": "Exploit_Kit",

    # Ransomware
    "CryptoWall": "Ransomware",
    "Locky": "Ransomware",
    "WannaCry": "Ransomware",
    "Cerber": "Ransomware",
}


def get_malware_type(family: str) -> str:
    """Get the malware type for a family name."""
    normalized = normalize_category(family)
    return FAMILY_TO_TYPE.get(normalized, "Unknown")


# Known benign categories
BENIGN_CATEGORIES = {
    "BitTorrent", "FTP", "Facetime", "Gmail", "MySQL", "Outlook", "SMB",
    "Skype", "Weibo", "WorldOfWarcraft", "aim", "bittorrent", "email",
    "facebook", "ftps", "hangout", "icq", "netflix", "sftp", "skype",
    "spotify", "vimeo", "voipbuster", "youtube"
}


def is_malicious(category: str) -> bool:
    """Determine if a category is malicious."""
    return category.lower() not in {c.lower() for c in BENIGN_CATEGORIES}


def normalize_category(category: str) -> str:
    """Normalize category name for comparison."""
    # Handle common variations
    mappings = {
        "lumma": "Lumma_Stealer",
        "lumma_stealer": "Lumma_Stealer", 
        "agent_tesla": "AgentTesla",
        "agenttesla": "AgentTesla",
        "cobalt_strike": "CobaltStrike",
        "cobaltstrike": "CobaltStrike",
        "icedid": "IcedID",
        "iced_id": "IcedID",
        "trickbot": "TrickBot",
        "trick_bot": "TrickBot",
        "darkgate": "DarkGate",
        "dark_gate": "DarkGate",
        "bazarloader": "BazarLoader",
        "bazar_loader": "BazarLoader",
        "remcos": "Remcos_RAT",
        "remcos_rat": "Remcos_RAT",
        "netsupport": "NetSupport_RAT",
        "netsupport_rat": "NetSupport_RAT",
        "redline": "Redline_Stealer",
        "redline_stealer": "Redline_Stealer",
        "meduza": "Meduza_Stealer",
        "meduza_stealer": "Meduza_Stealer",
        "ssload": "SSLoad",
        "ss_load": "SSLoad",
        "socgholish": "SocGholish",
        "soc_gholish": "SocGholish",
        "asyncrat": "AsyncRAT",
        "async_rat": "AsyncRAT",
    }
    
    normalized = category.lower().strip()
    return mappings.get(normalized, category)


def load_benchmark_manifest(manifest_path: str) -> List[Dict]:
    """Load benchmark manifest file.
    
    Expected format:
    {
        "samples": [
            {"pcap": "path/to/file.pcap", "label": "Emotet", "set": "benchmark"},
            ...
        ]
    }
    """
    with open(manifest_path, 'r') as f:
        data = json.load(f)
    return data.get("samples", data)  # Support both formats


def run_benchmark(
    manifest_path: str,
    config: InferenceConfig,
    output_dir: str = "benchmark_results",
    limit: Optional[int] = None,
    filter_set: Optional[str] = None
) -> BenchmarkReport:
    """Run benchmark evaluation on all samples in manifest.
    
    Args:
        manifest_path: Path to benchmark manifest JSON
        config: Inference configuration
        output_dir: Directory to save results
        limit: Maximum number of samples to evaluate (None = all)
        filter_set: Only evaluate samples from this set (e.g., "benchmark", "leakage")
    """
    samples = load_benchmark_manifest(manifest_path)
    
    if filter_set:
        samples = [s for s in samples if s.get("set") == filter_set]
        
    if limit:
        samples = samples[:limit]
        
    print(f"\n{'='*60}")
    print(f"AIPAM Benchmark Evaluation")
    print(f"{'='*60}")
    print(f"Model: {config.model}")
    print(f"Samples: {len(samples)}")
    print(f"{'='*60}\n")
    
    results = []
    correct = 0
    malicious_correct = 0
    type_correct = 0
    inference_times = []

    # Track predictions per class for precision/recall
    true_positives = Counter()
    false_positives = Counter()
    false_negatives = Counter()
    confusion = {}
    type_confusion = {}  # Type-level confusion matrix
    
    for i, sample in enumerate(samples):
        pcap_path = sample["pcap"]
        ground_truth = normalize_category(sample["label"])
        
        print(f"[{i+1}/{len(samples)}] {Path(pcap_path).name}...", end=" ", flush=True)
        
        start_time = time.time()
        try:
            result = analyze_pcap(pcap_path, config=config, num_packets=10)
            prediction = normalize_category(result.get("classification", "unknown"))
            confidence = result.get("confidence", 0.0)
            error = None if result["status"] == "success" else result.get("error")
        except Exception as e:
            prediction = "error"
            confidence = 0.0
            error = str(e)
        inference_time = time.time() - start_time
        inference_times.append(inference_time)

        # Check correctness
        is_exact_match = prediction.lower() == ground_truth.lower()
        is_malicious_match = is_malicious(prediction) == is_malicious(ground_truth)

        # Check type-level accuracy (Loader, Stealer, RAT, etc.)
        expected_type = get_malware_type(ground_truth)
        predicted_type = get_malware_type(prediction)
        is_type_match = expected_type == predicted_type and expected_type != "Unknown"

        if is_exact_match:
            correct += 1
            true_positives[ground_truth] += 1
        else:
            false_positives[prediction] += 1
            false_negatives[ground_truth] += 1

        if is_malicious_match:
            malicious_correct += 1

        if is_type_match:
            type_correct += 1

        # Update confusion matrix
        if ground_truth not in confusion:
            confusion[ground_truth] = {}
        confusion[ground_truth][prediction] = confusion[ground_truth].get(prediction, 0) + 1

        # Update type confusion matrix
        if expected_type not in type_confusion:
            type_confusion[expected_type] = {}
        type_confusion[expected_type][predicted_type] = type_confusion[expected_type].get(predicted_type, 0) + 1

        # Show type info in output for better insight
        type_status = "T" if is_type_match else "t"
        status = "✅" if is_exact_match else ("⚠️" if is_malicious_match else "❌")
        print(f"{status} {prediction} (expected: {ground_truth}) [{inference_time:.1f}s]")

        results.append(BenchmarkResult(
            pcap_path=pcap_path,
            ground_truth=ground_truth,
            prediction=prediction,
            confidence=confidence,
            is_correct=is_exact_match,
            is_malicious_correct=is_malicious_match,
            inference_time=inference_time,
            error=error
        ))

    # Calculate per-family metrics
    all_families = set(true_positives.keys()) | set(false_positives.keys()) | set(false_negatives.keys())
    precision_per_family = {}
    recall_per_family = {}
    f1_per_family = {}

    for family in all_families:
        tp = true_positives[family]
        fp = false_positives[family]
        fn = false_negatives[family]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        precision_per_family[family] = precision
        recall_per_family[family] = recall
        f1_per_family[family] = f1

    # Build report
    report = BenchmarkReport(
        timestamp=datetime.now().isoformat(),
        model_name=config.model,
        total_samples=len(samples),
        correct=correct,
        accuracy=correct / len(samples) if samples else 0.0,
        malicious_detection_accuracy=malicious_correct / len(samples) if samples else 0.0,
        type_accuracy=type_correct / len(samples) if samples else 0.0,
        precision_per_family=precision_per_family,
        recall_per_family=recall_per_family,
        f1_per_family=f1_per_family,
        confusion_matrix=confusion,
        type_confusion_matrix=type_confusion,
        avg_inference_time=sum(inference_times) / len(inference_times) if inference_times else 0.0,
        results=results
    )

    # Save report
    os.makedirs(output_dir, exist_ok=True)
    report_path = Path(output_dir) / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    report_dict = {
        "timestamp": report.timestamp,
        "model_name": report.model_name,
        "total_samples": report.total_samples,
        "correct": report.correct,
        "accuracy": report.accuracy,
        "malicious_detection_accuracy": report.malicious_detection_accuracy,
        "type_accuracy": report.type_accuracy,
        "avg_inference_time": report.avg_inference_time,
        "precision_per_family": report.precision_per_family,
        "recall_per_family": report.recall_per_family,
        "f1_per_family": report.f1_per_family,
        "confusion_matrix": report.confusion_matrix,
        "type_confusion_matrix": report.type_confusion_matrix,
        "results": [
            {
                "pcap": r.pcap_path,
                "ground_truth": r.ground_truth,
                "prediction": r.prediction,
                "confidence": r.confidence,
                "is_correct": r.is_correct,
                "inference_time": r.inference_time,
                "error": r.error
            }
            for r in report.results
        ]
    }

    with open(report_path, 'w') as f:
        json.dump(report_dict, f, indent=2)

    # Print summary
    print(f"\n{'='*60}")
    print("BENCHMARK SUMMARY")
    print(f"{'='*60}")
    print(f"Total Samples: {report.total_samples}")
    print(f"Correct: {report.correct}")
    print(f"\n--- Accuracy Metrics ---")
    print(f"Malicious Detection Accuracy: {report.malicious_detection_accuracy:.2%}")
    print(f"Type Accuracy (Loader/Stealer/RAT/etc): {report.type_accuracy:.2%}")
    print(f"Exact Family Match Accuracy: {report.accuracy:.2%}")
    print(f"\n--- Performance ---")
    print(f"Avg Inference Time: {report.avg_inference_time:.2f}s")

    # Print type confusion summary
    if type_confusion:
        print(f"\n--- Type Confusion Matrix ---")
        for expected_t, predictions in sorted(type_confusion.items()):
            pred_str = ", ".join(f"{p}:{c}" for p, c in sorted(predictions.items(), key=lambda x: -x[1]))
            print(f"  {expected_t}: {pred_str}")

    print(f"\nReport saved to: {report_path}")

    return report


def main():
    parser = argparse.ArgumentParser(description="AIPAM Benchmark Evaluation")
    parser.add_argument("manifest", help="Path to benchmark manifest JSON")
    parser.add_argument("--model", default="aipam-trafficllm-v4", help="Ollama model name")
    parser.add_argument("--endpoint", default="http://localhost:11434/v1/chat/completions")
    parser.add_argument("--output", default="benchmark_results", help="Output directory")
    parser.add_argument("--limit", type=int, help="Limit number of samples")
    parser.add_argument("--set", dest="filter_set", help="Filter by set (benchmark, leakage, etc)")

    args = parser.parse_args()

    config = InferenceConfig(endpoint=args.endpoint, model=args.model)

    run_benchmark(
        args.manifest,
        config=config,
        output_dir=args.output,
        limit=args.limit,
        filter_set=args.filter_set
    )


if __name__ == "__main__":
    main()

