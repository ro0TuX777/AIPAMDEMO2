#!/usr/bin/env python3
"""
Evaluate Benchmark Using External APIs (e.g., GPT, Claude)

This script evaluates the benchmark dataset using external APIs like GPT or Claude.
It sends `.pcap` metadata or content to the API and collects predictions for evaluation.
"""

import os
import json
import argparse
import time
from pathlib import Path
from typing import Dict, List, Optional
import requests

# API Configuration
API_URL = "https://api.openai.com/v1/chat/completions"  # OpenAI API endpoint
API_KEY = "REMOVED_OPENAI_API_KEY"  # Replace with your API key

# Benchmark Manifest
BENCHMARK_MANIFEST = "benchmark/manifests/trained_families_benchmark.json"

# Output File
OUTPUT_RESULTS = "benchmark/results_with_apis.json"

def call_api(pcap_metadata: Dict) -> Dict:
    """Call the OpenAI API with pcap metadata."""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "gpt-4",  # Specify the OpenAI model
        "messages": [
            {"role": "system", "content": "You are a cybersecurity assistant."},
            {"role": "user", "content": f"Analyze the following PCAP metadata and predict its label: {json.dumps(pcap_metadata)}"}
        ],
        "temperature": 0.7
    }
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        prediction = data["choices"][0]["message"]["content"].strip()
        return {"prediction": prediction, "confidence": 0.5}  # Placeholder confidence
    except requests.RequestException as e:
        print(f"Error calling API: {e}")
        return {"error": str(e)}

def evaluate_benchmark():
    """Evaluate the benchmark using the external API."""
    # Load benchmark manifest
    with open(BENCHMARK_MANIFEST, "r") as f:
        benchmark_data = json.load(f)
        benchmark_samples = benchmark_data.get("samples", [])

    results = []

    for sample in benchmark_samples:
        pcap_path = sample.get("pcap")
        ground_truth = sample.get("label")

        # Prepare metadata for API
        pcap_metadata = {
            "pcap_path": pcap_path,
            "ground_truth": ground_truth,
        }

        print(f"Evaluating: {pcap_path}")
        start_time = time.time()

        # Call the API
        api_response = call_api(pcap_metadata)

        # Record result
        result = {
            "pcap_path": pcap_path,
            "ground_truth": ground_truth,
            "prediction": api_response.get("prediction"),
            "confidence": api_response.get("confidence"),
            "is_correct": api_response.get("prediction") == ground_truth,
            "is_malicious_correct": (ground_truth == "malicious") == (api_response.get("prediction") == "malicious"),
            "error": api_response.get("error"),
            "inference_time": time.time() - start_time,
        }
        results.append(result)

        # Print the API response for this sample
        print(f"Prediction: {api_response.get('prediction')}, Confidence: {api_response.get('confidence')}")

    # Save results
    with open(OUTPUT_RESULTS, "w") as f:
        json.dump(results, f, indent=4)

    print(f"Results saved to {OUTPUT_RESULTS}")
    print(f"Total samples evaluated: {len(results)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate Benchmark Using External APIs")
    parser.add_argument(
        "--manifest",
        type=str,
        default=BENCHMARK_MANIFEST,
        help="Path to the benchmark manifest file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=OUTPUT_RESULTS,
        help="Path to save the evaluation results",
    )
    args = parser.parse_args()

    # Update paths if provided
    BENCHMARK_MANIFEST = args.manifest
    OUTPUT_RESULTS = args.output

    evaluate_benchmark()