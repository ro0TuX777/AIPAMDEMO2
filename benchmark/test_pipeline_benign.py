#!/usr/bin/env python3
"""Test all benign PCAPs through the full AIPAM pipeline (Zeek + Suricata + LLM).

Submits each benign PCAP via the API, waits for completion, and extracts the
pipeline's classification to measure the effective false positive rate.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

API_BASE = os.environ.get("AIPAM_API_BASE", "http://localhost:8000/api/v1")

# Known benign classification strings (case-insensitive)
BENIGN_LABELS = {"benign", "normal", "legitimate", "clean"}


def submit_pcap(pcap_path: str) -> str:
    """Submit a single PCAP through the pipeline. Returns job_id."""
    with open(pcap_path, "rb") as f:
        files = {"pcap_files": (os.path.basename(pcap_path), f, "application/octet-stream")}
        data = {"mode": "single_window", "metadata": json.dumps({})}
        resp = requests.post(f"{API_BASE}/jobs", files=files, data=data, timeout=60)
    resp.raise_for_status()
    return resp.json()["job_id"]


def wait_for_job(job_id: str, timeout: int = 600, poll_interval: int = 5) -> dict:
    """Poll until job completes or fails. Returns status response."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = requests.get(f"{API_BASE}/jobs/{job_id}", timeout=30)
        resp.raise_for_status()
        status_data = resp.json()
        status = status_data["status"]
        if status in ("completed", "failed"):
            return status_data
        time.sleep(poll_interval)
    return {"status": "timeout", "job_id": job_id}


def get_result(job_id: str) -> dict:
    """Fetch job result. Returns result dict or empty dict on error."""
    try:
        resp = requests.get(f"{API_BASE}/jobs/{job_id}/result", timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"    [ERROR] Failed to get result for {job_id}: {e}")
        return {}


def is_benign_classification(classification: str | None) -> bool:
    """Check if a classification string indicates benign traffic."""
    if not classification:
        return False
    return classification.strip().lower() in BENIGN_LABELS


def main():
    parser = argparse.ArgumentParser(description="Test benign PCAPs through full AIPAM pipeline")
    parser.add_argument("manifest", help="Path to benign benchmark manifest JSON")
    parser.add_argument("--timeout", type=int, default=600, help="Max wait per job (seconds)")
    parser.add_argument("--output", default="pipeline_benign_results", help="Output directory")
    parser.add_argument("--concurrency", type=int, default=1, help="Jobs to run concurrently (1=sequential)")
    args = parser.parse_args()

    with open(args.manifest) as f:
        manifest = json.load(f)

    samples = manifest["samples"]
    print(f"{'=' * 60}")
    print(f"AIPAM Pipeline Benign Benchmark")
    print(f"{'=' * 60}")
    print(f"API:     {API_BASE}")
    print(f"Samples: {len(samples)}")
    print(f"Timeout: {args.timeout}s per job")
    print(f"{'=' * 60}\n")

    results = []
    correct = 0
    failed_jobs = 0
    total = len(samples)

    for i, sample in enumerate(samples, 1):
        pcap_path = sample["pcap"]
        pcap_name = os.path.basename(pcap_path)
        expected = sample["label"]

        print(f"[{i}/{total}] {pcap_name}...", end=" ", flush=True)

        if not os.path.exists(pcap_path):
            print(f"❌ FILE NOT FOUND")
            results.append({"pcap": pcap_name, "expected": expected, "predicted": "FILE_NOT_FOUND",
                            "correct": False, "job_id": None, "severity": None, "time_s": 0})
            continue

        t0 = time.time()
        try:
            job_id = submit_pcap(pcap_path)
        except Exception as e:
            print(f"❌ SUBMIT FAILED: {e}")
            results.append({"pcap": pcap_name, "expected": expected, "predicted": "SUBMIT_ERROR",
                            "correct": False, "job_id": None, "severity": None, "time_s": 0})
            continue

        status_data = wait_for_job(job_id, timeout=args.timeout)
        elapsed = time.time() - t0

        if status_data["status"] == "failed":
            err = status_data.get("error_message", "unknown error")
            print(f"❌ JOB FAILED: {err} [{elapsed:.1f}s]")
            results.append({"pcap": pcap_name, "expected": expected, "predicted": "JOB_FAILED",
                            "correct": False, "job_id": job_id, "severity": None, "time_s": elapsed})
            failed_jobs += 1
            continue

        if status_data["status"] == "timeout":
            print(f"⏱️ TIMEOUT [{elapsed:.1f}s]")
            results.append({"pcap": pcap_name, "expected": expected, "predicted": "TIMEOUT",
                            "correct": False, "job_id": job_id, "severity": None, "time_s": elapsed})
            continue

        # Job completed - get result
        result = get_result(job_id)
        classification = result.get("summary", {}).get("classification", "Unknown")
        severity = result.get("summary", {}).get("severity", "unknown")
        is_correct = is_benign_classification(classification)

        if is_correct:
            correct += 1
            print(f"✅ Benign (sev={severity}) [{elapsed:.1f}s]")
        else:
            print(f"❌ {classification} (sev={severity}) [{elapsed:.1f}s]")

        results.append({"pcap": pcap_name, "expected": expected, "predicted": classification,
                        "correct": is_correct, "job_id": job_id, "severity": severity, "time_s": elapsed})

    # Summary
    evaluated = total - failed_jobs
    benign_rate = (correct / evaluated * 100) if evaluated > 0 else 0
    fp_rate = 100 - benign_rate
    valid_times = [r["time_s"] for r in results if r["time_s"] > 0]
    avg_time = sum(valid_times) / max(1, len(valid_times))

    print(f"\n{'=' * 60}")
    print(f"PIPELINE BENIGN BENCHMARK SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total Samples:          {total}")
    print(f"  Evaluated (non-failed): {evaluated}")
    print(f"  Correctly Benign:       {correct}")
    print(f"  Benign Detection Rate:  {benign_rate:.1f}%")
    print(f"  False Positive Rate:    {fp_rate:.1f}%")
    print(f"  Failed Jobs:            {failed_jobs}")
    print(f"  Avg Pipeline Time:      {avg_time:.1f}s")

    # Misclassification breakdown
    misclassified = [r for r in results if not r["correct"] and r["predicted"] not in ("FILE_NOT_FOUND", "SUBMIT_ERROR", "JOB_FAILED", "TIMEOUT")]
    if misclassified:
        print(f"\n  False Positive Breakdown:")
        from collections import Counter
        fp_counts = Counter(r["predicted"] for r in misclassified)
        for label, count in fp_counts.most_common():
            print(f"    {label}: {count}")

    # Save report
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "benchmark": "benign_pipeline",
        "timestamp": datetime.now().isoformat(),
        "api_base": API_BASE,
        "total_samples": total,
        "evaluated": evaluated,
        "correct_benign": correct,
        "benign_detection_rate": round(benign_rate, 2),
        "false_positive_rate": round(fp_rate, 2),
        "failed_jobs": failed_jobs,
        "avg_pipeline_time_s": round(avg_time, 2),
        "results": results,
    }
    report_path = out_dir / f"pipeline_benign_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved: {report_path}")

    # Compare with raw model benchmark
    print(f"\n{'=' * 60}")
    print(f"COMPARISON: Raw Model vs Full Pipeline")
    print(f"{'=' * 60}")
    print(f"  Raw Model Benign Detection:  3.7% (1/27)")
    print(f"  Full Pipeline Benign Detection: {benign_rate:.1f}% ({correct}/{evaluated})")
    improvement = benign_rate - 3.7
    print(f"  Improvement: {'+' if improvement >= 0 else ''}{improvement:.1f}%")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()

