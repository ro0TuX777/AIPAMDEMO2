#!/usr/bin/env python3
"""
Verify Model Bias & Accuracy

This script loads the fine-tuned model and runs inference on the validation set.
It calculates:
1. Overall Accuracy
2. Per-Family Accuracy (Precision/Recall)
3. Specific checks for 'Loader' bias (e.g., Pikabot vs IcedID)
4. Hallucinated Citation Rate (HCR) — Phase 6.1 ORPO metric
5. Teacher vs Student Retention Rate — Phase 6.3 Distillation metric
6. Reasoning Entropy (RE) — Phase 6.5 LocFT metric

Usage:
    python verify_model_bias.py --model models/aipam-llama --data models/aipam-llama-balanced/valid.jsonl
    python verify_model_bias.py --model aipam-edge-1b-v6 --compare-teacher --teacher-model llama-3.1-8b-bnb-4bit
    python verify_model_bias.py --test-entropy  # Unit test for entropy computation
"""

import argparse
import json
import math
import re
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple

def extract_classification_from_text(text: str) -> str:
    """Extract classification from model response text."""
    # 1. Try JSON parsing first (most robust)
    try:
        # cleanup markdown code blocks if present
        clean_text = text.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_text)
        if "classification" in data:
            # Check for attack_type or classification
            if data.get("classification") == "malicious" and data.get("attack_type"):
                return data["attack_type"]
            return data["classification"]
    except json.JSONDecodeError:
        pass

    # 2. Regex fallbacks
    # Look for JSON-like "classification": "value" pattern first
    json_match = re.search(r'"classification":\s*"([^"]+)"', text)
    if json_match:
        return json_match.group(1)
    
    # Fallback: Look for "Classification: value"
    text_match = re.search(r'Classification:\s*([^\n]+)', text, re.IGNORECASE)
    if text_match:
        return text_match.group(1).strip()
        
    return "unknown"


# =============================================================================
# Phase 6.1 — Hallucinated Citation Rate (HCR) Metric
# =============================================================================

IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
MITRE_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')


def extract_evidence_markers(text: str) -> Tuple[Set[str], Set[str]]:
    """Extract IP addresses and MITRE technique IDs from text.

    Returns:
        Tuple of (set of IPs, set of MITRE IDs).
    """
    ips = set(IP_PATTERN.findall(text))
    mitre_ids = set(MITRE_PATTERN.findall(text))
    return ips, mitre_ids


def compute_hallucination_rate(
    prompt_text: str,
    response_text: str,
) -> Dict:
    """Compute hallucinated citation metrics for a single response.

    Checks if the model response cites IPs or MITRE technique IDs
    that do not appear anywhere in the input prompt.

    Returns:
        Dict with hallucination details.
    """
    prompt_ips, prompt_mitre = extract_evidence_markers(prompt_text)
    resp_ips, resp_mitre = extract_evidence_markers(response_text)

    # IPs in response but not in prompt = hallucinated
    hallucinated_ips = resp_ips - prompt_ips
    # MITRE IDs in response but using clearly invalid range (T9xxx)
    hallucinated_mitre = {m for m in resp_mitre if m.startswith("T9")}
    # Also check MITRE IDs that aren't in prompt
    novel_mitre = resp_mitre - prompt_mitre

    return {
        "total_ips_cited": len(resp_ips),
        "hallucinated_ips": len(hallucinated_ips),
        "hallucinated_ip_list": sorted(hallucinated_ips),
        "total_mitre_cited": len(resp_mitre),
        "hallucinated_mitre": len(hallucinated_mitre),
        "novel_mitre": len(novel_mitre),
        "hallucinated_mitre_list": sorted(hallucinated_mitre),
        "has_hallucination": len(hallucinated_ips) > 0 or len(hallucinated_mitre) > 0,
    }


# =============================================================================
# Phase 6.5 — Reasoning Entropy (RE) Metric
# =============================================================================

def compute_reasoning_entropy(probs: List[float]) -> float:
    """Compute Shannon entropy of a probability distribution.

    Measures the diversity of the model's output token distribution.
    Low entropy = model is "narrow-minded" (entropy collapse).
    High entropy = model maintains diverse reasoning capacity.

    Args:
        probs: List of probabilities (must be non-negative, should sum to ~1.0).

    Returns:
        Shannon entropy in bits.
    """
    if not probs:
        return 0.0
    return -sum(p * math.log2(p) for p in probs if p > 0)


def compute_label_distribution_entropy(labels: List[str]) -> float:
    """Compute entropy from a distribution of categorical labels.

    Used as a proxy for Reasoning Entropy when GPU inference is unavailable.
    A model predicting diverse families has high entropy;
    one that collapses to a single prediction has near-zero entropy.

    Args:
        labels: List of predicted/ground-truth label strings.

    Returns:
        Shannon entropy in bits.
    """
    if not labels:
        return 0.0
    counter = Counter(labels)
    total = len(labels)
    probs = [count / total for count in counter.values()]
    return compute_reasoning_entropy(probs)


def report_reasoning_entropy(
    entropy_value: float,
    threshold: float,
    label: str = "Reasoning Entropy",
    num_classes: int = 0,
) -> None:
    """Print the Phase 6.5 Reasoning Entropy report section."""
    print("\n" + "=" * 60)
    print("Phase 6.5 — Reasoning Entropy (RE) Report")
    print("=" * 60)

    if num_classes > 0:
        max_entropy = math.log2(num_classes)
        print(f"  Max possible entropy ({num_classes} classes): {max_entropy:.3f} bits")

    print(f"  {label}: {entropy_value:.3f} bits")
    print(f"  Threshold: {threshold:.3f} bits")

    if entropy_value < threshold:
        print(f"\n  ⚠️  ENTROPY COLLAPSE DETECTED — Model is \"Narrow-Minded\"")
        print(f"  RE ({entropy_value:.3f}) < threshold ({threshold:.3f})")
        print(f"  RECOMMENDATION: Initiate Breadth-First refresh from v6 base.")
        print(f"  The model's output distribution has collapsed, indicating")
        print(f"  it may be over-specialized on recent training families.")
    else:
        print(f"\n  ✅ Entropy healthy — Model maintains diverse reasoning capacity")


def run_entropy_self_test() -> bool:
    """Run unit tests for the entropy computation functions."""
    print("=" * 60)
    print("Phase 6.5 — Reasoning Entropy Self-Test")
    print("=" * 60)

    all_passed = True

    # Test 1: Uniform distribution should have max entropy
    uniform = [0.25, 0.25, 0.25, 0.25]
    expected = 2.0  # log2(4) = 2.0
    result = compute_reasoning_entropy(uniform)
    passed = abs(result - expected) < 0.001
    print(f"  [{'PASS' if passed else 'FAIL'}] Uniform(4): {result:.3f} == {expected:.3f}")
    all_passed = all_passed and passed

    # Test 2: Degenerate distribution (all mass on one) should have 0 entropy
    degenerate = [1.0, 0.0, 0.0, 0.0]
    expected = 0.0
    result = compute_reasoning_entropy(degenerate)
    passed = abs(result - expected) < 0.001
    print(f"  [{'PASS' if passed else 'FAIL'}] Degenerate: {result:.3f} == {expected:.3f}")
    all_passed = all_passed and passed

    # Test 3: Binary equal distribution
    binary = [0.5, 0.5]
    expected = 1.0
    result = compute_reasoning_entropy(binary)
    passed = abs(result - expected) < 0.001
    print(f"  [{'PASS' if passed else 'FAIL'}] Binary(0.5, 0.5): {result:.3f} == {expected:.3f}")
    all_passed = all_passed and passed

    # Test 4: Label distribution entropy
    labels = ["IcedID", "IcedID", "Emotet", "Emotet", "DarkGate", "DarkGate"]
    expected = math.log2(3)  # Uniform across 3 classes
    result = compute_label_distribution_entropy(labels)
    passed = abs(result - expected) < 0.001
    print(f"  [{'PASS' if passed else 'FAIL'}] Labels(3 uniform): {result:.3f} == {expected:.3f}")
    all_passed = all_passed and passed

    # Test 5: Collapsed labels (all same)
    labels_collapsed = ["IcedID"] * 10
    expected = 0.0
    result = compute_label_distribution_entropy(labels_collapsed)
    passed = abs(result - expected) < 0.001
    print(f"  [{'PASS' if passed else 'FAIL'}] Labels(collapsed): {result:.3f} == {expected:.3f}")
    all_passed = all_passed and passed

    # Test 6: Empty input
    result = compute_reasoning_entropy([])
    passed = result == 0.0
    print(f"  [{'PASS' if passed else 'FAIL'}] Empty: {result:.3f} == 0.000")
    all_passed = all_passed and passed

    # Test 7: Skewed distribution (should be between 0 and max)
    skewed = [0.9, 0.05, 0.03, 0.02]
    result = compute_reasoning_entropy(skewed)
    passed = 0.0 < result < 2.0
    print(f"  [{'PASS' if passed else 'FAIL'}] Skewed: {result:.3f} (0 < x < 2)")
    all_passed = all_passed and passed

    status_msg = "\u2705 All tests passed!" if all_passed else "\u274c Some tests failed!"
    print(f"\n  {status_msg}")
    return all_passed


def load_validation_data(data_path: str) -> List[Dict]:
    """Load validation samples.

    Supports three formats:
      - SFT ChatML: {"text": "..."}
      - Raw ChatML: {"messages": [...]}
      - ORPO preference pairs: {"prompt": "...", "chosen": "...", "rejected": "..."}
    """
    samples = []
    with open(data_path) as f:
        for line in f:
            try:
                data = json.loads(line)
                ground_truth = "unknown"
                instruction = ""

                # Check if it's pre-formatted text (as generated by create_balanced_dataset.py)
                if "text" in data:
                    text = data["text"]
                    # Extract User Content
                    user_part = text.split("<|start_header_id|>user<|end_header_id|>\n\n")[-1]
                    instruction = user_part.split("<|eot_id|>")[0]
                    
                    # Extract Assistant Content
                    if "<|start_header_id|>assistant<|end_header_id|>\n\n" in text:
                        assist_part = text.split("<|start_header_id|>assistant<|end_header_id|>\n\n")[-1]
                        assist_response = assist_part.split("<|eot_id|>")[0]
                        ground_truth = extract_classification_from_text(assist_response)

                # ORPO preference-pair format
                elif "prompt" in data and "chosen" in data:
                    prompt = data["prompt"]
                    # Extract user instruction from prompt
                    if "<|start_header_id|>user<|end_header_id|>\n\n" in prompt:
                        user_part = prompt.split("<|start_header_id|>user<|end_header_id|>\n\n")[-1]
                        instruction = user_part.split("<|eot_id|>")[0]
                    else:
                        instruction = prompt

                    ground_truth = extract_classification_from_text(data["chosen"])

                # Check if it's structured messages (raw ChatML)
                elif "messages" in data:
                    for msg in data["messages"]:
                        if msg["role"] == "assistant":
                            ground_truth = extract_classification_from_text(msg["content"])
                        if msg["role"] == "user":
                            instruction = msg["content"]
                        
                samples.append({
                    "instruction": instruction,
                    "ground_truth": ground_truth,
                    "raw_sample": data
                })
            except json.JSONDecodeError:
                continue
    return samples

def main():
    parser = argparse.ArgumentParser(description="Verify AIPAM Model Bias")
    parser.add_argument("--model", default="models/aipam-llama", help="Path to fine-tuned model/adapter")
    parser.add_argument("--data", default="models/aipam-llama-balanced/valid.jsonl", help="Validation data path")
    parser.add_argument("--base-model", default="unsloth/llama-3.1-8b-bnb-4bit", help="Base model")
    parser.add_argument(
        "--compare-teacher", action="store_true",
        help="Phase 6.3: Compare Student vs Teacher accuracy (retention verification)"
    )
    parser.add_argument(
        "--teacher-model", default="unsloth/llama-3.1-8b-bnb-4bit",
        help="Teacher model for retention comparison"
    )
    # Phase 6.5 — Reasoning Entropy
    parser.add_argument(
        "--entropy-threshold", type=float, default=1.5,
        help="Phase 6.5: Minimum acceptable reasoning entropy in bits (default 1.5). "
             "Below this threshold triggers an Entropy Collapse warning."
    )
    parser.add_argument(
        "--test-entropy", action="store_true",
        help="Phase 6.5: Run entropy computation self-tests and exit"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("AIPAM Model Bias Verification (Phase 6.1 + 6.3 + 6.5)")
    print("=" * 60)

    # Phase 6.5: Self-test mode
    if args.test_entropy:
        passed = run_entropy_self_test()
        return 0 if passed else 1

    # 1. Load Data
    print(f"\nLoading validation data: {args.data}")
    if not Path(args.data).exists():
        print(f"Error: Data file not found: {args.data}")
        return
        
    samples = load_validation_data(args.data)
    print(f"Loaded {len(samples)} samples.")
    
    # 2. Check for GPU (mock run if no GPU)
    gpu_available = False
    try:
        import torch
        if torch.cuda.is_available():
            gpu_available = True
    except ImportError:
        pass

    if not gpu_available:
        print("\n[WARNING] No GPU detected. Cannot run actual inference.")
        print("This script is ready to run on your GPU training machine.")
        print("\n--- Simulation Mode (Logic Check) ---")
        print("Verifying data parsing logic...")
        
        # Verify we can correctly parse ground truth from the samples
        categories = Counter()
        for s in samples:
            categories[s['ground_truth']] += 1
            
        print("\nGround Truth Distribution in Validation Set:")
        for cat, count in categories.items():
            print(f"  - {cat}: {count}")

        # Phase 6.1: HCR check on validation data (chosen vs prompt)
        print("\n" + "-" * 60)
        print("Phase 6.1 — Hallucinated Citation Rate (Ground Truth)")
        print("-" * 60)
        hcr_count = 0
        hcr_total = 0
        for s in samples:
            raw = s["raw_sample"]
            if "prompt" in raw and "chosen" in raw:
                hcr_result = compute_hallucination_rate(raw["prompt"], raw["chosen"])
                hcr_total += 1
                if hcr_result["has_hallucination"]:
                    hcr_count += 1
        if hcr_total > 0:
            hcr_pct = (hcr_count / hcr_total) * 100
            print(f"  Samples checked: {hcr_total}")
            print(f"  Ground-truth HCR: {hcr_pct:.1f}% ({hcr_count}/{hcr_total})")
            print(f"  (Expect ~0% for 'chosen' responses — these are gold standard)")
        else:
            print("  No ORPO preference pairs found in validation data.")
            print("  HCR metric requires ORPO-format data (prompt/chosen/rejected).")

        # Phase 6.5: Reasoning Entropy (proxy from label distribution)
        print("\n" + "-" * 60)
        print("Phase 6.5 — Reasoning Entropy (Ground Truth Distribution)")
        print("-" * 60)
        gt_labels = [s["ground_truth"] for s in samples]
        gt_entropy = compute_label_distribution_entropy(gt_labels)
        num_classes = len(set(gt_labels))
        report_reasoning_entropy(
            gt_entropy,
            threshold=args.entropy_threshold,
            label="Ground-truth label entropy (proxy)",
            num_classes=num_classes,
        )

        print("\n✓ Logic check complete. Run this script on a GPU machine for full verification.")
        return

    # 3. Load Model (Only runs if GPU present)
    print(f"\nLoading model: {args.model}")
    from unsloth import FastLanguageModel
    
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, # Loads adapter if present
        max_seq_length=32768,
        dtype=None,
        load_in_4bit=True,
    )
    FastLanguageModel.for_inference(model)

    # 4. Run Inference
    print("\nRunning inference...")
    correct = 0
    total = len(samples)
    y_true = []
    y_pred = []
    hallucination_results = []
    
    for i, sample in enumerate(samples):
        inputs = tokenizer.apply_chat_template(
            [{"role": "user", "content": sample["instruction"]}],
            tokenize=True,
            return_tensors="pt",
        ).to("cuda")

        outputs = model.generate(input_ids=inputs, max_new_tokens=256, use_cache=True)
        response_text = tokenizer.batch_decode(outputs)
        response_content = response_text[0].split("<|start_header_id|>assistant<|end_header_id|>\n\n")[-1]
        
        prediction = extract_classification_from_text(response_content)
        ground_truth = sample["ground_truth"]
        
        y_true.append(ground_truth)
        y_pred.append(prediction)
        
        is_correct = (prediction.lower() == ground_truth.lower())
        if is_correct:
            correct += 1
        
        # Phase 6.1: HCR per response
        hcr = compute_hallucination_rate(sample["instruction"], response_content)
        hallucination_results.append(hcr)
        
        hcr_flag = " [HALLUC]" if hcr["has_hallucination"] else ""
        print(f"[{i+1}/{total}] True: {ground_truth} | Pred: {prediction} | {'✓' if is_correct else '✗'}{hcr_flag}")

    # 5. Metrics
    accuracy = correct / total
    print("\n" + "=" * 60)
    print(f"Overall Accuracy: {accuracy:.2%}")
    print("=" * 60)
    
    # Per-Class Analysis
    from sklearn.metrics import classification_report
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred))

    # 6. Phase 6.1 — Hallucinated Citation Rate Report
    print("=" * 60)
    print("Phase 6.1 — Hallucinated Citation Rate (HCR) Report")
    print("=" * 60)

    total_hcr = len(hallucination_results)
    halluc_count = sum(1 for h in hallucination_results if h["has_hallucination"])
    hcr_rate = (halluc_count / total_hcr * 100) if total_hcr > 0 else 0

    total_ips = sum(h["total_ips_cited"] for h in hallucination_results)
    halluc_ips = sum(h["hallucinated_ips"] for h in hallucination_results)
    total_mitre = sum(h["total_mitre_cited"] for h in hallucination_results)
    halluc_mitre = sum(h["hallucinated_mitre"] for h in hallucination_results)

    print(f"\n  Responses with hallucinations: {halluc_count}/{total_hcr} ({hcr_rate:.1f}%)")
    print(f"  IP citations:    {total_ips} total, {halluc_ips} hallucinated ({halluc_ips/max(total_ips,1)*100:.1f}%)")
    print(f"  MITRE citations: {total_mitre} total, {halluc_mitre} hallucinated ({halluc_mitre/max(total_mitre,1)*100:.1f}%)")

    if hcr_rate < 5:
        print("\n  ✅ HCR < 5% — ORPO alignment is effective")
    elif hcr_rate < 15:
        print("\n  ⚠️  HCR 5-15% — Consider additional ORPO training epochs")
    else:
        print("\n  ❌ HCR > 15% — Significant hallucination problem, review training data")

    # 7. Phase 6.5 — Reasoning Entropy Report
    pred_entropy = compute_label_distribution_entropy(y_pred)
    num_pred_classes = len(set(y_pred))
    report_reasoning_entropy(
        pred_entropy,
        threshold=args.entropy_threshold,
        label="Prediction distribution entropy",
        num_classes=num_pred_classes,
    )

    # 7. Phase 6.3 — Teacher vs Student Retention Comparison
    if args.compare_teacher:
        print("\n" + "=" * 60)
        print("Phase 6.3 — Teacher vs Student Retention Report")
        print("=" * 60)

        student_accuracy = accuracy  # From the model we just tested
        student_preds = dict(zip(range(len(y_true)), zip(y_true, y_pred)))

        # Load Teacher model
        print(f"\nLoading Teacher model: {args.teacher_model}")
        teacher_model, teacher_tokenizer = FastLanguageModel.from_pretrained(
            model_name=args.teacher_model,
            max_seq_length=32768,
            dtype=None,
            load_in_4bit=True,
        )
        FastLanguageModel.for_inference(teacher_model)

        # Run Teacher inference
        print("Running Teacher inference for comparison...")
        teacher_correct = 0
        teacher_y_pred = []
        teacher_per_family = defaultdict(lambda: {"correct": 0, "total": 0})
        student_per_family = defaultdict(lambda: {"correct": 0, "total": 0})

        for i, sample in enumerate(samples):
            inputs = teacher_tokenizer.apply_chat_template(
                [{"role": "user", "content": sample["instruction"]}],
                tokenize=True,
                return_tensors="pt",
            ).to("cuda")

            outputs = teacher_model.generate(
                input_ids=inputs, max_new_tokens=256, use_cache=True
            )
            response_text = teacher_tokenizer.batch_decode(outputs)
            response_content = response_text[0].split(
                "<|start_header_id|>assistant<|end_header_id|>\n\n"
            )[-1]

            teacher_pred = extract_classification_from_text(response_content)
            ground_truth = sample["ground_truth"]
            teacher_y_pred.append(teacher_pred)

            is_correct = (teacher_pred.lower() == ground_truth.lower())
            if is_correct:
                teacher_correct += 1

            # Per-family tracking
            family = ground_truth
            teacher_per_family[family]["total"] += 1
            student_per_family[family]["total"] += 1
            if is_correct:
                teacher_per_family[family]["correct"] += 1
            if y_pred[i].lower() == ground_truth.lower():
                student_per_family[family]["correct"] += 1

            t_flag = "✓" if is_correct else "✗"
            s_flag = "✓" if y_pred[i].lower() == ground_truth.lower() else "✗"
            print(f"  [{i+1}/{total}] {ground_truth}: "
                  f"Teacher={teacher_pred} [{t_flag}] | "
                  f"Student={y_pred[i]} [{s_flag}]")

        teacher_accuracy = teacher_correct / total
        retention_rate = (student_accuracy / teacher_accuracy * 100) if teacher_accuracy > 0 else 0

        print(f"\n{'=' * 60}")
        print(f"  Teacher Accuracy:   {teacher_accuracy:.2%}")
        print(f"  Student Accuracy:   {student_accuracy:.2%}")
        print(f"  Retention Rate:     {retention_rate:.1f}%")

        # Per-family retention
        print(f"\n  {'Family':<25} {'Teacher':>8} {'Student':>8} {'Retention':>10}")
        print(f"  {'-' * 55}")
        all_families = set(list(teacher_per_family.keys()) + list(student_per_family.keys()))
        for family in sorted(all_families):
            t_stats = teacher_per_family[family]
            s_stats = student_per_family[family]
            t_acc = t_stats["correct"] / max(t_stats["total"], 1)
            s_acc = s_stats["correct"] / max(s_stats["total"], 1)
            f_retention = (s_acc / t_acc * 100) if t_acc > 0 else 0
            flag = "✅" if f_retention >= 90 else "⚠️" if f_retention >= 75 else "❌"
            print(f"  {flag} {family:<23} {t_acc:>7.0%} {s_acc:>7.0%} {f_retention:>9.1f}%")

        # Pass/Fail Gate
        print(f"\n{'=' * 60}")
        if retention_rate >= 90:
            print(f"  ✅ RETENTION GATE PASSED — {retention_rate:.1f}% ≥ 90%")
            print(f"  AIPAM-Edge 1B is ready for deployment.")
        elif retention_rate >= 80:
            print(f"  ⚠️  MARGINAL — {retention_rate:.1f}% (80-90%)")
            print(f"  Consider: more Teacher labels, additional epochs, or try 3B student.")
        else:
            print(f"  ❌ RETENTION GATE FAILED — {retention_rate:.1f}% < 80%")
            print(f"  Recommendation: Switch to Llama-3.2-3B-Instruct as Student.")

if __name__ == "__main__":
    main()
