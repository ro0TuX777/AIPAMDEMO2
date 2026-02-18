#!/usr/bin/env python3
"""
Phase 6.3 — Teacher Labeling for Specialist Distillation

Runs the 8B Teacher model over processed training data to generate
high-quality forensic labels. These labels become the "chosen" responses
for ORPO training of the 1B Student (AIPAM-Edge).

The Teacher can be swapped later via Core Engine (e.g., from base 8B
to fine-tuned v6 Specialist).

Usage:
    # Generate Teacher labels (requires GPU)
    python distill_generate_labels.py

    # Dry-run to validate pipeline
    python distill_generate_labels.py --dry-run --limit 5

    # Use custom Teacher model
    python distill_generate_labels.py --teacher-model path/to/v6-specialist
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional

# --- FIX for Unsloth/Torch/_inductor AttributeError ---
try:
    import torch
    import torch._inductor.config
    if hasattr(torch, "__version__") and not hasattr(torch, "int1"):
        torch.int1 = torch.int8
except (ImportError, AttributeError):
    pass
# ------------------------------------------------------

# DAWN seed per constitutional requirement
DAWN_RANDOM_SEED = 3407
random.seed(DAWN_RANDOM_SEED)

# Import AIPAM dataset utilities
sys.path.insert(0, str(Path(__file__).parent))
from create_balanced_dataset import (
    SYSTEM_PROMPT,
    create_user_prompt,
    corrupt_evidence,
)

BASE_DIR = Path(__file__).parent.absolute()


def load_processed_samples(
    data_path: str,
    limit: Optional[int] = None,
) -> List[Dict]:
    """Load processed samples from JSONL file.

    Supports both v5 (per-PCAP) and v6 (session-IR) formats.

    Args:
        data_path: Path to processed_samples JSONL file.
        limit: Max samples to load.

    Returns:
        List of sample dicts.
    """
    samples = []
    path = Path(data_path)

    if not path.exists():
        print(f"Error: Data file not found: {data_path}")
        return samples

    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                sample = json.loads(line)
                samples.append(sample)
                if limit and len(samples) >= limit:
                    break
            except json.JSONDecodeError as e:
                print(f"  [Warning] Line {line_num}: JSON parse error: {e}")
                continue

    print(f"  Loaded {len(samples)} samples from {data_path}")
    return samples


def run_teacher_inference(
    model,
    tokenizer,
    prompt_text: str,
    max_new_tokens: int = 1024,
) -> str:
    """Run Teacher model inference on a single prompt.

    Args:
        model: Loaded Teacher model.
        tokenizer: Corresponding tokenizer.
        prompt_text: Full user prompt text.
        max_new_tokens: Max tokens to generate.

    Returns:
        Teacher's response text.
    """
    # Build conversation in ChatML format
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_text},
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt",
    ).to("cuda")

    outputs = model.generate(
        input_ids=inputs,
        max_new_tokens=max_new_tokens,
        use_cache=True,
        temperature=0.1,  # Low temperature for consistent, high-quality labels
        top_p=0.9,
    )

    # Decode and extract assistant response
    full_response = tokenizer.decode(outputs[0], skip_special_tokens=False)

    # Split on assistant header to get just the response
    if "<|start_header_id|>assistant<|end_header_id|>" in full_response:
        response = full_response.split(
            "<|start_header_id|>assistant<|end_header_id|>"
        )[-1]
        # Clean up trailing tokens
        response = response.replace("<|eot_id|>", "").strip()
    else:
        response = full_response.strip()

    return response


def generate_teacher_labels(
    model,
    tokenizer,
    samples: List[Dict],
    output_dir: Path,
    dry_run: bool = False,
) -> List[Dict]:
    """Generate Teacher labels for all samples.

    For each processed sample:
    1. Construct user prompt via create_user_prompt()
    2. Run Teacher inference
    3. Create ORPO pair (chosen=Teacher, rejected=corrupt)

    Args:
        model: Teacher model (or None if dry_run).
        tokenizer: Tokenizer (or None if dry_run).
        samples: Processed samples to label.
        output_dir: Directory to write outputs.
        dry_run: If True, skip inference and use placeholder data.

    Returns:
        List of ORPO preference-pair dicts.
    """
    orpo_pairs = []
    teacher_labels = []

    for i, sample in enumerate(samples):
        label = sample.get("normalized_label", sample.get("label", "unknown"))

        # Build user prompt using the same function as training pipeline
        try:
            user_prompt = create_user_prompt(sample)
        except Exception as e:
            print(f"  [{i+1}/{len(samples)}] Skipping — prompt creation failed: {e}")
            continue

        # Run Teacher inference
        if dry_run:
            # Placeholder for dry-run validation
            teacher_response = json.dumps({
                "overall_severity": "high",
                "classification": "malicious",
                "attack_type": label,
                "confidence": 0.95,
                "attack_chain": [{
                    "stage": "detection",
                    "description": f"[DRY-RUN] Teacher label for {label}",
                    "evidence": [f"Observed {label} patterns"],
                    "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}],
                }],
                "host_findings": [],
                "anomalies": [],
                "mitre_techniques_overall": [{"id": "T1071", "name": "Application Layer Protocol"}],
            }, indent=2)
        else:
            try:
                teacher_response = run_teacher_inference(
                    model, tokenizer, user_prompt
                )
            except Exception as e:
                print(f"  [{i+1}/{len(samples)}] Inference failed: {e}")
                continue

        # Build ChatML prompt for ORPO
        chatml_prompt = (
            f"<|start_header_id|>system<|end_header_id|>\n\n{SYSTEM_PROMPT}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n{user_prompt}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
        )

        # Create rejected version with corrupted evidence
        rejected_response = corrupt_evidence(teacher_response)

        # Teacher label record
        teacher_labels.append({
            "instruction": user_prompt,
            "output": teacher_response,
            "label": label,
            "source": "teacher_8b",
        })

        # ORPO pair
        orpo_pairs.append({
            "prompt": chatml_prompt,
            "chosen": teacher_response,
            "rejected": rejected_response,
        })

        status = "DRY-RUN" if dry_run else "OK"
        print(f"  [{i+1}/{len(samples)}] {label} — {status} "
              f"(chosen={len(teacher_response)} chars)")

    return orpo_pairs, teacher_labels


def main():
    parser = argparse.ArgumentParser(
        description="Phase 6.3 — Generate Teacher labels for Specialist Distillation"
    )
    parser.add_argument(
        "--data", default="finetuning/data/processed/processed_samples_v5.jsonl",
        help="Path to processed samples JSONL"
    )
    parser.add_argument(
        "--teacher-model", default="unsloth/llama-3.1-8b-bnb-4bit",
        help="Teacher model name/path (swappable via Core Engine)"
    )
    parser.add_argument(
        "--output-dir", default="finetuning/data/v6-distill",
        help="Output directory for teacher labels and ORPO pairs"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Limit number of samples to process"
    )
    parser.add_argument(
        "--max-new-tokens", type=int, default=1024,
        help="Max tokens for Teacher generation"
    )
    parser.add_argument(
        "--max-seq-length", type=int, default=32768,
        help="Max sequence length for Teacher model"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate pipeline without running inference"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Phase 6.3 — Teacher Label Generation")
    print(f"Teacher: {args.teacher_model}")
    print(f"Data: {args.data}")
    print(f"Seed: {DAWN_RANDOM_SEED} (DAWN Constitutional)")
    if args.dry_run:
        print("[DRY-RUN MODE — No inference will be run]")
    print("=" * 60)

    # 1. Load processed samples
    print("\n[1/4] Loading processed samples...")
    samples = load_processed_samples(args.data, limit=args.limit)

    if not samples:
        print("Error: No samples loaded. Ensure processed data exists at:")
        print(f"  {args.data}")
        print("Generate with: python finetuning/process_training_data.py")
        return

    # 2. Load Teacher model
    model = None
    tokenizer = None

    if not args.dry_run:
        print(f"\n[2/4] Loading Teacher model: {args.teacher_model}")
        try:
            import torch
            if not torch.cuda.is_available():
                print("⚠️  No GPU detected. Teacher inference requires CUDA.")
                print("  Use --dry-run to validate pipeline without GPU.")
                return

            from unsloth import FastLanguageModel
            from vram_monitor import log_vram_snapshot, check_vram_sufficient

            check_vram_sufficient(min_gb=12.0)

            model, tokenizer = FastLanguageModel.from_pretrained(
                model_name=args.teacher_model,
                max_seq_length=args.max_seq_length,
                dtype=None,
                load_in_4bit=True,
            )
            FastLanguageModel.for_inference(model)
            log_vram_snapshot("teacher_model_loaded")

        except Exception as e:
            print(f"Error loading Teacher model: {e}")
            import traceback
            traceback.print_exc()
            return
    else:
        print("\n[2/4] Skipping model load (dry-run)")

    # 3. Generate Teacher labels
    print(f"\n[3/4] Generating Teacher labels for {len(samples)} samples...")
    orpo_pairs, teacher_labels = generate_teacher_labels(
        model, tokenizer, samples,
        output_dir=Path(args.output_dir),
        dry_run=args.dry_run,
    )

    if not orpo_pairs:
        print("Error: No labels generated!")
        return

    # 4. Save outputs
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Split ORPO pairs into train/val (90/10)
    random.shuffle(orpo_pairs)
    split_idx = int(len(orpo_pairs) * 0.9)
    train_pairs = orpo_pairs[:split_idx]
    val_pairs = orpo_pairs[split_idx:]

    if args.dry_run:
        print(f"\n[4/4] [DRY-RUN] Would write to {output_dir}:")
        print(f"  teacher_labels.jsonl: {len(teacher_labels)} labels")
        print(f"  teacher_orpo_train.jsonl: {len(train_pairs)} pairs")
        print(f"  teacher_orpo_valid.jsonl: {len(val_pairs)} pairs")
        print("\n✓ Dry-run validation passed.")
        return

    print(f"\n[4/4] Saving outputs to {output_dir}...")

    # Teacher labels (raw)
    with open(output_dir / "teacher_labels.jsonl", "w") as f:
        for label in teacher_labels:
            f.write(json.dumps(label) + "\n")

    # ORPO training pairs
    with open(output_dir / "teacher_orpo_train.jsonl", "w") as f:
        for pair in train_pairs:
            f.write(json.dumps(pair) + "\n")

    # ORPO validation pairs
    with open(output_dir / "teacher_orpo_valid.jsonl", "w") as f:
        for pair in val_pairs:
            f.write(json.dumps(pair) + "\n")

    # DAWN Ledger entry
    try:
        from dawn_training_ledger import compute_config_hash, log_training_event

        config = {
            "phase": "6.3",
            "event": "teacher_labeling",
            "teacher_model": args.teacher_model,
            "data_source": args.data,
            "total_samples": len(samples),
            "orpo_pairs_generated": len(orpo_pairs),
            "train_pairs": len(train_pairs),
            "val_pairs": len(val_pairs),
            "random_seed": DAWN_RANDOM_SEED,
        }
        log_training_event("distill_teacher_labeling", config)
        print(f"[DAWN] Teacher labeling event logged to ledger")
    except Exception as e:
        print(f"[DAWN] Ledger logging skipped: {e}")

    print(f"\n{'=' * 60}")
    print(f"✓ Teacher labeling complete!")
    print(f"  teacher_labels.jsonl:       {len(teacher_labels)} labels")
    print(f"  teacher_orpo_train.jsonl:   {len(train_pairs)} pairs")
    print(f"  teacher_orpo_valid.jsonl:   {len(val_pairs)} pairs")
    print(f"  Output directory:           {output_dir}")
    print(f"\nNext: python finetune_llama_distill.py --data {output_dir}/teacher_orpo_train.jsonl")


if __name__ == "__main__":
    main()
