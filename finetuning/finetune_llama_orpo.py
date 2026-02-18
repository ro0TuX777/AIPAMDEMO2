#!/usr/bin/env python3
"""
Fine-tune llama3.1:8b with ORPO (Odds Ratio Preference Optimization)

Phase 6.1 — Contrastive Evidentiary Training (CET)
Phase 6.2 — Temporal Expansion (32k context for session-level forensics)
Phase 6.5 — LocFT: Localized Fine-Tuning (surgical down_proj + layer masking)

Uses Unsloth for efficient training with ORPOTrainer from TRL.
The model learns that 'Correct Classification + Wrong Evidence = Failure'
by training on preference pairs where the rejected response has
corrupted evidentiary fields (IPs, MITRE IDs, evidence chains).

At 32k context (Phase 6.2), the model can observe 15-minute PCAP sessions
and detect low-and-slow C2 heartbeats and data exfiltration patterns.

Phase 6.5 LocFT mode restricts LoRA to down_proj matrices in layers 16-30,
enabling surgical knowledge edits without degrading grammar/instruction layers.

Requirements:
    pip install unsloth
    pip install --no-deps trl>=0.8.0 peft accelerate bitsandbytes

Usage:
    python finetune_llama_orpo.py --data data/v6-orpo/train.jsonl --output models/aipam-llama-v6
    python finetune_llama_orpo.py --data data/v6-orpo/train.jsonl --locft-mode   # Surgical mode
    python finetune_llama_orpo.py --data data/v6-orpo/train.jsonl --no-locft-mode  # Full LoRA
"""

import argparse
import json
import os
import sys
from pathlib import Path

# --- FIX for Unsloth/Torch/_inductor AttributeError ---
try:
    import torch
    import torch._inductor.config

    # Satisfy torchao or other libraries expecting torch.int1 (added in 2.5+)
    if hasattr(torch, "__version__") and not hasattr(torch, "int1"):
        torch.int1 = torch.int8  # Use int8 for 1-bit mapping satisfaction
except (ImportError, AttributeError):
    pass
# ------------------------------------------------------

# DAWN seed per constitutional requirement
DAWN_RANDOM_SEED = 3407


def check_dependencies():
    """Check if required dependencies are installed."""
    missing = []
    try:
        import torch
    except ImportError:
        missing.append("torch")

    try:
        from unsloth import FastLanguageModel
    except ImportError:
        missing.append("unsloth")

    try:
        from trl import ORPOTrainer, ORPOConfig
    except ImportError:
        missing.append("trl>=0.8.0 (ORPOTrainer)")

    if missing:
        print("Missing dependencies:", ", ".join(missing))
        print("\nInstall with:")
        print("  pip install unsloth")
        print("  pip install --no-deps 'trl>=0.8.0' peft accelerate bitsandbytes")
        return False
    return True


def load_preference_data(data_path: str):
    """Load ORPO preference-pair data from JSONL file.

    Expected format per line:
        {"prompt": "...", "chosen": "...", "rejected": "..."}
    """
    samples = []
    with open(data_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                sample = json.loads(line)
                # Validate required keys
                if not all(k in sample for k in ("prompt", "chosen", "rejected")):
                    print(f"  [Warning] Line {line_num}: missing required keys, skipping")
                    continue
                samples.append(sample)
            except json.JSONDecodeError as e:
                print(f"  [Warning] Line {line_num}: invalid JSON: {e}")
                continue
    return samples


def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune llama3.1:8b with ORPO for AIPAM Phase 6.1+6.2"
    )
    parser.add_argument(
        "--data", default="finetuning/data/v6-orpo/train.jsonl",
        help="Training data path (preference pairs JSONL)"
    )
    parser.add_argument(
        "--val-data", default="finetuning/data/v6-orpo/valid.jsonl",
        help="Validation data path"
    )
    parser.add_argument(
        "--output", default="finetuning/aipam_gpu_training/aipam-llama-lora-v6",
        help="Output model/adapter path"
    )
    parser.add_argument(
        "--base-model", default="unsloth/llama-3.1-8b-bnb-4bit",
        help="Base model to fine-tune"
    )
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument(
        "--batch-size", type=int, default=1,
        help="Batch size per device (keep low for ORPO VRAM)"
    )
    parser.add_argument(
        "--gradient-accumulation", type=int, default=8,
        help="Gradient accumulation steps"
    )
    parser.add_argument(
        "--learning-rate", type=float, default=5e-5, help="Learning rate"
    )
    parser.add_argument("--lora-r", type=int, default=128, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=128, help="LoRA alpha")
    parser.add_argument(
        "--max-seq-length", type=int, default=32768,
        help="Max sequence length (32768 for Phase 6.2 session-level forensics)"
    )
    parser.add_argument(
        "--chunked-cross-entropy", action="store_true",
        help="Enable Unsloth Chunked Cross Entropy to save ~30%% VRAM (use if OOM at 32k)"
    )
    parser.add_argument(
        "--beta", type=float, default=0.1,
        help="ORPO odds-ratio weight (higher = stronger preference signal)"
    )
    parser.add_argument(
        "--export-gguf", action="store_true", help="Export to GGUF for Ollama"
    )
    parser.add_argument(
        "--validate-data", action="store_true",
        help="Validate data loading without training"
    )
    parser.add_argument(
        "--resume-from", type=str, default=None,
        help="Path to existing adapter/model to continue training"
    )
    # Phase 6.5 — LocFT (Localized Fine-Tuning)
    parser.add_argument(
        "--locft-mode", action=argparse.BooleanOptionalAction, default=True,
        help="Phase 6.5: Surgical LoRA — target only down_proj in layers 16-30 "
             "(default: enabled). Use --no-locft-mode for full-model LoRA."
    )
    parser.add_argument(
        "--locft-layers-start", type=int, default=16,
        help="LocFT: first transformer layer to train (inclusive, default 16)"
    )
    parser.add_argument(
        "--locft-layers-end", type=int, default=31,
        help="LocFT: last transformer layer to train (exclusive, default 31 → layers 16-30)"
    )
    args = parser.parse_args()

    # ── Data validation ──
    train_path = Path(args.data)
    if not train_path.exists():
        print(f"Error: Training data not found at {train_path}")
        print("Run first: python finetuning/create_balanced_dataset.py --orpo")
        return

    print("=" * 60)
    locft_label = "LocFT (Surgical)" if args.locft_mode else "Full-Model"
    print(f"AIPAM Phase 6.1+6.2+6.5 — ORPO Fine-Tuning [{locft_label}]")
    print(f"Seed: {DAWN_RANDOM_SEED} (DAWN Constitutional)")
    print(f"Context Window: {args.max_seq_length} tokens")
    if args.locft_mode:
        print(f"LocFT: target_modules=[down_proj], layers {args.locft_layers_start}-{args.locft_layers_end - 1}")
    print("=" * 60)

    # Load and validate preference pairs
    print(f"\nLoading preference pairs from: {args.data}")
    train_samples = load_preference_data(args.data)
    print(f"Training pairs: {len(train_samples)}")

    if not train_samples:
        print("Error: No valid training samples found!")
        return

    # Quick validation
    sample = train_samples[0]
    print(f"\n[Sample Pair Preview]")
    print(f"  Prompt length:   {len(sample['prompt'])} chars")
    print(f"  Chosen length:   {len(sample['chosen'])} chars")
    print(f"  Rejected length: {len(sample['rejected'])} chars")
    assert sample["chosen"] != sample["rejected"], \
        "ERROR: Chosen and Rejected are identical — corruption failed!"
    print(f"  ✓ Chosen ≠ Rejected (corruption verified)")

    if args.validate_data:
        print("\n[Data Validation Mode] All checks passed.")
        # Show stats
        prompt_lens = [len(s["prompt"]) for s in train_samples]
        chosen_lens = [len(s["chosen"]) for s in train_samples]
        print(f"  Avg prompt length: {sum(prompt_lens)/len(prompt_lens):.0f} chars")
        print(f"  Avg chosen length: {sum(chosen_lens)/len(chosen_lens):.0f} chars")
        print(f"  Total pairs: {len(train_samples)}")
        return

    if not check_dependencies():
        return

    # ── DAWN Ledger: Log training start ──
    from dawn_training_ledger import compute_config_hash, log_training_event
    from vram_monitor import log_vram_snapshot, check_vram_sufficient

    training_config = {
        "random_seed": DAWN_RANDOM_SEED,
        "base_model": args.base_model,
        "dataset_path": args.data,
        "dataset_samples": len(train_samples),
        "lora_r": args.lora_r,
        "lora_alpha": args.lora_alpha,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "batch_size": args.batch_size,
        "gradient_accumulation_steps": args.gradient_accumulation,
        "max_seq_length": args.max_seq_length,
        "beta": args.beta,
        "trainer_type": "ORPOTrainer",
        "context_window": args.max_seq_length,
        "chunked_cross_entropy": args.chunked_cross_entropy,
        # Phase 6.5 — LocFT config
        "locft_mode": args.locft_mode,
        "locft_target_modules": ["down_proj"] if args.locft_mode else [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        "locft_layers": list(range(args.locft_layers_start, args.locft_layers_end))
            if args.locft_mode else None,
    }

    config_hash = compute_config_hash(training_config)
    print(f"\n[DAWN] Config hash: {config_hash}")

    # VRAM pre-flight (Phase 6.2)
    min_vram = 20.0 if args.max_seq_length >= 32768 else 12.0
    check_vram_sufficient(min_gb=min_vram)

    log_training_event("orpo_training_start", training_config)
    print(f"[DAWN] Training start logged to ledger")

    # ── Load model ──
    from unsloth import FastLanguageModel
    from trl import ORPOTrainer, ORPOConfig
    from datasets import Dataset

    model_name = args.resume_from if args.resume_from else args.base_model
    print(f"\nLoading model: {model_name}")

    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=args.max_seq_length,
            dtype=None,  # Auto-detect
            load_in_4bit=True,
        )
        # Phase 6.2: Log VRAM after model load
        vram_post_load = log_vram_snapshot("post_model_load")
    except Exception as e:
        import traceback
        traceback.print_exc()
        log_training_event(
            "orpo_training_failed", training_config,
            metrics={"error": str(e), "stage": "model_load"}
        )
        if "CUDA" in str(e) or "GPU" in str(e):
            print(f"\n[CRITICAL] GPU/CUDA Error detected: {e}")
            print("[VRAM BOTTLENECK] Report this to the PM.")
            return
        raise e

    # ── LoRA adapters ──
    from peft import PeftModel

    if isinstance(model, PeftModel) or (
        args.resume_from and Path(args.resume_from).exists()
    ):
        print("Resuming from existing adapter/checkpoint...")
        model.train()
    else:
        # Phase 6.5: Surgical vs Full-Model LoRA selection
        if args.locft_mode:
            locft_modules = ["down_proj"]
            locft_layers = list(range(args.locft_layers_start, args.locft_layers_end))
            print(f"Adding LocFT LoRA adapters (surgical mode)...")
            print(f"  target_modules: {locft_modules}")
            print(f"  layers_to_transform: {locft_layers[0]}-{locft_layers[-1]}")
        else:
            locft_modules = [
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ]
            locft_layers = None
            print("Adding full-model LoRA adapters...")
            print(f"  target_modules: {locft_modules}")

        peft_kwargs = dict(
            r=args.lora_r,
            target_modules=locft_modules,
            lora_alpha=args.lora_alpha,
            lora_dropout=0,
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=DAWN_RANDOM_SEED,
        )
        if locft_layers is not None:
            peft_kwargs["layers_to_transform"] = locft_layers

        model = FastLanguageModel.get_peft_model(model, **peft_kwargs)

    # ── Prepare dataset ──
    train_dataset = Dataset.from_list(train_samples)
    print(f"Dataset loaded: {len(train_dataset)} preference pairs")

    # ── ORPO Config ──
    orpo_config = ORPOConfig(
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation,
        warmup_steps=10,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        fp16=False,
        bf16=True,
        logging_steps=5,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=DAWN_RANDOM_SEED,
        output_dir=args.output,
        save_strategy="epoch",
        beta=args.beta,
        max_length=args.max_seq_length,
        max_prompt_length=args.max_seq_length // 2,
    )

    # ── Initialize ORPO Trainer ──
    trainer = ORPOTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        args=orpo_config,
    )

    # ── Train ──
    print("\n" + "=" * 60)
    print("Starting ORPO Training...")
    print(f"  Beta (odds-ratio weight): {args.beta}")
    print(f"  Effective batch size: {args.batch_size * args.gradient_accumulation}")
    print(f"  Seed: {DAWN_RANDOM_SEED}")
    print("=" * 60)

    try:
        train_result = trainer.train()

        # Phase 6.2: Log peak VRAM after training
        vram_post_train = log_vram_snapshot("post_training")

        # ── DAWN Ledger: Log training completion ──
        completion_metrics = {
            "train_loss": train_result.training_loss,
            "train_runtime": train_result.metrics.get("train_runtime"),
            "train_samples_per_second": train_result.metrics.get(
                "train_samples_per_second"
            ),
            "context_window": args.max_seq_length,
        }
        if vram_post_train:
            completion_metrics["peak_vram_gb"] = vram_post_train["peak_reserved_gb"]
        log_training_event(
            "orpo_training_complete", training_config, metrics=completion_metrics
        )
        print(f"\n[DAWN] Training completion logged to ledger")
        print(f"[DAWN] Final loss: {train_result.training_loss:.4f}")

    except Exception as e:
        log_training_event(
            "orpo_training_failed", training_config,
            metrics={"error": str(e), "stage": "training"}
        )
        print(f"\n[CRITICAL] Training failed: {e}")
        if "CUDA out of memory" in str(e) or "OOM" in str(e):
            print("[VRAM BOTTLENECK] Try reducing --batch-size to 1")
            print("  or --gradient-accumulation to 4")
            print("  Report this to the PM.")
        raise e

    # ── Save model ──
    print(f"\nSaving model to: {args.output}")
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)

    # ── Export to GGUF if requested ──
    if args.export_gguf:
        print("\nExporting to GGUF format for Ollama...")
        model.save_pretrained_gguf(
            args.output,
            tokenizer,
            quantization_method="q4_k_m",
        )
        print(f"✓ GGUF model saved to: {args.output}")

    print("\n" + "=" * 60)
    print("ORPO Fine-tuning complete!")
    print(f"Config hash: {config_hash}")
    print(f"DAWN seed:   {DAWN_RANDOM_SEED}")
    print(f"Model saved: {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
