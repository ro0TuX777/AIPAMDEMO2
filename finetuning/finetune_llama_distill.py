#!/usr/bin/env python3
"""
Phase 6.3 — Student Distillation Training (AIPAM-Edge)
Phase 6.5 — LocFT: Localized Fine-Tuning (surgical down_proj + layer masking)

Trains a Llama 3.2 1B Student model on Teacher-generated ORPO labels.
The Student learns to replicate the 8B Teacher's forensic reasoning
at 1/8th the parameter count, enabling edge-sensor deployment.

Phase 6.5 LocFT mode restricts LoRA to down_proj matrices in mid-to-late
layers, enabling surgical knowledge edits without degrading core capabilities.
Note: The 1B model has 16 layers, so LocFT defaults to layers 8-15.

Teacher: unsloth/llama-3.1-8b-bnb-4bit (swappable via Core Engine)
Student: unsloth/Llama-3.2-1B-Instruct-bnb-4bit

Requirements:
    pip install unsloth
    pip install --no-deps trl>=0.8.0 peft accelerate bitsandbytes

Usage:
    python finetune_llama_distill.py --data data/v6-distill/teacher_orpo_train.jsonl
    python finetune_llama_distill.py --data data/v6-distill/teacher_orpo_train.jsonl --locft-mode
    python finetune_llama_distill.py --data data/v6-distill/teacher_orpo_train.jsonl --no-locft-mode
    python finetune_llama_distill.py --data data/v6-distill/teacher_orpo_train.jsonl --export-gguf
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
    if hasattr(torch, "__version__") and not hasattr(torch, "int1"):
        torch.int1 = torch.int8
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
    """Load ORPO preference-pair data from JSONL file."""
    samples = []
    with open(data_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                sample = json.loads(line)
                if not all(k in sample for k in ("prompt", "chosen", "rejected")):
                    print(f"  [Warning] Line {line_num}: missing required keys, skipping")
                    continue
                samples.append(sample)
            except json.JSONDecodeError as e:
                print(f"  [Warning] Line {line_num}: JSON parse error: {e}")
                continue

    return samples


def main():
    parser = argparse.ArgumentParser(
        description="Phase 6.3 — Distill 8B Teacher knowledge into 1B Student"
    )
    parser.add_argument(
        "--data", default="finetuning/data/v6-distill/teacher_orpo_train.jsonl",
        help="Teacher-generated ORPO training data"
    )
    parser.add_argument(
        "--val-data", default="finetuning/data/v6-distill/teacher_orpo_valid.jsonl",
        help="Validation data"
    )
    parser.add_argument(
        "--output", default="finetuning/aipam_gpu_training/aipam-edge-1b-v6",
        help="Output path for Student model"
    )
    parser.add_argument(
        "--student-model", default="unsloth/Llama-3.2-1B-Instruct-bnb-4bit",
        help="Student base model (1B or 3B)"
    )
    parser.add_argument(
        "--epochs", type=int, default=3, help="Training epochs"
    )
    parser.add_argument(
        "--batch-size", type=int, default=2,
        help="Batch size per device (1B is memory-efficient)"
    )
    parser.add_argument(
        "--gradient-accumulation", type=int, default=4,
        help="Gradient accumulation steps"
    )
    parser.add_argument(
        "--learning-rate", type=float, default=5e-5, help="Learning rate"
    )
    parser.add_argument(
        "--lora-r", type=int, default=64,
        help="LoRA rank (64 for 1B, can go higher for 3B)"
    )
    parser.add_argument(
        "--lora-alpha", type=int, default=64, help="LoRA alpha"
    )
    parser.add_argument(
        "--max-seq-length", type=int, default=8192,
        help="Max sequence length (8192 for 1B edge model)"
    )
    parser.add_argument(
        "--beta", type=float, default=0.1,
        help="ORPO odds-ratio weight"
    )
    parser.add_argument(
        "--export-gguf", action="store_true",
        help="Export to GGUF Q4_K_M for Ollama edge deployment"
    )
    parser.add_argument(
        "--validate-data", action="store_true",
        help="Validate data loading without training"
    )
    parser.add_argument(
        "--resume-from", type=str, default=None,
        help="Path to existing adapter to continue training"
    )
    # Phase 6.5 — LocFT (Localized Fine-Tuning)
    parser.add_argument(
        "--locft-mode", action=argparse.BooleanOptionalAction, default=True,
        help="Phase 6.5: Surgical LoRA — target only down_proj in mid-to-late layers "
             "(default: enabled). Use --no-locft-mode for full-model LoRA."
    )
    parser.add_argument(
        "--locft-layers-start", type=int, default=8,
        help="LocFT: first transformer layer to train (inclusive, default 8 for 1B)"
    )
    parser.add_argument(
        "--locft-layers-end", type=int, default=16,
        help="LocFT: last transformer layer to train (exclusive, default 16 for 1B)"
    )
    args = parser.parse_args()

    # ── Validate data ──
    train_path = Path(args.data)
    if not train_path.exists():
        print(f"Error: Training data not found at {train_path}")
        print("Run first: python finetuning/distill_generate_labels.py")
        return

    print("=" * 60)
    locft_label = "LocFT (Surgical)" if args.locft_mode else "Full-Model"
    print(f"Phase 6.3+6.5 — AIPAM-Edge Distillation Training [{locft_label}]")
    print(f"Teacher → Student Knowledge Transfer")
    print(f"Student: {args.student_model}")
    print(f"Seed: {DAWN_RANDOM_SEED} (DAWN Constitutional)")
    print(f"Context Window: {args.max_seq_length} tokens")
    print(f"LoRA: r={args.lora_r}, alpha={args.lora_alpha}")
    if args.locft_mode:
        print(f"LocFT: target_modules=[down_proj], layers {args.locft_layers_start}-{args.locft_layers_end - 1}")
    print("=" * 60)

    # Load preference pairs
    print(f"\nLoading Teacher-generated ORPO pairs from: {args.data}")
    train_samples = load_preference_data(args.data)
    print(f"Training pairs: {len(train_samples)}")

    if not train_samples:
        print("Error: No valid training samples found!")
        return

    # Quick validation
    sample = train_samples[0]
    print(f"\n[Sample Validation]")
    print(f"  Prompt length: {len(sample['prompt'])} chars")
    print(f"  Chosen length: {len(sample['chosen'])} chars")
    print(f"  Rejected length: {len(sample['rejected'])} chars")
    assert sample["chosen"] != sample["rejected"], "Chosen and rejected must differ!"
    print(f"  ✓ Chosen ≠ Rejected — ORPO pairs valid")

    if args.validate_data:
        print("\n✓ Data validation passed. Exiting without training.")
        return

    # Check GPU dependencies only when actually training
    if not check_dependencies():
        return

    # ── Load validation data ──
    val_samples = []
    val_path = Path(args.val_data)
    if val_path.exists():
        val_samples = load_preference_data(args.val_data)
        print(f"Validation pairs: {len(val_samples)}")

    # ── DAWN Ledger: Log training start ──
    from dawn_training_ledger import compute_config_hash, log_training_event
    from vram_monitor import log_vram_snapshot, check_vram_sufficient

    training_config = {
        "phase": "6.3+6.5",
        "random_seed": DAWN_RANDOM_SEED,
        "student_model": args.student_model,
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
        "trainer_type": "ORPOTrainer (Distillation)",
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

    # VRAM pre-flight (1B is lightweight)
    check_vram_sufficient(min_gb=6.0)

    log_training_event("distill_student_training_start", training_config)
    print(f"[DAWN] Training start logged to ledger")

    # ── Load Student model ──
    print(f"\nLoading Student model: {args.student_model}")
    from unsloth import FastLanguageModel

    model_name = args.resume_from if args.resume_from else args.student_model

    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=args.max_seq_length,
            dtype=None,
            load_in_4bit=True,
        )
        vram_post_load = log_vram_snapshot("student_model_loaded")
    except Exception as e:
        import traceback
        traceback.print_exc()
        log_training_event(
            "distill_student_training_failed", training_config,
            metrics={"error": str(e), "stage": "model_load"}
        )
        return

    # ── Apply LoRA adapters ──
    # Phase 6.5: Surgical vs Full-Model LoRA selection
    if args.locft_mode:
        locft_modules = ["down_proj"]
        locft_layers = list(range(args.locft_layers_start, args.locft_layers_end))
        print(f"\nApplying LocFT LoRA adapters (surgical mode)...")
        print(f"  target_modules: {locft_modules}")
        print(f"  layers_to_transform: {locft_layers[0]}-{locft_layers[-1]}")
    else:
        locft_modules = [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ]
        locft_layers = None
        print(f"\nApplying full-model LoRA adapters (r={args.lora_r}, alpha={args.lora_alpha})...")
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

    # Print trainable parameters
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Trainable: {trainable_params:,} / {total_params:,} "
          f"({trainable_params/total_params*100:.1f}%)")

    # ── Prepare dataset ──
    from datasets import Dataset

    train_dataset = Dataset.from_list(train_samples)
    eval_dataset = Dataset.from_list(val_samples) if val_samples else None

    # ── Configure ORPO Trainer ──
    from trl import ORPOTrainer, ORPOConfig

    training_args = ORPOConfig(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation,
        learning_rate=args.learning_rate,
        beta=args.beta,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        optim="adamw_8bit",
        weight_decay=0.01,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=5,
        save_strategy="epoch",
        evaluation_strategy="epoch" if eval_dataset else "no",
        seed=DAWN_RANDOM_SEED,
        max_length=args.max_seq_length,
        max_prompt_length=int(args.max_seq_length * 0.75),
        report_to="none",
    )

    trainer = ORPOTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        tokenizer=tokenizer,
    )

    # ── Train ──
    print(f"\n{'=' * 60}")
    print(f"Starting AIPAM-Edge Distillation Training")
    print(f"  Student: {args.student_model}")
    print(f"  Pairs: {len(train_samples)}")
    print(f"  Epochs: {args.epochs}")
    print(f"  Effective batch: {args.batch_size * args.gradient_accumulation}")
    print(f"{'=' * 60}")

    try:
        train_result = trainer.train()

        # Log peak VRAM
        vram_post_train = log_vram_snapshot("post_distillation_training")

        # ── DAWN Ledger: Log completion ──
        completion_metrics = {
            "train_loss": train_result.training_loss,
            "train_runtime": train_result.metrics.get("train_runtime"),
            "train_samples_per_second": train_result.metrics.get(
                "train_samples_per_second"
            ),
        }
        if vram_post_train:
            completion_metrics["peak_vram_gb"] = vram_post_train["peak_reserved_gb"]
        log_training_event(
            "distill_student_training_complete", training_config,
            metrics=completion_metrics
        )
        print(f"\n[DAWN] Distillation training complete!")
        print(f"[DAWN] Final loss: {train_result.training_loss:.4f}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        log_training_event(
            "distill_student_training_failed", training_config,
            metrics={"error": str(e), "stage": "training"}
        )
        return

    # ── Save model ──
    print(f"\nSaving Student model to: {args.output}")
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)

    # ── Export to GGUF for edge deployment ──
    if args.export_gguf:
        print("\n" + "=" * 60)
        print("Exporting AIPAM-Edge to GGUF (Q4_K_M)")
        print("=" * 60)

        try:
            model.save_pretrained_gguf(
                args.output + "-gguf",
                tokenizer,
                quantization_method="q4_k_m",
            )
            gguf_path = Path(args.output + "-gguf")
            print(f"  ✅ GGUF exported to: {gguf_path}")

            # Log GGUF export
            gguf_files = list(gguf_path.glob("*.gguf"))
            if gguf_files:
                size_mb = gguf_files[0].stat().st_size / (1024 ** 2)
                print(f"  File: {gguf_files[0].name} ({size_mb:.0f}MB)")

            log_training_event(
                "distill_gguf_export", training_config,
                metrics={"format": "q4_k_m", "output": str(gguf_path)}
            )
        except Exception as e:
            print(f"  ⚠️  GGUF export failed: {e}")
            print("  You can export manually later with:")
            print(f"    model.save_pretrained_gguf('{args.output}-gguf', tokenizer, 'q4_k_m')")

    print(f"\n{'=' * 60}")
    print(f"✓ AIPAM-Edge 1B Distillation Complete!")
    print(f"  Model: {args.output}")
    print(f"  Next: python finetuning/verify_model_bias.py --model {args.output} --compare-teacher")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
