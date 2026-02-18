#!/usr/bin/env python3
"""
VRAM Monitor — Phase 6.2 GPU Memory Management

Lightweight utility for monitoring GPU VRAM usage during training.
Integrates with the DAWN training ledger for audit trail.

Usage:
    # As a module
    from vram_monitor import log_vram_snapshot, check_vram_sufficient

    # Standalone pre-flight check
    python vram_monitor.py
"""

import sys
from typing import Dict, Optional


def _get_torch_cuda():
    """Lazy import torch.cuda, returns None if unavailable."""
    try:
        import torch
        if torch.cuda.is_available():
            return torch.cuda
    except ImportError:
        pass
    return None


def log_vram_snapshot(label: str = "snapshot") -> Optional[Dict]:
    """Log current VRAM usage.

    Args:
        label: Human-readable label for this snapshot (e.g., "post_model_load").

    Returns:
        Dict with VRAM stats in GB, or None if no GPU.
    """
    cuda = _get_torch_cuda()
    if cuda is None:
        print(f"  [VRAM:{label}] No GPU available")
        return None

    allocated = cuda.memory_allocated() / (1024 ** 3)
    reserved = cuda.memory_reserved() / (1024 ** 3)
    peak_reserved = cuda.max_memory_reserved() / (1024 ** 3)
    total = cuda.get_device_properties(0).total_mem / (1024 ** 3)

    snapshot = {
        "label": label,
        "allocated_gb": round(allocated, 2),
        "reserved_gb": round(reserved, 2),
        "peak_reserved_gb": round(peak_reserved, 2),
        "total_gb": round(total, 2),
        "free_gb": round(total - reserved, 2),
        "utilization_pct": round((reserved / total) * 100, 1),
    }

    print(f"  [VRAM:{label}] "
          f"Allocated: {allocated:.2f}GB | "
          f"Reserved: {reserved:.2f}GB | "
          f"Peak: {peak_reserved:.2f}GB | "
          f"Total: {total:.2f}GB | "
          f"Free: {total - reserved:.2f}GB")

    return snapshot


def check_vram_sufficient(min_gb: float = 20.0) -> bool:
    """Pre-flight check: is enough VRAM available?

    Args:
        min_gb: Minimum required VRAM in GB.

    Returns:
        True if sufficient, False otherwise.
    """
    cuda = _get_torch_cuda()
    if cuda is None:
        print(f"[VRAM Pre-flight] No GPU detected. Cannot verify VRAM.")
        return False

    total = cuda.get_device_properties(0).total_mem / (1024 ** 3)
    device_name = cuda.get_device_name(0)

    print(f"[VRAM Pre-flight] GPU: {device_name}")
    print(f"[VRAM Pre-flight] Total VRAM: {total:.1f}GB (need {min_gb:.1f}GB)")

    if total < min_gb:
        print(f"[VRAM Pre-flight] ⚠️  INSUFFICIENT — {total:.1f}GB < {min_gb:.1f}GB")
        print(f"  → Enable --chunked-cross-entropy to save ~30% VRAM")
        return False

    print(f"[VRAM Pre-flight] ✅ Sufficient VRAM")
    return True


def estimate_context_vram(
    seq_length: int = 32768,
    model_params_b: float = 8.0,
    quantization_bits: int = 4,
) -> Dict:
    """Rough VRAM estimate for a given context length.

    Based on empirical data from Unsloth benchmarks:
    - 4-bit Llama 3.1 8B at 8k ≈ 10-12GB
    - 4-bit Llama 3.1 8B at 32k ≈ 18-22GB (with gradient checkpointing)
    - Attention memory scales ~O(n²) but Flash Attention reduces to ~O(n)

    Args:
        seq_length: Target sequence length.
        model_params_b: Model parameters in billions.
        quantization_bits: Quantization level (4, 8, 16).

    Returns:
        Dict with estimated VRAM breakdown.
    """
    # Model weights (rough: params * bits / 8)
    model_vram = model_params_b * quantization_bits / 8

    # KV cache (rough: 2 * n_layers * n_heads * head_dim * seq_len * dtype_size)
    # For Llama 3.1 8B: 32 layers, 8 KV heads, 128 head_dim
    n_layers, n_kv_heads, head_dim = 32, 8, 128
    kv_bytes = 2 * n_layers * n_kv_heads * head_dim * seq_length * 2  # fp16
    kv_vram = kv_bytes / (1024 ** 3)

    # Activation memory (rough, with gradient checkpointing)
    # With Unsloth's gradient checkpointing: ~30% of naive
    activation_vram = (seq_length / 4096) * 2.0 * 0.3  # baseline 2GB at 4k

    # LoRA overhead (~0.5-1GB)
    lora_vram = 0.8

    total = model_vram + kv_vram + activation_vram + lora_vram
    # Add 15% safety margin
    total_safe = total * 1.15

    return {
        "seq_length": seq_length,
        "model_weights_gb": round(model_vram, 2),
        "kv_cache_gb": round(kv_vram, 2),
        "activations_gb": round(activation_vram, 2),
        "lora_overhead_gb": round(lora_vram, 2),
        "estimated_total_gb": round(total, 2),
        "recommended_min_gb": round(total_safe, 1),
    }


def reset_peak_stats():
    """Reset CUDA peak memory tracking for fresh measurement."""
    cuda = _get_torch_cuda()
    if cuda:
        cuda.reset_peak_memory_stats()
        cuda.empty_cache()
        print("  [VRAM] Peak stats reset")


def main():
    """Standalone pre-flight check."""
    print("=" * 60)
    print("AIPAM Phase 6.2 — VRAM Pre-Flight Check")
    print("=" * 60)

    # Check GPU
    sufficient = check_vram_sufficient(min_gb=20.0)

    # Estimate for 32k context
    print("\n--- VRAM Estimates ---")
    for seq_len in [4096, 8192, 16384, 32768]:
        est = estimate_context_vram(seq_length=seq_len)
        flag = "✅" if est["recommended_min_gb"] <= 24 else "⚠️"
        print(f"  {flag} {seq_len:>6} tokens: ~{est['estimated_total_gb']:.1f}GB "
              f"(recommend {est['recommended_min_gb']:.0f}GB)")

    if not sufficient:
        print("\n[RECOMMENDATION] Use --chunked-cross-entropy flag during training.")
        print("  This saves ~30% VRAM with only 1.9% time overhead.")

    return 0 if sufficient else 1


if __name__ == "__main__":
    sys.exit(main())
