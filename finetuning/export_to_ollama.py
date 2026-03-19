#!/usr/bin/env python3
"""
Export trained LoRA adapters → merged GGUF → Ollama model.

Steps:
  1. Load base model + trained LoRA adapters via Unsloth
  2. Merge adapters into base model
  3. Export to GGUF (q4_k_m quantization)
  4. Detect next version number from Ollama
  5. Create Modelfile and register with Ollama

Usage:
    python export_to_ollama.py \
        --adapter-dir finetuning/data/models/run_20260317_123456 \
        --base-model unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit \
        --model-prefix aipam-trafficllm \
        --ollama-url http://localhost:11434
"""

import argparse
import json
import os
import re
import subprocess
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
# -------------------------------------------------------


def get_next_version(model_prefix: str, ollama_url: str) -> int:
    """Query Ollama for existing models and find next version number."""
    try:
        import urllib.request
        req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        models = data.get("models", [])
        pattern = re.compile(rf"^{re.escape(model_prefix)}-v(\d+)")
        max_ver = 0
        for m in models:
            name = m.get("name", "").split(":")[0]  # strip :latest
            match = pattern.match(name)
            if match:
                ver = int(match.group(1))
                if ver > max_ver:
                    max_ver = ver
        return max_ver + 1
    except Exception as e:
        print(f"[EXPORT] Warning: Could not query Ollama for versions: {e}")
        return 9  # Safe default


def create_modelfile(gguf_path: str, output_path: str) -> str:
    """Create an Ollama Modelfile pointing to the GGUF."""
    # Ollama requires absolute paths in the FROM directive
    abs_gguf_path = os.path.abspath(gguf_path)
    modelfile_content = f"""FROM {abs_gguf_path}

TEMPLATE \"\"\"{{{{ if .System }}}}<|start_header_id|>system<|end_header_id|>

{{{{ .System }}}}<|eot_id|>{{{{ end }}}}{{{{ if .Prompt }}}}<|start_header_id|>user<|end_header_id|>

{{{{ .Prompt }}}}<|eot_id|>{{{{ end }}}}<|start_header_id|>assistant<|end_header_id|>

{{{{ .Response }}}}<|eot_id|>\"\"\"

PARAMETER stop "<|start_header_id|>"
PARAMETER stop "<|end_header_id|>"
PARAMETER stop "<|eot_id|>"
PARAMETER temperature 0.1
PARAMETER num_ctx 4096

SYSTEM \"\"\"You are AIPAM, an expert AI network forensics analyst specializing in PCAP analysis, malware traffic detection, and incident response. You analyze network traffic with precision, identifying threats, protocols, and anomalies. Always provide structured, evidence-based analysis.\"\"\"
"""
    modelfile_path = os.path.join(output_path, "Modelfile")
    with open(modelfile_path, "w") as f:
        f.write(modelfile_content)
    print(f"[EXPORT] Modelfile written to: {modelfile_path}")
    return modelfile_path


def _resolve_base_model_path(model, base_model_name: str):
    """
    Resolve the 16-bit base model from HF cache and patch model.config._name_or_path
    so Unsloth's merge_and_overwrite_lora can find it in offline mode.
    """
    import re as _re

    # Strip quantization suffixes to get the 16-bit model name
    clean_name = _re.sub(r'-bnb-[48]bit$', '', base_model_name)

    # Candidate model repo IDs to search for in the HF cache
    candidates = [clean_name]
    # Also try the upstream repo (e.g. unsloth/X -> meta-llama/X)
    model_short = clean_name.split("/")[-1]
    # Common upstream mappings
    if clean_name.startswith("unsloth/"):
        # Try meta-llama variant (strip "Meta-" prefix if present)
        stripped = _re.sub(r'^Meta-', '', model_short)
        candidates.append(f"meta-llama/{stripped}")
        candidates.append(f"meta-llama/{model_short}")

    cache_dir = Path.home() / ".cache" / "huggingface" / "hub"
    for repo_id in candidates:
        # HF cache uses models--{org}--{name} directory structure
        cache_model_dir = cache_dir / f"models--{repo_id.replace('/', '--')}"
        if not cache_model_dir.exists():
            continue
        snapshots_dir = cache_model_dir / "snapshots"
        if not snapshots_dir.exists():
            continue
        # Find the first snapshot that has safetensors files
        for snapshot in sorted(snapshots_dir.iterdir()):
            if snapshot.is_dir() and any(snapshot.glob("*.safetensors")):
                resolved_path = str(snapshot)
                print(f"[EXPORT] Resolved 16-bit base model path: {resolved_path}")
                model.config._name_or_path = resolved_path
                return
    print(f"[EXPORT] WARNING: Could not resolve 16-bit base model in HF cache for: {base_model_name}")


def main():
    parser = argparse.ArgumentParser(description="Export LoRA → GGUF → Ollama")
    parser.add_argument("--adapter-dir", required=True, help="Path to trained LoRA adapter directory")
    parser.add_argument("--base-model", default="unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit", help="Base model name")
    parser.add_argument("--model-prefix", default="aipam-trafficllm", help="Model name prefix for Ollama")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama API URL")
    parser.add_argument("--quantization", default="q4_k_m", help="GGUF quantization method")
    parser.add_argument("--max-seq-length", type=int, default=4096, help="Max sequence length")
    parser.add_argument("--version", type=int, default=None, help="Force specific version number")
    args = parser.parse_args()

    adapter_dir = Path(args.adapter_dir)
    if not adapter_dir.exists():
        print(f"[EXPORT] ERROR: Adapter directory not found: {adapter_dir}")
        sys.exit(1)

    # Step 1: Determine version
    if args.version:
        version = args.version
    else:
        version = get_next_version(args.model_prefix, args.ollama_url)
    model_name = f"{args.model_prefix}-v{version}"
    print(f"\n{'='*60}")
    print(f"[EXPORT] Exporting as: {model_name}")
    print(f"[EXPORT] Adapter dir:  {adapter_dir}")
    print(f"[EXPORT] Base model:   {args.base_model}")
    print(f"[EXPORT] Quantization: {args.quantization}")
    print(f"{'='*60}\n")

    # Step 2: Load model + LoRA adapters
    print("[EXPORT] Step 1/4: Loading base model + LoRA adapters...")
    from unsloth import FastLanguageModel
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(adapter_dir),
        max_seq_length=args.max_seq_length,
        dtype=None,
        load_in_4bit=True,
    )
    print("[EXPORT] Model loaded successfully.")

    # Step 3: Resolve 16-bit base model path for offline merge
    # Unsloth strips '-bnb-4bit' and looks for the 16-bit base model.
    # In offline mode, it can't find it via HF API, and the HF cache path
    # isn't checked by check_local_model_exists(). We resolve it manually.
    _resolve_base_model_path(model, args.base_model)

    # Step 4: Merge and export to GGUF
    gguf_dir = adapter_dir / "gguf_export"
    gguf_dir.mkdir(parents=True, exist_ok=True)

    # Map string quantization types to numeric IDs for llama-quantize.
    # Some builds of llama-quantize fail to parse string type names when an
    # output filename is provided (stoi error), so we always use numeric IDs.
    QUANT_TYPE_MAP = {
        "q4_0": "2", "q4_1": "3", "q5_0": "8", "q5_1": "9",
        "q2_k": "10", "q2_k_s": "21", "q3_k_s": "11", "q3_k_m": "12",
        "q3_k_l": "13", "q4_k_s": "14", "q4_k_m": "15", "q4_k": "15",
        "q5_k_s": "16", "q5_k_m": "17", "q5_k": "17", "q6_k": "18",
        "q8_0": "7", "f16": "1", "bf16": "32", "f32": "0",
    }

    # Symlink llama.cpp so Unsloth's check_llama_cpp finds the binaries
    project_llama_cpp = Path(__file__).resolve().parent.parent / "llama.cpp"
    local_link = gguf_dir / "llama.cpp"
    if project_llama_cpp.exists() and not local_link.exists():
        local_link.symlink_to(project_llama_cpp)
        print(f"[EXPORT] Symlinked llama.cpp -> {project_llama_cpp}")

    # Step 2a: Use Unsloth to merge LoRA and convert to BF16 GGUF only.
    # We skip Unsloth's quantization because the local llama-quantize build
    # doesn't accept string type names in 4-arg mode (stoi bug).
    print(f"[EXPORT] Step 2/4: Merging LoRA + exporting BF16 GGUF to {gguf_dir}...")
    old_cwd = os.getcwd()
    os.chdir(str(gguf_dir))
    try:
        model.save_pretrained_gguf(
            str(gguf_dir),
            tokenizer,
            quantization_method="bf16",
        )
    finally:
        os.chdir(old_cwd)
    print("[EXPORT] BF16 GGUF export complete.")

    # Find the BF16 GGUF file
    bf16_files = list(gguf_dir.glob("*.BF16.gguf")) or list(gguf_dir.glob("*.gguf"))
    if not bf16_files:
        bf16_files = list(gguf_dir.glob("**/*.gguf"))
    if not bf16_files:
        print("[EXPORT] ERROR: No BF16 GGUF file found after merge")
        sys.exit(1)
    bf16_path = bf16_files[0]
    print(f"[EXPORT] BF16 file: {bf16_path}")

    # Step 2b: Quantize BF16 -> target quantization using llama-quantize
    # with numeric type ID to avoid the stoi parsing bug.
    quant_key = args.quantization.lower()
    if quant_key == "bf16":
        # Already BF16, no further quantization needed
        gguf_path = str(bf16_path)
    else:
        quant_id = QUANT_TYPE_MAP.get(quant_key)
        if quant_id is None:
            print(f"[EXPORT] ERROR: Unknown quantization type '{args.quantization}'")
            print(f"[EXPORT] Supported: {', '.join(sorted(QUANT_TYPE_MAP.keys()))}")
            sys.exit(1)
        quant_label = args.quantization.upper().replace("-", "_")
        output_name = bf16_path.stem.replace(".BF16", "") + f".{quant_label}.gguf"
        output_path = gguf_dir / output_name
        quantizer = str(project_llama_cpp / "llama-quantize")
        print(f"[EXPORT] Quantizing BF16 -> {quant_label} (type {quant_id})...")
        try:
            result = subprocess.run(
                [quantizer, str(bf16_path), str(output_path), quant_id],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode != 0:
                print(f"[EXPORT] ERROR: llama-quantize failed (exit {result.returncode})")
                print(f"[EXPORT] stderr: {result.stderr.strip()}")
                sys.exit(1)
            print(f"[EXPORT] Quantization complete.")
        except subprocess.TimeoutExpired:
            print("[EXPORT] ERROR: llama-quantize timed out after 600s")
            sys.exit(1)
        gguf_path = str(output_path)

        # Remove the large BF16 intermediate file to save disk space
        try:
            bf16_path.unlink()
            print(f"[EXPORT] Removed intermediate BF16 file")
        except OSError:
            pass

    print(f"[EXPORT] GGUF file: {gguf_path}")

    # Step 4: Create Modelfile
    print("[EXPORT] Step 3/4: Creating Modelfile...")
    modelfile_path = create_modelfile(gguf_path, str(gguf_dir))

    # Step 5: Register with Ollama
    print(f"[EXPORT] Step 4/4: Registering {model_name} with Ollama...")
    try:
        result = subprocess.run(
            ["ollama", "create", model_name, "-f", modelfile_path],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0:
            print(f"[EXPORT] ✓ Model registered: {model_name}")
            print(f"[EXPORT] Output: {result.stdout.strip()}")
        else:
            print(f"[EXPORT] ERROR: ollama create failed (exit {result.returncode})")
            print(f"[EXPORT] stderr: {result.stderr.strip()}")
            sys.exit(1)
    except FileNotFoundError:
        print("[EXPORT] ERROR: 'ollama' command not found. Is Ollama installed?")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[EXPORT] ERROR: ollama create timed out after 600s")
        sys.exit(1)

    # Output summary as JSON for the host trainer to parse
    summary = {
        "status": "success",
        "model_name": model_name,
        "version": version,
        "gguf_path": gguf_path,
        "quantization": args.quantization,
        "adapter_dir": str(adapter_dir),
    }
    print(f"\n[EXPORT_RESULT]{json.dumps(summary)}")
    print(f"\n{'='*60}")
    print(f"[EXPORT] ✓ Successfully deployed {model_name}")
    print(f"[EXPORT] You can now use it in AIPAM or test with:")
    print(f"[EXPORT]   ollama run {model_name}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

