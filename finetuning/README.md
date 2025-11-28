# AIPAM Fine-tuning Pipeline

Fine-tune llama3.1:8b for network traffic analysis using TrafficLLM's training methodology.

## Quick Start

### Apple Silicon (M1/M2/M3 Mac) - Recommended

```bash
# 1. Install dependencies
pip install mlx mlx-lm

# 2. Download training data
python download_training_data.py

# 3. Process PCAP files (after downloading datasets)
python process_training_data.py

# 4. Create fine-tuning dataset
python create_finetuning_dataset.py

# 5. Fine-tune with MLX
python finetune_mlx.py

# 6. Convert to GGUF
python convert_mlx_to_gguf.py

# 7. Import to Ollama
./import_to_ollama.sh models/aipam-llama.gguf aipam-traffic-llm
```

### NVIDIA GPU (Linux/Windows)

```bash
# 1. Install dependencies
pip install unsloth
pip install --no-deps trl peft accelerate bitsandbytes

# 2. Download training data
python download_training_data.py

# 3. Process PCAP files (after downloading datasets)
python process_training_data.py

# 4. Create fine-tuning dataset
python create_finetuning_dataset.py

# 5. Fine-tune the model
python finetune_llama.py --export-gguf

# 6. Import to Ollama
./import_to_ollama.sh
```

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Fine-tuning Pipeline                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ Raw PCAPs   │───▶│ Zeek/AIPAM  │───▶│ Processed Samples   │  │
│  │ (labeled)   │    │ Pipeline    │    │ (JSONL)             │  │
│  └─────────────┘    └─────────────┘    └──────────┬──────────┘  │
│                                                    │             │
│                                                    ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ GGUF Model  │◀───│ Unsloth     │◀───│ Training Dataset    │  │
│  │ (Ollama)    │    │ Fine-tune   │    │ (ChatML format)     │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Training Data Sources

Based on TrafficLLM's methodology, we use these public datasets:

| Dataset | Type | Description |
|---------|------|-------------|
| USTC-TFC-2016 | Malware | 10 malware families + 10 normal apps |
| ISCX-Botnet-2014 | Botnet | Botnet C2 traffic |
| CSIC-2010 | Web Attack | SQL injection, XSS, etc. |
| DAPT-2020 | APT | Advanced persistent threats |
| ISCX-VPN-2016 | VPN | Encrypted VPN detection |
| ISCX-Tor-2016 | Tor | Tor network traffic |

## Directory Structure

```
finetuning/
├── download_training_data.py   # Download datasets
├── process_training_data.py    # Process PCAPs through AIPAM
├── create_finetuning_dataset.py # Create ChatML training format
├── finetune_mlx.py             # Fine-tune with MLX (Apple Silicon)
├── finetune_llama.py           # Fine-tune with Unsloth (NVIDIA)
├── convert_mlx_to_gguf.py      # Convert MLX model to GGUF
├── import_to_ollama.sh         # Import GGUF to Ollama
├── README.md                   # This file
└── data/                       # Created by scripts
    ├── raw/                    # Raw PCAP files
    ├── processed/              # Processed samples
    └── training/               # Final training data
```

## Hardware Requirements

### Apple Silicon (MLX)

| Mac Model | RAM | Notes |
|-----------|-----|-------|
| M1/M2 (8GB) | 8GB | Works with 4-bit models, slower |
| M1/M2 Pro (16GB) | 16GB | Good performance |
| M1/M2 Max (32GB+) | 32GB+ | Best performance |

MLX is optimized for Apple Silicon and uses unified memory efficiently.

### NVIDIA GPU (Unsloth)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU | 8GB VRAM | 16GB+ VRAM |
| RAM | 16GB | 32GB+ |
| Storage | 50GB | 100GB+ |

Unsloth reduces memory requirements by ~70%, making 8B parameter fine-tuning possible on consumer GPUs.

## Using Your Fine-tuned Model

After importing to Ollama, update your AIPAM configuration:

```yaml
# docker-compose.yml
environment:
  - LLM_MODEL_NAME=aipam-traffic-llm  # Your fine-tuned model
```

## Adding Custom Training Data

1. Place labeled PCAPs in `data/raw/<category>/`
2. Run `python process_training_data.py`
3. Run `python create_finetuning_dataset.py`
4. Fine-tune with additional epochs

## References

- [TrafficLLM Paper](https://arxiv.org/abs/2310.12456)
- [TrafficLLM GitHub](https://github.com/ZGC-LLM-Safety/TrafficLLM)
- [Unsloth](https://github.com/unslothai/unsloth)

