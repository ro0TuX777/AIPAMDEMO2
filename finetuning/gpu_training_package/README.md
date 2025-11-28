# AIPAM Traffic LLM - GPU Training Package

Fine-tune Llama 3.1 8B for network traffic analysis on a CUDA GPU.

## Requirements

- **GPU**: NVIDIA GPU with 16GB+ VRAM (RTX 3090, 4090, A100, etc.)
- **CUDA**: 11.8 or higher
- **Python**: 3.10+
- **Hugging Face**: Account with Llama 3.1 access (accept license at https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct)

## Quick Start

### 1. Setup Environment
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Login to Hugging Face (required for Llama access)
huggingface-cli login
```

### 2. Train the Model
```bash
python train_cuda.py
```

Training takes ~30-60 minutes on a single GPU.

### 3. Merge & Convert to GGUF
```bash
python merge_and_convert.py
```

This creates `aipam-traffic-llm.gguf` (~8GB file).

### 4. Transfer to Mac & Import to Ollama
```bash
# On Mac:
ollama create aipam-traffic-llm -f Modelfile
ollama run aipam-traffic-llm
```

## File Structure

```
gpu_training_package/
├── README.md              # This file
├── requirements.txt       # Python dependencies
├── train_cuda.py          # Main training script
├── merge_and_convert.py   # Convert to GGUF
└── data/
    ├── train.jsonl        # Training data
    └── valid.jsonl        # Validation data
```

## Expected Training Output

```
CUDA Device: NVIDIA RTX 4090
VRAM: 24.0 GB

Loading model meta-llama/Llama-3.1-8B-Instruct...
trainable params: 41,943,040 || all params: 8,030,261,248 || trainable%: 0.5222

Training samples: 1800
Validation samples: 200

Starting training...
{'loss': 1.234, 'learning_rate': 1.9e-05, 'epoch': 0.5}
{'loss': 0.856, 'learning_rate': 1.5e-05, 'epoch': 1.0}
{'loss': 0.623, 'learning_rate': 1.0e-05, 'epoch': 1.5}
...
Training complete!
```

## Troubleshooting

### Out of Memory
Reduce batch size in `train_cuda.py`:
```python
BATCH_SIZE = 2  # or 1
```

### Hugging Face Access Denied
1. Go to https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct
2. Accept the license agreement
3. Wait for approval (usually instant)
4. Re-run `huggingface-cli login`

### CUDA Not Found
```bash
# Check CUDA version
nvidia-smi

# Install PyTorch with correct CUDA version
pip install torch --index-url https://download.pytorch.org/whl/cu118
```

## Model Details

- **Base Model**: meta-llama/Llama-3.1-8B-Instruct
- **Training Method**: LoRA (Low-Rank Adaptation)
- **Task**: Network traffic classification (malware, VPN, Tor detection)
- **Training Data**: TrafficLLM balanced dataset

