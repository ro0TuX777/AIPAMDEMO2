# TrafficLLM Service Dockerfile
# Based on https://github.com/ZGC-LLM-Safety/TrafficLLM

FROM nvidia/cuda:11.8-devel-ubuntu22.04

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    python3.10-dev \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.10 as default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

WORKDIR /app

# Install PyTorch with CUDA support
RUN pip install --no-cache-dir torch==2.0.1 torchvision==0.15.2 --index-url https://download.pytorch.org/whl/cu118

# Install TrafficLLM dependencies
RUN pip install --no-cache-dir \
    transformers==4.33.0 \
    peft==0.5.0 \
    accelerate==0.23.0 \
    bitsandbytes==0.41.1 \
    sentencepiece==0.1.99 \
    protobuf==3.20.0 \
    cpm_kernels \
    fastapi \
    uvicorn \
    httpx \
    pydantic

# Clone TrafficLLM repository
RUN git clone https://github.com/ZGC-LLM-Safety/TrafficLLM.git /app/trafficllm

# Copy our custom server
COPY server.py /app/server.py
COPY config.json /app/config.json

# Create models directory
RUN mkdir -p /app/models

# Expose API port
EXPOSE 8001

# Environment variables for model configuration
ENV TRAFFICLLM_MODEL_PATH=/app/models/chatglm2-6b \
    TRAFFICLLM_PEFT_PATH=/app/models/peft \
    TRAFFICLLM_PORT=8001

# Run the server
CMD ["python", "server.py"]

