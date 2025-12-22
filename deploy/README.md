# AIPAM Deployment Guide

**AI-Powered PCAP Analysis Module - Customer Deployment**

## Quick Start

```bash
# 1. Load the Docker images (provided as tar files)
docker load < aipam-app.tar
docker load < aipam-ollama.tar

# 2. Start the stack
docker-compose -f docker-compose.yml up -d

# 3. Access the application
open http://localhost
```

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 20 GB | 50 GB |
| **GPU** | None (CPU mode) | NVIDIA GPU 8GB+ VRAM |
| **Docker** | v20.10+ | v24+ |
| **OS** | Ubuntu 20.04+ / Windows 10+ / macOS 12+ | Ubuntu 22.04 LTS |

## Deployment Options

### Option 1: Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Option 2: Individual Containers

```bash
# Start Ollama (LLM server)
docker run -d --name aipam-ollama \
  -p 11434:11434 \
  -v ollama-models:/root/.ollama \
  aipam-ollama:latest

# Start App (after Ollama is healthy)
docker run -d --name aipam-app \
  -p 80:80 \
  -e OLLAMA_HOST=http://aipam-ollama:11434 \
  -v aipam-data:/app/data \
  --link aipam-ollama:ollama \
  aipam-app:latest
```

## GPU Support (Optional)

For faster inference, enable GPU support:

```yaml
# In docker-compose.yml, uncomment:
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: 1
          capabilities: [gpu]
```

Requires: [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama server URL |
| `DATABASE_URL` | `sqlite:///data/aipam.db` | Database connection |

### Volumes

| Volume | Purpose |
|--------|---------|
| `aipam-data` | SQLite database, analysis results |
| `aipam-uploads` | Uploaded PCAP files |
| `ollama-models` | Cached LLM model weights |

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 80 | App | Web interface & API |
| 11434 | Ollama | LLM API (internal) |

## Health Checks

```bash
# Check app health
curl http://localhost/api/health

# Check Ollama health  
curl http://localhost:11434/api/tags

# Check all containers
docker-compose ps
```

## Troubleshooting

### Ollama taking too long to start
The first startup imports the model (~2-5 minutes). Check logs:
```bash
docker logs aipam-ollama
```

### Out of memory errors
Reduce context size in Modelfile or add more RAM.

### GPU not detected
Ensure NVIDIA Container Toolkit is installed:
```bash
nvidia-container-cli info
```

## Support

For issues, contact: support@blue-cloak.com

