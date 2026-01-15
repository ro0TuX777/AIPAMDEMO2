# Team Test & Deploy Guide (v4 model)

This guide is for teammates to run AIPAM from the repo and use the **v4 Ollama model** (`aipam-trafficllm-v4`).

## Prerequisites
- Docker + Docker Compose
- Ollama installed on the host (or use the `deploy/` offline bundle path)
- A test PCAP file

## 1) Clone repo
```bash
git clone https://github.com/NhanBC/AIPAM.git
cd AIPAM
```

## 2) Install / import the v4 model into Ollama
From the share drive, copy files into the repo:
- `deploy/models/aipam-trafficllm-v4.gguf`
- `deploy/Modelfile.trafficllm-v4`

Then import:
```bash
cd deploy
ollama serve  # keep running in a terminal if not already running
ollama create aipam-trafficllm-v4 -f Modelfile.trafficllm-v4
ollama list | grep aipam-trafficllm-v4
cd ..
```

## 3) Start the app (recommended: docker-compose)
From repo root:
```bash
docker compose up -d --build
```

Services:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- Backend health: http://localhost:8000/healthz

## 4) Smoke test (API)
Create a job from a PCAP:
```bash
curl -s -X POST \
  -F "mode=single_window" \
  -F "pcap_files=@/path/to/sample.pcap" \
  http://localhost:8000/api/v1/jobs
```
Then check status:
- `GET http://localhost:8000/api/v1/jobs/{job_id}`

## 5) Configuration notes
- Model name is configured via `LLM_MODEL_NAME`.
- Default in repo is **`aipam-trafficllm-v4`**.
- Ollama endpoint in docker-compose uses `http://host.docker.internal:11434/...`.

## Troubleshooting
- If the backend can’t reach Ollama: confirm `ollama serve` is running and `curl http://localhost:11434/api/tags` works on the host.
- If jobs are stuck in `queued`: check the `worker` container logs (`docker compose logs -f worker`).

