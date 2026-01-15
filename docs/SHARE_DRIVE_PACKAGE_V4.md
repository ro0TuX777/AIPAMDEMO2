# Share Drive Package (AIPAM + TrafficLLM v4)

This repo does **not** store GGUF model weights in git. To let teammates test the v4 model, place these files on a share drive.

## Required files (minimum)
1) **GGUF model**
- `aipam-trafficllm-v4.gguf`  (the v4 TrafficLLM merged GGUF)

2) **Ollama Modelfile**
- `Modelfile.trafficllm-v4`  (use the one from this repo: `deploy/Modelfile.trafficllm-v4`)

## Recommended share-drive folder layout
```
AIPAM_SHARE/
  v4_model/
    aipam-trafficllm-v4.gguf
    Modelfile.trafficllm-v4
```

## Teammate install steps (from repo root)
1) Copy the share-drive files into the repo:
- `deploy/models/aipam-trafficllm-v4.gguf`
- `deploy/Modelfile.trafficllm-v4`

2) Import the model into Ollama:
- `cd deploy`
- `ollama create aipam-trafficllm-v4 -f Modelfile.trafficllm-v4`

3) Confirm it exists:
- `ollama list | grep aipam-trafficllm-v4`

## Integrity checks (recommended)
On the machine where the GGUF is produced:
- `sha256sum aipam-trafficllm-v4.gguf > aipam-trafficllm-v4.gguf.sha256`

On the teammate machine (after copy):
- `sha256sum -c aipam-trafficllm-v4.gguf.sha256`

## Optional (offline / customer-style delivery)
If your environment is air-gapped or you want a fully offline bundle, you can also provide Docker image tarballs created by:
- `./deploy/build.sh`
- `./deploy/package-for-customer.sh`

(Those scripts expect the GGUF to be placed under `deploy/models/` before building.)

