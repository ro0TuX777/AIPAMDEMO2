"""
TrafficLLM API Server

Provides an OpenAI-compatible API endpoint for TrafficLLM inference.
This allows AIPAM to use TrafficLLM as a drop-in replacement for Ollama.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Add TrafficLLM to path
sys.path.insert(0, "/app/trafficllm")

app = FastAPI(title="TrafficLLM API Server", version="1.0.0")

# Global model references
model = None
tokenizer = None
peft_models = {}
current_task = None


class Message(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[Message]
    temperature: float = 0.1
    max_tokens: int = 2000
    response_format: Optional[Dict[str, str]] = None


class ChatCompletionResponse(BaseModel):
    id: str = "chatcmpl-trafficllm"
    object: str = "chat.completion"
    created: int = 0
    model: str = "trafficllm"
    choices: List[Dict[str, Any]]
    usage: Dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def load_model():
    """Load the base ChatGLM2 model and PEFT adapters."""
    global model, tokenizer, peft_models

    model_path = os.getenv("TRAFFICLLM_MODEL_PATH", "/app/models/chatglm2-6b")
    peft_path = os.getenv("TRAFFICLLM_PEFT_PATH", "/app/models/peft")

    print(f"Loading base model from {model_path}...")

    try:
        from transformers import AutoModel, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        model = AutoModel.from_pretrained(
            model_path,
            trust_remote_code=True,
            torch_dtype=torch.float16,
            device_map="auto",
        )

        # Load PEFT adapters if available
        if os.path.exists(peft_path):
            config_file = os.path.join(peft_path, "config.json")
            if os.path.exists(config_file):
                with open(config_file) as f:
                    peft_config = json.load(f)
                    for task_name, adapter_path in peft_config.get("peft_set", {}).items():
                        full_path = os.path.join(peft_path, adapter_path)
                        if os.path.exists(full_path):
                            print(f"Found PEFT adapter for {task_name}: {full_path}")
                            peft_models[task_name] = full_path

        print("Model loaded successfully!")
        return True

    except Exception as e:
        print(f"Warning: Could not load model: {e}")
        print("Server will run in mock mode")
        return False


def detect_task(prompt: str) -> str:
    """Detect which TrafficLLM task to use based on the prompt."""
    prompt_lower = prompt.lower()

    task_keywords = {
        "MTD": ["malware", "malicious traffic", "malware detection"],
        "BND": ["botnet", "bot detection", "botnet detection"],
        "WAD": ["web attack", "sql injection", "xss", "web application"],
        "AAD": ["apt", "advanced persistent", "apt attack"],
        "EVD": ["vpn", "encrypted vpn", "vpn detection"],
        "TBD": ["tor", "onion", "tor detection", "tor behavior"],
    }

    for task, keywords in task_keywords.items():
        if any(kw in prompt_lower for kw in keywords):
            return task

    # Default to malware traffic detection for security analysis
    return "MTD"


def generate_response(prompt: str, system_prompt: str, temperature: float, max_tokens: int) -> str:
    """Generate a response using TrafficLLM or mock response."""
    global model, tokenizer, current_task

    if model is None:
        # Return mock response for testing
        return json.dumps({
            "overall_severity": "medium",
            "attack_chain": [{
                "stage": "initial_access",
                "description": "TrafficLLM detected potential malicious traffic patterns.",
                "evidence": ["Suspicious network flow patterns detected."],
                "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]
            }],
            "host_findings": [],
            "anomalies": [],
            "mitre_techniques_overall": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]
        })

    # Detect task and load appropriate PEFT adapter
    task = detect_task(prompt)
    if task != current_task and task in peft_models:
        print(f"Switching to PEFT adapter for task: {task}")
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, peft_models[task])
        current_task = task

    # Generate response
    full_prompt = f"{system_prompt}\n\n{prompt}"
    inputs = tokenizer(full_prompt, return_tensors="pt").to(model.device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            temperature=temperature,
            do_sample=temperature > 0,
        )

    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    # Extract only the generated part
    response = response[len(full_prompt):].strip()

    return response


@app.on_event("startup")
async def startup_event():
    """Load model on startup."""
    load_model()


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "model_loaded": model is not None}


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest) -> ChatCompletionResponse:
    """OpenAI-compatible chat completions endpoint."""
    try:
        system_prompt = ""
        user_prompt = ""

        for msg in request.messages:
            if msg.role == "system":
                system_prompt = msg.content
            elif msg.role == "user":
                user_prompt = msg.content

        response_text = generate_response(
            user_prompt, system_prompt, request.temperature, request.max_tokens
        )

        return ChatCompletionResponse(
            model=request.model,
            choices=[{"index": 0, "message": {"role": "assistant", "content": response_text}, "finish_reason": "stop"}],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("TRAFFICLLM_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)

