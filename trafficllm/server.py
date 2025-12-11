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
config_data = {}

# IOC lookup for new malware families (from malware-traffic-analysis.net training data)
NEW_MALWARE_IOCS = {
    "Lumma_Stealer": {
        "indicators": ["lufrfrof.buzz", "wrsjqyf.click", "cloudflare-ipfs.com", "/api/", "User-Agent: Mozilla/5.0"],
        "ports": [80, 443],
        "description": "Info stealer targeting browser credentials and crypto wallets"
    },
    "Remcos_RAT": {
        "indicators": ["remcos", "ScreenCapture", "Keylogger", "GuLoader"],
        "ports": [2404, 4782, 5555],
        "description": "Remote Access Trojan used for surveillance and data theft"
    },
    "AsyncRAT": {
        "indicators": ["AsyncClient", "AsyncRAT", "VenomRAT", "pastebin.com"],
        "ports": [6606, 7707, 8808],
        "description": "Open-source RAT with keylogging and remote control capabilities"
    },
    "DarkGate": {
        "indicators": ["darkgate", ".autoit", "hVNC", "aadg"],
        "ports": [80, 443, 8080],
        "description": "Malware-as-a-Service loader with RAT capabilities"
    },
    "Danabot": {
        "indicators": ["danabot", "Matanbuchus", "dll injection"],
        "ports": [443, 8080],
        "description": "Banking trojan targeting financial credentials"
    },
    "CobaltStrike": {
        "indicators": ["beacon", "stager", "malleable", "/jquery-", "cdn.bootcss.com"],
        "ports": [80, 443, 8080, 50050],
        "description": "Adversary simulation toolkit commonly abused by threat actors"
    },
    "NetSupport_RAT": {
        "indicators": ["NetSupport", "client32.exe", "NSTN", "SmartApeSG"],
        "ports": [5405, 5421],
        "description": "Legitimate remote support tool often abused for unauthorized access"
    },
    "Formbook": {
        "indicators": ["XLoader", "formbook", "form grabber"],
        "ports": [80, 443],
        "description": "Form-grabbing malware that steals credentials from web forms"
    },
    "Redline_Stealer": {
        "indicators": ["redline", "stealer", "wallet.dat", "Login Data"],
        "ports": [80, 443],
        "description": "Info stealer targeting credentials, crypto wallets, and system info"
    },
    "Pikabot": {
        "indicators": ["pikabot", "ta577", "Meduza"],
        "ports": [443, 2078],
        "description": "Modular backdoor often distributed via malspam campaigns"
    },
    "Latrodectus": {
        "indicators": ["latrodectus", "BackConnect", "IcedID successor"],
        "ports": [443, 8443],
        "description": "Downloader malware linked to IcedID threat actors"
    }
}


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
    """Load the base ChatGLM2 model with prefix tuning support."""
    global model, tokenizer, peft_models, config_data

    # Load from config.json first, then env vars, then defaults
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, "config.json")

    if os.path.exists(config_file):
        with open(config_file) as f:
            config_data = json.load(f)
        # Resolve relative paths from config.json
        model_path = os.path.join(script_dir, config_data.get("model_path", "./models/chatglm2-6b"))
        peft_path = os.path.join(script_dir, config_data.get("peft_path", "./models/peft"))
    else:
        model_path = os.getenv("TRAFFICLLM_MODEL_PATH", "/app/models/chatglm2-6b")
        peft_path = os.getenv("TRAFFICLLM_PEFT_PATH", "/app/models/peft")
        config_data = {}

    print(f"Loading base model from {model_path}...")

    try:
        from transformers import AutoModel, AutoTokenizer, AutoConfig, BitsAndBytesConfig

        tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        # Load with pre_seq_len=128 for prefix tuning (required by TrafficLLM)
        model_config = AutoConfig.from_pretrained(model_path, trust_remote_code=True, pre_seq_len=128)

        # Use 4-bit quantization to fit in 12GB GPU while keeping prefix encoder trainable
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4"
        )

        model = AutoModel.from_pretrained(
            model_path,
            config=model_config,
            trust_remote_code=True,
            quantization_config=quantization_config,
            device_map="auto"
        )

        # Store PEFT adapter paths from config
        if os.path.exists(peft_path) and config_data.get("peft_set"):
            for task_name, adapter_path in config_data["peft_set"].items():
                full_path = os.path.join(peft_path, adapter_path)
                if os.path.exists(full_path):
                    print(f"Found prefix tuning adapter for {task_name}: {full_path}")
                    peft_models[task_name] = full_path

        print("Model loaded successfully!")
        return True

    except Exception as e:
        print(f"Warning: Could not load model: {e}")
        import traceback
        traceback.print_exc()
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


def check_ioc_matches(traffic_data: str) -> List[Dict[str, Any]]:
    """Check traffic data against known IOCs for new malware families."""
    matches = []
    traffic_lower = traffic_data.lower()

    for malware_name, ioc_info in NEW_MALWARE_IOCS.items():
        for indicator in ioc_info["indicators"]:
            if indicator.lower() in traffic_lower:
                matches.append({
                    "malware": malware_name,
                    "matched_indicator": indicator,
                    "description": ioc_info["description"],
                    "known_ports": ioc_info["ports"]
                })
                break  # One match per malware family is enough

    return matches


def get_preprompt(task: str, traffic_data: str) -> str:
    """Get the task-specific preprompt for TrafficLLM."""
    # Extended malware categories including new families from malware-traffic-analysis.net
    # Original categories: BitTorrent, FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft,
    #                      Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus
    # New categories: Lumma_Stealer, Remcos_RAT, NetSupport_RAT, AsyncRAT, DarkGate, Danabot, Formbook,
    #                 Redline_Stealer, CobaltStrike, Pikabot, Latrodectus
    preprompt_set = {
        "MTD": "Given the following traffic data <packet> that contains protocol fields, traffic features, and "
               "payloads. Please conduct the ENCRYPTED MALWARE DETECTION TASK to determine which application "
               "category the encrypted beign or malicious traffic belongs to. The categories include 'BitTorrent, "
               "FTP, Facetime, Gmail, MySQL, Outlook, SMB, Skype, Weibo, WorldOfWarcraft, Cridex, Geodo, Htbot, Miuref, "
               "Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus, Lumma_Stealer, Remcos_RAT, NetSupport_RAT, AsyncRAT, "
               "DarkGate, Danabot, Formbook, Redline_Stealer, CobaltStrike, Pikabot, Latrodectus'.\n",
        "BND": "Given the following traffic data <packet> that contains protocol fields, traffic features, "
               "and payloads. Please conduct the BOTNET DETECTION TASK to determine which type of network the "
               "traffic belongs to. The categories include 'IRC, Neris, RBot, Virut, normal'.\n",
        "WAD": "Classify the given HTTP request into benign and malicious categories. Each HTTP request will consist "
               "of three parts: method, URL, and body, presented in JSON format. If a web attack is detected in an "
               "HTTP request, please output an 'exception'. Only output 'malicious' or 'benign', no additional output "
               "is required. The given HTTP request is as follows:\n",
        "AAD": "Classify the given HTTP request into normal and abnormal categories. Each HTTP request will consist "
               "of three parts: method, URL, and body, presented in JSON format. If a web attack is detected in an "
               "HTTP request, please output an 'exception'. Only output 'abnormal' or 'normal', no additional output "
               "is required. The given HTTP request is as follows:\n",
        "EVD": "Given the following traffic data <packet> that contains protocol fields, traffic features, "
               "and payloads. Please conduct the encrypted VPN detection task to determine which behavior or "
               "application category the VPN encrypted traffic belongs to. The categories include 'aim, bittorrent, "
               "email, facebook, ftps, hangout, icq, netflix, sftp, skype, spotify, vimeo, voipbuster, youtube'.\n",
        "TBD": "Given the following traffic data <packet> that contains protocol fields, traffic features, and "
               "payloads. Please conduct the TOR BEHAVIOR DETECTION TASK to determine which behavior or application "
               "category the traffic belongs to under the Tor network. The categories include 'audio, browsing, chat, "
               "file, mail, p2p, video, voip'.\n"
    }

    if task == "AAD":
        # AAD expects the traffic data without the <packet>: prefix
        if "<packet>:" in traffic_data:
            traffic_data = traffic_data.split("<packet>:")[1]
        return preprompt_set[task] + traffic_data
    else:
        return preprompt_set[task] + traffic_data


def load_prefix_tuning(model_to_load, ptuning_path):
    """Load prefix tuning weights into model (TrafficLLM's approach)."""
    if ptuning_path is None:
        return model_to_load

    pytorch_model_path = os.path.join(ptuning_path, "pytorch_model.bin")
    if not os.path.exists(pytorch_model_path):
        print(f"Warning: {pytorch_model_path} not found")
        return model_to_load

    print(f"Loading prefix tuning from {ptuning_path}...")
    prefix_state_dict = torch.load(pytorch_model_path, map_location="cpu")
    new_prefix_state_dict = {}
    for k, v in prefix_state_dict.items():
        if k.startswith("transformer.prefix_encoder."):
            new_prefix_state_dict[k[len("transformer.prefix_encoder."):]] = v

    # Load prefix encoder weights with assign=True for meta tensors
    if hasattr(model_to_load, 'transformer') and hasattr(model_to_load.transformer, 'prefix_encoder'):
        # Get device of the model
        device = next(model_to_load.parameters()).device
        # Move weights to correct device and load with assign=True
        for k in new_prefix_state_dict:
            new_prefix_state_dict[k] = new_prefix_state_dict[k].to(device)
        model_to_load.transformer.prefix_encoder.load_state_dict(new_prefix_state_dict, assign=True)
        # Keep prefix encoder in float32 for stability (per TrafficLLM's approach)
        model_to_load.transformer.prefix_encoder.float()
        print(f"Prefix encoder loaded successfully")
    else:
        print("Warning: Model doesn't have prefix_encoder, skipping prefix tuning load")

    return model_to_load


def custom_generate(model_to_use, tokenizer_to_use, prompt: str, max_length: int = 256, temperature: float = 0.1) -> str:
    """Generate response using manual token-by-token generation with prefix tuning."""
    device = next(model_to_use.parameters()).device

    # Build prompt in ChatGLM format
    formatted_prompt = f"[Round 1]\n\n问：{prompt}\n\n答："
    inputs = tokenizer_to_use([formatted_prompt], return_tensors="pt")
    input_ids = inputs["input_ids"].to(device)

    eos_token_id = tokenizer_to_use.eos_token_id or 2

    # Generate tokens one by one without using cache (to avoid DynamicCache issues)
    generated_ids = input_ids.clone()

    with torch.no_grad():
        for step in range(max_length):
            # Forward pass through the full model
            outputs = model_to_use(
                input_ids=generated_ids,
                use_cache=False,  # Disable cache to avoid DynamicCache issues
                return_dict=True
            )

            # Get logits for the last token
            logits = outputs.logits[:, -1, :]

            # Apply temperature
            if temperature > 0:
                logits = logits / temperature
                probs = torch.softmax(logits, dim=-1)
                next_token = torch.multinomial(probs, num_samples=1)
            else:
                next_token = torch.argmax(logits, dim=-1, keepdim=True)

            # Append to generated sequence
            generated_ids = torch.cat([generated_ids, next_token], dim=-1)

            # Check for EOS
            if next_token.item() == eos_token_id:
                break

    # Decode response
    response_ids = generated_ids[0, input_ids.shape[1]:]
    response = tokenizer_to_use.decode(response_ids, skip_special_tokens=True)

    # Process response (remove special markers)
    response = response.strip()
    if "答：" in response:
        response = response.split("答：")[-1].strip()

    return response


def generate_response(prompt: str, system_prompt: str, temperature: float, max_tokens: int) -> str:
    """Generate a response using TrafficLLM or mock response."""
    global model, tokenizer, current_task

    # Check for IOC matches in the prompt (enhanced detection)
    ioc_matches = check_ioc_matches(prompt)
    if ioc_matches:
        print(f"IOC matches found: {[m['malware'] for m in ioc_matches]}")

    if model is None:
        # Return mock response for testing (enhanced with IOC matches)
        response_data = {
            "overall_severity": "medium" if not ioc_matches else "high",
            "attack_chain": [{
                "stage": "initial_access",
                "description": "TrafficLLM detected potential malicious traffic patterns.",
                "evidence": ["Suspicious network flow patterns detected."],
                "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]
            }],
            "host_findings": [],
            "anomalies": [],
            "mitre_techniques_overall": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]
        }

        # Add IOC-based detections
        if ioc_matches:
            for match in ioc_matches:
                response_data["attack_chain"].append({
                    "stage": "command_and_control",
                    "description": f"IOC match: {match['malware']} - {match['description']}",
                    "evidence": [f"Matched indicator: {match['matched_indicator']}"],
                    "mitre_techniques": [{"id": "T1071", "name": "Application Layer Protocol"}]
                })

        return json.dumps(response_data)

    # Detect task and load appropriate prefix tuning adapter
    task = detect_task(prompt)
    if task != current_task and task in peft_models:
        print(f"Switching to prefix tuning adapter for task: {task}")
        model_with_peft = load_prefix_tuning(model, peft_models[task])
        current_task = task
    else:
        model_with_peft = model

    model_with_peft = model_with_peft.eval()

    # Check if prompt contains traffic data (indicated by <packet> tag)
    if "<packet>" in prompt:
        # Use task-specific preprompt for traffic analysis
        full_prompt = get_preprompt(task, prompt)
        print(f"Using {task} preprompt for traffic analysis")
    else:
        # For general queries, use the prompt as-is
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

    try:
        response = custom_generate(
            model_with_peft, tokenizer, full_prompt,
            max_length=max_tokens,
            temperature=max(temperature, 0.01)
        )

        # Enhance response with IOC matches if detected
        if ioc_matches and "malware" in response.lower():
            ioc_info = " IOC matches: " + ", ".join([m['malware'] for m in ioc_matches])
            response = response.rstrip('.') + "." + ioc_info

        return response
    except Exception as e:
        print(f"Custom generate failed: {e}")
        import traceback
        traceback.print_exc()
        return f"Error generating response: {str(e)}"


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

