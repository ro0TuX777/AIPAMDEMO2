export interface HelpEntry {
    title: string;
    description: string;
    acceptedValues: string;
    dependencies: string[];
    section: string;
}

export const settingsHelpData: Record<string, HelpEntry> = {
    /* ── LLM Settings ─────────────────────────────────── */
    llm_endpoint: {
        title: "Endpoint URL",
        description:
            "The base URL of your Ollama (or compatible) inference server. AIPAM sends all LLM requests — analysis, chat, and forensic reasoning — to this endpoint. If Ollama is running locally inside Docker, the default is typically http://host.docker.internal:11434/v1/chat/completions. For remote GPU servers, point this to their address.",
        acceptedValues:
            "A fully-qualified HTTP/HTTPS URL, e.g. http://host.docker.internal:11434/v1/chat/completions",
        dependencies: [],
        section: "LLM Settings",
    },
    llm_model_name: {
        title: "Default Model Name",
        description:
            "The fallback model AIPAM will use when neither a Forensic Model nor a General Model has been explicitly assigned. This is the \"catch-all\" model for any inference request that doesn't match a specialised role. If you only have one model pulled in Ollama, set it here.",
        acceptedValues:
            "Any valid Ollama model tag, e.g. llama3.1:8b, qwen2:7b, mistral:latest",
        dependencies: ["llm_endpoint"],
        section: "LLM Settings",
    },
    forensic_model_name: {
        title: "Forensic Model",
        description:
            "The model assigned to deep packet analysis, MITRE ATT&CK mapping, and forensic reasoning tasks. This should ideally be a model fine-tuned (or well-suited) for cybersecurity and network forensics. When a PCAP is analysed, AIPAM routes the heavy analytical work to this model. If left blank, the Default Model Name is used instead.",
        acceptedValues:
            "Select from locally available Ollama models. Recommended: a fine-tuned AIPAM model or a larger parameter model (8B+) for accuracy.",
        dependencies: ["llm_endpoint", "llm_model_name"],
        section: "LLM Settings",
    },
    general_model_name: {
        title: "General Model",
        description:
            "The model assigned to general reasoning, out-of-distribution queries, chat interactions, and tasks that fall outside of forensic specialisation. This can be a versatile, smaller model optimised for speed. If left blank, the Default Model Name is used instead.",
        acceptedValues:
            "Select from locally available Ollama models. A fast, general-purpose model (e.g. 3B–8B) works well here.",
        dependencies: ["llm_endpoint", "llm_model_name"],
        section: "LLM Settings",
    },
    llm_max_tokens: {
        title: "Max Tokens",
        description:
            "The maximum number of tokens the LLM is allowed to generate in a single response. Higher values allow more detailed analysis output but consume more GPU memory and increase latency. For forensic reports, 2048–4096 is recommended. For quick triage, 512–1024 may suffice.",
        acceptedValues: "Integer, typically 512–32768. Default: 1024.",
        dependencies: ["llm_endpoint"],
        section: "LLM Settings",
    },
    llm_temperature: {
        title: "Temperature",
        description:
            "Controls the randomness of the LLM's output. Lower values (closer to 0) produce deterministic, reproducible results — critical for forensic evidence that must be auditable. Higher values introduce more creativity but less consistency. For DAWN-compliant forensic work, 0.0–0.2 is strongly recommended.",
        acceptedValues: "Decimal between 0.0 and 1.0. Forensic recommended: 0.1.",
        dependencies: ["llm_endpoint"],
        section: "LLM Settings",
    },

    /* ── Fine-Tuning ──────────────────────────────────── */
    finetune_base_model: {
        title: "Base Model (Fine-Tuning)",
        description:
            "The HuggingFace model ID that serves as the starting checkpoint for fine-tuning. AIPAM's training pipeline downloads this model and applies LoRA adapters on top of it. Choose a model that is compatible with Unsloth for 4-bit QLoRA training. This is only used when you initiate a training run from the Training page — it does not affect inference.",
        acceptedValues:
            'HuggingFace model ID, e.g. "unsloth/Meta-Llama-3.1-8B-bnb-4bit".',
        dependencies: ["finetune_dataset_url", "finetune_lora_rank", "finetune_learning_rate", "finetune_max_seq_length"],
        section: "Fine-Tuning",
    },
    finetune_dataset_url: {
        title: "Dataset Source",
        description:
            "The HuggingFace dataset repository URL or ID used for training. This dataset should be in the AIPAM-expected format (instruction / input / output columns). The training pipeline loads this automatically at the start of a run. You can point this to your own curated forensic dataset or the default AIPAM training set.",
        acceptedValues:
            'HuggingFace URL or repo ID, e.g. "https://huggingface.co/datasets/your-org/aipam-forensic-v6".',
        dependencies: ["finetune_base_model"],
        section: "Fine-Tuning",
    },
    finetune_lora_rank: {
        title: "LoRA Rank",
        description:
            "The rank of the Low-Rank Adaptation (LoRA) matrices injected into the base model during fine-tuning. Higher ranks capture more nuanced forensic patterns but require more VRAM and training time. A rank of 16 is a strong default; increase to 32–64 if you have ample GPU memory and a large, diverse dataset.",
        acceptedValues: "Integer between 4 and 256. Default: 16.",
        dependencies: ["finetune_base_model"],
        section: "Fine-Tuning",
    },
    finetune_learning_rate: {
        title: "Learning Rate",
        description:
            "Controls how aggressively the model weights are updated during training. Too high and the model may overfit or diverge; too low and training will be slow. The default of 2e-4 is well-tuned for AIPAM's forensic datasets with 4-bit QLoRA.",
        acceptedValues: "Small decimal, e.g. 0.0002 (2e-4). Range: 1e-5 to 1e-3.",
        dependencies: ["finetune_base_model"],
        section: "Fine-Tuning",
    },
    finetune_max_seq_length: {
        title: "Context Window (Fine-Tuning)",
        description:
            "The maximum sequence length (in tokens) used during training. This determines how much of a network capture the model can \"see\" in a single training example. AIPAM Phase 6 expanded this to 32,768 tokens to enable analysis of 15+ minutes of traffic. Larger windows require more VRAM.",
        acceptedValues:
            "Integer in multiples of 1024. Range: 1024–32768. Default: 32768.",
        dependencies: ["finetune_base_model"],
        section: "Fine-Tuning",
    },

    /* ── Security Onion ───────────────────────────────── */
    security_onion_mode: {
        title: "Security Onion Mode",
        description:
            'Determines how AIPAM retrieves PCAPs and logs from Security Onion. In "Filesystem" mode, AIPAM reads directly from mounted directories (ideal for air-gapped lab environments). In "API" mode, AIPAM queries Security Onion\'s REST API (requires the API URL and Token fields below).',
        acceptedValues: '"Filesystem" or "API".',
        dependencies: [],
        section: "Security Onion",
    },
    security_onion_base_pcap_path: {
        title: "Base PCAP Path",
        description:
            "The directory where Security Onion stores PCAP files on the local filesystem. AIPAM scans this path for new captures when running in Filesystem mode. In Docker, this path should match the volume mount defined in docker-compose.yml.",
        acceptedValues:
            'Absolute file path, e.g. "/srv/aipam/so-pcaps".',
        dependencies: ["security_onion_mode"],
        section: "Security Onion",
    },
    security_onion_zeek_log_path: {
        title: "Zeek Log Path",
        description:
            "The directory containing Zeek (Bro) network connection logs. AIPAM parses conn.log, dns.log, http.log and other Zeek outputs to enrich its flow analysis before sending data to the LLM. Only used in Filesystem mode.",
        acceptedValues: 'Absolute file path, e.g. "/nsm/zeek/logs/current".',
        dependencies: ["security_onion_mode"],
        section: "Security Onion",
    },
    security_onion_suricata_log_path: {
        title: "Suricata Log Path",
        description:
            "The directory containing Suricata IDS/IPS alert logs (typically eve.json). AIPAM cross-references Suricata alerts with its own LLM-based analysis to validate threat detections. Only used in Filesystem mode.",
        acceptedValues: 'Absolute file path, e.g. "/nsm/suricata/eve.json".',
        dependencies: ["security_onion_mode"],
        section: "Security Onion",
    },
    security_onion_api_url: {
        title: "Security Onion API URL",
        description:
            "The base URL of the Security Onion REST API. Required when Mode is set to \"API\". AIPAM uses this to programmatically query and retrieve PCAPs and alerts from a remote Security Onion instance.",
        acceptedValues:
            'HTTPS URL, e.g. "https://securityonion.local/api".',
        dependencies: ["security_onion_mode", "security_onion_api_token"],
        section: "Security Onion",
    },
    security_onion_api_token: {
        title: "Security Onion API Token",
        description:
            "The authentication token for the Security Onion REST API. Generate this from your Security Onion admin panel. Required when Mode is set to \"API\". This value is stored securely and masked in the UI.",
        acceptedValues: "Bearer token string from Security Onion.",
        dependencies: ["security_onion_mode", "security_onion_api_url"],
        section: "Security Onion",
    },

    /* ── Arkime ───────────────────────────────────────── */
    arkime_api_url: {
        title: "Arkime API URL",
        description:
            "The base URL of your Arkime (formerly Moloch) full-packet-capture system. AIPAM can query Arkime to retrieve historical PCAP sessions for re-analysis. This enables retrospective forensic investigations across large capture archives.",
        acceptedValues: 'HTTP/HTTPS URL, e.g. "https://arkime.local:8005".',
        dependencies: ["arkime_api_username", "arkime_api_password"],
        section: "Arkime",
    },
    arkime_api_username: {
        title: "Arkime Username",
        description:
            "The username for authenticating to the Arkime API. Must have read access to sessions and PCAP data. Used together with the Arkime Password/Token to form Basic Auth credentials.",
        acceptedValues: "Plain text username.",
        dependencies: ["arkime_api_url", "arkime_api_password"],
        section: "Arkime",
    },
    arkime_api_password: {
        title: "Arkime Password / Token",
        description:
            "The password or API token for authenticating to Arkime. Combined with the Username field to access Arkime's session and PCAP retrieval endpoints. This value is stored securely and masked in the UI.",
        acceptedValues: "Password or API token string.",
        dependencies: ["arkime_api_url", "arkime_api_username"],
        section: "Arkime",
    },

    /* ── Storage ──────────────────────────────────────── */
    file_storage_path: {
        title: "File Storage Path",
        description:
            "The local directory where AIPAM stores uploaded PCAPs, analysis results, training artifacts, and generated reports. In Docker, this should correspond to the mounted volume. Ensure the path has adequate disk space for large PCAP files and model checkpoints.",
        acceptedValues:
            'Absolute file path, e.g. "/srv/aipam/storage". Must be writable by the AIPAM process.',
        dependencies: [],
        section: "Storage",
    },
};

/** Look up a help entry by its settings key */
export function getHelpEntry(key: string): HelpEntry | null {
    return settingsHelpData[key] ?? null;
}

/** Get the human-readable title for a settings key (for cross-references) */
export function getFieldTitle(key: string): string {
    return settingsHelpData[key]?.title ?? key;
}
