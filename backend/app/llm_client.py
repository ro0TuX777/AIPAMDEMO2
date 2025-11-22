from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List

import httpx


@dataclass
class LLMConfig:
    endpoint: str
    model: str
    temperature: float = 0.1
    max_tokens: int = 2000


SYSTEM_PROMPT = (
    "You are a senior network security analyst and incident responder.\n\n"
    "You are given:\n"
    "- Aggregated network flow summaries\n"
    "- Protocol summaries (HTTP, DNS, SMB, RDP, SSH, TLS, etc.)\n"
    "- Signature alerts (Suricata, YARA, IOC matches)\n"
    "- Optional baseline vs exploit traffic comparisons\n\n"
    "Your goals:\n"
    "1. Identify evidence of attacks, exploitation, malware activity, command-and-control (C2), lateral movement, or data exfiltration.\n"
    "2. Highlight anomalies not covered by signatures (potential zero-days or novel techniques).\n"
    "3. Map observed behavior to MITRE ATT&CK techniques where possible.\n"
    "4. Clearly distinguish between confirmed malicious behavior and suspicious but unconfirmed behavior.\n"
    "5. Output both:\n"
    "   - A concise human-readable summary.\n"
    "   - A structured JSON object in the exact schema requested.\n\n"
    "Do not invent facts. Base your conclusions only on the provided data. If something is uncertain, mark it as \"possible\" or \"inconclusive\" and explain why."
)


class LLMClient:
    def __init__(self, config: LLMConfig | None = None) -> None:
        if config is None:
            endpoint = os.getenv("LLM_ENDPOINT", "http://localhost:11434/v1/chat/completions")
            model = os.getenv("LLM_MODEL_NAME", "local-llm")
            temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))
            max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2000"))
            config = LLMConfig(
                endpoint=endpoint,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        self.config = config

    async def analyze_chunk(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single JSON bundle to the LLM and return parsed JSON.

        This matches the spec's requirement for an OpenAI-compatible API
        and strict JSON output.
        """

        llm_chunk_json = json.dumps(bundle, default=str)
        
        user_prompt = f"""Context:
- Exercise ID: {{exercise_id}}
- Analysis mode: {{mode}}
- Time ranges:
  - Baseline: {{baseline_start}} to {{baseline_end}}
  - Exploit: {{exploit_start}} to {{exploit_end}}

You are given the following JSON object representing aggregated and normalized network behavior:

```json
{llm_chunk_json}
```

This JSON includes:
	•	host_summaries_baseline
	•	host_summaries_exploit
	•	hostpair_summaries_baseline
	•	hostpair_summaries_exploit
	•	change_summaries
	•	alerts

Task:
	1.	Compare baseline vs exploit behavior for the hosts and host pairs in this JSON. Identify:
	•	Likely initial access vector(s).
	•	Signs of exploitation and payload delivery.
	•	Evidence of lateral movement.
	•	Signs of C2 or beaconing.
	•	Evidence of potential data exfiltration.
	2.	Identify key anomalies that could indicate zero-day or previously unseen behavior.
	3.	Map each major observed behavior to MITRE ATT&CK techniques (include technique IDs and names).
	4.	Produce the following JSON object and nothing else, in this exact structure:

{{
"overall_severity": "low|medium|high|critical",
"attack_chain": [
{{
"stage": "initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|lateral_movement|collection|command_and_control|exfiltration|impact",
"description": "Short description of what happened at this stage.",
"evidence": [
"Specific evidence string referencing hosts, protocols, time windows, or alerts."
],
"mitre_techniques": [
{{ "id": "TXXXX", "name": "Technique Name" }}
]
}}
],
"host_findings": [
{{
"ip": "x.x.x.x",
"role_in_attack": "attacker|victim|infrastructure|unknown",
"summary": "Short textual summary.",
"suspicious_behaviors": [
"Behavior description with evidence."
]
}}
],
"anomalies": [
{{
"description": "Description of anomaly.",
"related_hosts": ["x.x.x.x", "y.y.y.y"],
"confidence": 0.0,
"reason": "Why this is considered anomalous."
}}
],
"mitre_techniques_overall": [
{{ "id": "TXXXX", "name": "Technique Name" }}
]
}}

Respond ONLY with this JSON. Do not include any extra text or explanation.
"""

        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(self.config.endpoint, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            print(f"Warning: LLM connection failed ({e}). Using mock response.")
            # Return mock data for development/testing when LLM is offline
            return {
                "overall_severity": "medium",
                "attack_chain": [
                    {
                        "stage": "initial_access",
                        "description": "Simulated initial access via phishing.",
                        "evidence": ["Mock evidence of phishing email."],
                        "mitre_techniques": [{"id": "T1566", "name": "Phishing"}]
                    }
                ],
                "host_findings": [
                    {
                        "ip": "192.168.1.105",
                        "role_in_attack": "victim",
                        "summary": "Host showed signs of compromise.",
                        "suspicious_behaviors": ["Unexpected outbound connection."]
                    }
                ],
                "anomalies": [],
                "mitre_techniques_overall": [{"id": "T1566", "name": "Phishing"}]
            }

        try:
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except Exception:
            # Fallback: return an empty but structurally valid object
            parsed = {
                "overall_severity": "unknown",
                "attack_chain": [],
                "host_findings": [],
                "anomalies": [],
                "mitre_techniques_overall": [],
            }
        return parsed


async def analyze_chunks(bundles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    client = LLMClient()
    results: List[Dict[str, Any]] = []
    for b in bundles:
        results.append(await client.analyze_chunk(b))
    return results

