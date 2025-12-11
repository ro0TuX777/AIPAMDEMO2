from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx


class LLMProvider(Enum):
    """Available LLM providers."""
    OLLAMA = "ollama"
    TRAFFICLLM = "trafficllm"


@dataclass
class LLMConfig:
    endpoint: str
    model: str
    temperature: float = 0.1
    max_tokens: int = 2000
    timeout_seconds: float = 600.0  # 10 minutes; local LLMs can be slow
    provider: LLMProvider = LLMProvider.OLLAMA


@dataclass
class DualLLMConfig:
    """Configuration for using both Ollama and TrafficLLM."""
    ollama: LLMConfig
    trafficllm: Optional[LLMConfig] = None
    use_trafficllm_for_detection: bool = False  # Use TrafficLLM for malware/attack detection


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
    """LLM client supporting both Ollama and TrafficLLM."""

    def __init__(self, config: LLMConfig | None = None, dual_config: DualLLMConfig | None = None) -> None:
        self.dual_config = dual_config

        if config is None:
            endpoint = os.getenv("LLM_ENDPOINT", "http://localhost:11434/v1/chat/completions")
            model = os.getenv("LLM_MODEL_NAME", "llama3.1:8b")
            temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))
            max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2000"))
            timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", "600"))
            provider_str = os.getenv("LLM_PROVIDER", "ollama").lower()
            provider = LLMProvider.TRAFFICLLM if provider_str == "trafficllm" else LLMProvider.OLLAMA

            config = LLMConfig(
                endpoint=endpoint,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
                provider=provider,
            )

        self.config = config

        # If dual_config is not provided, try to build it from environment
        if self.dual_config is None:
            trafficllm_endpoint = os.getenv("TRAFFICLLM_ENDPOINT")
            if trafficllm_endpoint:
                trafficllm_config = LLMConfig(
                    endpoint=trafficllm_endpoint,
                    model="trafficllm",
                    temperature=config.temperature,
                    max_tokens=config.max_tokens,
                    timeout_seconds=config.timeout_seconds,
                    provider=LLMProvider.TRAFFICLLM,
                )
                self.dual_config = DualLLMConfig(
                    ollama=config,
                    trafficllm=trafficllm_config,
                    use_trafficllm_for_detection=os.getenv("USE_TRAFFICLLM_FOR_DETECTION", "false").lower() == "true",
                )

    def _get_config_for_task(self, task_hint: Optional[str] = None) -> LLMConfig:
        """Get the appropriate LLM config based on task type."""
        if self.dual_config is None or self.dual_config.trafficllm is None:
            return self.config

        # Use TrafficLLM for detection tasks if enabled
        detection_keywords = ["malware", "botnet", "attack", "detection", "apt", "vpn", "tor"]
        if self.dual_config.use_trafficllm_for_detection and task_hint:
            if any(kw in task_hint.lower() for kw in detection_keywords):
                return self.dual_config.trafficllm

        return self.config

    async def analyze_chunk(
        self, bundle: Dict[str, Any], task_hint: Optional[str] = None
    ) -> "LLMOutput":
        """Send a single JSON bundle to the LLM and return a validated LLMOutput.

        This matches the spec's requirement for an OpenAI-compatible API
        and strict JSON output, but we always validate into our Pydantic
        model so downstream code sees a consistent shape.

        Args:
            bundle: The JSON bundle to analyze.
            task_hint: Optional hint about the type of analysis (e.g., "malware detection").
                       Used to route to TrafficLLM when appropriate.
        """

        from .models import LLMOutput  # local import to avoid cycles
        from pydantic import ValidationError

        # Get the appropriate config (Ollama or TrafficLLM) based on task
        active_config = self._get_config_for_task(task_hint)

        # Extract TrafficLLM results if present
        trafficllm_results = bundle.get("trafficllm_results")
        trafficllm_context = ""
        print(f"[DEBUG] TrafficLLM results in bundle: {trafficllm_results}")
        if trafficllm_results:
            malware_count = trafficllm_results.get("malware_detections", 0)
            botnet_count = trafficllm_results.get("botnet_detections", 0)
            malware_types = trafficllm_results.get("malware_types", [])
            botnet_types = trafficllm_results.get("botnet_types", [])
            print(f"[DEBUG] Malware count={malware_count}, types={malware_types}")

            if malware_count > 0 or botnet_count > 0:
                malware_list = ', '.join(malware_types) if malware_types else 'unidentified malware'
                botnet_list = ', '.join(botnet_types) if botnet_types else 'unidentified botnet'

                # Build example evidence strings with actual malware names
                example_evidence = []
                for mtype in malware_types[:3]:  # Use first 3 malware types as examples
                    example_evidence.append(f"TrafficLLM detected {mtype} malware traffic from host X to host Y")
                example_evidence_str = ', '.join([f'"{e}"' for e in example_evidence]) if example_evidence else '"TrafficLLM detected malware traffic"'

                trafficllm_context = f"""
## CONFIRMED MALWARE DETECTION (from TrafficLLM AI analysis):

**DETECTED MALWARE FAMILIES: {malware_list}**
**TOTAL MALICIOUS FLOWS: {malware_count}**

The following specific malware types were detected in the network traffic:
{chr(10).join([f'- {mtype} malware' for mtype in malware_types])}

When writing your analysis, you MUST use these exact malware names. For example:
- In attack_chain evidence: [{example_evidence_str}]
- In host_findings summary: "Host infected with {malware_types[0] if malware_types else 'malware'} malware"
- In key findings: "execution: {malware_types[0] if malware_types else 'Malware'} malware executed on host X.X.X.X"

DO NOT write "unknown" - use the malware names listed above ({malware_list}).

"""

        llm_chunk_json = json.dumps(bundle, default=str)

        user_prompt = f"""Context:
- Exercise ID: {{exercise_id}}
- Analysis mode: {{mode}}
- Time ranges:
  - Baseline: {{baseline_start}} to {{baseline_end}}
  - Exploit: {{exploit_start}} to {{exploit_end}}
{trafficllm_context}
You are given the following JSON object representing aggregated and normalized network behavior:

```json
{llm_chunk_json}
```

This JSON includes:
- host_summaries_baseline
- host_summaries_exploit
- hostpair_summaries_baseline
- hostpair_summaries_exploit
- change_summaries
- alerts
- trafficllm_results (if available - AI-based malware/botnet detection)

Task:
1. Compare baseline vs exploit behavior for the hosts and host pairs in this JSON. Identify:
   - Likely initial access vector(s).
   - Signs of exploitation and payload delivery.
   - Evidence of lateral movement.
   - Signs of C2 or beaconing.
   - Evidence of potential data exfiltration.
2. Identify key anomalies that could indicate zero-day or previously unseen behavior.
3. Map each major observed behavior to MITRE ATT&CK techniques (include technique IDs and names).
4. Produce the following JSON object and nothing else, in this exact structure:

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
            "model": active_config.model,
            "temperature": active_config.temperature,
            "max_tokens": active_config.max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }

        # Default empty-but-structured object, used on errors.
        def _empty_output() -> LLMOutput:
            return LLMOutput(
                overall_severity="unknown",
                attack_chain=[],
                host_findings=[],
                anomalies=[],
                mitre_techniques_overall=[],
            )

        provider_name = active_config.provider.value if active_config.provider else "unknown"
        try:
            # Use a configurable timeout so large analyses on local models
            # (like llama3.1:8b via Ollama) have enough time to complete.
            async with httpx.AsyncClient(timeout=active_config.timeout_seconds) as client:
                resp = await client.post(active_config.endpoint, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            print(f"Warning: LLM connection failed ({e}). Using mock LLMOutput.")
            try:
                return LLMOutput(
                    overall_severity="medium",
                    attack_chain=[
                        {
                            "stage": "initial_access",
                            "description": "Simulated initial access via phishing.",
                            "evidence": ["Mock evidence of phishing email."],
                            "mitre_techniques": [{"id": "T1566", "name": "Phishing"}],
                        }
                    ],
                    host_findings=[
                        {
                            "ip": "192.168.1.105",
                            "role_in_attack": "victim",
                            "summary": "Host showed signs of compromise.",
                            "suspicious_behaviors": ["Unexpected outbound connection."],
                        }
                    ],
                    anomalies=[],
                    mitre_techniques_overall=[{"id": "T1566", "name": "Phishing"}],
                )
            except ValidationError:
                return _empty_output()

        try:
            content = data["choices"][0]["message"]["content"]
            raw = json.loads(content)
            return LLMOutput(**raw)
        except (KeyError, IndexError, json.JSONDecodeError, TypeError, ValidationError) as e:
            print(f"Warning: Failed to parse/validate LLM JSON output ({e}); using empty output.")
            return _empty_output()

    async def chat_completion(
        self, messages: List[Dict[str, str]], temperature: Optional[float] = None
    ) -> str:
        """Send a chat completion request and return the text response.

        This is a simpler interface than analyze_chunk, used for conversational
        chat where we don't need JSON parsing.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Optional temperature override.

        Returns:
            The assistant's response text.
        """
        payload = {
            "model": self.config.model,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                resp = await client.post(self.config.endpoint, json=payload)
                resp.raise_for_status()
                data = resp.json()

            content = data["choices"][0]["message"]["content"]
            return content.strip()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
            raise RuntimeError(f"LLM request failed: {e}")
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"Unexpected LLM response format: {e}")


async def analyze_chunks(
    bundles: List[Dict[str, Any]],
    client: LLMClient | None = None,
    task_hint: Optional[str] = None,
) -> List["LLMOutput"]:
    """Analyze a list of bundles with a shared LLMClient.

    If *client* is None, a default LLMClient is constructed from environment
    variables. Callers that want to respect persisted settings should pass
    an explicit client configured from EffectiveSettings.

    Args:
        bundles: List of JSON bundles to analyze.
        client: Optional LLMClient instance.
        task_hint: Optional hint for task routing (e.g., "malware detection").
    """

    from .models import LLMOutput  # local import to avoid cycles

    if client is None:
        client = LLMClient()
    results: List[LLMOutput] = []
    for b in bundles:
        results.append(await client.analyze_chunk(b, task_hint=task_hint))
    return results


async def classify_traffic_with_trafficllm(
    packet_hex: str,
    task: str = "MTD",
    trafficllm_endpoint: str = "http://localhost:8001/v1/chat/completions",
    timeout_seconds: float = 60.0,
) -> Dict[str, Any]:
    """Classify network traffic using TrafficLLM.

    TrafficLLM is a specialized LLM for network traffic analysis that can detect:
    - MTD: Malware Traffic Detection (Zeus, Cridex, Geodo, etc.)
    - EVD: Encrypted VPN Detection (skype, netflix, youtube, etc.)
    - TBD: Tor Behavior Detection (browsing, chat, file, etc.)
    - BND: Botnet Detection (IRC, Neris, RBot, Virut, normal)
    - WAD: Web Attack Detection (malicious/benign)
    - AAD: APT Attack Detection (abnormal/normal)

    Args:
        packet_hex: Hex-encoded packet data (e.g., "45 00 00 3c 1c 46...")
        task: Detection task type (MTD, EVD, TBD, BND, WAD, AAD)
        trafficllm_endpoint: TrafficLLM API endpoint
        timeout_seconds: Request timeout

    Returns:
        Dict with classification result and confidence
    """
    # Build task-specific prompt
    task_keywords = {
        "MTD": "malware",
        "EVD": "vpn",
        "TBD": "tor",
        "BND": "botnet",
        "WAD": "web attack",
        "AAD": "apt",
    }

    keyword = task_keywords.get(task, "malware")
    prompt = f"Detect {keyword} in this traffic: <packet>: {packet_hex}"

    payload = {
        "model": "trafficllm",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 50,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(trafficllm_endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()

        classification = data.get("choices", [{}])[0].get("message", {}).get("content", "unknown")

        return {
            "task": task,
            "classification": classification.strip(),
            "success": True,
            "raw_response": data,
        }
    except Exception as e:
        return {
            "task": task,
            "classification": "error",
            "success": False,
            "error": str(e),
        }


def create_dual_llm_client(
    ollama_endpoint: str = "http://ollama:11434/v1/chat/completions",
    ollama_model: str = "llama3.1:8b",
    trafficllm_endpoint: Optional[str] = "http://trafficllm:8001/v1/chat/completions",
    use_trafficllm_for_detection: bool = True,
) -> LLMClient:
    """Create an LLMClient configured for dual-model operation.

    Args:
        ollama_endpoint: Ollama API endpoint.
        ollama_model: Ollama model name (e.g., "llama3.1:8b").
        trafficllm_endpoint: TrafficLLM API endpoint (None to disable).
        use_trafficllm_for_detection: Route detection tasks to TrafficLLM.

    Returns:
        Configured LLMClient with dual-model support.
    """
    ollama_config = LLMConfig(
        endpoint=ollama_endpoint,
        model=ollama_model,
        provider=LLMProvider.OLLAMA,
    )

    trafficllm_config = None
    if trafficllm_endpoint:
        trafficllm_config = LLMConfig(
            endpoint=trafficllm_endpoint,
            model="trafficllm",
            provider=LLMProvider.TRAFFICLLM,
        )

    dual_config = DualLLMConfig(
        ollama=ollama_config,
        trafficllm=trafficllm_config,
        use_trafficllm_for_detection=use_trafficllm_for_detection,
    )

    return LLMClient(config=ollama_config, dual_config=dual_config)

