# Forensic Analysis Guide for AIPAM

This guide helps you use the AIPAM model effectively for forensic investigation.

## How to use the model for forensics

The fine-tuned model has been enhanced to provide detailed reasoning alongside its classification. When you upload a PCAP, the model doesn't just give you a name (e.g., "DarkGate"); it explains *why* it thinks so.

### Key Forensic Indicators the model looks for:
- **Protocol Anomalies:** Misuse of HTTP/S, non-standard TLS handshakes, or suspicious DNS queries.
- **Payload Patterns:** Hexadecimal patterns in TCP/UDP payloads that match known C2 beaconing or exploit signatures.
- **Traffic Spikes/Timing:** Indicators of automated beaconing (regular intervals) or rapid data exfiltration.
- **Port Usage:** Use of commonly restricted ports for non-standard services.

## Interpreting Results

Every analysis result follows a structured "Forensic Report" format:

| Section | Description |
|---------|-------------|
| **Classification** | The most likely malware family or application category. |
| **Forensic Evidence** | The specific "smoking gun" indicators found in the packets. |
| **MITRE ATT&CK** | Mappings to the professional cybersecurity taxonomy. |
| **Attack Chain Phase** | Where this traffic fits (e.g., C2, Discovery, Lateral Movement). |

## Pro-Tips for Investigators

1. **Verify the Evidence:** Always cross-reference the model's "Forensic Evidence" with raw `tshark` or `Zeek` logs.
2. **Context Matters:** A single packet might be misclassified, but a sequence of 10+ packets (majority vote in `inference.py`) provides much higher confidence.
3. **Look for the "Unknown" or "Anomalous":** If the model flags a potential zero-day, it will use the `Anomalous/Zero-Day` classification. These are the most critical for manual investigation.

## Zero-Day Hunting

Zero-days are characterized by malicious intent without a matching signature. The model is trained to spot these by looking for:
- **Heuristic Anomalies:** Values in protocol fields that are technically valid but practically impossible (e.g., a 10MB HTTP header).
- **Entropy Shifts:** Sudden shifts in payload randomness that suggest on-the-fly encryption or obfuscation.
- **Novel C2 Beacons:** Heartbeat patterns that don't match known families but exhibit clear "check-in" behavior.
