# Zero-Day Forensic Methodology

When the AIPAM model flags traffic as **Anomalous/Zero-Day**, follow this structured investigation methodology to confirm and document the threat.

## Phase 1: Confirmation
1. **Rule out False Positives:** Verify if the "anomaly" is actually a custom internal protocol or a legitimate but rare application.
2. **Isolate the Flow:** Using `tshark`, extract the specific flow identified by the model:
   ```bash
   tshark -r capture.pcap -Y "ip.addr == [SRC] && ip.addr == [DST]" -w suspicious_flow.pcap
   ```
3. **Check for Exploit Patterns:** Search the raw payload for common exploit artifacts (e.g., NOP sleds, shellcode patterns, or directory traversal strings).

## Phase 2: Behavioral Analysis
- **Temporal Patterns:** Is the traffic periodic? Zero-day C2 often uses non-standard intervals (jitter) to avoid basic detection.
- **Dependency Check:** Did this flow happen after a suspicious DNS query or a large inbound file transfer?
- **Protocol Variance:** Does the traffic deviate from its own protocol's RFC in a way that suggests data tunneling?

## Phase 3: Documentation & Escalation
- **Save the Evidence:** Archive the `Anomalous/Zero-Day` report from AIPAM alongside the raw PCAP.
- **Extract Indicators:** Document any novel IP addresses, domain names, or unique payload strings.
- **Generate Report:** Use the AIPAM `FORENSIC_GUIDE` to draft a formal incident report highlighting the specific zero-day indicators found.

> [!CAUTION]
> Treat `Anomalous/Zero-Day` flags as high-priority. A zero-day exploit often indicates a targeted attack or an advanced persistent threat (APT).
