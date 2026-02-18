# AIPAM x DAWN Architectural Constitution

## 1. The Core Invariants (Do Not Break)
- **Deterministic Execution:** Identical PCAP inputs MUST produce identical `bundle_sha256` hashes and identical analysis results.
- **Contract Enforcement:** No Link may be modified without verifying its `link.yaml`. If an output schema changes, all downstream `requires` must be updated simultaneously.
- **Isolation:** Links MUST NOT share state via global variables or external databases. Communication is strictly via the DAWN `artifact_store`.
- **Audit Integrity:** Every AI-driven decision MUST log a `GUARDRAIL` or `REASONING` event to the `events.jsonl` ledger.

## 2. The Link Protocol
When modifying or adding a feature:
1. **Define the Artifact:** Update the `produces` section of the `link.yaml` first.
2. **Bind the Provenance:** Every finding artifact MUST include the `source_bundle_sha256` to ensure stale-safety.
3. **Sandbox Compliance:** Use `sandbox.publish()` for all outputs. Direct file writes to outside the `artifacts/` directory are forbidden.

## 3. The Forensic Engine Standards
- **Chain-of-Thought:** LLM logic must remain multi-stage (Triage -> Deep Analysis). Do not collapse back into a single-prompt monolith.
- **Anti-Hallucination:** Every LLM-cited identifier (Flow ID, IP, Hash) MUST be validated against the `FlowDB` before being committed to the findings artifact.
- **Evidentiary Integrity (Phase 6.1+):** The Hallucinated Citation Rate (HCR) MUST remain below 5%. ORPO preference training enforces that *correct classification with fabricated evidence = failure*.
- **Reasoning Diversity (Phase 6.5+):** Reasoning Entropy (RE) MUST remain above the configured threshold (default 1.5 bits). Entropy collapse triggers a mandatory breadth-first refresh from the v6 base model.
- **Analyst Gating:** The `hitl.findings_review` link is the final authority. No finding is "Confirmed" until it passes this link.

## 4. Verification Requirements
Before any merge or "recompile":
- **Ledger Audit:** Run the pipeline and verify that `ledger/events.jsonl` contains a complete trace.
- **Release Audit:** The `quality.release_verifier` MUST return a `PASS` status.
- **Regression Suite:** All 142+ functional tests and the 7-stage DAWN verification script must pass.
- **DAWN Training Ledger (Phase 6.1+):** Every fine-tuning run MUST produce an immutable entry in `dawn_training_ledger.jsonl` with a SHA-256 config hash. Runs without ledger entries are non-reproducible and MUST NOT be deployed.
- **Breadth-First Buffer (Phase 6.5+):** Self-healing LoRA delta training MUST NOT execute on fewer than 3 distinct malware families. Single-family training risks catastrophic overwriting of adjacent family representations.
- **LocFT Surgical Constraint (Phase 6.5+):** Self-healing delta updates MUST target only `down_proj` in layers 16–30 (8B) or 8–15 (1B). Grammar layers (early layers) are frozen to preserve instruction-following stability.