/**
 * Help data for page-level headings.
 * Each key maps to a heading's help-hint identifier used in the UI.
 */

export interface FieldGlossaryItem {
    label: string;
    description: string;
}

export interface PageHelpEntry {
    title: string;
    description: string;
    section: string;
    fields?: FieldGlossaryItem[];
}

export const pageHelpData: Record<string, PageHelpEntry> = {
    /* ── Jobs ──────────────────────────────────────────── */
    jobs_list: {
        title: "Jobs",
        description:
            "The Jobs list shows every PCAP analysis job in the system. Each job represents a single forensic analysis run — from PCAP upload through Suricata alerting, Zeek logging, anomaly detection, and AI-powered explanation. You can filter by status, sort by date, and click any job to drill into its detailed findings, alerts, hosts, and evidence graph.",
        section: "Jobs",
    },
    job_detail: {
        title: "Job Detail",
        description:
            "The Job Detail page shows the complete results of a single PCAP analysis. It includes the execution status, pipeline stages, sensor coverage, and an AI-generated summary. From here you can navigate to findings, alerts, hosts, IOCs, timeline, evidence graph, theories, and more. This is your central hub for investigating a specific capture.",
        section: "Jobs",
    },
    job_summary: {
        title: "Summary",
        description:
            "The Summary section provides an AI-generated executive overview of the analysis results. It highlights the most significant threats detected, alert and finding counts, and key indicators. Think of it as the 'bottom line' — what happened in this capture, distilled into a paragraph by the forensic LLM.",
        section: "Jobs",
    },
    job_sensors: {
        title: "Sensors",
        description:
            "Sensors are the analysis engines that processed the PCAP file. Each sensor (e.g., Suricata for signature-based detection, Zeek for protocol analysis, anomaly detectors for behavioral analysis) runs independently and contributes its own findings. This section shows which sensors were active and their processing status.",
        section: "Jobs",
    },
    job_pipeline: {
        title: "Pipeline Stages",
        description:
            "Pipeline Stages show the step-by-step progression of the analysis — from PCAP validation and upload, through sensor execution (Suricata, Zeek), to AI-powered explanation and enrichment. Each stage has a status indicator so you can see exactly where the analysis is and whether any stage encountered issues.",
        section: "Jobs",
    },

    /* ── Investigation Queue ────────────────────────────── */
    investigation_queue: {
        title: "Investigation Queue",
        description:
            "The Investigation Queue is a unified, priority-ranked triage list combining findings, alerts, and theories from across the analysis. Items are scored and sorted so the most critical threats surface first. Use filters to narrow by status, source type, host, MITRE technique, or corroboration. Click any row to open the Evidence Drawer for a deep-dive.",
        section: "Investigation",
        fields: [
            { label: "Score", description: "A composite priority score (0–1) computed from five weighted factors: Severity (30%), Confidence (25%), Corroboration (20%), Blast Radius (15%), and Recency (10%). Higher scores mean more urgent triage priority." },
            { label: "Confidence", description: "How certain the detection engine is that this item represents a real threat (0–1). For findings, this comes from the AI model. For alerts, it's derived from severity. For theories, it maps from high/medium/low." },
            { label: "Corroborating", description: "The number of other items that share evidence with this one. For findings/alerts, this counts other items involving the same host IPs. For theories, it counts the supporting evidence references (findings + alerts) that back the hypothesis." },
            { label: "Blast Radius", description: "How many distinct hosts are affected by this item. A high blast radius means the threat touches many machines — indicating lateral movement, worm-like behavior, or widespread impact." },
            { label: "MITRE ATT&CK IDs", description: "Technique identifiers from the MITRE ATT&CK framework (e.g., T1566 for Phishing, T1071 for Application Layer Protocol). These map the detected behavior to known adversary tactics and techniques." },
            { label: "Status", description: "Analyst triage status: Unreviewed (new), Confirmed (true positive), False Positive (benign), Needs Review (flagged for second opinion), or Deferred (needs more context later)." },
            { label: "Evidence Drawer", description: "A side panel that opens when you click a row. It shows related findings, alerts, network connections, and a timeline — all cross-referenced by shared host IPs or explicit evidence links." },
            { label: "Source Type", description: "Whether the item originated as a Finding (AI-enriched observation), Alert (Suricata signature match), or Theory (AI-generated hypothesis)." },
            { label: "Review Mode", description: "Toggle that switches the queue to show only reviewed items (non-unreviewed), grouped with 'Needs Review' items first. Useful for team leads auditing analyst progress." },
            { label: "Review Rate", description: "Percentage of queue items that have been reviewed (any status other than 'unreviewed'). Shown as a progress bar above the summary stats. 100% means every item has been triaged." },
            { label: "Needs Review", description: "A special status indicating that an item should be examined by a second analyst. Items marked 'Needs Review' are highlighted in purple and appear first in Review Mode." },
            { label: "Confirmation Gate", description: "Downstream actions like rule export and forensic memory indexing are blocked until an item is explicitly confirmed. This prevents unverified leads from polluting production systems." },
        ],
    },

    /* ── Findings ──────────────────────────────────────── */
    findings: {
        title: "Findings",
        description:
            "Findings are AI-enriched forensic observations discovered during analysis. Each finding has a severity (critical/high/medium/low/info), confidence score, MITRE ATT&CK mapping, and a plain-English explanation generated by the forensic LLM. Findings go beyond raw alerts — they represent the analyst-level interpretation of what happened. Click any finding to expand its full explanation, supporting evidence, and recommended actions.",
        section: "Analysis",
        fields: [
            { label: "Severity", description: "Threat level assigned by the AI: critical, high, medium, low, or info. Severity reflects the potential damage if this finding represents a real attack." },
            { label: "Confidence", description: "The AI model's certainty (0–1) that this finding accurately describes a real security event, not a false positive." },
            { label: "Category", description: "The type of finding — e.g., malware, intrusion, exfiltration, policy violation, reconnaissance. Helps you group related findings." },
            { label: "MITRE ATT&CK", description: "Framework technique IDs mapping the finding to known adversary behavior patterns." },
        ],
    },

    /* ── Alerts ────────────────────────────────────────── */
    alerts: {
        title: "Alerts",
        description:
            "Alerts are signature-based detections from Suricata IDS. Each alert includes the rule signature, severity, source/destination IPs and ports, and category. Alerts represent known-bad patterns — exploit kits, malware callbacks, policy violations, etc. Filter by severity to focus on the most critical detections, or click an alert to see its full details, related hosts, and connections.",
        section: "Analysis",
        fields: [
            { label: "Signature", description: "The Suricata rule name that triggered this alert — describes the specific threat pattern detected." },
            { label: "Severity", description: "Priority level (1 = highest) assigned by the Suricata rule. Maps to critical/high/medium/low." },
            { label: "SID", description: "Signature ID — the unique numeric identifier of the Suricata rule. Useful for looking up rule details or tuning." },
            { label: "Src / Dest", description: "Source and destination IP addresses and ports showing the direction of the suspicious traffic flow." },
        ],
    },

    /* ── Hosts ─────────────────────────────────────────── */
    hosts: {
        title: "Hosts",
        description:
            "Hosts are IP addresses observed in the PCAP traffic. Each host is classified by role (internal, external, DNS, gateway) and shows its associated alerts, findings, and connection patterns. Use this page to identify which machines were involved in suspicious activity and pivot to their detailed analysis.",
        section: "Analysis",
    },

    /* ── IOCs ──────────────────────────────────────────── */
    iocs: {
        title: "Indicators of Compromise",
        description:
            "Indicators of Compromise (IOCs) are specific artifacts — IP addresses, domains, file hashes, URLs — that indicate malicious activity. AIPAM extracts IOCs from alerts, findings, and network traffic, then enriches them with threat intelligence lookups. Each IOC has a type, confidence score, and severity. Use this page to build block lists, feed your SIEM, or report to your threat intel team.",
        section: "Analysis",
    },

    /* ── Timeline ──────────────────────────────────────── */
    timeline: {
        title: "Timeline",
        description:
            "The Timeline shows all security events in chronological order. It correlates alerts, findings, and network events onto a single timeline so you can see the attack narrative unfold. Use this to understand the sequence of events — what happened first, what triggered what, and how the attacker progressed through their kill chain.",
        section: "Analysis",
    },

    /* ── Evidence Graph ────────────────────────────────── */
    evidence_graph: {
        title: "Evidence Graph",
        description:
            "The Evidence Graph is an interactive D3-powered visualization that maps relationships between all evidence entities — hosts, alerts, findings, IOCs, theories, slices, and annotations. Nodes are color-coded by type and edges show how entities connect (e.g., which host triggered which alert). Click nodes to inspect details, drag to rearrange, and use the Proof Builder sidebar to pin evidence into a formal proof.",
        section: "Visualization",
    },
    network_topology: {
        title: "Network Topology",
        description:
            "Network Topology mode shows the communication patterns between hosts as a force-directed graph. Internal hosts, external hosts, DNS servers, and gateways are displayed as interconnected nodes with edges representing observed connections. This view helps identify lateral movement, beaconing patterns, and unusual communication flows.",
        section: "Visualization",
    },

    /* ── Theories ──────────────────────────────────────── */
    theories: {
        title: "Theory of the Case",
        description:
            "The Theory of the Case engine automatically generates and ranks hypotheses about what happened in the captured traffic. Each theory (e.g., 'C2 Beaconing', 'Data Exfiltration', 'Malware Delivery', 'Benign/Normal') is scored based on supporting and contradicting evidence. The engine shows its work — listing which alerts, findings, and IOCs support or contradict each theory. Use this to guide your investigation and identify the most likely attack scenario.",
        section: "Investigation",
        fields: [
            { label: "Score", description: "A 0–1 confidence score for the theory. Higher means more supporting evidence and fewer contradictions. Scores above 0.7 are considered high-confidence." },
            { label: "Confidence", description: "The theory engine's qualitative confidence level: high, medium, or low. Based on the quantity and quality of supporting evidence." },
            { label: "Supporting Evidence", description: "Findings, alerts, and IOCs that corroborate this theory. More supporting evidence = stronger hypothesis." },
            { label: "Contradicting Evidence", description: "Evidence that weakens or disproves the theory. A strong theory has many supporters and few contradictions." },
            { label: "Scope", description: "Whether the theory applies to a specific host (host-scoped) or the entire job (job-scoped). Host-scoped theories are more targeted." },
        ],
    },

    /* ── Slices ────────────────────────────────────────── */
    slices: {
        title: "Incident Slices",
        description:
            "Incident Slices group related security events into coherent attack threads. Each slice represents a distinct phase or technique in the attack — for example, 'Initial Exploit Kit Download', 'C2 Beaconing Phase', or 'Lateral Movement via SMB'. Slices help you decompose a complex incident into manageable investigation units, each with its own severity, timeline, and supporting evidence.",
        section: "Investigation",
        fields: [
            { label: "Slice Type", description: "The category of attack thread — e.g., exploit, c2, lateral_movement, exfiltration. Helps classify the phase of the attack." },
            { label: "Severity", description: "The highest severity among all events grouped into this slice." },
            { label: "Community IDs", description: "Network flow identifiers that tie related packets together. Slices group events sharing these IDs into a single attack thread." },
        ],
    },

    /* ── Annotations ───────────────────────────────────── */
    annotations: {
        title: "Why Unusual?",
        description:
            "Annotations explain why specific network behaviors were flagged as unusual by the anomaly detection engine. Each annotation provides context about what baseline behavior looks like and why the observed traffic deviates from it. This helps distinguish true threats from normal-but-unusual activity and reduces false positive fatigue.",
        section: "Investigation",
    },


    /* ── Report ────────────────────────────────────────── */
    report: {
        title: "Network Analysis Report",
        description:
            "The Report page generates a comprehensive, printable forensic report for a completed analysis job. It includes an executive summary, alert analysis with severity distribution, detailed findings with MITRE ATT&CK mappings, IOC tables, host analysis, threat signals, and actionable recommendations. You can switch between a structured report view and a Report Composer that generates executive or technical summaries using the AI.",
        section: "Reporting",
    },

    /* ── Proof Builder / Build Case ─────────────────────── */
    proof_builder: {
        title: "Build Case (Proof Builder)",
        description:
            "The Build Case workspace lets you curate collections of evidence ('Proofs') and generate structured Markdown narratives for handoff, reporting, or archival. Pin findings, alerts, theories, IOCs, and hosts as supporting, contradicting, or contextual evidence. Choose a report mode (SOC Handoff, IR Technical, or Executive Summary), write a conclusion, then generate an AI-powered narrative.",
        section: "Reporting",
        fields: [
            { label: "Proof", description: "A curated collection of evidence items with a title, conclusion, severity, and confidence. Can be in Draft, Final, or Archived status." },
            { label: "Mode", description: "The report template to use: SOC Handoff (key findings, affected systems, recommended actions), IR Technical (attack path, MITRE mapping, timeline, containment), or Executive Summary (business impact, risk, remediation)." },
            { label: "Pinned Evidence", description: "Items added to the proof with a role: Supports (✅), Contradicts (❌), or Context (ℹ️). Each item links to a finding, alert, theory, host, IOC, or slice." },
            { label: "Quick Add", description: "Confirmed items from the Investigation Queue that haven't been added yet. One-click to pin them as supporting evidence." },
            { label: "Generate Narrative", description: "Uses the LLM to produce a structured Markdown report grounded in the pinned evidence and the analyst's conclusion. Falls back to template-based rendering if the LLM is unavailable." },
            { label: "Warnings", description: "Alerts shown after generation if evidence items haven't been confirmed by an analyst. Maintains the trust chain from the HITL Review Workflow." },
            { label: "Export", description: "Download the narrative as Markdown (.md) or HTML for pasting into tickets, emails, or incident management systems." },
            { label: "Conclusion", description: "The analyst's own summary of what happened. This is fed into the LLM prompt to ground the narrative in the analyst's judgment." },
        ],
    },

    /* ── Compare (Temporal) ────────────────────────────── */
    compare: {
        title: "Before / After Comparison",
        description:
            "The Compare workspace enables temporal delta analysis between two labeled PCAP phases (e.g., 'before' and 'after' a mitigation). It surfaces new and resolved alerts, findings, IOCs, DNS domains, and connection flows — giving analysts a clear picture of what changed. Containment Indicators highlight successful mitigations such as removed C2 connections. An AI Security Assessment can be generated to narrate the overall impact.",
        section: "Temporal Analysis",
        fields: [
            { label: "Phase Summary", description: "Side-by-side counts of hosts, alerts, findings, connections, and IOCs for each labeled PCAP phase." },
            { label: "Severity Shifts", description: "How alert volumes migrated across severity levels between phases. A shift from critical to low/info suggests successful mitigation." },
            { label: "Containment Indicators", description: "Heuristic signals that mitigation worked: removed C2 connections, reduced alert categories, and new defensive activity observed in the 'after' phase." },
            { label: "Alert Signature Changes", description: "Diff table showing NEW, RESOLVED, and CHANGED alert signatures between phases, with before/after hit counts." },
            { label: "Finding Changes", description: "New or resolved AI-generated findings between phases, with severity and originating sensor." },
            { label: "IOC Changes", description: "Indicators of Compromise that appeared or disappeared between phases." },
            { label: "DNS Domain Changes", description: "DNS domains that appeared or disappeared between phases — new suspicious domains or removed C2 domains." },
            { label: "New Connection Flows", description: "Network flows observed only in the 'after' phase, ranked by session count and byte volume." },
            { label: "AI Security Assessment", description: "An LLM-generated narrative summarizing the temporal changes, assessing mitigation effectiveness, and providing actionable recommendations." },
            { label: "Export Report", description: "Download a Markdown export of the full temporal comparison for offline review or inclusion in incident reports." },
        ],
    },

    /* ── Rules Management ──────────────────────────────── */
    rules_management: {
        title: "Suricata Rule Management",
        description:
            "The Rule Management page lets you view, edit, and manage Suricata IDS detection rules. You can browse rules by file, search for specific signatures, enable or disable individual rules, and generate new detection rules from findings. Rules are the backbone of signature-based detection — keeping them tuned and up-to-date is critical for effective threat detection.",
        section: "Configuration",
    },

    /* ── Training ──────────────────────────────────────── */
    training: {
        title: "Training Intelligence",
        description:
            "The Training Intelligence page manages the fine-tuning pipeline for the forensic LLM. It shows active model details, training phase statistics, the self-healing feedback loop, and a timeline of training runs. AIPAM uses QLoRA (Quantized Low-Rank Adaptation) to continuously improve its forensic analysis capabilities based on analyst feedback and new threat data.",
        section: "AI & Training",
    },

    /* ── New Analysis ──────────────────────────────────── */
    new_analysis: {
        title: "New Analysis",
        description:
            "Start a new forensic analysis by uploading one or more PCAP capture files. You can optionally assign labels to each file (e.g., 'before', 'during', 'after') for temporal comparative analysis. Choose an execution profile (quick, standard, deep) and configure which sensors to run. Once submitted, the analysis pipeline will process the PCAPs through all stages automatically.",
        section: "Jobs",
    },

    /* ── Global Hosts ──────────────────────────────────── */
    global_hosts: {
        title: "Global Hosts",
        description:
            "Global Hosts tracks IP addresses and hostnames across all analysis jobs in the system. Unlike per-job hosts, Global Hosts provides a cross-investigation view — showing how the same host appears in multiple analyses, what roles it plays, and its cumulative threat profile. Use this to identify persistent attackers, compromised infrastructure, or recurring C2 servers across your entire forensic history.",
        section: "Cross-Job Analysis",
    },

    /* ── Artifacts ─────────────────────────────────────── */
    artifacts: {
        title: "Artifacts",
        description:
            "Artifacts are downloadable evidence packages generated from the analysis. An evidence package bundles findings, alerts, IOCs, host data, and other forensic artifacts into a structured format suitable for sharing with other analysts, importing into a SIEM, or archiving for compliance. Click 'Generate Evidence Package' to create a new bundle.",
        section: "Reporting",
    },

    /* ── Extracted Files ───────────────────────────────── */
    extracted_files: {
        title: "Extracted Files",
        description:
            "Extracted Files shows files that were carved out of the PCAP traffic during analysis — executables, documents, scripts, archives, and other file transfers detected in the network capture. Each file shows its name, type, size, and hash. These are critical artifacts for malware analysis and can be submitted to sandboxes or threat intel platforms for further investigation.",
        section: "Analysis",
    },

    /* ── Chat ──────────────────────────────────────────── */
    chat: {
        title: "AI Chat",
        description:
            "The AI Chat provides an interactive conversational interface for investigating analysis results. Ask questions about findings, alerts, hosts, or attack patterns, and the forensic LLM will answer using a 3-source RAG (Retrieval-Augmented Generation) approach — combining the job's evidence data, the knowledge base, and the model's training. Use the Ask AI buttons throughout the app to pre-fill questions with context.",
        section: "AI & Training",
    },

    /* ── Alert Detail ──────────────────────────────────── */
    alert_detail: {
        title: "Alert Detail",
        description:
            "The Alert Detail page shows the complete information for a single Suricata alert — including the signature, severity, SID, category, source and destination IPs/ports, references, related hosts, and connection flows. Use this to understand exactly what triggered the alert and assess whether it's a true positive.",
        section: "Analysis",
    },

    /* ── Host Detail ───────────────────────────────────── */
    host_detail: {
        title: "Host Detail",
        description:
            "The Host Detail page shows all forensic information about a single IP address within a specific analysis job — its role (internal/external/DNS/gateway), associated alerts, findings, IOCs, connection patterns, and behavioral anomalies. This is your deep-dive view for understanding what a specific machine did in the captured traffic.",
        section: "Analysis",
    },

    /* ── Global Host Detail ────────────────────────────── */
    global_host_detail: {
        title: "Global Host Detail",
        description:
            "The Global Host Detail page shows cross-job forensic history for a single IP or hostname. It aggregates data from every analysis job where this host appeared — showing role changes, alert patterns, and threat evolution over time. Use this to track persistent threats and build a comprehensive profile of known-bad infrastructure.",
        section: "Cross-Job Analysis",
    },
    global_host_history: {
        title: "Cross-Job History",
        description:
            "Cross-Job History lists every analysis job where this host was observed, along with the role it played and any associated findings or alerts in each job. This chronological view helps identify patterns — such as a host that was benign in early captures but became a C2 server in later ones.",
        section: "Cross-Job Analysis",
    },
};

/** Look up a page help entry by its key */
export function getPageHelpEntry(key: string): PageHelpEntry | null {
    return pageHelpData[key] ?? null;
}