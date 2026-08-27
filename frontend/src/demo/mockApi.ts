const SCHEMA = "1.0";

const COMPLETED_JOB_ID = "a7f3c2e1-9b04-4d17-8e62-3fc51a0d7b88";
const RUNNING_JOB_ID = "c41d8b60-27ae-4f93-a5d1-6b7e90c2f314";
const FAILED_JOB_ID = "5e8a1f77-33c2-4a0b-9d45-118cf6de2a90";

const nowIso = () => new Date().toISOString();

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function parsePath(url, apiBase) {
  const u = new URL(url, "http://localhost");
  const apiUrl = new URL(apiBase, "http://localhost");
  if (!u.pathname.startsWith(apiUrl.pathname)) return null;
  const path = u.pathname.slice(apiUrl.pathname.length) || "/";
  return { path, searchParams: u.searchParams };
}

function toPage(items, limit = 200, offset = 0) {
  const safeOffset = Math.max(0, Number(offset) || 0);
  const safeLimit = Math.max(1, Number(limit) || 200);
  const sliced = items.slice(safeOffset, safeOffset + safeLimit);
  return {
    items: sliced,
    total: items.length,
    limit: safeLimit,
    offset: safeOffset,
    page: {
      has_more: safeOffset + safeLimit < items.length,
      next_cursor: safeOffset + safeLimit < items.length ? String(safeOffset + safeLimit) : null,
    },
  };
}

const demoJobs = [
  {
    job_id: COMPLETED_JOB_ID,
    job_name: "Emotet Epoch-5 / Cobalt Strike Case",
    notes: "Static demo case",
    created_at: "2026-02-11T14:02:18.114Z",
    started_at: "2026-02-11T14:02:32.000Z",
    completed_at: "2026-02-11T14:09:47.902Z",
    status: "completed",
    execution_profile: "standard",
    priority: "normal",
    pcap_filename: "2026-02-11-emotet-epoch5-cobaltstrike.pcap",
    pcap_size_bytes: 412600000,
  },
  {
    job_id: RUNNING_JOB_ID,
    job_name: "Security Onion Pull - GTE SO-0042",
    notes: "Running sample for partial results",
    created_at: "2026-02-11T15:31:05.660Z",
    started_at: "2026-02-11T15:31:12.000Z",
    completed_at: null,
    status: "running",
    execution_profile: "triage",
    priority: "high",
    pcap_filename: "security-onion://sensor-gte-01,sensor-gte-02",
    pcap_size_bytes: 228900000,
  },
  {
    job_id: FAILED_JOB_ID,
    job_name: "Arkime Session Pull",
    notes: "Failure path sample",
    created_at: "2026-02-11T11:47:52.001Z",
    started_at: "2026-02-11T11:47:55.000Z",
    completed_at: "2026-02-11T11:48:03.774Z",
    status: "failed",
    execution_profile: "standard",
    priority: "normal",
    pcap_filename: "arkime://ip.src == 10.11.27.101",
    pcap_size_bytes: 0,
    error_summary: "No PCAP files available for ingest",
  },
];

const completedAlerts = [
  {
    alert_id: "9812771",
    ts: "2026-02-11T09:14:03.221Z",
    severity: "medium",
    engine: "suricata",
    signature: "ET POLICY PE EXE or DLL Windows file download HTTP",
    category: "Potentially Bad Traffic",
    sid: "2018959",
    src_ip: "10.11.27.101",
    src_port: 49731,
    dest_ip: "45.83.192.211",
    dest_port: 80,
    proto: "tcp",
    community_id: "1:tYf1",
    refs: ["https://attack.mitre.org/techniques/T1566/001/"],
    tags: ["initial_access"],
  },
  {
    alert_id: "9812804",
    ts: "2026-02-11T09:14:41.884Z",
    severity: "high",
    engine: "suricata",
    signature: "ET MALWARE Win32/Emotet CnC Activity (POST)",
    category: "A Network Trojan was detected",
    sid: "2033203",
    src_ip: "10.11.27.101",
    src_port: 49744,
    dest_ip: "185.220.101.47",
    dest_port: 8080,
    proto: "tcp",
    community_id: "1:Qad2",
    refs: ["https://attack.mitre.org/techniques/T1071/001/"],
    tags: ["c2"],
  },
  {
    alert_id: "9813120",
    ts: "2026-02-11T09:22:10.006Z",
    severity: "high",
    engine: "suricata",
    signature: "ET MALWARE Cobalt Strike Beacon Observed",
    category: "A Network Trojan was detected",
    sid: "2027963",
    src_ip: "10.11.27.101",
    src_port: 49802,
    dest_ip: "91.219.236.18",
    dest_port: 443,
    proto: "tcp",
    community_id: "1:B3ac",
    refs: ["https://attack.mitre.org/techniques/T1573/002/"],
    tags: ["beacon"],
  },
  {
    alert_id: "9815551",
    ts: "2026-02-11T12:26:47.412Z",
    severity: "high",
    engine: "suricata",
    signature: "ET POLICY SMB2 NT Create AndX Request For an Executable File In ADMIN$",
    category: "Potential Corporate Privacy Violation",
    sid: "2025692",
    src_ip: "10.11.27.101",
    src_port: 50310,
    dest_ip: "10.11.27.8",
    dest_port: 445,
    proto: "tcp",
    community_id: "1:Lm77",
    refs: ["https://attack.mitre.org/techniques/T1021/002/"],
    tags: ["lateral_movement"],
  },
  {
    alert_id: "9816033",
    ts: "2026-02-11T13:41:09.775Z",
    severity: "medium",
    engine: "suricata",
    signature: "ET POLICY Large Outbound Data Transfer to Non-Corporate Netblock",
    category: "Potentially Bad Traffic",
    sid: "2019401",
    src_ip: "10.11.27.101",
    src_port: 50588,
    dest_ip: "91.219.236.18",
    dest_port: 443,
    proto: "tcp",
    community_id: "1:B3ac",
    refs: ["https://attack.mitre.org/techniques/T1041/"],
    tags: ["exfiltration"],
  },
];

const completedFindings = [
  {
    finding_id: "F-BEACON-001",
    title: "Fixed 60-second callback to 91.219.236.18:443",
    severity: "critical",
    category: "beacon",
    sensor: "beacon_detector",
    pcap_label: "during",
    summary: "412 connections over 6h58m with 2.1% jitter; strong C2 check-in profile.",
    evidence: {
      affected_hosts: ["10.11.27.101"],
      interval_jitter_pct: 2.1,
      connection_count: 412,
      confidence_reason: "variance below fleet baseline",
      mitre: ["T1071.001", "T1573.002"],
    },
    feedback: null,
    confidence: 0.94,
    evidence_status: "confirmed",
    corroboration_score: 0.93,
    corroborating_sources: ["suricata", "heuristics"],
    analyst_status: "confirmed",
    analyst_notes: "Beacon profile and cert metadata align with operator-controlled listener.",
    reviewed_at: "2026-02-11T15:12:20.000Z",
    reviewer_id: "analyst-01",
  },
  {
    finding_id: "F-DNS-002",
    title: "DGA-like subdomain fan-out on telemetry-sync[.]org",
    severity: "high",
    category: "dns_beacon",
    sensor: "dns_entropy",
    pcap_label: "during",
    summary: "214 unique subdomains with 71% NXDOMAIN and elevated label entropy.",
    evidence: {
      affected_hosts: ["10.11.27.101", "10.11.27.2"],
      nxdomain_rate: 0.71,
      mitre: ["T1568.002"],
    },
    feedback: null,
    confidence: 0.83,
    evidence_status: "corroborated",
    corroboration_score: 0.81,
    corroborating_sources: ["dns", "timeline"],
    analyst_status: "needs_review",
    analyst_notes: null,
    reviewed_at: null,
    reviewer_id: null,
  },
  {
    finding_id: "F-LAT-003",
    title: "Executable write to ADMIN$ from workstation",
    severity: "high",
    category: "lateral_movement",
    sensor: "smb_anomaly",
    pcap_label: "during",
    summary: "svcupdate.exe written to \\\\10.11.27.8\\ADMIN$ at 12:26:47Z.",
    evidence: {
      affected_hosts: ["10.11.27.101", "10.11.27.8"],
      mitre: ["T1021.002"],
    },
    feedback: null,
    confidence: 0.86,
    evidence_status: "confirmed",
    corroboration_score: 0.84,
    corroborating_sources: ["suricata"],
    analyst_status: "confirmed",
    analyst_notes: "No prior ADMIN$ writes from this workstation in 30d baseline.",
    reviewed_at: "2026-02-11T15:20:12.000Z",
    reviewer_id: "analyst-01",
  },
];

const completedIocs = [
  { ioc_id: "IOC-1", type: "ip", value: "91.219.236.18", severity: "high", confidence: 0.92, sources: ["suricata", "finding"], context: "C2 beacon endpoint" },
  { ioc_id: "IOC-2", type: "ip", value: "185.220.101.47", severity: "high", confidence: 0.88, sources: ["suricata"], context: "Emotet registration host" },
  { ioc_id: "IOC-3", type: "domain", value: "telemetry-sync.org", severity: "medium", confidence: 0.79, sources: ["dns"], context: "DGA fallback domain" },
  { ioc_id: "IOC-4", type: "url", value: "http://45.83.192.211/wp-content/o8fj/", severity: "high", confidence: 0.85, sources: ["flow", "alert"], context: "Payload download path" },
];

const completedHosts = [
  { ip: "10.11.27.101", role: "internal", conn_count: 8412, bytes_sent: 1740000000, bytes_recv: 42000000, alert_count: 44, top_domains: ["telemetry-sync.org", "cdn-update-svc.net"] },
  { ip: "10.11.27.8", role: "internal", conn_count: 3106, bytes_sent: 22000000, bytes_recv: 11000000, alert_count: 9, top_domains: [] },
  { ip: "10.11.27.2", role: "internal", conn_count: 5921, bytes_sent: 18000000, bytes_recv: 21000000, alert_count: 3, top_domains: ["telemetry-sync.org"] },
  { ip: "10.11.27.51", role: "internal", conn_count: 964, bytes_sent: 4000000, bytes_recv: 3000000, alert_count: 4, top_domains: [] },
  { ip: "91.219.236.18", role: "external", conn_count: 412, bytes_sent: 0, bytes_recv: 0, alert_count: 2, top_domains: [] },
];

const completedTheories = [
  {
    theory_id: "TH-001",
    scope_type: "job",
    scope_id: null,
    label: "Emotet delivery with Cobalt Strike follow-on",
    hypothesis_type: "c2",
    score: 0.91,
    confidence: "high",
    rank: 1,
    supporting_evidence: [{ id: "9812804", type: "alert", label: "Emotet C2 POST" }, { id: "F-BEACON-001", type: "finding", label: "60-second beacon" }],
    contradicting_evidence: [],
    score_breakdown: {
      findings: 0.5,
      alerts: 0.3,
      iocs: 0.11,
      finding_count: 2,
      alert_count: 3,
      ioc_count: 2,
      reason: "Beaconing plus known Emotet transport shape",
    },
    explanation: "Behavior class confidence is high; family attribution remains moderate.",
    next_steps: ["Contain host 10.11.27.101", "Block known C2 IPs", "Review ADMIN$ writes on DC"],
    pcap_label: "during",
    created_at: "2026-02-11T14:10:00.000Z",
  },
];

const completedSlices = [
  {
    slice_id: "SL-INITIAL-01",
    label: "Initial Access and Loader Delivery",
    slice_type: "attack_thread",
    severity: "high",
    confidence: 0.87,
    community_ids: ["1:tYf1", "1:Qad2"],
    host_ips: ["10.11.27.101"],
    time_start: "2026-02-11T09:14:00.000Z",
    time_end: "2026-02-11T09:25:00.000Z",
    alert_ids: ["9812771", "9812804"],
    finding_ids: ["F-BEACON-001"],
    ioc_ids: ["IOC-2", "IOC-4"],
    connection_ids: ["CONN-1"],
    summary: "Macro chain to PE download followed by Emotet registration.",
    rank: 1,
    created_at: "2026-02-11T14:11:00.000Z",
  },
  {
    slice_id: "SL-LATERAL-02",
    label: "Lateral Attempt via SMB ADMIN$",
    slice_type: "lateral",
    severity: "high",
    confidence: 0.82,
    community_ids: ["1:Lm77"],
    host_ips: ["10.11.27.101", "10.11.27.8"],
    time_start: "2026-02-11T12:26:00.000Z",
    time_end: "2026-02-11T12:30:00.000Z",
    alert_ids: ["9815551"],
    finding_ids: ["F-LAT-003"],
    ioc_ids: [],
    connection_ids: ["CONN-2"],
    summary: "Executable write to domain controller share from non-management host.",
    rank: 2,
    created_at: "2026-02-11T14:12:00.000Z",
  },
];

const completedAnnotations = [
  {
    annotation_id: "ANN-01",
    host_ip: "10.11.27.101",
    metric_name: "beacon_interval_jitter",
    metric_category: "temporal",
    baseline_value: 0.14,
    observed_value: 0.021,
    deviation_factor: 6.67,
    population_size: 214,
    severity: "high",
    confidence: 0.91,
    title: "Callback interval is unnaturally stable",
    description: "Outbound callback variance is far below workstation baseline.",
    why_unusual: "Most benign polling on this subnet varies 8-20%; this flow varies 2.1%.",
    related_alert_ids: ["9813120"],
    related_finding_ids: ["F-BEACON-001"],
    created_at: "2026-02-11T14:13:00.000Z",
  },
  {
    annotation_id: "ANN-02",
    host_ip: "10.11.27.101",
    metric_name: "upload_download_ratio",
    metric_category: "volume",
    baseline_value: 0.07,
    observed_value: 41,
    deviation_factor: 585.7,
    population_size: 180,
    severity: "high",
    confidence: 0.88,
    title: "Data egress inversion",
    description: "Host switched from download-heavy to extreme upload-heavy behavior.",
    why_unusual: "41:1 upload:download ratio over 22 minutes while destination remained constant.",
    related_alert_ids: ["9816033"],
    related_finding_ids: ["F-BEACON-001"],
    created_at: "2026-02-11T14:13:30.000Z",
  },
];

const completedTimeline = [
  { ts: "2026-02-11T09:14:03.221Z", type: "alert", title: "PE download over HTTP", description: "45.83.192.211/wp-content/o8fj/", severity: "medium", entities: { src_ip: "10.11.27.101", dest_ip: "45.83.192.211", dest_port: 80 }, refs: { alert_id: "9812771" }, sensor: "suricata" },
  { ts: "2026-02-11T09:14:41.884Z", type: "alert", title: "Emotet registration", description: "POST to 185.220.101.47:8080", severity: "high", entities: { src_ip: "10.11.27.101", dest_ip: "185.220.101.47", dest_port: 8080 }, refs: { alert_id: "9812804" }, sensor: "suricata" },
  { ts: "2026-02-11T09:22:10.006Z", type: "finding", title: "Cobalt Strike beacon pattern", description: "Fixed 60-second callback begins", severity: "critical", entities: { src_ip: "10.11.27.101", dest_ip: "91.219.236.18", dest_port: 443 }, refs: { finding_id: "F-BEACON-001" }, sensor: "beacon_detector" },
  { ts: "2026-02-11T12:26:47.412Z", type: "alert", title: "ADMIN$ executable write", description: "svcupdate.exe to domain controller", severity: "high", entities: { src_ip: "10.11.27.101", dest_ip: "10.11.27.8", dest_port: 445 }, refs: { alert_id: "9815551" }, sensor: "suricata" },
  { ts: "2026-02-11T13:41:09.775Z", type: "finding", title: "Bulk outbound transfer", description: "1.74 GB over existing TLS channel", severity: "high", entities: { src_ip: "10.11.27.101", dest_ip: "91.219.236.18", dest_port: 443 }, refs: { finding_id: "F-BEACON-001" }, sensor: "volume" },
];

const completedRawEvents = [
  {
    event_id: "EV-1",
    event_type: "http_download",
    timestamp: "2026-02-11T09:14:03.221Z",
    source_type: "zeek",
    source_system: "zeek-http",
    hostname: "WS-101",
    username: "jdoe",
    src_ip: "10.11.27.101",
    src_port: 49731,
    dest_ip: "45.83.192.211",
    dest_port: 80,
    proto: "tcp",
    evidence_status: "observed",
    tags: ["initial_access"],
    data: { uri: "/wp-content/o8fj/", user_agent: "Microsoft Office Protocol Discovery", mime: "application/x-msdownload" },
  },
  {
    event_id: "EV-2",
    event_type: "http_post",
    timestamp: "2026-02-11T09:14:41.884Z",
    source_type: "zeek",
    source_system: "zeek-http",
    hostname: "WS-101",
    username: "jdoe",
    src_ip: "10.11.27.101",
    src_port: 49744,
    dest_ip: "185.220.101.47",
    dest_port: 8080,
    proto: "tcp",
    evidence_status: "observed",
    tags: ["c2"],
    data: { method: "POST", cookie_shape: "base64", body_len: 1388 },
  },
  {
    event_id: "EV-3",
    event_type: "tls_session",
    timestamp: "2026-02-11T09:22:10.006Z",
    source_type: "zeek",
    source_system: "zeek-ssl",
    hostname: "WS-101",
    username: "jdoe",
    src_ip: "10.11.27.101",
    src_port: 49802,
    dest_ip: "91.219.236.18",
    dest_port: 443,
    proto: "tcp",
    evidence_status: "observed",
    tags: ["beacon", "tls"],
    data: { ja3: "5d2f0c1a9be3", cert_validity_hours: 24, sni: null },
  },
  {
    event_id: "EV-4",
    event_type: "smb_write",
    timestamp: "2026-02-11T12:26:47.412Z",
    source_type: "zeek",
    source_system: "zeek-smb",
    hostname: "WS-101",
    username: "jdoe",
    src_ip: "10.11.27.101",
    src_port: 50310,
    dest_ip: "10.11.27.8",
    dest_port: 445,
    proto: "tcp",
    evidence_status: "observed",
    tags: ["lateral"],
    data: { path: "\\\\10.11.27.8\\ADMIN$\\svcupdate.exe", operation: "CREATE" },
  },
  {
    event_id: "EV-5",
    event_type: "bulk_transfer",
    timestamp: "2026-02-11T13:41:09.775Z",
    source_type: "derived",
    source_system: "aipam-volume",
    hostname: "WS-101",
    username: "jdoe",
    src_ip: "10.11.27.101",
    src_port: 50588,
    dest_ip: "91.219.236.18",
    dest_port: 443,
    proto: "tcp",
    evidence_status: "inferred",
    tags: ["exfiltration"],
    data: { bytes_out: 1740000000, window_minutes: 22, ratio_upload_download: 41 },
  },
];

const partialRunning = {
  pcap_stats: { file_count: 4, total_bytes: 228900000 },
  top_hosts: [
    { ip: "10.11.27.144", total_bytes: 98422320 },
    { ip: "10.11.27.2", total_bytes: 18551222 },
    { ip: "10.11.27.8", total_bytes: 16444200 },
    { ip: "10.11.27.1", total_bytes: 12000911 },
  ],
  protocol_distribution: { tcp: 84, udp: 11, dns: 5 },
  alert_summary: { total: 61, by_severity: { high: 17, medium: 29, low: 15 } },
  sensor_summary: {
    total: 10,
    completed: 6,
    failed: 0,
    skipped: 0,
    sensors: [
      { name: "zeek", status: "completed", duration_ms: 3600 },
      { name: "suricata", status: "completed", duration_ms: 5200 },
      { name: "beacon_detector", status: "completed", duration_ms: 1200 },
      { name: "dns_entropy", status: "completed", duration_ms: 980 },
      { name: "volume", status: "completed", duration_ms: 700 },
      { name: "lateral", status: "completed", duration_ms: 840 },
      { name: "llm_analysis", status: "running", duration_ms: 0 },
    ],
  },
  finding_count: 4,
  alert_count: 61,
  host_count: 6,
};

const demoReportMarkdown = `# AIPAM Forensic Report\n\n**Job:** ${COMPLETED_JOB_ID}\n\n**Capture:** 2026-02-11-emotet-epoch5-cobaltstrike.pcap (412.6 MB)\n\n**Classification:** Malicious — Emotet loader with Cobalt Strike follow-on\n\n## Executive Summary\n\nA single workstation (10.11.27.101) was compromised through a macro-delivery chain, then established a fixed-interval C2 beacon and attempted lateral movement to the domain controller.\n\n## Timeline\n\n- 09:14:03 — PE download over HTTP from 45.83.192.211\n- 09:14:41 — Emotet registration POST to 185.220.101.47\n- 09:22:10 — Cobalt Strike beacon starts (60-second cadence)\n- 12:26:47 — ADMIN$ write to domain controller\n- 13:41:09 — 1.74 GB outbound transfer over existing TLS channel\n\n## Recommended Actions\n\n1. Isolate 10.11.27.101 and collect memory before shutdown.\n2. Block 91.219.236.18, 185.220.101.47, 45.83.192.211.\n3. Investigate ADMIN$ writes and service creation on 10.11.27.8.\n4. Rotate service account credentials observed in post-lateral Kerberos activity.\n\n*Static demo — fictional data. No upload or inference occurs in this build.*\n`;

let reportCounter = 2;
let reportItems = [
  {
    report_id: "RPT-001",
    mode: "analyst",
    title: "Analyst Report - Emotet/Cobalt Strike",
    threat_level: "High",
    confidence: 0.88,
    pcap_label: null,
    content_markdown: demoReportMarkdown,
    content_json: { classification: "malicious", campaign: "emotet-cobalt" },
    theory_count: completedTheories.length,
    slice_count: completedSlices.length,
    finding_count: completedFindings.length,
    alert_count: completedAlerts.length,
    ioc_count: completedIocs.length,
    host_count: completedHosts.length,
    annotation_count: completedAnnotations.length,
    evidence_refs: ["9812804", "9813120", "F-BEACON-001"],
    created_at: "2026-02-11T14:10:18.000Z",
  },
];

let integrationSettings = {
  security_onion_api_url: "https://so-manager.gte.local",
  security_onion_username: "aipam-svc",
  security_onion_password: "••••••••",
  arkime_api_url: "https://arkime.gte.local:8005",
  arkime_api_username: "aipam-svc",
  arkime_api_password: "••••••••",
};

let settings = {
  llm_endpoint: "http://host.docker.internal:11434",
  llm_model_name: "aipam-cybersec-v7",
  llm_max_tokens: 4096,
  llm_temperature: 0.2,
  forensic_model_name: "aipam-cybersec-v7",
  general_model_name: "llama3.1:8b",
  finetune_base_model: "meta-llama/Meta-Llama-3.1-8B-Instruct",
  finetune_dataset_url: "https://huggingface.co/datasets/aipam/trafficllm-v7",
  finetune_lora_rank: 16,
  finetune_learning_rate: 0.0002,
  finetune_max_seq_length: 32768,
  file_storage_path: "/data/storage",
  reports_path: "/data/storage/reports",
};

const availableModels = [
  { name: "aipam-cybersec-v7", size: 4920000000, family: "llama", parameter_size: "8B", quantization: "Q4_K_M" },
  { name: "aipam-trafficllm-v5", size: 4920000000, family: "llama", parameter_size: "8B", quantization: "Q4_K_M" },
  { name: "llama3.1:8b", size: 4700000000, family: "llama", parameter_size: "8B", quantization: "Q4_0" },
  { name: "qwen2.5:14b", size: 8990000000, family: "qwen2", parameter_size: "14B", quantization: "Q4_K_M" },
];

const trainingSummary = {
  has_data: true,
  latest_run: {
    timestamp: "2026-02-10T22:41:09Z",
    event_type: "phase",
    phase_label: "Phase 6.4 — Self-Heal Loop",
    status: "completed",
    learning_rate: 0.0002,
    max_seq_length: 32768,
  },
  active_model: {
    name: "aipam-cybersec-v7",
    phase: "Phase 6.4",
    context_window: 32768,
    lora_r: 16,
    lora_alpha: 32,
    trained_at: "2026-02-10T22:41:09Z",
    loss: 0.4127,
    dawn_seed: 7,
  },
  phase_counts: {
    "Phase 6.1": { total_events: 12, completed: 12, failed: 0, latest_timestamp: "2026-02-10T11:04:55Z", latest_loss: 0.42 },
    "Phase 6.2": { total_events: 9, completed: 8, failed: 1, latest_timestamp: "2026-02-10T16:58:31Z", latest_loss: 0.40 },
    "Phase 6.3": { total_events: 6, completed: 6, failed: 0, latest_timestamp: "2026-02-10T20:12:44Z", latest_loss: 0.39 },
    "Phase 6.4": { total_events: 4, completed: 3, failed: 1, latest_timestamp: "2026-02-10T22:41:09Z", latest_loss: 0.41 },
  },
  models: ["aipam-cybersec-v7", "aipam-cybersec-v6"],
  peak_vram_gb: 17.3,
  self_healing: {
    runs: 4,
    total_synthetic_pcaps: 214,
    families_augmented: ["emotet", "qakbot", "cobalt_strike"],
    latest_timestamp: "2026-02-10T22:41:09Z",
  },
  total_events: 148,
};

const trainingConfig = {
  base_model: "meta-llama/Meta-Llama-3.1-8B-Instruct",
  dataset_url: "https://huggingface.co/datasets/aipam/trafficllm-v7",
  lora_rank: 16,
  learning_rate: 0.0002,
  max_seq_length: 32768,
  configured: true,
};

let trainingStatus = {
  trainer_online: true,
  job_id: "f3d90b41-6c22-4e88-9a17-5b0e7c41d2a6",
  status: "running",
  current_iter: 1840,
  total_iters: 3000,
  percent: 61.3,
  last_loss: 0.4127,
  it_per_sec: 1.42,
  elapsed_seconds: 4320,
  eta_seconds: 2720,
};

const trainingLedger = {
  entries: [
    { timestamp: "2026-02-10T22:41:09Z", event_type: "phase", phase_label: "Phase 6.4 — Self-Heal Loop", status: "completed", metrics: { duration_seconds: 6180, message: "Regenerated 214 low-confidence samples" } },
    { timestamp: "2026-02-10T20:12:44Z", event_type: "phase", phase_label: "Phase 6.3 — ORPO Preference Tuning", status: "completed", metrics: { duration_seconds: 9720, message: "1,422 preference pairs" } },
    { timestamp: "2026-02-10T16:58:31Z", event_type: "phase", phase_label: "Phase 6.2 — Forensic COT Distillation", status: "completed", metrics: { duration_seconds: 15840, samples: 530769 } },
    { timestamp: "2026-02-10T12:20:07Z", event_type: "phase", phase_label: "Phase 6.2 — Forensic COT Distillation", status: "failed", metrics: { message: "OOM at iter 2,110" } },
  ],
  total: 4,
  ledger_path: "/data/training/ledger.jsonl",
  ledger_exists: true,
};

const distillConfig = {
  endpoint: "https://api.openai.com/v1",
  model: "gpt-4.1",
  temperature: 0.2,
  max_tokens: 1200,
  timeout_seconds: 45,
  enabled: true,
  configured: true,
  api_key_set: true,
  api_key_preview: "sk-••••••",
};

const distillStats = {
  total_samples: 18422,
  file_size_mb: 228.4,
  file_path: "/data/training/distill_samples.jsonl",
  exists: true,
  teacher_models: ["gpt-4.1", "claude-3.7-sonnet"],
  jobs_distilled: [COMPLETED_JOB_ID],
  per_task: { triage: 8221, reasoning: 7142, recommendation: 3059 },
  rejected_count: 193,
};

let conversations = [
  { id: "conv-demo-1", job_id: COMPLETED_JOB_ID, created_at: "2026-02-11T14:12:00Z", updated_at: "2026-02-11T14:15:38Z", title: "Containment triage", message_count: 6 },
];

let conversationHistory = {
  "conv-demo-1": {
    id: "conv-demo-1",
    job_id: COMPLETED_JOB_ID,
    created_at: "2026-02-11T14:12:00Z",
    updated_at: "2026-02-11T14:15:38Z",
    messages: [
      { role: "user", content: "What hosts were compromised?", timestamp: "2026-02-11T14:12:03Z" },
      {
        role: "assistant",
        content: "One host is confirmed compromised and one is a contested target.\n\n10.11.27.101 is patient zero with sustained C2 and exfiltration behavior.\n10.11.27.8 shows attempted lateral movement evidence but no outbound C2 in this capture.",
        citations: [
          { type: "alert", id: "9815551", snippet: "ADMIN$ executable write from 10.11.27.101 to 10.11.27.8" },
          { type: "finding", id: "F-BEACON-001", snippet: "412 TLS sessions with 60.2s interval" },
        ],
        timestamp: "2026-02-11T14:12:11Z",
      },
    ],
  },
};

let kbJobDocs = [
  {
    id: "kb-1",
    job_id: COMPLETED_JOB_ID,
    name: "Containment Playbook",
    doc_type: "soc_playbook",
    description: "SOC response steps for beacon + lateral movement",
    chunk_count: 6,
    status: "ready",
    created_at: "2026-02-11T13:00:00Z",
    updated_at: "2026-02-11T13:02:00Z",
  },
];

let kbLibraryDocs = [
  {
    id: "lib-1",
    job_id: null,
    name: "Cobalt Strike Hunt Guide",
    doc_type: "reference",
    description: "Operator TTP and network signatures",
    chunk_count: 12,
    status: "ready",
    created_at: "2026-02-10T10:00:00Z",
    updated_at: "2026-02-10T10:02:00Z",
  },
];

const alertsForJob = {
  [COMPLETED_JOB_ID]: completedAlerts,
  [RUNNING_JOB_ID]: [
    {
      alert_id: "R-1",
      ts: "2026-02-11T15:32:09.000Z",
      severity: "high",
      engine: "suricata",
      signature: "ET MALWARE Cobalt Strike Beacon Observed",
      category: "A Network Trojan was detected",
      sid: "2027963",
      src_ip: "10.11.27.144",
      src_port: 50112,
      dest_ip: "91.219.236.18",
      dest_port: 443,
      proto: "tcp",
      community_id: "1:rbe1",
      refs: [],
      tags: ["beacon"],
    },
  ],
};

const findingsForJob = {
  [COMPLETED_JOB_ID]: completedFindings,
  [RUNNING_JOB_ID]: [
    {
      finding_id: "RF-1",
      title: "Early periodic callback detected",
      severity: "high",
      category: "beacon",
      sensor: "beacon_detector",
      pcap_label: null,
      summary: "Periodic outbound callback observed before full LLM analysis completed.",
      evidence: { affected_hosts: ["10.11.27.144"] },
      feedback: null,
      confidence: 0.88,
      evidence_status: "inferred",
      corroboration_score: 0.7,
      corroborating_sources: ["heuristics"],
      analyst_status: "unreviewed",
      analyst_notes: null,
      reviewed_at: null,
      reviewer_id: null,
    },
  ],
};

const iocsForJob = {
  [COMPLETED_JOB_ID]: completedIocs,
  [RUNNING_JOB_ID]: [{ ioc_id: "R-IOC-1", type: "ip", value: "91.219.236.18", severity: "high", confidence: 0.82, sources: ["suricata"], context: "probable C2" }],
};

const hostsForJob = {
  [COMPLETED_JOB_ID]: completedHosts,
  [RUNNING_JOB_ID]: [
    { ip: "10.11.27.144", role: "internal", conn_count: 8412, bytes_sent: 620000000, bytes_recv: 22000000, alert_count: 44, top_domains: ["telemetry-sync.org"] },
    { ip: "10.11.27.8", role: "internal", conn_count: 3106, bytes_sent: 18000000, bytes_recv: 9000000, alert_count: 9, top_domains: [] },
    { ip: "10.11.27.2", role: "internal", conn_count: 5921, bytes_sent: 12000000, bytes_recv: 24000000, alert_count: 3, top_domains: ["telemetry-sync.org"] },
  ],
};

function filterList(list, searchParams) {
  let out = [...list];
  const severity = searchParams.get("severity");
  const q = searchParams.get("q");
  const type = searchParams.get("type");
  if (severity) out = out.filter((x) => String(x.severity || "").toLowerCase() === severity.toLowerCase());
  if (type) out = out.filter((x) => String(x.type || "").toLowerCase() === type.toLowerCase());
  if (q) {
    const needle = q.toLowerCase();
    out = out.filter((x) => JSON.stringify(x).toLowerCase().includes(needle));
  }
  return out;
}

function getJob(jobId) {
  return demoJobs.find((j) => j.job_id === jobId) || null;
}

function getJobDetailPayload(jobId) {
  const base = getJob(jobId);
  if (!base) return null;

  const metrics = {
    pcap_stats: {
      packet_count: jobId === COMPLETED_JOB_ID ? 48213 : 22905,
      capture_duration_seconds: jobId === COMPLETED_JOB_ID ? 21600 : 9600,
    },
    durations: {
      ingest: 12.4,
      parse: 93.1,
      aggregate: 17.9,
      llm_analysis: jobId === RUNNING_JOB_ID ? 0 : 165.2,
      report: jobId === RUNNING_JOB_ID ? 0 : 8.7,
    },
  };

  const stages = [
    { stage: "ingest", status: "completed", started_at: base.created_at, completed_at: "2026-02-11T14:03:10.000Z" },
    { stage: "parse", status: "completed", started_at: "2026-02-11T14:03:10.000Z", completed_at: "2026-02-11T14:05:10.000Z" },
    { stage: "aggregate", status: "completed", started_at: "2026-02-11T14:05:10.000Z", completed_at: "2026-02-11T14:06:01.000Z" },
    { stage: "llm_analysis", status: jobId === RUNNING_JOB_ID ? "running" : "completed", started_at: "2026-02-11T14:06:02.000Z", completed_at: jobId === RUNNING_JOB_ID ? null : "2026-02-11T14:09:30.000Z" },
    { stage: "report", status: jobId === RUNNING_JOB_ID ? "pending" : "completed", started_at: jobId === RUNNING_JOB_ID ? null : "2026-02-11T14:09:31.000Z", completed_at: jobId === RUNNING_JOB_ID ? null : "2026-02-11T14:09:47.902Z" },
  ];

  const sensors = [
    { sensor: "zeek", status: "completed", meta: { sensor_name: "zeek", sensor_version: "6.0.0", aipam_version: "v9" }, stats: { runtime_seconds: 12.6, findings_count: 0 } },
    { sensor: "suricata", status: "completed", meta: { sensor_name: "suricata", sensor_version: "7.0.4", aipam_version: "v9" }, stats: { runtime_seconds: 23.7, findings_count: 0 } },
    { sensor: "beacon_detector", status: "completed", meta: { sensor_name: "beacon_detector", sensor_version: "1.3.0", aipam_version: "v9" }, stats: { runtime_seconds: 3.2, findings_count: 1 } },
    { sensor: "dns_entropy", status: "completed", meta: { sensor_name: "dns_entropy", sensor_version: "1.2.1", aipam_version: "v9" }, stats: { runtime_seconds: 2.8, findings_count: 1 } },
    { sensor: "lateral", status: "completed", meta: { sensor_name: "lateral", sensor_version: "1.0.4", aipam_version: "v9" }, stats: { runtime_seconds: 2.9, findings_count: 1 } },
    { sensor: "llm_analysis", status: jobId === RUNNING_JOB_ID ? "running" : "completed", meta: { sensor_name: "llm_analysis", sensor_version: "v7", aipam_version: "v9" }, stats: { runtime_seconds: jobId === RUNNING_JOB_ID ? null : 165.2, findings_count: 1 } },
  ];

  const pcaps = [
    {
      id: 1,
      upload_id: "up-1",
      label: "during",
      filename: base.pcap_filename,
      ordinal: 0,
      size_bytes: base.pcap_size_bytes,
      sha256: "5d23c4e11e4f60f5a449d8a7cc2a7e64d19cdd90c8fa0313ef338f67c729cc32",
    },
    {
      id: 2,
      upload_id: "up-2",
      label: "after",
      filename: "2026-02-11-emotet-epoch5-cobaltstrike-after-containment.pcap",
      ordinal: 1,
      size_bytes: 112300000,
      sha256: "e8b9f4f1f4f3d0b5f13a2f6fd2c83e43f4dd49f5b842b49d0b319970f4b1fb22",
    },
  ];

  const detail = {
    ...base,
    metrics,
    stages,
    sensors,
    pcaps,
    log_sources: [
      {
        id: 1,
        upload_id: "bundle-1",
        label: "during",
        filename: "sysmon-2026-02-11.json",
        source_system: "sysmon",
        parser_hint: "sysmon_json",
        ordinal: 0,
        size_bytes: 2432211,
        sha256: "a8871b85de0d7f119b4eb949808fa9a9c8dfd2a29a522fded16e11f6ad38f20c",
        parse_status: "ok",
        parse_parser: "sysmon_json",
        parse_events: 1823,
      },
      {
        id: 2,
        upload_id: "bundle-2",
        label: "during",
        filename: "operator-console.log",
        source_system: "c2_operator",
        parser_hint: "generic_log",
        ordinal: 1,
        size_bytes: 412002,
        sha256: "d65f16a918c6f6dc61a5f6033ff13657ea5c9552acfaf2c91b2f1b3b1e8f4b8d",
        parse_status: "ok",
        parse_parser: "generic_log",
        parse_events: 219,
      },
    ],
    temporal_correlations: [
      {
        id: 1,
        log_event_id: "op-928",
        log_source: "c2_operator",
        log_source_filename: "operator-console.log",
        log_event_type: "tasked_beacon",
        log_timestamp: "2026-02-11T09:22:13.000Z",
        log_summary: "Operator confirms active beacon",
        pcap_entity_type: "alert",
        pcap_entity_id: "9813120",
        pcap_summary: "Cobalt Strike Beacon Observed",
        pcap_timestamp: "2026-02-11T09:22:10.006Z",
        shared_ip: "91.219.236.18",
        time_delta_seconds: 2.994,
        match_score: 0.97,
        match_type: "community_id",
      },
    ],
  };

  if (jobId === FAILED_JOB_ID) {
    detail.stages = [
      { stage: "ingest", status: "failed", started_at: base.created_at, completed_at: base.completed_at, error: "No PCAP files available for ingest", error_code: "INGEST_EMPTY" },
      { stage: "parse", status: "pending", started_at: null, completed_at: null },
      { stage: "aggregate", status: "pending", started_at: null, completed_at: null },
      { stage: "llm_analysis", status: "pending", started_at: null, completed_at: null },
      { stage: "report", status: "pending", started_at: null, completed_at: null },
    ];
    detail.sensors = [];
    detail.pcaps = [];
    detail.log_sources = [];
    detail.temporal_correlations = [];
  }

  return detail;
}

function buildJobSummary(jobId) {
  if (jobId === RUNNING_JOB_ID) {
    return {
      schema_version: SCHEMA,
      job_id: RUNNING_JOB_ID,
      headline: "Analysis in progress. Heuristics flagged potential C2 activity before LLM completion.",
      top_signals: ["Periodic outbound callback", "Rare JA3 + short-lived certificate", "Elevated alert density on one host"],
      recommendations: ["Continue monitoring for lateral movement", "Stage containment plan for suspected host"],
      alert_count: 61,
      finding_count: 4,
      ioc_count: 1,
      host_count: 6,
    };
  }

  if (jobId === FAILED_JOB_ID) {
    return {
      schema_version: SCHEMA,
      job_id: FAILED_JOB_ID,
      headline: "Ingest failed before packet parsing. No evidence available for analysis.",
      top_signals: [],
      recommendations: ["Verify data source query and time window", "Retry with known-good capture path"],
      alert_count: 0,
      finding_count: 0,
      ioc_count: 0,
      host_count: 0,
    };
  }

  return {
    schema_version: SCHEMA,
    job_id: COMPLETED_JOB_ID,
    headline: "Malicious activity consistent with Emotet loader behavior and Cobalt Strike follow-on.",
    top_signals: [
      "Fixed 60-second outbound beacon over TLS for 6h58m.",
      "Executable write to ADMIN$ on domain controller.",
      "1.74 GB outbound transfer over established C2 channel.",
      "High NXDOMAIN-rate DGA-like DNS fan-out.",
    ],
    recommendations: [
      "Isolate 10.11.27.101 and capture volatile memory.",
      "Block 91.219.236.18, 185.220.101.47, and 45.83.192.211.",
      "Audit service creation and ADMIN$ writes on 10.11.27.8.",
      "Rotate potentially exposed service account credentials.",
    ],
    alert_count: completedAlerts.length,
    finding_count: completedFindings.length,
    ioc_count: completedIocs.length,
    host_count: completedHosts.length,
  };
}

function aggregateEvents(field) {
  const buckets = new Map();
  for (const ev of completedRawEvents) {
    const key = ev[field] ?? null;
    const k = key == null ? "null" : String(key);
    buckets.set(k, (buckets.get(k) || 0) + 1);
  }
  return Array.from(buckets.entries()).map(([value, count]) => ({ value: value === "null" ? null : value, count })).sort((a, b) => b.count - a.count);
}

function eventFlow() {
  const nodeMap = new Map();
  const nodes = [];
  const links = [];

  function getNode(label, kind) {
    const key = `${kind}:${label}`;
    if (nodeMap.has(key)) return nodeMap.get(key);
    const id = nodes.length;
    nodes.push({ id: key, label, kind });
    nodeMap.set(key, id);
    return id;
  }

  const weight = new Map();
  for (const e of completedRawEvents) {
    if (!e.src_ip || !e.dest_ip) continue;
    const s = getNode(e.src_ip, "src");
    const d = getNode(e.dest_ip, "host");
    const k = `${s}->${d}`;
    weight.set(k, (weight.get(k) || 0) + 1);
  }

  for (const [k, v] of weight.entries()) {
    const [source, target] = k.split("->").map(Number);
    links.push({ source, target, value: v });
  }

  return {
    schema_version: SCHEMA,
    nodes,
    links,
    flows_considered: completedRawEvents.length,
  };
}

function nextChatReply(prompt) {
  const p = (prompt || "").toLowerCase();
  if (p.includes("contain") || p.includes("first")) {
    return {
      response: "In order: isolate 10.11.27.101 at the switch, block known C2 IPs, inspect ADMIN$ writes on 10.11.27.8, and rotate exposed service account credentials.",
      citations: [
        { type: "finding", id: "F-BEACON-001", snippet: "Sustained C2 beacon on 10.11.27.101" },
        { type: "alert", id: "9815551", snippet: "ADMIN$ executable write to domain controller" },
      ],
      suggested_followups: ["What evidence suggests successful lateral movement?", "What data likely left during exfiltration window?"],
    };
  }
  if (p.includes("confiden") || p.includes("emotet")) {
    return {
      response: "Confidence is high for malicious behavior class and moderate for exact malware family. Transport shape and signatures are Emotet-consistent, but family naming remains less reliable than behavior evidence.",
      citations: [
        { type: "alert", id: "9812804", snippet: "Win32/Emotet CnC Activity (POST)" },
        { type: "finding", id: "F-BEACON-001", snippet: "Fixed-interval beacon profile" },
      ],
      suggested_followups: ["Show all evidence supporting beacon classification.", "List MITRE techniques with strongest confidence."],
    };
  }
  return {
    response: "Patient-zero behavior is concentrated on 10.11.27.101: payload retrieval, Emotet-style registration, fixed-interval beaconing, lateral SMB write attempts, and high-volume outbound transfer.",
    citations: [
      { type: "alert", id: "9812771", snippet: "PE download HTTP alert" },
      { type: "alert", id: "9813120", snippet: "Cobalt Strike Beacon Observed" },
      { type: "alert", id: "9816033", snippet: "Large outbound transfer" },
    ],
    suggested_followups: ["Which host should be isolated first?", "What prevents family over-attribution here?"],
  };
}

function mkJson(body) {
  return Promise.resolve(clone(body));
}

export async function handleDemoApiRequest(url, init, apiBase) {
  const parsed = parsePath(url, apiBase);
  if (!parsed) return null;

  const method = (init.method || "GET").toUpperCase();
  const { path, searchParams } = parsed;

  // Upload-like calls return synthetic IDs immediately.
  if (method === "POST" && path === "/uploads") {
    return mkJson({ schema_version: SCHEMA, upload_id: `up-${Date.now()}`, filename: "demo-upload.pcap", size_bytes: 1024, sha256: "demo" });
  }
  if (method === "POST" && path === "/uploads/bundle") {
    return mkJson({ schema_version: SCHEMA, upload_id: `bundle-${Date.now()}`, filename: "demo-bundle.zip", size_bytes: 2048, sha256: "demo" });
  }
  const uploadValidateMatch = path.match(/^\/uploads\/([^/]+)\/validate$/);
  if (method === "POST" && uploadValidateMatch) {
    return mkJson({
      schema_version: SCHEMA,
      is_valid: true,
      format: "pcapng",
      linktype: "EN10MB",
      packet_count: 48213,
      capture_duration_seconds: 21600,
      estimated_runtime: { triage: 40, standard: 110, deep: 250 },
      warnings: [],
    });
  }

  if (method === "GET" && path === "/settings/setup_status") {
    return mkJson({ model_configured: true, llm_model_name: "aipam-cybersec-v7" });
  }

  if (method === "GET" && path === "/jobs") {
    const status = searchParams.get("status");
    const profile = searchParams.get("profile");
    const q = (searchParams.get("q") || "").toLowerCase();
    const sort = searchParams.get("sort") || "created_at";
    const order = (searchParams.get("order") || "desc").toLowerCase() === "asc" ? "asc" : "desc";

    let items = [...demoJobs];
    if (status) items = items.filter((j) => j.status === status);
    if (profile) items = items.filter((j) => j.execution_profile === profile);
    if (q) items = items.filter((j) => JSON.stringify(j).toLowerCase().includes(q));

    items.sort((a, b) => {
      const av = a[sort] ?? "";
      const bv = b[sort] ?? "";
      return order === "asc" ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });

    return mkJson({ schema_version: SCHEMA, items, page: { has_more: false, next_cursor: null } });
  }

  if (method === "POST" && path === "/jobs") {
    return mkJson({ schema_version: SCHEMA, job_id: RUNNING_JOB_ID });
  }

  if (method === "POST" && path === "/jobs/from_security_onion") {
    return mkJson({ job_id: RUNNING_JOB_ID });
  }

  if (method === "POST" && path === "/jobs/from_arkime") {
    return mkJson({ job_id: FAILED_JOB_ID });
  }

  if (method === "POST" && path === "/jobs/batch") {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    return mkJson({ schema_version: SCHEMA, accepted: body.job_ids || [], rejected: [] });
  }

  const jobGetMatch = path.match(/^\/jobs\/([^/]+)$/);
  if (method === "GET" && jobGetMatch) {
    const detail = getJobDetailPayload(jobGetMatch[1]);
    if (!detail) throw new Error("Not found");
    return mkJson({ schema_version: SCHEMA, job: detail });
  }

  if (method === "DELETE" && jobGetMatch) {
    return mkJson(undefined);
  }

  const jobSummaryMatch = path.match(/^\/jobs\/([^/]+)\/summary$/);
  if (method === "GET" && jobSummaryMatch) {
    return mkJson(buildJobSummary(jobSummaryMatch[1]));
  }

  const jobSensorsMatch = path.match(/^\/jobs\/([^/]+)\/sensors$/);
  if (method === "GET" && jobSensorsMatch) {
    const detail = getJobDetailPayload(jobSensorsMatch[1]);
    return mkJson({ schema_version: SCHEMA, items: detail?.sensors || [] });
  }

  const partialMatch = path.match(/^\/jobs\/([^/]+)\/partial-results$/);
  if (method === "GET" && partialMatch) {
    return mkJson({ schema_version: SCHEMA, job_id: partialMatch[1], completed_stages: ["ingest", "parse", "aggregate"], current_stage: "llm_analysis", partial_data: partialRunning });
  }

  const listHostsMatch = path.match(/^\/jobs\/([^/]+)\/hosts$/);
  if (method === "GET" && listHostsMatch) {
    const jobId = listHostsMatch[1];
    const role = searchParams.get("role");
    let items = [...(hostsForJob[jobId] || [])];
    if (role) items = items.filter((h) => h.role === role);
    return mkJson({ schema_version: SCHEMA, items, page: { has_more: false, next_cursor: null } });
  }

  const listAlertsMatch = path.match(/^\/jobs\/([^/]+)\/alerts$/);
  if (method === "GET" && listAlertsMatch) {
    const jobId = listAlertsMatch[1];
    const items = filterList(alertsForJob[jobId] || [], searchParams);
    return mkJson({ schema_version: SCHEMA, items, page: { has_more: false, next_cursor: null } });
  }

  const listFindingsMatch = path.match(/^\/jobs\/([^/]+)\/findings$/);
  if (method === "GET" && listFindingsMatch) {
    const jobId = listFindingsMatch[1];
    const items = filterList(findingsForJob[jobId] || [], searchParams);
    return mkJson({ schema_version: SCHEMA, items, page: { has_more: false, next_cursor: null } });
  }

  const findingExplainMatch = path.match(/^\/jobs\/([^/]+)\/findings\/([^/]+)\/explain$/);
  if (method === "POST" && findingExplainMatch) {
    const findingId = findingExplainMatch[2];
    const finding = (findingsForJob[findingExplainMatch[1]] || []).find((f) => f.finding_id === findingId);
    return mkJson({
      schema_version: SCHEMA,
      format: "markdown",
      content: `### Why this matters\n\n${finding?.summary || "Potential malicious behavior detected."}\n\n### Recommended next steps\n\n- Validate host timeline\n- Correlate with alerts and DNS\n- Contain if confidence remains high`,
      duration_ms: 120,
      source: "deterministic",
      sections: [
        { id: "assessment", title: "Assessment", body: finding?.summary || "", bullets: [], citations: [] },
        { id: "recommended_next_steps", title: "Recommended Next Steps", body: null, bullets: ["Validate host timeline", "Correlate evidence", "Contain if needed"], citations: [] },
      ],
      evidence_items: [],
      explanation_feedback: null,
    });
  }

  const iocListMatch = path.match(/^\/jobs\/([^/]+)\/iocs$/);
  if (method === "GET" && iocListMatch) {
    const jobId = iocListMatch[1];
    const items = filterList(iocsForJob[jobId] || [], searchParams);
    return mkJson({ schema_version: SCHEMA, items, page: { has_more: false, next_cursor: null } });
  }

  const theoriesMatch = path.match(/^\/jobs\/([^/]+)\/theories$/);
  if (method === "GET" && theoriesMatch) {
    return mkJson({ schema_version: SCHEMA, items: theoriesMatch[1] === COMPLETED_JOB_ID ? completedTheories : [], job_id: theoriesMatch[1], scope_type: "job", scope_id: null });
  }

  const slicesMatch = path.match(/^\/jobs\/([^/]+)\/slices$/);
  if (method === "GET" && slicesMatch) {
    return mkJson({ schema_version: SCHEMA, items: slicesMatch[1] === COMPLETED_JOB_ID ? completedSlices : [], job_id: slicesMatch[1] });
  }

  const annotationsMatch = path.match(/^\/jobs\/([^/]+)\/annotations$/);
  if (method === "GET" && annotationsMatch) {
    return mkJson({ schema_version: SCHEMA, items: annotationsMatch[1] === COMPLETED_JOB_ID ? completedAnnotations : [], job_id: annotationsMatch[1] });
  }

  const timelineMatch = path.match(/^\/jobs\/([^/]+)\/timeline$/);
  if (method === "GET" && timelineMatch) {
    return mkJson({ schema_version: SCHEMA, items: timelineMatch[1] === COMPLETED_JOB_ID ? completedTimeline : [], page: { has_more: false, next_cursor: null } });
  }

  const rawEventsMatch = path.match(/^\/jobs\/([^/]+)\/raw-events$/);
  if (method === "GET" && rawEventsMatch) {
    const filtered = filterList(completedRawEvents, searchParams);
    const pg = toPage(filtered, Number(searchParams.get("limit") || 100), Number(searchParams.get("offset") || 0));
    return mkJson({ schema_version: SCHEMA, items: pg.items, total: pg.total, limit: pg.limit, offset: pg.offset });
  }

  const rawAggMatch = path.match(/^\/jobs\/([^/]+)\/raw-events\/aggregate$/);
  if (method === "GET" && rawAggMatch) {
    const field = searchParams.get("field") || "event_type";
    return mkJson({ schema_version: SCHEMA, field, buckets: aggregateEvents(field), total_events: completedRawEvents.length });
  }

  const rawFlowMatch = path.match(/^\/jobs\/([^/]+)\/raw-events\/flow$/);
  if (method === "GET" && rawFlowMatch) {
    return mkJson(eventFlow());
  }

  const reportsMatch = path.match(/^\/jobs\/([^/]+)\/reports$/);
  if (method === "GET" && reportsMatch) {
    return mkJson({ schema_version: SCHEMA, items: reportsMatch[1] === COMPLETED_JOB_ID ? reportItems : [], job_id: reportsMatch[1] });
  }

  const reportGetMatch = path.match(/^\/jobs\/([^/]+)\/reports\/([^/]+)$/);
  if (method === "GET" && reportGetMatch) {
    const report = reportItems.find((r) => r.report_id === reportGetMatch[2]);
    return mkJson({ schema_version: SCHEMA, item: report || reportItems[0], job_id: reportGetMatch[1] });
  }

  const reportGenerateMatch = path.match(/^\/jobs\/([^/]+)\/reports\/generate$/);
  if (method === "POST" && reportGenerateMatch) {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    const item = {
      ...reportItems[0],
      report_id: `RPT-${String(reportCounter).padStart(3, "0")}`,
      mode: body.mode || "analyst",
      title: `${body.mode === "executive" ? "Executive" : "Analyst"} Report - Demo`,
      created_at: nowIso(),
    };
    reportCounter += 1;
    reportItems = [item, ...reportItems];
    return mkJson({ schema_version: SCHEMA, item, job_id: reportGenerateMatch[1] });
  }

  const temporalDeltaMatch = path.match(/^\/jobs\/([^/]+)\/temporal-delta$/);
  if (method === "GET" && temporalDeltaMatch) {
    return mkJson({
      schema_version: SCHEMA,
      phase_labels: ["during", "after"],
      summary: {
        hosts: { before: 5, after: 4, new: 0, removed: 1 },
        alerts: { before: 5, after: 2, new_signatures: 0, removed_signatures: 3 },
        findings: { before: 3, after: 1, new: 0, removed: 2 },
        iocs: { before: 4, after: 2, new: 0, removed: 2 },
        dns_domains: { before: 12, after: 3, new: 0, removed: 9 },
        traffic: {
          before: { connections: 48213, bytes_sent: 1740000000, bytes_recv: 42000000 },
          after: { connections: 19521, bytes_sent: 9800000, bytes_recv: 25000000 },
        },
        theories: { before: 1, after: 1, new: 0, removed: 0 },
        tls_sessions: { before: 412, after: 44, new: 0, removed: 368 },
        severity_before: { critical: 1, high: 3, medium: 2, low: 0, info: 0 },
        severity_after: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
      },
      phase_summary: {
        before: { host_count: 5, alert_count: 5, finding_count: 3, connection_count: 48213, ioc_count: 4 },
        after: { host_count: 4, alert_count: 2, finding_count: 1, connection_count: 19521, ioc_count: 2 },
      },
      severity_shift: {
        critical: { before: 1, after: 0, delta: -1 },
        high: { before: 3, after: 1, delta: -2 },
        medium: { before: 2, after: 1, delta: -1 },
        low: { before: 0, after: 0, delta: 0 },
      },
      containment_indicators: {
        removed_c2_connections: 368,
        reduced_alert_categories: ["A Network Trojan was detected", "Potential Corporate Privacy Violation"],
        new_defensive_activity: ["Outbound block policy to known C2 netblocks"],
      },
      hosts: {
        added: [],
        removed: [{ ip: "91.219.236.18", role: "external", conn_count: 412, alert_count: 2 }],
        changed: [{ ip: "10.11.27.101", role: "internal", conn_before: 8412, conn_after: 1900, alert_before: 44, alert_after: 3 }],
      },
      alerts: [
        { signature: "ET MALWARE Cobalt Strike Beacon Observed", severity: "high", status: "removed", before_count: 1, after_count: 0 },
        { signature: "ET POLICY Large Outbound Data Transfer to Non-Corporate Netblock", severity: "medium", status: "removed", before_count: 1, after_count: 0 },
      ],
      findings: [
        { title: "Fixed 60-second callback to 91.219.236.18:443", severity: "critical", sensor: "beacon_detector", status: "removed" },
      ],
      iocs: { added: [], removed: ["91.219.236.18", "185.220.101.47"] },
      dns: { added: [], removed: ["telemetry-sync.org", "cdn-update-svc.net"] },
    });
  }

  const temporalFlowsMatch = path.match(/^\/jobs\/([^/]+)\/temporal-flows$/);
  if (method === "GET" && temporalFlowsMatch) {
    return mkJson({
      schema_version: SCHEMA,
      total_new_flows: 2,
      flows: [
        { src_ip: "10.11.27.101", dest_ip: "10.11.27.5", dest_port: 443, proto: "tcp", service: "https", count: 12, total_bytes_sent: 1700000, total_bytes_recv: 2000000 },
        { src_ip: "10.11.27.8", dest_ip: "10.11.27.2", dest_port: 53, proto: "udp", service: "dns", count: 44, total_bytes_sent: 12000, total_bytes_recv: 22000 },
      ],
    });
  }

  const temporalNarrativeMatch = path.match(/^\/jobs\/([^/]+)\/temporal-narrative$/);
  if (method === "POST" && temporalNarrativeMatch) {
    return mkJson({
      schema_version: SCHEMA,
      narrative_markdown: "### Temporal Summary\n\nPost-containment traffic shows a substantial reduction in beaconing and no renewed high-confidence C2 signature matches. Residual suspicious behavior remains low and should be monitored.",
    });
  }

  const relatedJobsMatch = path.match(/^\/jobs\/([^/]+)\/related-jobs$/);
  if (method === "GET" && relatedJobsMatch) {
    return mkJson({
      job_id: relatedJobsMatch[1],
      related_jobs: [
        {
          job_id: "29b8a5d7-84f9-4338-8fb2-50c6a2c2f9d8",
          job_name: "Qakbot + Cobalt Strike Investigation",
          job_created_at: "2026-01-22T18:20:14Z",
          overlap_type: "shared_behavior",
          shared_entities: ["fixed-interval beacon", "TLS self-signed short cert"],
          relevance_score: 0.83,
        },
      ],
    });
  }

  const arkimeStatusMatch = path.match(/^\/jobs\/([^/]+)\/arkime\/status$/);
  if (method === "GET" && arkimeStatusMatch) {
    const jobId = arkimeStatusMatch[1];
    return mkJson({ schema_version: SCHEMA, job_id: jobId, enabled: true, import_status: jobId === COMPLETED_JOB_ID ? "imported" : "not_imported", imported_at: jobId === COMPLETED_JOB_ID ? "2026-02-11T14:10:10.000Z" : null, pcap_count: jobId === COMPLETED_JOB_ID ? 2 : 1, message: null });
  }

  const arkimeImportMatch = path.match(/^\/jobs\/([^/]+)\/arkime\/import$/);
  if (method === "POST" && arkimeImportMatch) {
    return mkJson({ schema_version: SCHEMA, job_id: arkimeImportMatch[1], enabled: true, import_status: "queued", message: "Import queued" });
  }

  const soImportMatch = path.match(/^\/jobs\/([^/]+)\/security_onion\/import$/);
  if (method === "POST" && soImportMatch) {
    return mkJson({ schema_version: SCHEMA, job_id: soImportMatch[1], enabled: true, status: "accepted", message: "PCAP accepted by Security Onion", node_id: "so-node-01" });
  }

  if (method === "POST" && path === "/settings/test_llm") {
    return mkJson({ ok: true, message: "Connection successful", latency_ms: 51 });
  }

  if (method === "GET" && path === "/models/available") {
    return mkJson({ models: availableModels });
  }

  if (method === "GET" && path === "/settings") {
    return mkJson(settings);
  }

  if (method === "PUT" && path === "/settings") {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    settings = { ...settings, ...body };
    return mkJson(settings);
  }

  if (method === "GET" && path === "/admin/effective_settings") {
    return mkJson({ ...settings, source: "demo-static" });
  }

  if (method === "GET" && path === "/system/explain-telemetry") {
    return mkJson({ schema_version: SCHEMA, explain_response_counts: { deterministic: 31, llm: 12, fallback: 2 }, explain_latency_ms: { count: 45, average_ms: 182, min_ms: 30, max_ms: 902, last_ms: 120 } });
  }

  if (method === "POST" && path === "/system/explain-telemetry/reset") {
    return mkJson({ schema_version: SCHEMA, explain_response_counts: {}, explain_latency_ms: { count: 0, average_ms: 0, min_ms: 0, max_ms: 0, last_ms: 0 } });
  }

  if (method === "GET" && path === "/system/config") {
    return mkJson({
      schema_version: SCHEMA,
      aipam_version: "v9.0-demo",
      max_upload_bytes: 2147483648,
      profiles_enabled: ["triage", "standard", "deep"],
      default_limits: { sensor_timeout_seconds: 600, max_extracted_bytes: 536870912, max_job_disk_bytes: 10737418240 },
      explain_configuration: { mode: "deterministic", llm_enabled: true, llm_model_name: "aipam-cybersec-v7", llm_endpoint: "http://host.docker.internal:11434" },
    });
  }

  if (method === "GET" && path === "/system/ollama-status") {
    return mkJson({
      schema_version: SCHEMA,
      ollama_version: "0.6.2",
      gpu_detected: true,
      gpu_name: "NVIDIA RTX 4090",
      vram_total_bytes: 25769803776,
      vram_used_bytes: 9730785280,
      compute_device: "cuda",
      loaded_models: [
        { name: "aipam-cybersec-v7", size: 4920000000, size_vram: 4030000000, parameter_size: "8B", quantization: "Q4_K_M", family: "llama", context_length: 8192, gpu_offload_pct: 100 },
      ],
    });
  }

  if (method === "GET" && path === "/integrations/settings") {
    return mkJson(integrationSettings);
  }

  if (method === "PUT" && path === "/integrations/settings") {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    integrationSettings = { ...integrationSettings, ...body };
    return mkJson(integrationSettings);
  }

  if (method === "POST" && path === "/integrations/test") {
    return mkJson({ ok: true, message: "Connection successful", latency_ms: 82 });
  }

  if (method === "POST" && path === "/training/start") {
    trainingStatus = {
      ...trainingStatus,
      status: "running",
      current_iter: Math.max(trainingStatus.current_iter, 120),
      job_id: trainingStatus.job_id || "training-demo-1",
    };
    return mkJson({ ok: true, status: "running", job_id: trainingStatus.job_id });
  }

  if (method === "POST" && path === "/training/pause") {
    trainingStatus = { ...trainingStatus, status: trainingStatus.status === "paused" ? "running" : "paused" };
    return mkJson({ ok: true, status: trainingStatus.status });
  }

  if (method === "POST" && path === "/training/stop") {
    trainingStatus = { ...trainingStatus, status: "stopped" };
    return mkJson({ ok: true, status: "stopped" });
  }

  if (method === "GET" && path === "/training/summary") return mkJson(trainingSummary);
  if (method === "GET" && path === "/training/ledger") return mkJson(trainingLedger);
  if (method === "GET" && path === "/training/config") return mkJson(trainingConfig);
  if (method === "GET" && path === "/training/status") return mkJson(trainingStatus);
  if (method === "GET" && path === "/training/distill/config") return mkJson(distillConfig);
  if (method === "POST" && path === "/training/distill/config") {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    Object.assign(distillConfig, body);
    return mkJson({ ok: true });
  }
  if (method === "GET" && path === "/training/distill/stats") return mkJson(distillStats);
  if (method === "POST" && path === "/training/distill/test") return mkJson({ ok: true, message: "Teacher reachable", model: distillConfig.model, latency_ms: 632 });
  if (method === "POST" && path === "/training/export") return mkJson({ ok: true, status: "queued", job_id: "export-demo-1" });
  if (method === "GET" && path === "/training/export/status") return mkJson({ job_id: "export-demo-1", status: "idle", message: "No export currently running", model_name: "aipam-cybersec-v7", version: 7, gguf_path: "/models/aipam-cybersec-v7.gguf", elapsed_seconds: null });

  const convListMatch = path.match(/^\/jobs\/([^/]+)\/conversations$/);
  if (method === "GET" && convListMatch) {
    const jobId = convListMatch[1];
    return mkJson(conversations.filter((c) => c.job_id === jobId));
  }

  const convGetMatch = path.match(/^\/jobs\/([^/]+)\/conversations\/([^/]+)$/);
  if (method === "GET" && convGetMatch) {
    const convId = convGetMatch[2];
    return mkJson(conversationHistory[convId] || { id: convId, job_id: convGetMatch[1], messages: [], created_at: nowIso(), updated_at: nowIso() });
  }

  if (method === "PATCH" && convGetMatch) {
    const convId = convGetMatch[2];
    const body = init.body ? JSON.parse(String(init.body)) : {};
    conversations = conversations.map((c) => (c.id === convId ? { ...c, title: body.title || c.title, updated_at: nowIso() } : c));
    return mkJson(conversations.find((c) => c.id === convId));
  }

  if (method === "DELETE" && convGetMatch) {
    const convId = convGetMatch[2];
    conversations = conversations.filter((c) => c.id !== convId);
    delete conversationHistory[convId];
    return mkJson(undefined);
  }

  const chatMatch = path.match(/^\/jobs\/([^/]+)\/chat$/);
  if (method === "POST" && chatMatch) {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    const convId = body.conversation_id || `conv-demo-${Date.now()}`;
    const answer = nextChatReply(body.message);

    if (!conversationHistory[convId]) {
      conversationHistory[convId] = {
        id: convId,
        job_id: chatMatch[1],
        created_at: nowIso(),
        updated_at: nowIso(),
        messages: [],
      };
      conversations = [{ id: convId, job_id: chatMatch[1], created_at: nowIso(), updated_at: nowIso(), title: "New Conversation", message_count: 0 }, ...conversations];
    }

    conversationHistory[convId].messages.push(
      { role: "user", content: body.message, timestamp: nowIso() },
      { role: "assistant", content: answer.response, citations: answer.citations, timestamp: nowIso() },
    );
    conversationHistory[convId].updated_at = nowIso();
    conversations = conversations.map((c) => (c.id === convId ? { ...c, updated_at: nowIso(), message_count: (c.message_count || 0) + 2 } : c));

    return mkJson({
      response: answer.response,
      citations: answer.citations,
      conversation_id: convId,
      confidence: 0.88,
      evidence_refs: answer.citations.map((c) => ({ type: c.type, id: c.id, label: c.snippet })),
      suggested_followups: answer.suggested_followups,
    });
  }

  const kbListMatch = path.match(/^\/jobs\/([^/]+)\/kb\/documents$/);
  if (method === "GET" && kbListMatch) {
    const jobId = kbListMatch[1];
    return mkJson({ items: kbJobDocs.filter((d) => d.job_id === jobId), total: kbJobDocs.filter((d) => d.job_id === jobId).length });
  }

  if (method === "POST" && kbListMatch) {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    const id = `kb-${Date.now()}`;
    const item = { id, job_id: kbListMatch[1], name: body.name, doc_type: body.doc_type, description: body.description || "", chunk_count: 4, status: "ready", created_at: nowIso(), updated_at: nowIso() };
    kbJobDocs = [item, ...kbJobDocs];
    return mkJson(item);
  }

  const kbDocMatch = path.match(/^\/jobs\/([^/]+)\/kb\/documents\/([^/]+)$/);
  if (method === "DELETE" && kbDocMatch) {
    kbJobDocs = kbJobDocs.filter((d) => d.id !== kbDocMatch[2]);
    return mkJson(undefined);
  }

  if (method === "POST" && path.match(/^\/jobs\/([^/]+)\/kb\/documents\/([^/]+)\/reindex$/)) {
    return mkJson({ ok: true });
  }

  if (method === "GET" && path === "/kb/library/config") return mkJson({ admin_required: false });
  if (method === "GET" && path === "/kb/library/documents") return mkJson({ items: kbLibraryDocs, total: kbLibraryDocs.length });
  if (method === "POST" && path === "/kb/library/documents") {
    const body = init.body ? JSON.parse(String(init.body)) : {};
    const item = { id: `lib-${Date.now()}`, job_id: null, name: body.name, doc_type: body.doc_type, description: body.description || "", chunk_count: 5, status: "ready", created_at: nowIso(), updated_at: nowIso() };
    kbLibraryDocs = [item, ...kbLibraryDocs];
    return mkJson(item);
  }
  if (method === "DELETE" && path.match(/^\/kb\/library\/documents\/([^/]+)$/)) {
    const id = path.split("/").pop();
    kbLibraryDocs = kbLibraryDocs.filter((d) => d.id !== id);
    return mkJson(undefined);
  }
  if (method === "POST" && path.match(/^\/kb\/library\/documents\/([^/]+)\/reindex$/)) return mkJson({ ok: true });

  if (method === "POST" && path.match(/^\/jobs\/([^/]+)\/artifacts\/evidence-package$/)) {
    return mkJson({ schema_version: SCHEMA, artifact_id: `artifact-${Date.now()}`, status: "generating" });
  }

  const artifactsMatch = path.match(/^\/jobs\/([^/]+)\/artifacts$/);
  if (method === "GET" && artifactsMatch) {
    return mkJson({
      schema_version: SCHEMA,
      items: [
        { artifact_id: "artifact-report-md", type: "report_markdown", status: "available", created_at: "2026-02-11T14:09:47.902Z", filename: "job-report.md", size_bytes: 38124, sha256: "abc123" },
        { artifact_id: "artifact-report-html", type: "report_html", status: "available", created_at: "2026-02-11T14:09:47.902Z", filename: "job-report.html", size_bytes: 91244, sha256: "def456" },
      ],
    });
  }

  if (method === "GET" && path === "/rules/suricata") {
    return mkJson([
      { filename: "custom-beacon.rules", size_bytes: 1820, updated_at: "2026-02-11T10:00:00Z" },
      { filename: "aipam-demo.rules", size_bytes: 940, updated_at: "2026-02-11T10:00:00Z" },
    ]);
  }

  if (method === "GET" && path.match(/^\/rules\/suricata\/[^/]+$/)) {
    return mkJson({ filename: path.split("/").pop(), size_bytes: 1820, updated_at: "2026-02-11T10:00:00Z", content: "alert tls any any -> any 443 (msg:\"Demo rule\"; sid:9000101; rev:1;)" });
  }

  if (method === "GET" && path.match(/^\/rules\/suricata\/[^/]+\/stats$/)) {
    return mkJson({ filename: path.split("/")[3], total_rules: 2, enabled: 2, disabled: 0, categories: [{ name: "trojan-activity", total: 1, enabled: 1, disabled: 0 }, { name: "policy", total: 1, enabled: 1, disabled: 0 }] });
  }

  if (method === "GET" && path.match(/^\/rules\/suricata\/[^/]+\/parsed$/)) {
    return mkJson({
      items: [
        { sid: 9000101, enabled: true, action: "alert", msg: "Demo short-lived self-signed cert callback", classtype: "trojan-activity", severity: 1, protocol: "tls", src: "$HOME_NET", dst: "$EXTERNAL_NET", rev: 1, references: [], raw: "alert tls ...", line_number: 1 },
      ],
      total: 1,
      total_enabled: 1,
      total_disabled: 0,
      offset: 0,
      limit: 50,
    });
  }

  if (method === "POST" && path.match(/^\/rules\/suricata\/[^/]+\/toggle$/)) return mkJson({ changed: 1, total_targeted: 1, enabled: true });
  if (method === "PUT" && path.match(/^\/rules\/suricata\/[^/]+$/)) return mkJson({ filename: path.split("/").pop(), size_bytes: 1800, updated_at: nowIso(), content: "updated" });

  // Default null means let the real network request happen (not expected in demo mode).
  return null;
}
