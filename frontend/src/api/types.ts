// ─── V2 Enums ───────────────────────────────────────────────────────────────

export type ExecutionProfile = "triage" | "standard" | "deep";
export type Priority = "low" | "normal" | "high";
export type JobStatus =
  | "queued" | "running" | "completed" | "completed_with_errors"
  | "failed" | "canceled" | "deleting" | "deleted";
export type SensorStatus =
  | "pending" | "running" | "completed" | "failed"
  | "skipped" | "timeout" | "canceled";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type IocType =
  | "ip" | "domain" | "url" | "hash" | "ja3" | "ja3s"
  | "sni" | "email" | "mutex" | "registry";
export type HostRole = "internal" | "external" | "unknown";
export type SortOrder = "asc" | "desc";

// ─── V2 Shared ──────────────────────────────────────────────────────────────

export interface PageInfo {
  next_cursor: string | null;
  has_more: boolean;
}

export interface ErrorResponse {
  schema_version: string;
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

// ─── Uploads ────────────────────────────────────────────────────────────────

export interface UploadCreateResponse {
  schema_version: string;
  upload_id: string;
  filename: string;
  size_bytes: number;
  sha256: string;
}

export interface UploadValidateResponse {
  schema_version: string;
  is_valid: boolean;
  format?: string | null;
  linktype?: string | null;
  packet_count?: number | null;
  capture_duration_seconds?: number | null;
  estimated_runtime?: {
    triage?: number | null;
    standard?: number | null;
    deep?: number | null;
  };
  warnings?: string[];
}

// ─── Jobs ───────────────────────────────────────────────────────────────────

export interface PcapUploadItem {
  upload_id: string;
  label?: string;
}

export interface BundleUploadItem {
  upload_id: string;
  label?: string;  // phase label: "before", "during", "after", or custom
}

export interface JobLogSourceItem {
  id: number;
  upload_id?: string | null;
  label?: string | null;
  filename: string;
  source_system?: string | null;
  parser_hint?: string | null;
  ordinal: number;
  size_bytes?: number | null;
  sha256?: string | null;
  // Parse diagnostics
  parse_status?: string | null;   // "ok" | "skipped" | "error"
  parse_parser?: string | null;   // parser name
  parse_events?: number | null;   // events produced
  parse_error?: string | null;    // error/skip reason
}

export interface JobPcapItem {
  id: number;
  upload_id: string;
  label?: string | null;
  filename: string;
  ordinal: number;
  size_bytes?: number | null;
  sha256?: string | null;
}

// Mirrors backend SourceType. "binary" was missing here while the backend has
// shipped it since the binary pipeline landed — fixed alongside code_artifact.
export type SourceType =
  | "pcap" | "pcap+logs" | "log_bundle" | "netflow_bundle"
  | "c2_bundle" | "exercise_bundle" | "binary" | "code_artifact";

export interface BundleSourceEntry {
  filename: string;
  source_system?: string;   // e.g. "sysmon", "paloalto", "cobalt_strike"
  parser_hint?: string;     // suggested parser name
  label?: string;           // user-supplied tag
}

export interface JobCreateRequest {
  upload_id?: string;           // backward compat: single upload
  uploads?: PcapUploadItem[];   // multi-PCAP: list of uploads with optional labels
  job_name?: string;
  notes?: string;
  execution_profile: ExecutionProfile;
  priority?: Priority;
  // --- Telemetry fusion fields ---
  source_type?: SourceType;
  exercise_id?: string;
  bundle_entries?: BundleSourceEntry[];
  // --- Hybrid job: attach labeled log bundles alongside PCAPs ---
  bundle_uploads?: BundleUploadItem[];
  // --- BlueScrub code-artifact jobs ---
  // Optional. An unbound job still scans, but triage will not carry forward
  // until it is bound to a project.
  project_id?: string;
}

// ── BlueScrub DACV+R ──────────────────────────────────────────────────────

export type Pillar =
  | "Detectability" | "Attribution" | "Co-Optability"
  | "Vulnerability" | "RE-Feasibility";

export type PillarStatus = "assessed" | "degraded" | "not_assessed";

export interface PillarScore {
  status: PillarStatus;
  /** null when not_assessed. Never 0 — zero means "measured, nothing found". */
  score: number | null;
  coverage: number;
  findings: number;
  raw?: number;
  reason?: string;
  top_driver?: { finding_id: string; rule_id: string; contribution: number };
  unavailable_signals?: { signal: string; weight: number; reason: string }[];
  effort_band?: "Trivial" | "Hours" | "Days" | "Weeks";
}

export interface BlueScrubProject {
  project_id: string;
  display_name: string;
  created_at: string;
  archived: boolean;
}

export interface BlueScrubLineage {
  project_id: string | null;
  lineage_parent_job_id: string | null;
  derived_from_job_id: string | null;
  analysis_kind: "source_audit" | "re_assessment";
}

export interface BlueScrubBindResult {
  job_id: string;
  project_id: string;
  lineage_parent_job_id: string | null;
  carry_forward_enabled: boolean;
  note: string;
}

export interface DacvMetrics {
  schema: string;
  scoring_model: string;
  calibration: "provisional" | "calibrated";
  project_id: string | null;
  analysis_kind: "source_audit" | "re_assessment";
  profile: ExecutionProfile;
  compatibility_signature: string;
  pillars: Record<Pillar, PillarScore>;
  /** Artifact-level grade. null unless every pillar was assessed. */
  overall: { status: "complete" | "incomplete"; score: number | null; grade: string | null };
  /** Always present, and never an artifact-level grade — render it labelled. */
  scoped: {
    profile: ExecutionProfile; score: number; grade: string;
    pillars_assessed: number; pillars_total: 5; label: string;
  };
  disqualified: boolean;
  grade_override?: { finding_id: string; reason: string };
  files_scanned: number;
  unmapped_findings: number;
  partial: boolean;
  partial_reasons: {
    sensor: string; class: string; detail?: string; pillars_affected: Pillar[];
  }[];
}

export interface JobCreateResponse {
  schema_version: string;
  job_id: string;
}

export interface JobListItem {
  job_id: string;
  job_name?: string;
  notes?: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  status: JobStatus;
  execution_profile: ExecutionProfile;
  priority: Priority;
  pcap_filename?: string;
  pcap_size_bytes?: number;
  error_summary?: string | null;
}

export interface JobMetrics {
  pcap_stats?: {
    packet_count?: number | null;
    capture_duration_seconds?: number | null;
  };
  durations: Record<string, number>;
}

export interface StageItem {
  stage: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
  error_code?: string | null;
}

export interface SensorProvenance {
  sensor_name: string;
  sensor_version?: string | null;
  image_digest?: string | null;
  host_hostname?: string | null;
  aipam_version?: string | null;
  tool_versions?: Record<string, string>;
}

export interface SensorStats {
  runtime_seconds?: number | null;
  output_bytes?: number | null;
  findings_count?: number | null;
}

export interface SensorItem {
  sensor: string;
  status: SensorStatus;
  meta: SensorProvenance;
  stats?: SensorStats;
  started_at?: string | null;
  completed_at?: string | null;
  timeout_seconds?: number | null;
  error?: string | null;
  error_code?: string | null;
}

export interface TemporalCorrelationItem {
  id: number;
  log_event_id: string;
  log_source?: string | null;
  log_source_filename?: string | null;
  log_event_type?: string | null;
  log_timestamp: string;
  log_summary?: string | null;
  pcap_entity_type: string;     // "alert" | "connection"
  pcap_entity_id: string;
  pcap_summary?: string | null;
  pcap_timestamp: string;
  shared_ip: string;
  time_delta_seconds: number;
  match_score: number;
  match_type: string;
  // Enhanced correlation metadata (optional for backward compatibility)
  community_id?: string | null;
  match_keys?: string[];
  log_label?: string | null;
  pcap_label?: string | null;
  clock_offset_seconds?: number | null;
  adjusted_time_delta_seconds?: number | null;
  confidence_band?: string | null;
}

export interface TemporalCorrelationsResponse {
  schema_version: string;
  items: TemporalCorrelationItem[];
  page: { next_cursor?: string | null; has_more: boolean };
  total: number;
}

export interface JobDetail extends JobListItem {
  metrics?: JobMetrics;
  stages?: StageItem[];
  sensors?: SensorItem[];
  pcaps?: JobPcapItem[];
  log_sources?: JobLogSourceItem[];
  temporal_correlations?: TemporalCorrelationItem[];
}

export interface JobGetResponse {
  schema_version: string;
  job: JobDetail;
}

export interface JobListResponse {
  schema_version: string;
  items: JobListItem[];
  page: PageInfo;
}

export interface JobSummaryResponse {
  schema_version: string;
  job_id: string;
  headline: string;
  top_signals?: string[];
  top_hosts?: HostListItem[];
  top_iocs?: IocItem[];
  recommendations?: string[];
  alert_count?: number;
  finding_count?: number;
  ioc_count?: number;
  host_count?: number;
}

export interface SensorListResponse {
  schema_version: string;
  items: SensorItem[];
}

// ─── Hosts ──────────────────────────────────────────────────────────────────

export interface HostListItem {
  ip: string;
  role: HostRole;
  conn_count: number;
  bytes_sent?: number | null;
  bytes_recv?: number | null;
  alert_count: number;
  top_domains?: string[];
}

export interface HostDetail extends HostListItem {
  first_seen?: string | null;
  last_seen?: string | null;
  alerts_by_severity?: Record<string, number>;
  top_services?: string[];
  dns_summary?: { query_count?: number | null; top_qnames?: string[] };
  tls_summary?: { session_count?: number | null; top_sni?: string[]; top_ja3?: string[] };
  global_stats?: { job_count: number; total_alerts: number; total_findings: number };
  global_history?: Array<{
    job_id: string;
    ts: string;
    role: string;
    alert_count: number;
    finding_count: number;
  }>;
}

export interface HostListResponse {
  schema_version: string;
  items: HostListItem[];
  page: PageInfo;
}

export interface HostGetResponse {
  schema_version: string;
  host: HostDetail;
}

// ─── Global Hosts (Cross-Job) ───────────────────────────────────────────────

export interface GlobalHostListItem {
  ip: string;
  hostname?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  job_count: number;
  total_alerts: number;
  total_findings: number;
  seen_as_internal: boolean;
  roles: string[];
}

export interface GlobalHostDetail extends GlobalHostListItem {
  history: Array<{
    job_id: string;
    ts?: string | null;
    role?: string | null;
    alert_count: number;
    finding_count: number;
  }>;
}

export interface GlobalHostListResponse {
  schema_version: string;
  items: GlobalHostListItem[];
  page: PageInfo;
}

export interface GlobalHostGetResponse {
  schema_version: string;
  host: GlobalHostDetail;
}

export interface GlobalHostListParams extends PaginationParams {
  internal_only?: boolean;
}

// ─── Connections ────────────────────────────────────────────────────────────

export interface ConnectionItem {
  connection_id: string;
  community_id?: string | null;
  ts: string;
  src_ip: string;
  src_port?: number | null;
  dest_ip: string;
  dest_port?: number | null;
  proto: string;
  duration_seconds?: number | null;
  bytes_sent?: number | null;
  bytes_recv?: number | null;
  service?: string | null;
  alerts?: string[];
  iocs?: string[];
}

export interface ConnectionListResponse {
  schema_version: string;
  items: ConnectionItem[];
  page: PageInfo;
}

// ─── Binary / YARA analysis ─────────────────────────────────────────────────

export interface YaraMatchItem {
  rule: string;
  tags: string[];
  meta: Record<string, any>;
  strings: string[];
}

export interface BinaryAnalysisItem {
  file_id: string;
  filename?: string | null;
  size_bytes: number;
  sha256: string;
  md5?: string | null;
  sha1?: string | null;
  /** Shannon entropy 0–8; >7.2 suggests packing or encryption. */
  entropy?: number | null;
  format?: string | null;
  artifact_class?: string | null;
  yara_matches: YaraMatchItem[];
}

export interface BinaryAnalysisListResponse {
  schema_version: string;
  items: BinaryAnalysisItem[];
  total: number;
}

/** Shared shape of the analyze and inspect responses. */
export interface BinaryAnalysisResponse {
  schema_version: string;
  /** False when the yara module is not installed on the server. */
  yara_available: boolean;
  /** False when no rules could be compiled from the rules directory. */
  rules_compiled: boolean;
  /** Only present on the persisting endpoint. */
  findings_created?: number;
  analysis: BinaryAnalysisItem;
}

// ─── Sigma detections ───────────────────────────────────────────────────────

export interface SigmaDetectionItem {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  category?: string | null;
  tags: string[];
  event_id?: string | null;
  hostname?: string | null;
  timestamp?: string | null;
  evidence?: Record<string, any> | null;
}

export interface SigmaDetectionListResponse {
  schema_version: string;
  items: SigmaDetectionItem[];
  total: number;
}

export interface SigmaAnalyzeResponse {
  schema_version: string;
  rules_evaluated: number;
  events_scanned: number;
  detections_created: number;
  detections_total: number;
  items: SigmaDetectionItem[];
}

// ─── Raw event explorer ─────────────────────────────────────────────────────

/** A normalized event flattened for the explorer. */
export interface RawEventItem {
  event_id: string;
  event_type: string;
  timestamp: string;
  source_type: string;
  source_system?: string | null;
  hostname?: string | null;
  username?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  proto?: string | null;
  evidence_status?: string | null;
  tags: string[];
  data: Record<string, any>;
}

export interface RawEventListResponse {
  schema_version: string;
  items: RawEventItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface RawEventSearchParams {
  q?: string;
  event_type?: string;
  source_type?: string;
  src_ip?: string;
  dest_ip?: string;
  hostname?: string;
  limit?: number;
  offset?: number;
}

export interface AggregationBucket {
  value: string | null;
  count: number;
}

export interface EventAggregationResponse {
  schema_version: string;
  field: string;
  buckets: AggregationBucket[];
  total_events: number;
}

export interface FlowNode {
  id: string;
  label: string;
  /** "src" | "host" | "port" */
  kind: string;
}

export interface FlowLink {
  /** Index into `nodes`. */
  source: number;
  target: number;
  value: number;
}

export interface EventFlowResponse {
  schema_version: string;
  nodes: FlowNode[];
  links: FlowLink[];
  flows_considered: number;
}

// ─── Streams (raw stream forensics) ─────────────────────────────────────────

/** A PCAP within a job that streams can be extracted from. */
export interface StreamPcapItem {
  name: string;
  size_bytes: number;
  label?: string | null;
}

export interface StreamPcapListResponse {
  schema_version: string;
  items: StreamPcapItem[];
}

/** The 4-tuple + protocol that uniquely identifies a stream. */
export interface StreamSelector {
  src: string;
  sport: number;
  dst: string;
  dport: number;
  proto: "tcp" | "udp";
  /** Which PCAP to read; the server defaults to the first when omitted. */
  pcap?: string;
}

export interface StreamTranscriptResponse {
  schema_version: string;
  protocol: string;
  transcript: string;
  truncated: boolean;
  byte_count: number;
}

/** One packet's hexdump: a header line plus its hex/ascii rows. */
export interface StreamHexPacket {
  header: string;
  lines: string[];
}

export interface StreamHexdumpResponse {
  schema_version: string;
  protocol: string;
  packets: StreamHexPacket[];
  truncated: boolean;
}

// ─── DNS ────────────────────────────────────────────────────────────────────

export interface DnsQueryItem {
  dns_id: string;
  ts: string;
  src_ip: string;
  query: string;
  qtype?: string | null;
  answers?: string[];
  rcode?: string | null;
  ttl_seconds?: number | null;
  dest_ip?: string | null;
  community_id?: string | null;
  iocs?: string[];
  related_community_ids?: string[];
}

export interface DnsQueryListResponse {
  schema_version: string;
  items: DnsQueryItem[];
  page: PageInfo;
}

// ─── TLS ────────────────────────────────────────────────────────────────────

export interface TlsSessionItem {
  tls_id: string;
  ts: string;
  src_ip: string;
  dest_ip: string;
  dest_port?: number | null;
  sni?: string | null;
  ja3?: string | null;
  ja3s?: string | null;
  alpn?: string | null;
  version?: string | null;
  cert_subject?: string | null;
  cert_issuer?: string | null;
  cert_fingerprint_sha1?: string | null;
  community_id?: string | null;
  iocs?: string[];
}

export interface TlsSessionListResponse {
  schema_version: string;
  items: TlsSessionItem[];
  page: PageInfo;
}

// ─── Alerts ─────────────────────────────────────────────────────────────────

export interface AlertItem {
  alert_id: string;
  ts: string;
  severity: Severity;
  engine?: string | null;
  signature: string;
  category?: string | null;
  sid?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  proto?: string | null;
  community_id?: string | null;
  refs?: string[];
  tags?: string[];
}

export interface AlertListResponse {
  schema_version: string;
  items: AlertItem[];
  page: PageInfo;
}

export interface AlertRelatedHost {
  ip: string;
  role?: string | null;
  conn_count?: number | null;
  alert_count?: number | null;
}

export interface AlertRelatedConnection {
  connection_id: string;
  src_ip: string;
  src_port?: number | null;
  dest_ip: string;
  dest_port?: number | null;
  proto?: string | null;
  service?: string | null;
  ts?: string | null;
}

export interface AlertDetailResponse {
  schema_version: string;
  alert_id: string;
  ts: string;
  severity: Severity;
  engine?: string | null;
  signature: string;
  category?: string | null;
  sid?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  proto?: string | null;
  community_id?: string | null;
  refs?: string[];
  tags?: string[];
  related_hosts: AlertRelatedHost[];
  related_connections: AlertRelatedConnection[];
}

// ─── Graphs ─────────────────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity?: string | null;
  meta?: Record<string, any> | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  weight?: number;
}

export interface JobGraphResponse {
  schema_version: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface EvidenceGraphResponse {
  schema_version: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
}

// ─── Storyline ──────────────────────────────────────────────────────────────

export interface StorylineStage {
  name: string;
  display_name: string;
  node_count: number;
  edge_count: number;
  confidence: number;
  summary: string;
  host_ips: string[];
  time_start?: string | null;
  time_end?: string | null;
  node_ids: string[];
}

export interface StorylineResponse {
  schema_version: string;
  job_id: string;
  stages: StorylineStage[];
  host_timelines: Record<string, string[]>;
  narrative: string;
  total_nodes: number;
  total_edges: number;
  unclassified_count: number;
}

// ─── Files ──────────────────────────────────────────────────────────────────

export interface FileItem {
  file_id: string;
  filename?: string | null;
  ts?: string | null;
  sha256: string;
  md5?: string | null;
  ssdeep?: string | null;
  size_bytes: number;
  mime?: string | null;
  entropy?: number | null;
  source?: string | null;
  host_ip?: string | null;
  pcap_label?: string | null;
  extracted_path?: string | null;
  yara_matches?: string[];
  download_artifact_id?: string | null;
  related_community_ids?: string[];
}

export interface FileListResponse {
  schema_version: string;
  items: FileItem[];
  page: PageInfo;
}

// ─── Findings ───────────────────────────────────────────────────────────────

export interface FindingItem {
  finding_id: string;
  title: string;
  severity: Severity;
  category?: string | null;
  sensor?: string | null;
  pcap_label?: string | null;
  summary?: string;
  evidence?: Record<string, unknown>;
  feedback?: "confirmed" | "false_positive" | "false_negative" | null;
  confidence: number;
  // Ground-truth corroboration from uploaded logs. "confirmed" means a
  // ground-truth source (e.g. a C2 operator log) attests to this detection.
  evidence_status?: "observed" | "inferred" | "corroborated" | "confirmed";
  corroboration_score?: number;
  corroborating_sources?: string[];
  // HITL review state (Sprint 4)
  analyst_status?: string | null;
  analyst_notes?: string | null;
  reviewed_at?: string | null;
  reviewer_id?: string | null;
}

export type FindingExplainFeedback = "useful" | "not_useful";

export interface FindingRelatedHost {
  ip: string;
  role?: string | null;
  conn_count?: number | null;
  alert_count?: number | null;
  finding_count?: number | null;
}

export interface FindingRelatedAlert {
  alert_id: string;
  ts: string;
  severity: Severity;
  signature: string;
  category?: string | null;
  host_ip?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  proto?: string | null;
  pcap_label?: string | null;
}

export interface FindingRelatedConnection {
  connection_id: string;
  src_ip: string;
  src_port?: number | null;
  dest_ip: string;
  dest_port?: number | null;
  proto: string;
  service?: string | null;
  ts: string;
  pcap_label?: string | null;
}

export interface FindingDetailResponse extends FindingItem {
  community_id?: string | null;
  explanation_feedback?: FindingExplainFeedback | null;
  related_hosts: FindingRelatedHost[];
  related_alerts: FindingRelatedAlert[];
  related_connections: FindingRelatedConnection[];
}

export interface FindingListResponse {
  schema_version: string;
  items: FindingItem[];
  page: PageInfo;
}

export interface FindingExplainRequest {
  format: "markdown" | "text";
}

export interface FindingExplainSection {
  id: "assessment" | "why_it_matters" | "recommended_next_steps";
  title: string;
  body?: string | null;
  bullets: string[];
  citations: string[];
}

export interface FindingExplainEvidenceItem {
  label: string;
  value: string;
  citation: string;
}

export interface FindingExplainResponse {
  schema_version: string;
  format: "markdown" | "text";
  content: string;
  duration_ms: number;
  source: "deterministic" | "llm" | "fallback";
  warning?: string | null;
  explanation_feedback?: FindingExplainFeedback | null;
  sections: FindingExplainSection[];
  evidence_items: FindingExplainEvidenceItem[];
}

export interface FindingExplainFeedbackResponse {
  schema_version: string;
  explanation_feedback: FindingExplainFeedback | null;
}

// ─── IOCs ───────────────────────────────────────────────────────────────────

export interface IocItem {
  ioc_id: string;
  type: IocType;
  value: string;
  severity?: string | null;
  confidence?: number | null;
  sources?: string[];
  context?: string | null;
}

export interface IocListResponse {
  schema_version: string;
  items: IocItem[];
  page: PageInfo;
}

// ─── Theories (Theory of the Case) ──────────────────────────────────────────

export type HypothesisType =
  | "c2"
  | "malware_delivery"
  | "recon"
  | "lateral_movement"
  | "exfiltration"
  | "admin_tools"
  | "benign"
  | "inconclusive";

export interface EvidenceRef {
  id: string;
  type: "alert" | "finding" | "ioc" | "unknown";
  label: string;
}

export interface ScoreBreakdown {
  findings: number;
  alerts: number;
  iocs: number;
  finding_count: number;
  alert_count: number;
  ioc_count: number;
  reason?: string | null;
}

export interface TheoryItem {
  theory_id: string;
  scope_type: string;
  scope_id?: string | null;
  label: string;
  hypothesis_type: HypothesisType;
  score: number;
  confidence: "low" | "medium" | "high";
  rank: number;
  supporting_evidence: EvidenceRef[];
  contradicting_evidence: EvidenceRef[];
  score_breakdown?: ScoreBreakdown | null;
  explanation?: string | null;
  next_steps: string[];
  pcap_label?: string | null;
  created_at: string;
}

export interface TheoryListResponse {
  schema_version: string;
  items: TheoryItem[];
  job_id: string;
  scope_type: string;
  scope_id?: string | null;
}

export interface TheoryExplainResponse {
  schema_version: string;
  theory_id: string;
  explanation: string;
  source: "deterministic" | "llm" | "fallback";
  warning?: string | null;
}

// ─── Incident Slices ────────────────────────────────────────────────────────

export type SliceType =
  | "attack_thread"
  | "recon_phase"
  | "c2_session"
  | "lateral"
  | "exfil"
  | "misc";

export interface SliceItem {
  slice_id: string;
  label: string;
  slice_type: SliceType;
  severity: string;
  confidence: number;
  community_ids: string[];
  host_ips: string[];
  time_start?: string | null;
  time_end?: string | null;
  alert_ids: string[];
  finding_ids: string[];
  ioc_ids: string[];
  connection_ids: string[];
  summary?: string | null;
  rank: number;
  created_at: string;
}

export interface SliceListResponse {
  schema_version: string;
  items: SliceItem[];
  job_id: string;
}

export interface SliceDetailResponse {
  schema_version: string;
  item: SliceItem;
  job_id: string;
}

// ─── Context Annotations (Why Unusual?) ─────────────────────────────────────

export interface ContextAnnotationItem {
  annotation_id: string;
  host_ip: string;
  metric_name: string;
  metric_category: string;
  baseline_value: number | null;
  observed_value: number | null;
  deviation_factor: number | null;
  population_size: number | null;
  severity: string;
  confidence: number;
  title: string;
  description: string;
  why_unusual: string;
  related_alert_ids: string[];
  related_finding_ids: string[];
  created_at: string;
}

export interface ContextAnnotationListResponse {
  schema_version: string;
  items: ContextAnnotationItem[];
  job_id: string;
}

// ─── Reports ────────────────────────────────────────────────────────────────

export interface ReportItem {
  report_id: string;
  mode: string;
  title: string;
  threat_level: string;
  confidence: number;
  pcap_label?: string | null;
  content_markdown: string;
  content_json: Record<string, unknown>;
  theory_count: number;
  slice_count: number;
  finding_count: number;
  alert_count: number;
  ioc_count: number;
  host_count: number;
  annotation_count: number;
  evidence_refs: string[];
  created_at: string;
}

export interface ReportListResponse {
  schema_version: string;
  items: ReportItem[];
  job_id: string;
}

export interface ReportDetailResponse {
  schema_version: string;
  item: ReportItem;
  job_id: string;
}

// ─── Proofs ─────────────────────────────────────────────────────────────────

export type ProofMode = "soc_handoff" | "ir_technical" | "executive_summary";

export interface ProofItem {
  proof_id: string;
  job_id: string;
  title: string;
  conclusion: string | null;
  status: string;
  severity: string;
  confidence: number;
  mode: ProofMode;
  narrative_markdown: string | null;
  item_count: number;
  created_at: string;
  updated_at: string;
}

export interface ProofItemEntry {
  item_id: string;
  proof_id: string;
  entity_type: string;
  entity_id: string;
  role: string;
  analyst_note: string | null;
  order: number;
  label: string | null;
  severity: string | null;
  created_at: string;
}

export interface ProofListResponse {
  schema_version: string;
  items: ProofItem[];
  job_id: string;
}

export interface ProofDetailResponse {
  schema_version: string;
  item: ProofItem;
  job_id: string;
}

export interface ProofItemListResponse {
  schema_version: string;
  items: ProofItemEntry[];
  proof_id: string;
}

export interface ProofItemDetailResponse {
  schema_version: string;
  item: ProofItemEntry;
  proof_id: string;
}

export interface ProofNarrativeResponse {
  schema_version: string;
  proof_id: string;
  narrative_markdown: string;
  warnings: string[];
}

export interface ProofExportResponse {
  schema_version: string;
  content: string;
  filename: string;
}

// ─── Security Onion Import ──────────────────────────────────────────────────

export interface SecurityOnionImportResponse {
  schema_version: string;
  job_id: string;
  enabled: boolean;
  status: string;
  message?: string | null;
  node_id?: string | null;
}

// ─── Arkime ─────────────────────────────────────────────────────────────────

export type ArkimeImportState = "not_imported" | "queued" | "running" | "imported" | "failed";
export type ArkimePivotBasis = "community_id" | "five_tuple" | "none";

export interface ArkimeImportResponse {
  schema_version: string;
  job_id: string;
  enabled: boolean;
  import_status: ArkimeImportState;
  message?: string | null;
}

export interface ArkimeStatusResponse {
  schema_version: string;
  job_id: string;
  enabled: boolean;
  import_status: ArkimeImportState;
  imported_at?: string | null;
  pcap_count: number;
  message?: string | null;
}

export interface ArkimePivotResponse {
  schema_version: string;
  enabled: boolean;
  url?: string | null;
  basis: ArkimePivotBasis;
  import_status: ArkimeImportState;
  message?: string | null;
}

// ─── Timeline ───────────────────────────────────────────────────────────────

export interface TimelineEntityFields {
  src_ip?: string | null;
  dest_ip?: string | null;
  src_port?: number | null;
  dest_port?: number | null;
  community_id?: string | null;
  domain?: string | null;
}

export interface TimelineRefs {
  alert_id?: string | null;
  finding_id?: string | null;
  ioc_id?: string | null;
}

export interface TimelineItem {
  ts: string;
  type: string;
  title: string;
  description?: string | null;
  severity?: Severity;
  entities?: TimelineEntityFields;
  refs?: TimelineRefs;
  evidence_status?: string | null;
  sensor?: string | null;
}

export interface TimelineListResponse {
  schema_version: string;
  items: TimelineItem[];
  page: PageInfo;
}

// ─── Artifacts ──────────────────────────────────────────────────────────────

export interface ArtifactItem {
  artifact_id: string;
  type: string;
  status: "available" | "generating" | "failed" | "purged";
  created_at: string;
  filename?: string | null;
  sha256?: string | null;
  size_bytes?: number | null;
  error?: string | null;
}

export interface ArtifactListResponse {
  schema_version: string;
  items: ArtifactItem[];
}

export interface EvidencePackageCreateResponse {
  schema_version: string;
  artifact_id: string;
  status: "generating";
}

// ─── Batch ──────────────────────────────────────────────────────────────────

export type BatchAction = "cancel" | "delete" | "export_iocs";

export interface BatchJobsRequest {
  action: BatchAction;
  job_ids: string[];
}

export interface BatchJobsResponse {
  schema_version: string;
  accepted: string[];
  rejected: { job_id: string; reason: string }[];
  export_iocs?: IocListResponse;
}

// ─── System ─────────────────────────────────────────────────────────────────

export interface SystemConfigResponse {
  schema_version: string;
  aipam_version: string;
  max_upload_bytes: number;
  profiles_enabled: ExecutionProfile[];
  default_limits: {
    sensor_timeout_seconds?: number;
    max_extracted_bytes?: number;
    max_job_disk_bytes?: number;
  };
  explain_configuration: {
    mode: "deterministic" | "llm";
    llm_enabled: boolean;
    llm_model_name?: string | null;
    llm_endpoint?: string | null;
  };
}

export interface HealthResponse {
  schema_version: string;
  status: "ok" | "degraded";
  uptime_seconds: number;
  docker_ok: boolean;
  disk_ok: boolean;
  ollama_ok: boolean;
  current_job_id?: string | null;
  last_job_id?: string | null;
  last_job_status?: JobStatus;
}

export interface ExplainLatencySummary {
  count: number;
  average_ms: number;
  min_ms: number;
  max_ms: number;
  last_ms: number;
}

export interface ExplainTelemetryResponse {
  schema_version: string;
  explain_response_counts: Record<string, number>;
  explain_latency_ms: ExplainLatencySummary;
}

// ─── SSE Events ─────────────────────────────────────────────────────────────

export type SseEventType =
  | "job.status" | "job.complete" | "stage.status" | "sensor.status"
  | "sensor.log" | "sensor.finding" | "artifact.created"
  | "quota.hit" | "disk.warning" | "heartbeat" | "reset"
  | "partial_result" | "early_alert";

export interface SseEnvelope<T = unknown> {
  id: number;
  type: SseEventType;
  ts: string;
  data: T;
}

export interface SseJobStatusData { job_id: string; status: JobStatus; message?: string | null }
export interface SseJobCompleteData {
  job_id: string;
  status: JobStatus;
  summary?: { finding_count?: number; alert_count?: number; host_count?: number; ioc_count?: number; duration_sec?: number };
}
export interface SseStageStatusData { job_id: string; stage: string; status: string; step?: number; total_steps?: number; duration_ms?: number; message?: string | null }
export interface SseSensorStatusData { job_id: string; sensor: string; status: SensorStatus; step?: number; total_steps?: number; duration_ms?: number; message?: string | null }
export interface SseSensorLogData { job_id: string; sensor: string; stream: "stdout" | "stderr"; line: string }
export interface SseSensorFindingData { job_id: string; sensor: string; finding_id: string; severity: Severity; title?: string | null; confidence?: number }
export interface SseArtifactCreatedData { job_id: string; artifact_id: string; type: string }
export interface SseQuotaHitData { job_id: string; quota_type: "disk" | "extracted_bytes"; message?: string | null }
export interface SseDiskWarningData { usage_pct: number; free_bytes: number; threshold_pct: number; message?: string | null }
export interface SseHeartbeatData { job_id: string }
export interface SseResetData { reason: "event_id_expired" }
export interface SsePartialResultData {
  job_id: string;
  stage: string;
  partial_data: PartialData;
  completed_stages: string[];
  current_stage?: string | null;
}
export interface SseEarlyAlertData {
  job_id: string;
  title: string;
  severity: Severity;
  src_ip?: string | null;
  dst_ip?: string | null;
}

// ─── Partial Results ────────────────────────────────────────────────────────

export interface PartialData {
  pcap_stats?: { file_count?: number; total_bytes?: number };
  top_hosts?: Array<{ ip: string; total_bytes: number }>;
  protocol_distribution?: Record<string, number>;
  alert_summary?: { total: number; by_severity: Record<string, number> };
  sensor_summary?: {
    total: number;
    completed: number;
    failed: number;
    skipped: number;
    sensors: Array<{ name: string; status: string; duration_ms?: number | null }>;
  };
  correlation_counts?: Record<string, number>;
  finding_count?: number;
  alert_count?: number;
  host_count?: number;
}

export interface PartialResultsResponse {
  schema_version: string;
  job_id: string;
  completed_stages: string[];
  current_stage?: string | null;
  partial_data: PartialData;
}

// ─── Query Param helpers ────────────────────────────────────────────────────

export interface PaginationParams {
  cursor?: string;
  limit?: number;
  sort?: string;
  order?: SortOrder;
}

export interface JobListParams extends PaginationParams {
  status?: JobStatus;
  profile?: ExecutionProfile;
  q?: string;
}

export interface HostListParams extends PaginationParams {
  role?: HostRole;
  q?: string;
  pcap_label?: string;
}

export interface ConnectionListParams extends PaginationParams {
  direction?: "inbound" | "outbound" | "any";
  proto?: "tcp" | "udp" | "icmp" | "any";
  dest_ip?: string;
  dest_port?: number;
  service?: string;
  pcap_label?: string;
  community_id?: string;
  start_ts?: string;
  end_ts?: string;
}

export interface DnsListParams extends PaginationParams {
  q?: string;
  rcode?: string;
  qtype?: string;
  community_id?: string;
  start_ts?: string;
  pcap_label?: string;
  end_ts?: string;
}

export interface TlsListParams extends PaginationParams {
  sni?: string;
  ja3?: string;
  issuer?: string;
  community_id?: string;
  start_ts?: string;
  pcap_label?: string;
  end_ts?: string;
}

export interface AlertListParams extends PaginationParams {
  severity?: Severity;
  category?: string;
  sid?: string;
  community_id?: string;
  start_ts?: string;
  pcap_label?: string;
  end_ts?: string;
}

export interface FileListParams extends PaginationParams {
  mime?: string;
  sha256?: string;
  yara_rule?: string;
  community_id?: string;
  start_ts?: string;
  end_ts?: string;
}

export interface FindingListParams extends PaginationParams {
  severity?: Severity;
  category?: string;
  sensor?: string;
  q?: string;
  pcap_label?: string;
}

export interface TimelineListParams extends PaginationParams {
  severity?: Severity;
  type?: string;
  start_ts?: string;
  end_ts?: string;
}

export interface IocListParams extends PaginationParams {
  type?: IocType;
  severity?: Severity;
  q?: string;
  pcap_label?: string;
}

// ─── Temporal Analysis ──────────────────────────────────────────────────────

export interface CountDelta { before: number; after: number; new: number; removed: number; }
export interface AlertCountDelta { before: number; after: number; new_signatures: number; removed_signatures: number; }
export interface TrafficSnapshot { connections: number; bytes_sent: number; bytes_recv: number; }
export interface TrafficDelta { before: TrafficSnapshot; after: TrafficSnapshot; }
export interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }

export interface TemporalSummary {
  hosts: CountDelta; alerts: AlertCountDelta; findings: CountDelta;
  iocs: CountDelta; dns_domains: CountDelta; traffic: TrafficDelta;
  theories: CountDelta; tls_sessions: CountDelta;
  severity_before: SeverityCounts; severity_after: SeverityCounts;
}

export interface HostDiffItem { ip: string; role: string; conn_count: number; alert_count: number; }
export interface HostChangedItem { ip: string; role: string; conn_before: number; conn_after: number; alert_before: number; alert_after: number; }
export interface HostDiffs { added: HostDiffItem[]; removed: HostDiffItem[]; changed: HostChangedItem[]; }
export interface AlertDiffItem { signature: string; severity: string; status: string; before_count: number; after_count: number; }
export interface FindingDiffItem { title: string; severity: string; sensor?: string | null; status: string; }
export interface IocDiffs { added: string[]; removed: string[]; }
export interface DnsDiffs { added: string[]; removed: string[]; }

export interface PhaseSnapshot { host_count: number; alert_count: number; finding_count: number; connection_count: number; ioc_count: number; }
export interface PhaseSummary { before: PhaseSnapshot; after: PhaseSnapshot; }
export interface SeverityShiftItem { before: number; after: number; delta: number; }
export interface SeverityShift { critical: SeverityShiftItem; high: SeverityShiftItem; medium: SeverityShiftItem; low: SeverityShiftItem; }
export interface ContainmentIndicators { removed_c2_connections: number; reduced_alert_categories: string[]; new_defensive_activity: string[]; }

export interface TemporalDeltaResponse {
  schema_version: string;
  phase_labels: [string, string];
  summary: TemporalSummary;
  phase_summary: PhaseSummary;
  severity_shift: SeverityShift;
  containment_indicators: ContainmentIndicators;
  hosts: HostDiffs; alerts: AlertDiffItem[]; findings: FindingDiffItem[];
  iocs: IocDiffs; dns: DnsDiffs;
}

export interface TemporalFlowItem {
  src_ip: string; dest_ip: string; dest_port?: number | null;
  proto: string; service?: string | null; count: number;
  total_bytes_sent: number; total_bytes_recv: number;
}
export interface TemporalFlowsResponse { schema_version: string; flows: TemporalFlowItem[]; total_new_flows: number; }
export interface TemporalNarrativeResponse { schema_version: string; narrative_markdown: string; }

// ─── Investigation Queue ─────────────────────────────────────────────────────

export type AnalystStatus = "unreviewed" | "confirmed" | "false_positive" | "needs_review" | "deferred";
export type QueueItemSource = "finding" | "alert" | "theory";

export interface InvestigationQueueItem {
  item_id: string;
  source_type: QueueItemSource;
  source_id: string;
  job_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  category: string | null;
  sensor: string | null;
  description: string | null;
  pcap_label: string | null;
  rank_score: number;
  rank_position: number;
  // Sprint 2: enriched metadata
  corroborating_count: number;
  affected_hosts: string[];
  affected_hosts_count: number;
  mitre_ids: string[];
  analyst_status: AnalystStatus;
  analyst_notes: string | null;
  reviewed_at: string | null;
  reviewer_id: string | null;
  extra: Record<string, any>;
}

export interface EvidenceBundleResponse {
  schema_version: string;
  item: InvestigationQueueItem;
  related_findings: Record<string, any>[];
  related_alerts: Record<string, any>[];
  related_connections: Record<string, any>[];
  timeline_events: Record<string, any>[];
}

export interface QueueSummary {
  total: number;
  unreviewed: number;
  confirmed: number;
  false_positive: number;
  needs_review: number;
  deferred: number;
  review_rate: number;
}

export interface InvestigationQueueResponse {
  schema_version: string;
  items: InvestigationQueueItem[];
  page: PageInfo;
  summary: QueueSummary;
}

export interface StatusUpdateRequest {
  analyst_status: AnalystStatus;
  analyst_notes?: string | null;
  reviewer_id?: string | null;
}

export interface StatusUpdateResponse {
  schema_version: string;
  item_id: string;
  analyst_status: AnalystStatus;
  analyst_notes: string | null;
  reviewer_id: string | null;
  reviewed_at: string;
}

export interface BulkStatusUpdateRequest {
  item_ids: string[];
  analyst_status: AnalystStatus;
  analyst_notes?: string | null;
  reviewer_id?: string | null;
}

export interface BulkStatusUpdateResponse {
  schema_version: string;
  updated: string[];
  failed: string[];
}

export interface ReviewQueueResponse {
  schema_version: string;
  items: InvestigationQueueItem[];
  page: PageInfo;
  stats: QueueSummary;
}

// ═══════════════════════════════════════════════════════════════════════════
// V1 BACKWARD-COMPATIBLE ALIASES (to be removed when pages are refactored)
// ═══════════════════════════════════════════════════════════════════════════

/** @deprecated Use SystemConfigResponse */
export interface SettingsPayload { [key: string]: any }
export interface EffectiveSettingsResponse { [key: string]: any }
export interface OllamaModelInfo { name: string; size: number; family: string; parameter_size: string; quantization: string }
export interface SetupStatusResponse { model_configured: boolean; llm_model_name: string | null }

// ─── Telemetry Event Detail ─────────────────────────────────────────────────
export interface TelemetryEventDetail {
  event_id: string;
  event_type: string;
  timestamp: string;
  source_type: string | null;
  source_system: string | null;
  source_filename: string | null;
  parser_name: string | null;
  parser_version: string | null;
  evidence_status: string;
  corroboration_score: number;
  src_ip: string | null;
  dest_ip: string | null;
  src_port: number | null;
  dest_port: number | null;
  hostname: string | null;
  username: string | null;
  proto: string | null;
  community_id: string | null;
  session_id: string | null;
  process_guid: string | null;
  pcap_label: string | null;
  data: Record<string, any>;
  correlation_keys: Record<string, any>;
  tags: string[];
  raw_ref: string | null;
}

// ─── Integration Settings ──────────────────────────────────────────────────
export interface IntegrationSettingsPayload {
  security_onion_api_url?: string | null;
  security_onion_username?: string | null;
  security_onion_password?: string | null;
  arkime_api_url?: string | null;
  arkime_api_username?: string | null;
  arkime_api_password?: string | null;
}
export interface IntegrationTestRequest {
  integration_type: "security_onion" | "arkime";
  url: string;
  username?: string;
  password?: string;
}
export interface IntegrationTestResponse {
  ok: boolean;
  message: string;
  latency_ms?: number | null;
}

// ─── Ollama GPU status ──────────────────────────────────────────────────────
export interface LoadedModelInfo {
  name: string; size: number; size_vram: number; parameter_size: string;
  quantization: string; family: string; context_length: number; gpu_offload_pct: number;
}
export interface OllamaGpuStatusResponse {
  schema_version: string; ollama_version: string; gpu_detected: boolean;
  gpu_name: string | null; vram_total_bytes: number; vram_used_bytes: number;
  compute_device: string; loaded_models: LoadedModelInfo[];
}

// ─── Chat types ─────────────────────────────────────────────────────────────
export interface ChatCitation { type: string; id?: string; snippet: string }
export interface HistoricalFindingCitation extends ChatCitation {
  type: "historical_finding";
  id: string;
  source_job_id: string;
  source_project_id: string | null;
  href: string;
}
export interface ChatEvidenceRef { type: string; id?: string; label: string }
export type ChatMode = "baseline" | "mnemos";
export type MnemosRetrievalStatus = "used" | "no_matches" | "unavailable" | "error";
export interface ChatGenerationMetadata { temperature: number; max_tokens: number }
export interface ChatRequest {
  message: string;
  conversation_id?: string;
  context_hint?: string;
  mode?: ChatMode;
  request_id?: string;
  comparison_source_message_id?: string;
}
export interface ChatResponse {
  response: string;
  citations: Array<ChatCitation | HistoricalFindingCitation>;
  conversation_id: string;
  confidence?: number;
  evidence_refs?: ChatEvidenceRef[];
  suggested_followups?: string[];
  retrieval_status?: MnemosRetrievalStatus | null;
  model_id?: string | null;
  generation?: ChatGenerationMetadata | null;
  branch_id?: string | null;
  request_id?: string | null;
  status?: "pending" | "completed" | "error";
}
export interface ChatMessage {
  id: string;
  sequence: number;
  role: "user" | "assistant";
  content: string;
  citations: Array<ChatCitation | HistoricalFindingCitation>;
  metadata: Record<string, unknown> | null;
  request_id: string | null;
  timestamp: string;
}
export interface ChatComparisonBranch {
  id: string;
  conversation_id: string;
  label: string;
  source_message_id?: string | null;
  request_id?: string | null;
  history_cutoff_sequence: number;
  created_at: string;
  updated_at: string;
  messages: ChatMessage[];
}
export interface ChatComparisonGroup {
  group_id: string;
  job_id: string;
  root_conversation_id: string;
  title?: string | null;
  snapshot_branch_id: string;
  active_branch_id: string;
  conversation_id: string;
  created_at: string;
  updated_at: string;
  branches: ChatComparisonBranch[];
}
export interface ConversationSummary { id: string; job_id: string; created_at: string; updated_at: string; title?: string; message_count: number }
export interface ConversationHistoryOut { id: string; job_id: string; messages: ChatMessage[]; created_at: string; updated_at: string }
export interface SuricataRuleItem { filename: string; content?: string; size_bytes: number; updated_at: string }

// ─── Parsed Suricata Rule types ─────────────────────────────────────────────
export interface ParsedRule {
  sid: number;
  enabled: boolean;
  action: string;
  msg: string;
  classtype: string;
  severity: number;
  protocol: string;
  src: string;
  dst: string;
  rev: number;
  references: string[];
  raw: string;
  line_number: number;
}
export interface ParsedRuleListResponse {
  items: ParsedRule[];
  total: number;
  total_enabled: number;
  total_disabled: number;
  offset: number;
  limit: number;
}
export interface CategoryStats { name: string; total: number; enabled: number; disabled: number }
export interface RuleFileStats {
  filename: string;
  total_rules: number;
  enabled: number;
  disabled: number;
  categories: CategoryStats[];
}
export interface ToggleRulesRequest {
  sids?: number[];
  category?: string;
  enabled: boolean;
}

// ─── Detection-as-Code types ─────────────────────────────────────────────
export type RuleType = "suricata" | "sigma";
export interface GeneratedRuleResponse {
  rule_type: RuleType;
  rule_text: string;
  finding_id: string;
  description: string;
}

// ─── Knowledge Base types ───────────────────────────────────────────────────
export type KBDocType = "asset_inventory" | "network_map" | "baseline_profile" | "threat_intel" | "soc_playbook" | "policy" | "reference" | "user_guide" | "exploit_capability" | "other";
export interface KBDocumentCreate { name: string; doc_type: KBDocType; description?: string; content: string }
export interface KBDocumentOut { id: string; job_id: string | null; is_global?: boolean; name: string; doc_type: string; description?: string; filename?: string; chunk_count: number; status: string; error_message?: string; created_at: string; updated_at: string }
export interface KBDocumentDetail extends KBDocumentOut { content: string }
export interface KBDocumentListOut { items: KBDocumentOut[]; total: number }
export interface KBSearchResult { text: string; doc_name: string; doc_type: string; doc_id: string; score: number }
export interface KBSearchResponse { results: KBSearchResult[]; query: string }

// ─── V1 Training types (still used by TrainingPage) ─────────────────────────

export interface TrainingConfig {
  base_model: string | null; dataset_url: string | null; lora_rank: number | null;
  learning_rate: number | null; max_seq_length: number | null; configured: boolean;
}
export interface TrainingStatus {
  trainer_online: boolean; job_id: string | null; status: string;
  current_iter: number; total_iters: number; percent: number;
  last_loss: number; it_per_sec: number;
  elapsed_seconds: number | null; eta_seconds: number | null;
}
export interface TrainingLedgerEntry {
  timestamp: string; event_type: string; phase_label: string; status: string;
  config_hash?: string; random_seed?: number; base_model?: string;
  dataset_path?: string; dataset_samples?: number; lora_r?: number;
  lora_alpha?: number; epochs?: number; learning_rate?: number;
  batch_size?: number; max_seq_length?: number; trainer_type?: string;
  beta?: number; metrics?: Record<string, any>;
}
export interface TrainingLedgerResponse {
  entries: TrainingLedgerEntry[]; total: number; ledger_path: string; ledger_exists: boolean;
}
export interface PhaseStats {
  total_events: number; completed: number; failed: number;
  latest_timestamp: string | null; latest_loss: number | null;
}
export interface ActiveModel {
  name: string; phase: string; config_hash?: string; context_window?: number;
  lora_r?: number; lora_alpha?: number; trained_at?: string; loss?: number; dawn_seed?: number;
}
export interface SelfHealingStats {
  runs: number; total_synthetic_pcaps: number; families_augmented: string[]; latest_timestamp: string | null;
}
export interface TrainingSummary {
  has_data: boolean; latest_run: TrainingLedgerEntry | null;
  active_model: ActiveModel | null; phase_counts: Record<string, PhaseStats>;
  models: string[]; peak_vram_gb: number | null;
  self_healing: SelfHealingStats | null; total_events: number;
}
export interface ExportStatus {
  job_id: string | null; status: string; message: string;
  model_name: string | null; version: number | null;
  gguf_path: string | null; elapsed_seconds: number | null;
}


// ─── Frontier Knowledge Distillation types ──────────────────────────────────
export interface DistillConfig {
  endpoint: string; model: string; temperature: number; max_tokens: number;
  timeout_seconds: number; enabled: boolean; configured: boolean;
  api_key_set: boolean; api_key_preview: string;
}
export interface DistillConfigUpdate {
  endpoint?: string; api_key?: string; model?: string;
  temperature?: number; max_tokens?: number; timeout_seconds?: number;
  enabled?: boolean;
}
export interface DistillStats {
  total_samples: number; file_size_mb: number; file_path: string;
  exists: boolean; teacher_models: string[]; jobs_distilled: string[];
  per_task: Record<string, number>; rejected_count: number;
}

// ─── Admin Feedback Metrics (Sprint 7) ────────────────────────────────────
export interface SensorTrustProfile {
  sensor_name: string;
  total_items: number;
  confirmed: number;
  false_positive: number;
  deferred: number;
  confirmation_rate: number;
  false_positive_rate: number;
  avg_confidence_delta: number;
}
export interface NoisySignature {
  signature_name: string;
  category: string | null;
  false_positive_rate: number;
  total_occurrences: number;
  false_positive_count: number;
  confirmed_count: number;
  last_seen: string | null;
}
export interface OverallFeedbackStats {
  total_reviewed: number;
  total_items: number;
  confirmation_rate: number;
  false_positive_rate: number;
  most_trusted_sensor: string | null;
  noisiest_sensor: string | null;
}
export interface DailyReviewCount {
  date: string;
  confirmed: number;
  false_positive: number;
  deferred: number;
  needs_review: number;
}
export interface FeedbackTimeSeries {
  daily_reviews: DailyReviewCount[];
}
export interface FeedbackMetricsResponse {
  sensor_trust: SensorTrustProfile[];
  noisy_signatures: NoisySignature[];
  overall_stats: OverallFeedbackStats;
  time_series: FeedbackTimeSeries;
}

// ── Cross-Job Correlation (Sprint 8) ──────────────────────────────────────
export interface CorrelationMatch {
  job_id: string;
  job_name: string;
  job_created_at: string | null;
  match_type: "same_host" | "same_ioc" | "same_mitre" | "similar_pattern" | "behavioral_similarity";
  matched_entity: string;
  matched_item_id: string | null;
  matched_title: string | null;
  similarity_score: number;
  context: string;
}
export interface CampaignCandidate {
  campaign_id: string;
  label: string;
  job_ids: string[];
  shared_iocs: string[];
  shared_hosts: string[];
  shared_mitre_techniques: string[];
  confidence: number;
}
export interface CorrelationQuery {
  job_id: string;
  item_id: string | null;
  host: string | null;
  ioc: string | null;
}
export interface CorrelationResponse {
  query: CorrelationQuery;
  matches: CorrelationMatch[];
  campaigns: CampaignCandidate[];
  total_matches: number;
}
export interface RelatedJob {
  job_id: string;
  job_name: string;
  job_created_at: string | null;
  overlap_type: "shared_hosts" | "shared_iocs" | "shared_mitre" | "shared_behavior";
  shared_entities: string[];
  relevance_score: number;
}
export interface RelatedJobsResponse {
  job_id: string;
  related_jobs: RelatedJob[];
}
