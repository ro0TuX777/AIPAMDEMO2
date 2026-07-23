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

export type SourceType = "pcap" | "log_bundle" | "netflow_bundle" | "c2_bundle" | "exercise_bundle";

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

// ─── API Error ──────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public details?: Record<string, unknown>,
    public retryAfter?: number,
    public serverMessage?: string,
  ) {
    super(serverMessage || `[${status}] ${code}`);
    this.name = "ApiError";
  }
}

// ─── API Client ─────────────────────────────────────────────────────────────

const API_BASE =
  (import.meta as any).env.VITE_API_BASE_URL?.replace(/\/$/, "") ||
  "http://localhost:8000/api/v1";

function qs(params: object): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") parts.push(`${k}=${encodeURIComponent(String(v))}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

let _token: string | null = null;

/** Set the Bearer token used for all V2 API calls. */
export function setApiToken(token: string | null): void {
  _token = token;
}

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  if (_token) h["Authorization"] = `Bearer ${_token}`;
  return h;
}

async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
  const headers = { ...authHeaders(), ...(init.headers as Record<string, string> || {}) };
  const res = await fetch(url, { ...init, headers });
  if (!res.ok) {
    const retryAfter = res.headers.get("Retry-After");
    const parsedRetryAfter = retryAfter ? Number.parseInt(retryAfter, 10) : undefined;
    let body: any = {};
    try { body = await res.json(); } catch { /* empty */ }
    throw new ApiError(
      res.status,
      body.code || `HTTP_${res.status}`,
      body.details,
      typeof parsedRetryAfter === "number" && Number.isFinite(parsedRetryAfter) ? parsedRetryAfter : undefined,
      body.error || body.detail || undefined,
    );
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json();
}

function get<T>(path: string): Promise<T> { return request<T>(`${API_BASE}${path}`); }
function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${API_BASE}${path}`, {
    method: "POST",
    headers: body instanceof Blob ? {} : { "Content-Type": "application/json" },
    body: body instanceof Blob ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });
}
function del<T>(path: string): Promise<T> { return request<T>(`${API_BASE}${path}`, { method: "DELETE" }); }
function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${API_BASE}${path}`, {
    method: "PUT",
    headers: body instanceof Blob ? {} : { "Content-Type": "application/json" },
    body: body instanceof Blob ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });
}
function patch<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: body instanceof Blob ? {} : { "Content-Type": "application/json" },
    body: body instanceof Blob ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export const api = {
  // ── Uploads ────────────────────────────────────────────────────────────
  uploadPcap(file: File, onProgress?: (pct: number) => void): Promise<UploadCreateResponse> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${API_BASE}/uploads`);

      const headers = authHeaders();
      Object.keys(headers).forEach(k => xhr.setRequestHeader(k, headers[k]));
      xhr.setRequestHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(file.name)}"`);

      if (onProgress) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            onProgress(pct);
          }
        };
      }

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch (err) {
            reject(new Error("Invalid JSON response from server"));
          }
        } else {
          reject(new Error(`Upload failed with status ${xhr.status}`));
        }
      };

      xhr.onerror = () => reject(new Error("Network error during upload"));
      xhr.send(file);
    });
  },
  updateFindingFeedback(jobId: string, finding_id: string, feedback: string | null) {
    return patch<FindingItem>(`/jobs/${jobId}/findings/${finding_id}/feedback`, { feedback });
  },
  updateFindingExplainFeedback(jobId: string, finding_id: string, explanation_feedback: FindingExplainFeedback | null) {
    return patch<FindingExplainFeedbackResponse>(
      `/jobs/${jobId}/findings/${finding_id}/explain/feedback`,
      { explanation_feedback },
    );
  },
  uploadBundle(file: File, onProgress?: (pct: number) => void): Promise<UploadCreateResponse> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${API_BASE}/uploads/bundle`);

      const headers = authHeaders();
      Object.keys(headers).forEach(k => xhr.setRequestHeader(k, headers[k]));
      xhr.setRequestHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(file.name)}"`);

      if (onProgress) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            onProgress(pct);
          }
        };
      }

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch (err) {
            reject(new Error("Invalid JSON response from server"));
          }
        } else {
          let msg = `Upload failed with status ${xhr.status}`;
          try { msg = JSON.parse(xhr.responseText).detail || msg; } catch {}
          reject(new Error(msg));
        }
      };

      xhr.onerror = () => reject(new Error("Network error during upload"));
      xhr.send(file);
    });
  },
  validateUpload(uploadId: string): Promise<UploadValidateResponse> {
    return post<UploadValidateResponse>(`/uploads/${uploadId}/validate`);
  },
  getExportUrl(jobId: string): string {
    const tokenQs = _token ? `?token=${encodeURIComponent(_token)}` : "";
    return `${API_BASE}/jobs/${jobId}/export${tokenQs}`;
  },
  // ── Jobs ───────────────────────────────────────────────────────────────
  listJobs(p: JobListParams = {}): Promise<JobListResponse> {
    return get<JobListResponse>(`/jobs${qs(p)}`);
  },
  createJob(body: JobCreateRequest): Promise<JobCreateResponse> {
    return post<JobCreateResponse>("/jobs", body);
  },
  getJobDetail(jobId: string): Promise<JobGetResponse> {
    return get<JobGetResponse>(`/jobs/${jobId}`);
  },
  deleteJob(jobId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}`);
  },
  cancelJob(jobId: string): Promise<void> {
    return post<void>(`/jobs/${jobId}/cancel`);
  },
  rerunJob(jobId: string, body: { execution_profile: ExecutionProfile; priority?: Priority }): Promise<JobCreateResponse> {
    return post<JobCreateResponse>(`/jobs/${jobId}/rerun`, body);
  },
  batchJobs(body: BatchJobsRequest): Promise<BatchJobsResponse> {
    return post<BatchJobsResponse>("/jobs/batch", body);
  },
  getJobSummary(jobId: string): Promise<JobSummaryResponse> {
    return get<JobSummaryResponse>(`/jobs/${jobId}/summary`);
  },
  getJobSensors(jobId: string): Promise<SensorListResponse> {
    return get<SensorListResponse>(`/jobs/${jobId}/sensors`);
  },
  getPartialResults(jobId: string): Promise<PartialResultsResponse> {
    return get<PartialResultsResponse>(`/jobs/${jobId}/partial-results`);
  },

  // ── Hosts ──────────────────────────────────────────────────────────────
  listHosts(jobId: string, p: HostListParams = {}): Promise<HostListResponse> {
    return get<HostListResponse>(`/jobs/${jobId}/hosts${qs(p)}`);
  },
  getHost(jobId: string, ip: string): Promise<HostGetResponse> {
    return get<HostGetResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}`);
  },

  // ── Global Hosts (Cross-Job) ──────────────────────────────────────────
  listGlobalHosts(p: GlobalHostListParams = {}): Promise<GlobalHostListResponse> {
    return get<GlobalHostListResponse>(`/hosts${qs(p)}`);
  },
  getGlobalHost(ip: string): Promise<GlobalHostGetResponse> {
    return get<GlobalHostGetResponse>(`/hosts/${encodeURIComponent(ip)}`);
  },
  listConnections(jobId: string, ip: string, p: ConnectionListParams = {}): Promise<ConnectionListResponse> {
    return get<ConnectionListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/connections${qs(p)}`);
  },

  // ── Binary / YARA ──────────────────────────────────────────────────────
  listBinaryAnalyses(jobId: string): Promise<BinaryAnalysisListResponse> {
    return get<BinaryAnalysisListResponse>(`/jobs/${jobId}/binary`);
  },
  /**
   * Both binary endpoints take the file as a raw request body with the name in
   * a query param, not multipart — see _filename_from_request in binary.py.
   * `persist: false` routes to the stateless inspector.
   */
  analyzeBinary(
    file: File,
    opts: { jobId?: string; onProgress?: (pct: number) => void } = {},
  ): Promise<BinaryAnalysisResponse> {
    const path = opts.jobId
      ? `/jobs/${opts.jobId}/binary?filename=${encodeURIComponent(file.name)}`
      : `/binary/inspect?filename=${encodeURIComponent(file.name)}`;
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${API_BASE}${path}`);
      const headers = authHeaders();
      Object.keys(headers).forEach((k) => xhr.setRequestHeader(k, headers[k]));
      if (opts.onProgress) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) opts.onProgress!(Math.round((e.loaded / e.total) * 100));
        };
      }
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch {
            reject(new Error("Invalid JSON response from server"));
          }
        } else {
          let detail = `Analysis failed with status ${xhr.status}`;
          try {
            const body = JSON.parse(xhr.responseText);
            if (body?.detail) detail = body.detail;
          } catch { /* non-JSON error body */ }
          reject(new Error(detail));
        }
      };
      xhr.onerror = () => reject(new Error("Network error during upload"));
      xhr.send(file);
    });
  },

  // ── Sigma ──────────────────────────────────────────────────────────────
  listSigmaDetections(jobId: string): Promise<SigmaDetectionListResponse> {
    return get<SigmaDetectionListResponse>(`/jobs/${jobId}/sigma`);
  },
  analyzeSigma(jobId: string): Promise<SigmaAnalyzeResponse> {
    return post<SigmaAnalyzeResponse>(`/jobs/${jobId}/sigma/analyze`, {});
  },

  // ── Raw events ─────────────────────────────────────────────────────────
  searchRawEvents(jobId: string, p: RawEventSearchParams = {}): Promise<RawEventListResponse> {
    return get<RawEventListResponse>(`/jobs/${jobId}/raw-events${qs(p as any)}`);
  },
  aggregateRawEvents(jobId: string, field: string, limit = 50): Promise<EventAggregationResponse> {
    return get<EventAggregationResponse>(`/jobs/${jobId}/raw-events/aggregate${qs({ field, limit })}`);
  },
  getRawEventFlow(jobId: string, limit = 50): Promise<EventFlowResponse> {
    return get<EventFlowResponse>(`/jobs/${jobId}/raw-events/flow${qs({ limit })}`);
  },

  // ── Streams ────────────────────────────────────────────────────────────
  listStreamPcaps(jobId: string): Promise<StreamPcapListResponse> {
    return get<StreamPcapListResponse>(`/jobs/${jobId}/streams`);
  },
  getStreamAscii(jobId: string, s: StreamSelector): Promise<StreamTranscriptResponse> {
    return get<StreamTranscriptResponse>(`/jobs/${jobId}/streams/ascii${qs(s as any)}`);
  },
  getStreamHexdump(jobId: string, s: StreamSelector): Promise<StreamHexdumpResponse> {
    return get<StreamHexdumpResponse>(`/jobs/${jobId}/streams/hexdump${qs(s as any)}`);
  },
  /** Carve the stream server-side and save it as a .pcap. */
  async downloadStreamPcap(jobId: string, s: StreamSelector): Promise<void> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/streams/pcap${qs(s as any)}`, {
      headers: authHeaders(),
    });
    if (!res.ok) {
      // The server returns 404 when the filter matched no packets — surface
      // that rather than saving an empty file.
      let detail = `Carve failed: ${res.status}`;
      try {
        const body = await res.json();
        if (body?.detail) detail = body.detail;
      } catch { /* non-JSON error body */ }
      throw new Error(detail);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `stream-${s.src}_${s.sport}-${s.dst}_${s.dport}.pcap`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  listDns(jobId: string, ip: string, p: DnsListParams = {}): Promise<DnsQueryListResponse> {
    return get<DnsQueryListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/dns${qs(p)}`);
  },
  listTls(jobId: string, ip: string, p: TlsListParams = {}): Promise<TlsSessionListResponse> {
    return get<TlsSessionListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/tls${qs(p)}`);
  },
  listHostAlerts(jobId: string, ip: string, p: AlertListParams = {}): Promise<AlertListResponse> {
    return get<AlertListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/alerts${qs(p)}`);
  },
  listHostFiles(jobId: string, ip: string, p: FileListParams = {}): Promise<FileListResponse> {
    return get<FileListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/files${qs(p)}`);
  },

  // ── Alerts (job-level) ──────────────────────────────────────────────────
  listAlerts(jobId: string, p: AlertListParams = {}): Promise<AlertListResponse> {
    return get<AlertListResponse>(`/jobs/${jobId}/alerts${qs(p)}`);
  },
  getAlert(jobId: string, alertId: string): Promise<AlertDetailResponse> {
    return get<AlertDetailResponse>(`/jobs/${jobId}/alerts/${alertId}`);
  },

  // ── Findings ───────────────────────────────────────────────────────────
  listFindings(jobId: string, p: FindingListParams = {}): Promise<FindingListResponse> {
    return get<FindingListResponse>(`/jobs/${jobId}/findings${qs(p)}`);
  },
  getFinding(jobId: string, findingId: string): Promise<FindingDetailResponse> {
    return get<FindingDetailResponse>(`/jobs/${jobId}/findings/${findingId}`);
  },
  explainFinding(jobId: string, findingId: string, body: FindingExplainRequest): Promise<FindingExplainResponse> {
    return post<FindingExplainResponse>(`/jobs/${jobId}/findings/${findingId}/explain`, body);
  },

  // ── Theories ───────────────────────────────────────────────────────────
  listJobTheories(jobId: string, p: { pcap_label?: string } = {}): Promise<TheoryListResponse> {
    return get<TheoryListResponse>(`/jobs/${jobId}/theories${qs(p)}`);
  },
  listHostTheories(jobId: string, ip: string): Promise<TheoryListResponse> {
    return get<TheoryListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/theories`);
  },
  generateTheories(jobId: string): Promise<TheoryListResponse> {
    return post<TheoryListResponse>(`/jobs/${jobId}/theories/generate`);
  },
  explainTheory(jobId: string, theoryId: string): Promise<TheoryExplainResponse> {
    return post<TheoryExplainResponse>(`/jobs/${jobId}/theories/${encodeURIComponent(theoryId)}/explain`, { format: "markdown" });
  },

  // ── Slices ────────────────────────────────────────────────────────────
  listSlices(jobId: string, p: { pcap_label?: string } = {}): Promise<SliceListResponse> {
    return get<SliceListResponse>(`/jobs/${jobId}/slices${qs(p)}`);
  },
  getSlice(jobId: string, sliceId: string): Promise<SliceDetailResponse> {
    return get<SliceDetailResponse>(`/jobs/${jobId}/slices/${encodeURIComponent(sliceId)}`);
  },
  generateSlices(jobId: string): Promise<SliceListResponse> {
    return post<SliceListResponse>(`/jobs/${jobId}/slices/generate`);
  },

  // ── Annotations (Why Unusual?) ─────────────────────────────────────────
  listAnnotations(jobId: string, hostIp?: string, pcapLabel?: string): Promise<ContextAnnotationListResponse> {
    const p: Record<string, string> = {};
    if (hostIp) p.host_ip = hostIp;
    if (pcapLabel) p.pcap_label = pcapLabel;
    return get<ContextAnnotationListResponse>(`/jobs/${jobId}/annotations${qs(p)}`);
  },
  generateAnnotations(jobId: string): Promise<ContextAnnotationListResponse> {
    return post<ContextAnnotationListResponse>(`/jobs/${jobId}/annotations/generate`);
  },

  // ── Reports ─────────────────────────────────────────────────────────
  listReports(jobId: string): Promise<ReportListResponse> {
    return get<ReportListResponse>(`/jobs/${jobId}/reports`);
  },
  getReport(jobId: string, reportId: string): Promise<ReportDetailResponse> {
    return get<ReportDetailResponse>(`/jobs/${jobId}/reports/${reportId}`);
  },
  generateReport(jobId: string, mode: "executive" | "analyst" = "analyst", pcapLabel?: string): Promise<ReportDetailResponse> {
    const body: Record<string, string> = { mode };
    if (pcapLabel) body.pcap_label = pcapLabel;
    return post<ReportDetailResponse>(`/jobs/${jobId}/reports/generate`, body);
  },

  // ── Proofs ──────────────────────────────────────────────────────────
  listProofs(jobId: string): Promise<ProofListResponse> {
    return get<ProofListResponse>(`/jobs/${jobId}/proofs`);
  },
  getProof(jobId: string, proofId: string): Promise<ProofDetailResponse> {
    return get<ProofDetailResponse>(`/jobs/${jobId}/proofs/${proofId}`);
  },
  createProof(jobId: string, body: { title: string; conclusion?: string; severity?: string; confidence?: number; mode?: ProofMode }): Promise<ProofDetailResponse> {
    return post<ProofDetailResponse>(`/jobs/${jobId}/proofs`, body);
  },
  updateProof(jobId: string, proofId: string, body: Record<string, unknown>): Promise<ProofDetailResponse> {
    return patch<ProofDetailResponse>(`/jobs/${jobId}/proofs/${proofId}`, body);
  },
  deleteProof(jobId: string, proofId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/proofs/${proofId}`);
  },
  listProofItems(jobId: string, proofId: string): Promise<ProofItemListResponse> {
    return get<ProofItemListResponse>(`/jobs/${jobId}/proofs/${proofId}/items`);
  },
  addProofItem(jobId: string, proofId: string, body: { entity_type: string; entity_id: string; role?: string; analyst_note?: string }): Promise<ProofItemDetailResponse> {
    return post<ProofItemDetailResponse>(`/jobs/${jobId}/proofs/${proofId}/items`, body);
  },
  removeProofItem(jobId: string, proofId: string, itemId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/proofs/${proofId}/items/${itemId}`);
  },
  renderProofNarrative(jobId: string, proofId: string): Promise<ProofNarrativeResponse> {
    return post<ProofNarrativeResponse>(`/jobs/${jobId}/proofs/${proofId}/narrative`, {});
  },
  exportProof(jobId: string, proofId: string, fmt: "markdown" | "html" = "markdown"): Promise<ProofExportResponse> {
    return get<ProofExportResponse>(`/jobs/${jobId}/proofs/${proofId}/export?fmt=${fmt}`);
  },

  // ── Timeline ───────────────────────────────────────────────────────────
  listTimeline(jobId: string, p: TimelineListParams = {}): Promise<TimelineListResponse> {
    return get<TimelineListResponse>(`/jobs/${jobId}/timeline${qs(p)}`);
  },

  // ── IOCs ───────────────────────────────────────────────────────────────
  listIocs(jobId: string, p: IocListParams = {}): Promise<IocListResponse> {
    return get<IocListResponse>(`/jobs/${jobId}/iocs${qs(p)}`);
  },

  // ── Artifacts ──────────────────────────────────────────────────────────
  listArtifacts(jobId: string): Promise<ArtifactListResponse> {
    return get<ArtifactListResponse>(`/jobs/${jobId}/artifacts`);
  },
  listFiles(jobId: string, params: { cursor?: string; limit?: number }): Promise<FileListResponse> {
    return get<FileListResponse>(`/jobs/${jobId}/files${qs(params)}`);
  },
  getJobGraph(jobId: string): Promise<JobGraphResponse> {
    return get<JobGraphResponse>(`/jobs/${jobId}/graph`);
  },
  getEvidenceGraph(jobId: string, include?: string[]): Promise<EvidenceGraphResponse> {
    const params = include?.length ? `?include=${include.join(",")}` : "";
    return get<EvidenceGraphResponse>(`/jobs/${jobId}/evidence-graph${params}`);
  },
  getStoryline(jobId: string): Promise<StorylineResponse> {
    return get<StorylineResponse>(`/jobs/${jobId}/storyline`);
  },
  generateEvidencePackage(jobId: string): Promise<EvidencePackageCreateResponse> {
    return post<EvidencePackageCreateResponse>(`/jobs/${jobId}/artifacts/evidence-package`);
  },
  getArtifactDownloadUrl(artifactId: string): string {
    return `${API_BASE}/artifacts/${artifactId}/download`;
  },
  async downloadArtifact(artifactId: string, filename?: string): Promise<void> {
    const res = await fetch(`${API_BASE}/artifacts/${artifactId}/download`, {
      headers: authHeaders(),
    });
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || `artifact-${artifactId}.zip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  async downloadExtractedFile(jobId: string, fileId: string, filename?: string): Promise<void> {
    const res = await fetch(`${API_BASE}/jobs/${jobId}/files/${encodeURIComponent(fileId)}/download`, {
      headers: authHeaders(),
    });
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || fileId;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  // ── System ─────────────────────────────────────────────────────────────
  getHealth(): Promise<HealthResponse> { return get<HealthResponse>("/health"); },
  getSystemConfig(): Promise<SystemConfigResponse> { return get<SystemConfigResponse>("/system/config"); },
  getExplainTelemetry(): Promise<ExplainTelemetryResponse> {
    return get<ExplainTelemetryResponse>("/system/explain-telemetry");
  },
  resetExplainTelemetry(): Promise<ExplainTelemetryResponse> {
    return post<ExplainTelemetryResponse>("/system/explain-telemetry/reset");
  },
  getOllamaStatus(): Promise<OllamaGpuStatusResponse> {
    return get<OllamaGpuStatusResponse>("/system/ollama-status");
  },

  // ── SSE ────────────────────────────────────────────────────────────────
  /** Create an EventSource for job progress. Caller is responsible for closing it. */
  createJobEventSource(jobId: string, lastEventId?: string): EventSource {
    // EventSource does not support custom headers, so pass the token as a
    // query parameter. The backend's verify_token_or_query accepts both.
    const tokenQs = _token ? `?token=${encodeURIComponent(_token)}` : "";
    const url = `${API_BASE}/jobs/${jobId}/events${tokenQs}`;
    const es = new EventSource(url);
    return es;
  },

  // ── Temporal Analysis ────────────────────────────────────────────────
  getTemporalDelta(jobId: string): Promise<TemporalDeltaResponse> {
    return get<TemporalDeltaResponse>(`/jobs/${jobId}/temporal-delta`);
  },
  getTemporalFlows(jobId: string): Promise<TemporalFlowsResponse> {
    return get<TemporalFlowsResponse>(`/jobs/${jobId}/temporal-flows`);
  },
  generateTemporalNarrative(jobId: string): Promise<TemporalNarrativeResponse> {
    return post<TemporalNarrativeResponse>(`/jobs/${jobId}/temporal-narrative`);
  },
  getTemporalExportUrl(jobId: string, format: "markdown" | "html" = "markdown"): string {
    const tokenQs = _token ? `?token=${encodeURIComponent(_token)}&format=${format}` : `?format=${format}`;
    return `${API_BASE}/jobs/${jobId}/temporal-export${tokenQs}`;
  },
  getTemporalCorrelations(
    jobId: string,
    opts: { offset?: number; limit?: number; minScore?: number } = {},
  ): Promise<TemporalCorrelationsResponse> {
    const qs = new URLSearchParams();
    if (opts.offset != null) qs.set("offset", String(opts.offset));
    if (opts.limit != null) qs.set("limit", String(opts.limit));
    if (opts.minScore != null) qs.set("min_score", String(opts.minScore));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return get<TemporalCorrelationsResponse>(`/jobs/${jobId}/temporal-correlations${suffix}`);
  },

  // ── PCAP Management ─────────────────────────────────────────────────
  addJobPcap(jobId: string, body: { upload_id: string; label: string }): Promise<void> {
    return post<void>(`/jobs/${jobId}/pcaps`, body);
  },
  reanalyzeJob(jobId: string, pcapLabel: string): Promise<{ job_id: string; pcap_label: string; status: string }> {
    return post<{ job_id: string; pcap_label: string; status: string }>(`/jobs/${jobId}/reanalyze`, { pcap_label: pcapLabel });
  },

  // ═══════════════════════════════════════════════════════════════════════
  // V1 LEGACY METHOD STUBS  (keep existing pages compiling until refactored)
  // ═══════════════════════════════════════════════════════════════════════

  /** @deprecated V1 */
  createJobFromSecurityOnion(payload: any): Promise<{ job_id: string }> { return post<{ job_id: string }>("/jobs/from_security_onion", payload); },
  /** @deprecated V1 */
  createJobFromArkime(payload: any): Promise<{ job_id: string }> { return post<{ job_id: string }>("/jobs/from_arkime", payload); },

  // ── Settings (V1) ──
  /** @deprecated V1 */
  getSettings(): Promise<SettingsPayload> { return get<SettingsPayload>("/settings"); },
  /** @deprecated V1 */
  updateSettings(values: Record<string, any>): Promise<SettingsPayload> {
    return request<SettingsPayload>(`${API_BASE}/settings`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(values) });
  },
  /** @deprecated V1 */
  testLlmConnection(body: Record<string, any>): Promise<any> { return post<any>("/settings/test_llm", body); },
  /** @deprecated V1 */
  getEffectiveSettings(): Promise<EffectiveSettingsResponse> { return get<EffectiveSettingsResponse>("/admin/effective_settings"); },
  /** @deprecated V1 */
  getAvailableModels(): Promise<OllamaModelInfo[]> { return get<any>("/models/available").then((r: any) => r.models ?? r); },
  /** @deprecated V1 */
  getSetupStatus(): Promise<SetupStatusResponse> { return get<SetupStatusResponse>("/settings/setup_status"); },
  /** @deprecated V1 */
  validateStoragePath(path: string): Promise<any> { return post<any>("/settings/validate_storage_path", { path }); },

  // ── Knowledge Base (per-job) ──
  listKBDocuments(jobId: string, docType?: string): Promise<KBDocumentListOut> {
    const qs = docType ? `?doc_type=${encodeURIComponent(docType)}` : "";
    return get<KBDocumentListOut>(`/jobs/${jobId}/kb/documents${qs}`);
  },
  uploadKBDocument(jobId: string, body: KBDocumentCreate): Promise<KBDocumentOut> { return post<KBDocumentOut>(`/jobs/${jobId}/kb/documents`, body); },
  uploadKBBinaryFile(jobId: string, file: File, name: string, docType: string, description?: string): Promise<KBDocumentOut> {
    const form = new FormData();
    form.append("file", file);
    form.append("name", name);
    form.append("doc_type", docType);
    if (description) form.append("description", description);
    return request<KBDocumentOut>(`${API_BASE}/jobs/${jobId}/kb/upload-binary`, { method: "POST", body: form });
  },
  getKBDocument(jobId: string, docId: string): Promise<KBDocumentDetail> { return get<KBDocumentDetail>(`/jobs/${jobId}/kb/documents/${docId}`); },
  deleteKBDocument(jobId: string, docId: string): Promise<void> { return del<void>(`/jobs/${jobId}/kb/documents/${docId}`); },
  searchKB(jobId: string, query: string, nResults?: number, docType?: string): Promise<KBSearchResponse> {
    return post<KBSearchResponse>(`/jobs/${jobId}/kb/search`, { query, n_results: nResults ?? 5, doc_type: docType });
  },

  // ── Chat ──
  chatWithJob(jobId: string, body: ChatRequest): Promise<ChatResponse> { return post<ChatResponse>(`/jobs/${jobId}/chat`, body); },
  listConversations(jobId: string): Promise<ConversationSummary[]> {
    return get<ConversationSummary[]>(`/jobs/${jobId}/conversations`);
  },
  getConversation(jobId: string, convId: string): Promise<ConversationHistoryOut> {
    return get<ConversationHistoryOut>(`/jobs/${jobId}/conversations/${convId}`);
  },
  renameConversation(jobId: string, convId: string, title: string): Promise<ConversationSummary> {
    return patch<ConversationSummary>(`/jobs/${jobId}/conversations/${convId}`, { title });
  },
  deleteConversation(jobId: string, convId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/conversations/${convId}`);
  },

  // ── Rules ──
  listSuricataRules(): Promise<SuricataRuleItem[]> {
    return get<SuricataRuleItem[]>("/rules/suricata");
  },
  getSuricataRule(filename: string): Promise<SuricataRuleItem> {
    return get<SuricataRuleItem>(`/rules/suricata/${filename}`);
  },
  updateSuricataRule(filename: string, content: string): Promise<SuricataRuleItem> {
    return put<SuricataRuleItem>(`/rules/suricata/${filename}`, { content });
  },
  deleteSuricataRule(filename: string): Promise<void> {
    return del<void>(`/rules/suricata/${filename}`);
  },
  // ── Parsed Rules ──
  getRuleFileStats(filename: string): Promise<RuleFileStats> {
    return get<RuleFileStats>(`/rules/suricata/${filename}/stats`);
  },
  getParsedRules(filename: string, params: {
    search?: string; category?: string; enabled?: boolean;
    severity?: number; offset?: number; limit?: number;
  } = {}): Promise<ParsedRuleListResponse> {
    return get<ParsedRuleListResponse>(`/rules/suricata/${filename}/parsed${qs(params)}`);
  },
  toggleRules(filename: string, body: ToggleRulesRequest): Promise<{ changed: number; total_targeted: number; enabled: boolean }> {
    return post<{ changed: number; total_targeted: number; enabled: boolean }>(`/rules/suricata/${filename}/toggle`, body);
  },

  // ── Detection-as-Code: Rule Generation ──
  generateRule(jobId: string, findingId: string, ruleType: RuleType): Promise<GeneratedRuleResponse> {
    return post<GeneratedRuleResponse>(`/jobs/${jobId}/findings/${findingId}/generate-rule`, { rule_type: ruleType });
  },

  // ── Training (V1) ──
  /** @deprecated V1 */
  startTrainingJob(): Promise<any> { return post<any>("/training/start"); },
  /** @deprecated V1 */
  getTrainingSummary(): Promise<TrainingSummary> { return get<TrainingSummary>("/training/summary"); },
  /** @deprecated V1 */
  getTrainingLedger(): Promise<TrainingLedgerResponse> { return get<TrainingLedgerResponse>("/training/ledger"); },
  /** @deprecated V1 */
  getTrainingConfig(): Promise<TrainingConfig> { return get<TrainingConfig>("/training/config"); },
  /** @deprecated V1 */
  getTrainingStatus(): Promise<TrainingStatus> { return get<TrainingStatus>("/training/status"); },
  /** @deprecated V1 */
  pauseTraining(): Promise<any> { return post<any>("/training/pause"); },
  /** @deprecated V1 */
  stopTraining(): Promise<any> { return post<any>("/training/stop"); },

  // ── Frontier Knowledge Distillation ──
  getDistillConfig(): Promise<DistillConfig> { return get<DistillConfig>("/training/distill/config"); },
  updateDistillConfig(cfg: Partial<DistillConfigUpdate>): Promise<any> { return post<any>("/training/distill/config", cfg); },
  getDistillStats(): Promise<DistillStats> { return get<DistillStats>("/training/distill/stats"); },
  testTeacher(): Promise<any> { return post<any>("/training/distill/test"); },

  // ── Merge & Deploy (LoRA → GGUF → Ollama) ──
  exportModel(): Promise<any> { return post<any>("/training/export"); },
  getExportStatus(): Promise<ExportStatus> { return get<ExportStatus>("/training/export/status"); },

  // ── Investigation Queue ──
  getInvestigationQueue(jobId: string, params?: {
    status?: AnalystStatus; source?: QueueItemSource; severity?: string;
    q?: string; offset?: number; limit?: number;
    host?: string; mitre_id?: string; has_corroboration?: boolean; reviewed?: boolean;
  }): Promise<InvestigationQueueResponse> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.source) qs.set("source", params.source);
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.q) qs.set("q", params.q);
    if (params?.offset != null) qs.set("offset", String(params.offset));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    if (params?.host) qs.set("host", params.host);
    if (params?.mitre_id) qs.set("mitre_id", params.mitre_id);
    if (params?.has_corroboration != null) qs.set("has_corroboration", String(params.has_corroboration));
    if (params?.reviewed != null) qs.set("reviewed", String(params.reviewed));
    const q = qs.toString();
    return get<InvestigationQueueResponse>(`/jobs/${jobId}/investigation-queue${q ? `?${q}` : ""}`);
  },
  getEvidenceBundle(jobId: string, itemId: string): Promise<EvidenceBundleResponse> {
    return get<EvidenceBundleResponse>(`/jobs/${jobId}/investigation-queue/${encodeURIComponent(itemId)}/evidence-bundle`);
  },
  updateQueueItemStatus(jobId: string, itemId: string, body: StatusUpdateRequest): Promise<StatusUpdateResponse> {
    return patch<StatusUpdateResponse>(`/jobs/${jobId}/investigation-queue/${encodeURIComponent(itemId)}/status`, body);
  },
  bulkUpdateQueueStatus(jobId: string, body: BulkStatusUpdateRequest): Promise<BulkStatusUpdateResponse> {
    return post<BulkStatusUpdateResponse>(`/jobs/${jobId}/investigation-queue/bulk-status`, body);
  },
  getReviewQueue(jobId: string, params?: {
    status?: AnalystStatus; reviewer?: string; since?: string;
    offset?: number; limit?: number;
  }): Promise<ReviewQueueResponse> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.reviewer) qs.set("reviewer", params.reviewer);
    if (params?.since) qs.set("since", params.since);
    if (params?.offset != null) qs.set("offset", String(params.offset));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    const q = qs.toString();
    return get<ReviewQueueResponse>(`/jobs/${jobId}/review-queue${q ? `?${q}` : ""}`);
  },

  // ── Admin / Feedback Metrics ─────────────────────────────────────────
  getFeedbackMetrics(): Promise<FeedbackMetricsResponse> {
    return get<FeedbackMetricsResponse>("/admin/feedback-metrics");
  },

  // ── Cross-Job Correlation (Sprint 8) ──────────────────────────────────
  getCorrelations(
    jobId: string,
    params?: { item_id?: string; host?: string; ioc?: string; limit?: number },
  ): Promise<CorrelationResponse> {
    const qs = new URLSearchParams();
    if (params?.item_id) qs.set("item_id", params.item_id);
    if (params?.host) qs.set("host", params.host);
    if (params?.ioc) qs.set("ioc", params.ioc);
    if (params?.limit != null) qs.set("limit", String(params.limit));
    const q = qs.toString();
    return get<CorrelationResponse>(`/jobs/${jobId}/correlations${q ? `?${q}` : ""}`);
  },
  getRelatedJobs(jobId: string): Promise<RelatedJobsResponse> {
    return get<RelatedJobsResponse>(`/jobs/${jobId}/related-jobs`);
  },

  // ── Arkime ──────────────────────────────────────────────────────────────
  triggerArkimeImport(jobId: string): Promise<ArkimeImportResponse> {
    return post<ArkimeImportResponse>(`/jobs/${jobId}/arkime/import`);
  },
  getArkimeStatus(jobId: string): Promise<ArkimeStatusResponse> {
    return get<ArkimeStatusResponse>(`/jobs/${jobId}/arkime/status`);
  },
  getAlertArkimeLink(jobId: string, alertId: string): Promise<ArkimePivotResponse> {
    return get<ArkimePivotResponse>(`/jobs/${jobId}/alerts/${alertId}/arkime-link`);
  },
  getFindingArkimeLink(jobId: string, findingId: string): Promise<ArkimePivotResponse> {
    return get<ArkimePivotResponse>(`/jobs/${jobId}/findings/${findingId}/arkime-link`);
  },

  // ── Security Onion Import ──────────────────────────────────────────────
  triggerSecurityOnionImport(jobId: string): Promise<SecurityOnionImportResponse> {
    return post<SecurityOnionImportResponse>(`/jobs/${jobId}/security_onion/import`);
  },

  // ── Telemetry event detail ──────────────────────────────────────────
  getTelemetryEventDetail(jobId: string, eventId: string): Promise<TelemetryEventDetail> {
    return get<TelemetryEventDetail>(`/jobs/${jobId}/telemetry/${encodeURIComponent(eventId)}`);
  },

  // ── Integration Settings (Security Onion / Arkime) ───────────────────
  getIntegrationSettings(): Promise<IntegrationSettingsPayload> {
    return get<IntegrationSettingsPayload>("/integrations/settings");
  },
  saveIntegrationSettings(values: IntegrationSettingsPayload): Promise<IntegrationSettingsPayload> {
    return request<IntegrationSettingsPayload>(`${API_BASE}/integrations/settings`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(values),
    });
  },
  testIntegrationConnection(body: IntegrationTestRequest): Promise<IntegrationTestResponse> {
    return post<IntegrationTestResponse>("/integrations/test", body);
  },
};

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
export interface ChatEvidenceRef { type: string; id?: string; label: string }
export interface ChatRequest { message: string; conversation_id?: string; context_hint?: string }
export interface ChatResponse { response: string; citations: ChatCitation[]; conversation_id: string; confidence?: number; evidence_refs?: ChatEvidenceRef[]; suggested_followups?: string[] }
export interface ConversationSummary { id: string; job_id: string; created_at: string; updated_at: string; title?: string; message_count: number }
export interface ConversationHistoryOut { id: string; job_id: string; messages: any[]; created_at: string; updated_at: string }
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
export interface KBDocumentOut { id: string; job_id: string; name: string; doc_type: string; description?: string; filename?: string; chunk_count: number; status: string; error_message?: string; created_at: string; updated_at: string }
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