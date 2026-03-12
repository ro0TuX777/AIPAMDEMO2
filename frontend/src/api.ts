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

export interface JobPcapItem {
  id: number;
  upload_id: string;
  label?: string | null;
  filename: string;
  ordinal: number;
  size_bytes?: number | null;
  sha256?: string | null;
}

export interface JobCreateRequest {
  upload_id?: string;           // backward compat: single upload
  uploads?: PcapUploadItem[];   // multi-PCAP: list of uploads with optional labels
  job_name?: string;
  notes?: string;
  execution_profile: ExecutionProfile;
  priority?: Priority;
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

export interface JobDetail extends JobListItem {
  metrics?: JobMetrics;
  stages?: StageItem[];
  sensors?: SensorItem[];
  pcaps?: JobPcapItem[];
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
}

export type FindingExplainFeedback = "useful" | "not_useful";

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
  | "quota.hit" | "disk.warning" | "heartbeat" | "reset";

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
export interface SseStageStatusData { job_id: string; stage: string; status: string; message?: string | null }
export interface SseSensorStatusData { job_id: string; sensor: string; status: SensorStatus; message?: string | null }
export interface SseSensorLogData { job_id: string; sensor: string; stream: "stdout" | "stderr"; line: string }
export interface SseSensorFindingData { job_id: string; sensor: string; finding_id: string; severity: Severity; title?: string | null }
export interface SseArtifactCreatedData { job_id: string; artifact_id: string; type: string }
export interface SseQuotaHitData { job_id: string; quota_type: "disk" | "extracted_bytes"; message?: string | null }
export interface SseDiskWarningData { usage_pct: number; free_bytes: number; threshold_pct: number; message?: string | null }
export interface SseHeartbeatData { job_id: string }
export interface SseResetData { reason: "event_id_expired" }

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
}

export interface ConnectionListParams extends PaginationParams {
  direction?: "inbound" | "outbound" | "any";
  proto?: "tcp" | "udp" | "icmp" | "any";
  dest_ip?: string;
  dest_port?: number;
  service?: string;
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
  end_ts?: string;
}

export interface TlsListParams extends PaginationParams {
  sni?: string;
  ja3?: string;
  issuer?: string;
  community_id?: string;
  start_ts?: string;
  end_ts?: string;
}

export interface AlertListParams extends PaginationParams {
  severity?: Severity;
  category?: string;
  sid?: string;
  community_id?: string;
  start_ts?: string;
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
}

// ─── API Error ──────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public details?: Record<string, unknown>,
    public retryAfter?: number,
  ) {
    super(`[${status}] ${code}`);
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
  explainFinding(jobId: string, findingId: string, body: FindingExplainRequest): Promise<FindingExplainResponse> {
    return post<FindingExplainResponse>(`/jobs/${jobId}/findings/${findingId}/explain`, body);
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

  // ═══════════════════════════════════════════════════════════════════════
  // V1 LEGACY METHOD STUBS  (keep existing pages compiling until refactored)
  // ═══════════════════════════════════════════════════════════════════════

  /** @deprecated V1 — returns flat array */
  getJobs(): Promise<JobStatusResponse[]> { return get<JobStatusResponse[]>("/jobs"); },
  /** @deprecated V1 — returns V1 shape. Shadows V2 getJobDetail for legacy pages. */
  getJob(jobId: string): Promise<JobStatusResponse> { return get<JobStatusResponse>(`/jobs/${jobId}`); },
  /** @deprecated V1 */
  getJobResult(jobId: string): Promise<JobResultResponse> { return get<JobResultResponse>(`/jobs/${jobId}/result`); },
  /** @deprecated V1 */
  getPartialResult(jobId: string): Promise<PartialResultResponse> { return get<PartialResultResponse>(`/jobs/${jobId}/partial_result`); },
  /** @deprecated V1 */
  generateSimulation(jobId: string): Promise<any> { return post<any>(`/jobs/${jobId}/simulation`); },

  /** @deprecated V1 multipart upload */
  createJobUpload(files: File[], mode: string, meta?: Record<string, any>): Promise<{ job_id: string }> {
    const form = new FormData();
    files.forEach(f => form.append("pcap_files", f));
    form.append("mode", mode);
    if (meta) Object.entries(meta).forEach(([k, v]) => form.append(k, typeof v === "string" ? v : JSON.stringify(v)));
    return request<{ job_id: string }>(`${API_BASE}/jobs`, { method: "POST", body: form });
  },
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
};

// ═══════════════════════════════════════════════════════════════════════════
// V1 BACKWARD-COMPATIBLE ALIASES (to be removed when pages are refactored)
// ═══════════════════════════════════════════════════════════════════════════

/** @deprecated Use JobListItem / JobDetail instead */
export interface JobStatusResponse {
  job_id: string;
  status: string;
  created_at: string;
  updated_at: string;
  steps: { name: string; status: string; message?: string }[];
  error_message?: string;
}

/** @deprecated Use JobResultResponse → JobSummaryResponse */
export interface JobResultResponse {
  job_id: string;
  status: string;
  summary: { classification?: string; severity: string; key_findings: any[]; mitre_techniques: any[] };
  hosts: any[];
  raw: { alerts?: any[]; llm_analysis_raw?: { chunks?: any[]; summary?: any }; anomaly_detection?: AnomalyReport | null };
  report_urls: Record<string, string>;
}

/** @deprecated V1 anomaly types */
export interface AnomalyFinding {
  category: string; severity: string; description: string;
  evidence: string[]; affected_hosts: string[]; confidence: number; chain_of_thought: string;
}
export interface AnomalyReport {
  findings: AnomalyFinding[]; overall_anomaly_score: number; zero_day_likelihood: string; summary: string;
}

/** @deprecated */
export interface PartialResultResponse {
  flow_count: number; alert_count: number; top_alerts: any[];
  host_summaries: any[]; anomaly_detection: AnomalyReport | null; trafficllm: any | null;
}

/** @deprecated Use SystemConfigResponse */
export interface SettingsPayload { [key: string]: any }
export interface EffectiveSettingsResponse { [key: string]: any }
export interface OllamaModelInfo { name: string; size: number; family: string; parameter_size: string; quantization: string }
export interface SetupStatusResponse { model_configured: boolean; llm_model_name: string | null }

// ─── Chat types ─────────────────────────────────────────────────────────────
export interface ChatCitation { type: string; id?: string; snippet: string }
export interface ChatRequest { message: string; conversation_id?: string; context_hint?: string }
export interface ChatResponse { response: string; citations: ChatCitation[]; conversation_id: string; confidence?: number }
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

// ─── Knowledge Base types ───────────────────────────────────────────────────
export type KBDocType = "asset_inventory" | "network_map" | "baseline_profile" | "threat_intel" | "soc_playbook" | "other";
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