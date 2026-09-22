import type {
  HostListResponse,
  HostGetResponse,
  GlobalHostListResponse,
  GlobalHostGetResponse,
  GlobalHostListParams,
  ConnectionListResponse,
  DnsQueryListResponse,
  TlsSessionListResponse,
  AlertListResponse,
  FileListResponse,
  HostListParams,
  ConnectionListParams,
  DnsListParams,
  TlsListParams,
  AlertListParams,
  FileListParams,
} from "./types";
import {
  qs,
  get,
} from "./transport";

export const hostsApi = {
  listHosts(jobId: string, p: HostListParams = {}): Promise<HostListResponse> {
    return get<HostListResponse>(`/jobs/${jobId}/hosts${qs(p)}`);
  },

  getHost(jobId: string, ip: string): Promise<HostGetResponse> {
    return get<HostGetResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}`);
  },

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
};
