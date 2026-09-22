import type {
  RawEventListResponse,
  RawEventSearchParams,
  EventAggregationResponse,
  EventFlowResponse,
  StreamPcapListResponse,
  StreamSelector,
  StreamTranscriptResponse,
  StreamHexdumpResponse,
  TelemetryEventDetail,
} from "./types";
import {
  API_BASE,
  qs,
  authHeaders,
  get,
} from "./transport";

export const eventsApi = {
  searchRawEvents(jobId: string, p: RawEventSearchParams = {}): Promise<RawEventListResponse> {
    return get<RawEventListResponse>(`/jobs/${jobId}/raw-events${qs(p as any)}`);
  },

  aggregateRawEvents(jobId: string, field: string, limit = 50): Promise<EventAggregationResponse> {
    return get<EventAggregationResponse>(`/jobs/${jobId}/raw-events/aggregate${qs({ field, limit })}`);
  },

  getRawEventFlow(jobId: string, limit = 50): Promise<EventFlowResponse> {
    return get<EventFlowResponse>(`/jobs/${jobId}/raw-events/flow${qs({ limit })}`);
  },

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

  getTelemetryEventDetail(jobId: string, eventId: string): Promise<TelemetryEventDetail> {
    return get<TelemetryEventDetail>(`/jobs/${jobId}/telemetry/${encodeURIComponent(eventId)}`);
  },
};
