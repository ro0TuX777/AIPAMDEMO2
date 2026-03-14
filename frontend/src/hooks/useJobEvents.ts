import { useEffect, useRef, useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type {
  SseEventType,
  SseEnvelope,
  SseJobStatusData,
  SseJobCompleteData,
  SseStageStatusData,
  SseSensorStatusData,
  SseSensorLogData,
  SseSensorFindingData,
  SseArtifactCreatedData,
  SseQuotaHitData,
  SseDiskWarningData,
  SseResetData,
  JobStatus,
} from "../api";

// ─── Public event map (consumers subscribe by event type) ────────────────────

export interface JobEventMap {
  "job.status": SseJobStatusData;
  "job.complete": SseJobCompleteData;
  "stage.status": SseStageStatusData;
  "sensor.status": SseSensorStatusData;
  "sensor.log": SseSensorLogData;
  "sensor.finding": SseSensorFindingData;
  "artifact.created": SseArtifactCreatedData;
  "quota.hit": SseQuotaHitData;
  "disk.warning": SseDiskWarningData;
  "heartbeat": { job_id: string };
  "reset": SseResetData;
}

export type JobEventHandler<K extends keyof JobEventMap> = (data: JobEventMap[K]) => void;

// ─── Terminal statuses that stop SSE ─────────────────────────────────────────

const TERMINAL_STATUSES: Set<string> = new Set([
  "completed", "completed_with_errors", "failed", "canceled", "deleted",
]);

// ─── Hook ────────────────────────────────────────────────────────────────────

export interface UseJobEventsOptions {
  /** If false, the EventSource is not opened. Defaults to true. */
  enabled?: boolean;
  /** Callback map keyed by SSE event type. */
  on?: { [K in keyof JobEventMap]?: JobEventHandler<K> };
}

const API_BASE =
  (import.meta as any).env?.VITE_API_BASE_URL?.replace(/\/$/, "") ||
  "/api/v1";

const SSE_TOKEN = (import.meta as any).env?.VITE_API_TOKEN as string | undefined;

/**
 * React hook that opens an SSE connection for a job's event stream.
 *
 * - Automatically reconnects (native EventSource behaviour + Last-Event-ID).
 * - Invalidates React Query caches on status changes.
 * - Closes the connection when the job reaches a terminal state or on unmount.
 */
export function useJobEvents(
  jobId: string | undefined,
  options: UseJobEventsOptions = {},
) {
  const { enabled = true, on } = options;
  const queryClient = useQueryClient();
  const esRef = useRef<EventSource | null>(null);
  const lastEventIdRef = useRef<string | undefined>(undefined);
  const [connected, setConnected] = useState(false);
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null);
  const [progress, setProgress] = useState<{ step: number; total: number; label: string } | null>(null);

  // Stable ref for callbacks so effect doesn't re-run on every render
  const onRef = useRef(on);
  onRef.current = on;

  const close = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    setConnected(false);
  }, []);

  useEffect(() => {
    if (!jobId || !enabled) { close(); return; }

    const tokenQs = SSE_TOKEN ? `?token=${encodeURIComponent(SSE_TOKEN)}` : "";
    const url = `${API_BASE}/jobs/${jobId}/events${tokenQs}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    // Generic message handler — all events arrive here
    es.onmessage = (evt: MessageEvent) => {
      try {
        const envelope: SseEnvelope = JSON.parse(evt.data);
        const { type, data } = envelope;

        // Track last event id for reconnection
        if (evt.lastEventId) lastEventIdRef.current = evt.lastEventId;

        // Dispatch to caller's handler
        const handler = onRef.current?.[type as keyof JobEventMap];
        if (handler) (handler as any)(data);

        // React Query cache invalidation
        switch (type) {
          case "job.status":
            setJobStatus((data as SseJobStatusData).status);
            queryClient.invalidateQueries({ queryKey: ["job", jobId] });
            if (TERMINAL_STATUSES.has((data as SseJobStatusData).status)) close();
            break;
          case "job.complete":
            setJobStatus((data as SseJobCompleteData).status);
            queryClient.invalidateQueries({ queryKey: ["job", jobId] });
            close();
            break;
          case "stage.status": {
            const stage = data as SseStageStatusData;
            if (stage.step && stage.total_steps) {
              setProgress({ step: stage.step, total: stage.total_steps, label: `${stage.stage}: ${stage.status}` });
            }
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "sensors"] });
            break;
          }
          case "sensor.status": {
            const sensor = data as SseSensorStatusData;
            if (sensor.step && sensor.total_steps) {
              setProgress({ step: sensor.step, total: sensor.total_steps, label: `${sensor.sensor}: ${sensor.status}` });
            }
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "sensors"] });
            break;
          }
          case "sensor.finding":
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] });
            break;
          case "artifact.created":
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "artifacts"] });
            break;
          case "reset":
            // Server told us to refetch everything
            queryClient.invalidateQueries({ queryKey: ["job", jobId] });
            break;
        }
      } catch {
        // Ignore malformed events
      }
    };

    return () => close();
  }, [jobId, enabled, queryClient, close]);

  return { connected, jobStatus, progress, close };
}

