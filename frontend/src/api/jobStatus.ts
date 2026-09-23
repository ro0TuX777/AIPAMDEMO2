import type { JobStatus } from "./types";

const active = new Set<JobStatus>(["queued", "running", "canceling", "deleting"]);
const terminal = new Set<JobStatus>(["completed", "completed_with_errors", "failed", "canceled", "deleted"]);
const chatReady = new Set<JobStatus>(["completed", "completed_with_errors"]);

export const isActiveJobStatus = (status: JobStatus | null | undefined): boolean => !!status && active.has(status);
export const isTerminalJobStatus = (status: JobStatus | null | undefined): boolean => !!status && terminal.has(status);
export const isChatReadyJobStatus = (status: JobStatus | null | undefined): boolean => !!status && chatReady.has(status);
