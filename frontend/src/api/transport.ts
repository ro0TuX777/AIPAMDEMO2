import { handleDemoApiRequest } from "../demo/mockApi";

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

export const API_BASE =
  (import.meta as any).env.VITE_API_BASE_URL?.replace(/\/$/, "") ||
  "http://localhost:8000/api/v1";

export const DEMO_MODE = String((import.meta as any).env?.VITE_AIPAM_DEMO_MODE || "").toLowerCase() === "true";

export function isDemoMode(): boolean {
  return DEMO_MODE;
}

export function qs(params: object): string {
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

export function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  if (_token) h["Authorization"] = `Bearer ${_token}`;
  return h;
}

export async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
  if (DEMO_MODE) {
    const demoResponse = await handleDemoApiRequest(url, init, API_BASE);
    if (demoResponse !== null) return demoResponse as T;
  }

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

export function get<T>(path: string): Promise<T> { return request<T>(`${API_BASE}${path}`); }

export function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${API_BASE}${path}`, {
    method: "POST",
    headers: body instanceof Blob ? {} : { "Content-Type": "application/json" },
    body: body instanceof Blob ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function del<T>(path: string): Promise<T> { return request<T>(`${API_BASE}${path}`, { method: "DELETE" }); }

export function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${API_BASE}${path}`, {
    method: "PUT",
    headers: body instanceof Blob ? {} : { "Content-Type": "application/json" },
    body: body instanceof Blob ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function patch<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: body instanceof Blob ? {} : { "Content-Type": "application/json" },
    body: body instanceof Blob ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export function getApiToken(): string | null {
  return _token;
}
