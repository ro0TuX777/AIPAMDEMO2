import React, { createContext, useCallback, useContext, useRef, useState } from "react";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ToastSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface Toast {
  id: number;
  severity: ToastSeverity;
  title: string;
  body?: string;
  /** Link to navigate on click */
  href?: string;
  /** Auto-dismiss in ms (default 8000) */
  duration?: number;
}

interface ToastContextValue {
  addToast: (toast: Omit<Toast, "id">) => void;
}

const ToastContext = createContext<ToastContextValue>({ addToast: () => {} });

export const useToast = () => useContext(ToastContext);

// ─── Severity styling ───────────────────────────────────────────────────────

const SEV_STYLES: Record<ToastSeverity, { border: string; icon: string; bg: string; text: string }> = {
  critical: { border: "border-red-500/60", icon: "●", bg: "bg-red-950/90", text: "text-red-200" },
  high:     { border: "border-orange-500/60", icon: "●", bg: "bg-orange-950/90", text: "text-orange-200" },
  medium:   { border: "border-amber-500/50", icon: "●", bg: "bg-amber-950/80", text: "text-amber-200" },
  low:      { border: "border-slate-500/40", icon: "●", bg: "bg-slate-900/80", text: "text-slate-300" },
  info:     { border: "border-slate-700/40", icon: "●", bg: "bg-slate-900/80", text: "text-slate-300" },
};

// ─── Provider ───────────────────────────────────────────────────────────────

const MAX_VISIBLE = 5;

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idCounter = useRef(0);

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback((opts: Omit<Toast, "id">) => {
    const id = ++idCounter.current;
    const toast: Toast = { ...opts, id };
    setToasts((prev) => [...prev.slice(-(MAX_VISIBLE - 1)), toast]);

    // Auto-dismiss
    const dur = opts.duration ?? 8000;
    if (dur > 0) {
      setTimeout(() => removeToast(id), dur);
    }
  }, [removeToast]);

  return (
    <ToastContext.Provider value={{ addToast }}>
      {children}
      {/* Toast stack — fixed bottom-right */}
      {toasts.length > 0 && (
        <div className="fixed bottom-4 right-4 z-[9999] flex flex-col-reverse gap-2 max-w-sm w-full pointer-events-none">
          {toasts.map((t) => {
            const sev = SEV_STYLES[t.severity] ?? SEV_STYLES.info;
            return (
              <div
                key={t.id}
                className={`pointer-events-auto rounded-lg border ${sev.border} ${sev.bg} backdrop-blur-md shadow-2xl
                  px-4 py-3 flex items-start gap-3 animate-slide-in-right cursor-pointer group transition-opacity hover:opacity-95`}
                onClick={() => {
                  if (t.href) window.location.href = t.href;
                  removeToast(t.id);
                }}
                role="alert"
              >
                <span className="text-lg flex-shrink-0 mt-0.5">{sev.icon}</span>
                <div className="flex-1 min-w-0">
                  <div className={`text-sm font-semibold ${sev.text} truncate`}>{t.title}</div>
                  {t.body && (
                    <div className="text-xs text-slate-400 mt-0.5 line-clamp-2">{t.body}</div>
                  )}
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); removeToast(t.id); }}
                  className="text-slate-500 hover:text-slate-300 text-xs flex-shrink-0 mt-0.5 opacity-0 group-hover:opacity-100 transition-opacity"
                  aria-label="Dismiss"
                >
                  ✕
                </button>
              </div>
            );
          })}
        </div>
      )}
    </ToastContext.Provider>
  );
};

