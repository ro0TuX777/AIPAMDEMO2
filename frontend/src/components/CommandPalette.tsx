import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { jobStatusClass } from "../theme/colors";
import { useFocusTrap } from "../hooks/useFocusTrap";

/**
 * Global command palette (Ctrl/Cmd+K).
 *
 * The app had no cross-cutting way to get somewhere — every search was scoped
 * to one page. This jumps to any job (server-side search), any global host, or
 * any top-level section from a single keyboard-driven overlay.
 */

interface Item {
  id: string;
  label: string;
  hint?: string;
  /** Right-aligned status/badge text. */
  badge?: { text: string; cls: string };
  to: string;
  group: string;
}

const NAV_ITEMS: Item[] = [
  { id: "nav-jobs", label: "Jobs", to: "/jobs", group: "Go to" },
  { id: "nav-new", label: "New Analysis", to: "/new", group: "Go to" },
  { id: "nav-hosts", label: "Global Hosts", to: "/hosts", group: "Go to" },
  { id: "nav-rules", label: "Detection Rules", to: "/rules", group: "Go to" },
  { id: "nav-training", label: "Training", to: "/training", group: "Go to" },
  { id: "nav-settings", label: "Settings", to: "/settings", group: "Go to" },
];

/** Debounce a value so we don't hit the jobs API on every keystroke. */
function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export const CommandPalette: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const dialogRef = useFocusTrap<HTMLDivElement>(open);
  const navigate = useNavigate();

  const debouncedQuery = useDebounced(query.trim(), 180);

  // Open/close on Ctrl/Cmd+K globally; Esc closes. A custom event lets a
  // discoverable header button open the same palette without lifting state.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    const onOpenEvent = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("aipam:open-command-palette", onOpenEvent);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("aipam:open-command-palette", onOpenEvent);
    };
  }, []);

  // Reset when opened; initial focus is handled by the focus trap (the input is
  // the first focusable in the dialog).
  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  const jobsQ = useQuery({
    queryKey: ["cmd", "jobs", debouncedQuery],
    queryFn: () => api.listJobs({ q: debouncedQuery || undefined, limit: 8 }),
    enabled: open,
    staleTime: 15_000,
  });

  // Global hosts are fetched once and filtered client-side (no server-side
  // search param on that endpoint).
  const hostsQ = useQuery({
    queryKey: ["cmd", "global-hosts"],
    queryFn: () => api.listGlobalHosts({ limit: 500 }),
    enabled: open,
    staleTime: 60_000,
  });

  const items: Item[] = useMemo(() => {
    // Client-side filtering uses the immediate query so nav/host results update
    // on every keystroke; only the jobs API call is debounced. Otherwise Enter
    // pressed during the debounce window would act on a stale first item.
    const q = query.trim().toLowerCase();
    const nav = NAV_ITEMS.filter((n) => !q || n.label.toLowerCase().includes(q));

    const jobs: Item[] = (jobsQ.data?.items ?? []).map((j) => ({
      id: `job-${j.job_id}`,
      label: j.job_name || j.pcap_filename || j.job_id.slice(0, 8),
      hint: j.job_id.slice(0, 8),
      badge: { text: j.status.replace(/_/g, " "), cls: jobStatusClass(j.status) },
      to: `/jobs/${j.job_id}`,
      group: "Jobs",
    }));

    const hosts: Item[] = q
      ? (hostsQ.data?.items ?? [])
          .filter(
            (h) =>
              h.ip.toLowerCase().includes(q) ||
              (h.hostname ?? "").toLowerCase().includes(q),
          )
          .slice(0, 6)
          .map((h) => ({
            id: `host-${h.ip}`,
            label: h.ip,
            hint: h.hostname ?? `${h.job_count} job(s)`,
            to: `/hosts/${encodeURIComponent(h.ip)}`,
            group: "Global hosts",
          }))
      : [];

    return [...nav, ...jobs, ...hosts];
  }, [query, jobsQ.data, hostsQ.data]);

  // Keep the active index in range as the result set changes.
  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, items.length - 1)));
  }, [items.length]);

  const select = (item: Item | undefined) => {
    if (!item) return;
    setOpen(false);
    navigate(item.to);
  };

  const onInputKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      select(items[active]);
    }
  };

  // Scroll the active row into view.
  useEffect(() => {
    if (!open) return;
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  if (!open) return null;

  // Group rows for section headers while keeping a flat index for keyboard nav.
  let idx = -1;
  const groups: { name: string; rows: { item: Item; i: number }[] }[] = [];
  for (const item of items) {
    idx += 1;
    const g = groups.find((x) => x.name === item.group);
    const row = { item, i: idx };
    if (g) g.rows.push(row);
    else groups.push({ name: item.group, rows: [row] });
  }

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-black/50 pt-[12vh] px-4"
      data-testid="command-palette"
      onClick={() => setOpen(false)}
    >
      <div
        ref={dialogRef}
        className="w-full max-w-xl overflow-hidden rounded-lg border border-slate-700 bg-slate-900 shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => { setQuery(e.target.value); setActive(0); }}
          onKeyDown={onInputKey}
          placeholder="Search jobs, hosts, or jump to a section…"
          data-testid="command-input"
          className="w-full border-b border-slate-800 bg-transparent px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
        />
        <div ref={listRef} className="max-h-80 overflow-y-auto py-1">
          {items.length === 0 && (
            <p className="px-4 py-6 text-center text-sm text-slate-500">No matches.</p>
          )}
          {groups.map((g) => (
            <div key={g.name}>
              <div className="px-4 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                {g.name}
              </div>
              {g.rows.map(({ item, i }) => (
                <button
                  key={item.id}
                  data-idx={i}
                  data-testid={`command-item-${item.id}`}
                  onMouseMove={() => setActive(i)}
                  onClick={() => select(item)}
                  className={`flex w-full items-center gap-3 px-4 py-2 text-left text-sm ${
                    i === active ? "bg-blue-500/15 text-slate-100" : "text-slate-300 hover:bg-slate-800/60"
                  }`}
                >
                  <span className="truncate">{item.label}</span>
                  {item.hint && (
                    <span className="truncate font-mono text-xs text-slate-500">{item.hint}</span>
                  )}
                  {item.badge && (
                    <span className={`ml-auto shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium uppercase ${item.badge.cls}`}>
                      {item.badge.text}
                    </span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </div>
        <div className="flex items-center gap-3 border-t border-slate-800 px-4 py-1.5 text-[10px] text-slate-500">
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
};
