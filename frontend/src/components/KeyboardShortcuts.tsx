import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

/**
 * Global keyboard shortcuts.
 *
 * - `?`      toggle this help overlay
 * - `g` then a key  jump to a section (GitHub-style chord)
 * - Ctrl/⌘ K opens the command palette (handled by CommandPalette)
 *
 * Shortcuts are suppressed while typing in an input, textarea, select, or
 * contenteditable, so they never eat real keystrokes.
 */

interface Chord {
  key: string;
  to: string;
  label: string;
}

const GO_TO: Chord[] = [
  { key: "j", to: "/jobs", label: "Jobs" },
  { key: "n", to: "/new", label: "New Analysis" },
  { key: "h", to: "/hosts", label: "Global Hosts" },
  { key: "r", to: "/rules", label: "Detection Rules" },
  { key: "t", to: "/training", label: "Training" },
  { key: "s", to: "/settings", label: "Settings" },
];

/** How long after `g` the second key still counts as part of the chord. */
const CHORD_WINDOW_MS = 1200;

function isTypingTarget(el: EventTarget | null): boolean {
  const node = el as HTMLElement | null;
  if (!node) return false;
  const tag = node.tagName;
  return (
    tag === "INPUT" ||
    tag === "TEXTAREA" ||
    tag === "SELECT" ||
    node.isContentEditable === true
  );
}

export const KeyboardShortcuts: React.FC = () => {
  const [helpOpen, setHelpOpen] = useState(false);
  const navigate = useNavigate();
  const gPending = useRef<number | null>(null); // timestamp of a pending `g`

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return; // leave modified keys alone
      if (isTypingTarget(e.target)) return;

      if (e.key === "Escape") {
        setHelpOpen(false);
        gPending.current = null;
        return;
      }

      // `?` (Shift + /) toggles help.
      if (e.key === "?") {
        e.preventDefault();
        setHelpOpen((o) => !o);
        return;
      }

      // Chord: `g` arms, the next key within the window navigates.
      if (gPending.current && Date.now() - gPending.current < CHORD_WINDOW_MS) {
        const chord = GO_TO.find((c) => c.key === e.key.toLowerCase());
        gPending.current = null;
        if (chord) {
          e.preventDefault();
          setHelpOpen(false);
          navigate(chord.to);
        }
        return;
      }
      if (e.key.toLowerCase() === "g") {
        gPending.current = Date.now();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  if (!helpOpen) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 px-4"
      data-testid="shortcuts-help"
      onClick={() => setHelpOpen(false)}
    >
      <div
        className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 p-5 shadow-2xl"
        role="dialog"
        aria-label="Keyboard shortcuts"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">Keyboard shortcuts</h2>
          <button
            onClick={() => setHelpOpen(false)}
            className="text-slate-500 hover:text-slate-200"
            aria-label="Close"
          >
            ✕
          </button>
        </div>
        <dl className="space-y-1.5 text-sm">
          <Row keys={["⌘/Ctrl", "K"]} desc="Open command palette / search" />
          <Row keys={["?"]} desc="Toggle this help" />
          <div className="pt-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Go to (press g, then…)
          </div>
          {GO_TO.map((c) => (
            <Row key={c.key} keys={["g", c.key]} desc={c.label} />
          ))}
        </dl>
      </div>
    </div>
  );
};

const Row: React.FC<{ keys: string[]; desc: string }> = ({ keys, desc }) => (
  <div className="flex items-center justify-between">
    <dd className="text-slate-300">{desc}</dd>
    <dt className="flex gap-1">
      {keys.map((k) => (
        <kbd
          key={k}
          className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-300"
        >
          {k}
        </kbd>
      ))}
    </dt>
  </div>
);
