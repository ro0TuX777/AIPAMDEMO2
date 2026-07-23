import React from "react";
import { getHelpEntry, getFieldTitle } from "../data/settingsHelpData";
import { getPageHelpEntry } from "../data/pageHelpData";

/**
 * Contextual help drawer.
 *
 * Replaces the near-identical HelpGuidePanel and PageHelpPanel, which shared
 * the same CSS classes, overlay chrome, header and close button and differed
 * only in which data source they read and which body sections they rendered.
 *
 * The key is resolved against the page-help data first, then the settings-help
 * data, so a caller never has to say which kind of entry it wants.
 */

const SECTION_COLORS: Record<string, string> = {
  // page-help sections
  Navigation: "text-sky-400 bg-sky-400/10 border-sky-400/20",
  Jobs: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  Analysis: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  Visualization: "text-violet-400 bg-violet-400/10 border-violet-400/20",
  Investigation: "text-amber-400 bg-amber-400/10 border-amber-400/20",
  Reporting: "text-rose-400 bg-rose-400/10 border-rose-400/20",
  Configuration: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  "AI & Training": "text-fuchsia-400 bg-fuchsia-400/10 border-fuchsia-400/20",
  "Cross-Job Analysis": "text-orange-400 bg-orange-400/10 border-orange-400/20",
  // settings-help sections
  Hardware: "text-teal-400 bg-teal-400/10 border-teal-400/20",
  "LLM Settings": "text-sky-400 bg-sky-400/10 border-sky-400/20",
  "Fine-Tuning": "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  "Security Onion": "text-amber-400 bg-amber-400/10 border-amber-400/20",
  Arkime: "text-violet-400 bg-violet-400/10 border-violet-400/20",
  Storage: "text-rose-400 bg-rose-400/10 border-rose-400/20",
};

const SECTION_LABEL_FALLBACK = "text-slate-400 bg-slate-400/10 border-slate-400/20";

interface HelpPanelProps {
  activeField: string | null;
  onClose: () => void;
  /**
   * Jump to a dependent setting. Only meaningful for settings-help entries,
   * which list the other fields required for a setting to work end-to-end.
   */
  onNavigate?: (field: string) => void;
}

const SubHeading: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
    {children}
  </h4>
);

export const HelpPanel: React.FC<HelpPanelProps> = ({ activeField, onClose, onNavigate }) => {
  if (!activeField) return null;

  const pageEntry = getPageHelpEntry(activeField);
  const settingsEntry = pageEntry ? null : getHelpEntry(activeField);
  const entry = pageEntry ?? settingsEntry;

  /* Render nothing when collapsed — zero layout impact */
  if (!entry) return null;

  return (
    <div
      className="help-guide-panel help-guide-panel--open"
      data-testid={pageEntry ? "page-help-panel" : "help-guide-panel"}
    >
      <div className="help-guide-content animate-fadeIn">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1 min-w-0">
            <span
              className={`inline-block text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border mb-2 ${
                SECTION_COLORS[entry.section] ?? SECTION_LABEL_FALLBACK
              }`}
            >
              {entry.section}
            </span>
            <h3 className="text-base font-semibold text-slate-50 leading-tight">{entry.title}</h3>
          </div>
          <button
            onClick={onClose}
            className="ml-2 mt-0.5 text-slate-500 hover:text-slate-200 transition-colors text-lg leading-none flex-shrink-0"
            aria-label="Close help panel"
            data-testid={pageEntry ? "btn-close-page-help" : "btn-close-help"}
          >
            ×
          </button>
        </div>

        {/* Description — common to both entry kinds */}
        <div className="mb-4">
          <SubHeading>{pageEntry ? "What is this?" : "Description"}</SubHeading>
          <p className="text-sm text-slate-300 leading-relaxed">{entry.description}</p>
        </div>

        {/* Page-help body: field glossary */}
        {pageEntry?.fields && pageEntry.fields.length > 0 && (
          <div>
            <SubHeading>Field Guide</SubHeading>
            <dl className="space-y-2">
              {pageEntry.fields.map((f) => (
                <div key={f.label} className="bg-slate-800/50 rounded px-3 py-2 border border-slate-700/50">
                  <dt className="text-xs font-semibold text-slate-200">{f.label}</dt>
                  <dd className="text-xs text-slate-400 leading-relaxed mt-0.5">{f.description}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}

        {/* Settings-help body: accepted values + dependencies */}
        {settingsEntry && (
          <>
            <div className="mb-4">
              <SubHeading>Accepted Values</SubHeading>
              <div className="bg-slate-900/80 border border-slate-700/50 rounded px-2.5 py-2 text-xs text-slate-300 font-mono leading-relaxed">
                {settingsEntry.acceptedValues}
              </div>
            </div>

            {settingsEntry.dependencies.length > 0 ? (
              <div className="mb-4">
                <SubHeading>Required Fields</SubHeading>
                <p className="text-[11px] text-slate-400 mb-2">
                  These fields must also be configured for this setting to function end-to-end:
                </p>
                <ul className="space-y-1">
                  {settingsEntry.dependencies.map((dep) => (
                    <li key={dep}>
                      <button
                        onClick={() => onNavigate?.(dep)}
                        className="w-full text-left px-2.5 py-1.5 rounded bg-slate-800/60 border border-slate-700/40 hover:bg-slate-700/60 hover:border-slate-600/50 transition-colors group flex items-center gap-2"
                      >
                        <span className="text-emerald-400/70 group-hover:text-emerald-400 text-xs">→</span>
                        <span className="text-xs text-slate-300 group-hover:text-slate-100 transition-colors">
                          {getFieldTitle(dep)}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="mb-4">
                <SubHeading>Dependencies</SubHeading>
                <p className="text-xs text-slate-500 italic">
                  This field has no dependencies — it works independently.
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

/** Class names for a heading that opens the help panel when clicked. */
export function labelHint(field: string, activeField: string | null): string {
  const base = "help-label-hint";
  return activeField === field ? `${base} help-label-hint--active` : base;
}

/** Local state + toggle for a page's help panel. */
export function usePageHelp() {
  const [activeHelpField, setActiveHelpField] = React.useState<string | null>(null);
  const toggleHelp = (field: string) => {
    setActiveHelpField((prev) => (prev === field ? null : field));
  };
  return { activeHelpField, setActiveHelpField, toggleHelp };
}
