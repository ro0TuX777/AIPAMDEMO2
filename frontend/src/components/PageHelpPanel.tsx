import React from "react";
import { getPageHelpEntry, PageHelpEntry } from "../data/pageHelpData";

interface PageHelpPanelProps {
    activeField: string | null;
    onClose: () => void;
}

const sectionColors: Record<string, string> = {
    Navigation: "text-sky-400 bg-sky-400/10 border-sky-400/20",
    Jobs: "text-blue-400 bg-blue-400/10 border-blue-400/20",
    Analysis: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
    Visualization: "text-violet-400 bg-violet-400/10 border-violet-400/20",
    Investigation: "text-amber-400 bg-amber-400/10 border-amber-400/20",
    Reporting: "text-rose-400 bg-rose-400/10 border-rose-400/20",
    Configuration: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
    "AI & Training": "text-fuchsia-400 bg-fuchsia-400/10 border-fuchsia-400/20",
    "Cross-Job Analysis": "text-orange-400 bg-orange-400/10 border-orange-400/20",
};

export const PageHelpPanel: React.FC<PageHelpPanelProps> = ({
    activeField,
    onClose,
}) => {
    const entry: PageHelpEntry | null = activeField ? getPageHelpEntry(activeField) : null;

    /* Render nothing when collapsed — zero layout impact */
    if (!activeField || !entry) return null;

    return (
        <div
            className="help-guide-panel help-guide-panel--open"
            data-testid="page-help-panel"
        >
            <div className="help-guide-content animate-fadeIn">
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                    <div className="flex-1 min-w-0">
                        <span
                            className={`inline-block text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border mb-2 ${sectionColors[entry.section] ?? "text-slate-400 bg-slate-400/10 border-slate-400/20"
                                }`}
                        >
                            {entry.section}
                        </span>
                        <h3 className="text-base font-semibold text-slate-50 leading-tight">
                            {entry.title}
                        </h3>
                    </div>
                    <button
                        onClick={onClose}
                        className="ml-2 mt-0.5 text-slate-500 hover:text-slate-200 transition-colors text-lg leading-none flex-shrink-0"
                        aria-label="Close help panel"
                        data-testid="btn-close-page-help"
                    >
                        ×
                    </button>
                </div>

                {/* Description */}
                <div className="mb-4">
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                        What is this?
                    </h4>
                    <p className="text-sm text-slate-300 leading-relaxed">
                        {entry.description}
                    </p>
                </div>
            </div>
        </div>
    );
};

/** Small helper — returns class names for a clickable heading */
export function labelHint(field: string, activeField: string | null): string {
    const base = "help-label-hint";
    return activeField === field ? `${base} help-label-hint--active` : base;
}

/** Hook-like helper to create toggleHelp + state in a page */
export function usePageHelp() {
    const [activeHelpField, setActiveHelpField] = React.useState<string | null>(null);
    const toggleHelp = (field: string) => {
        setActiveHelpField((prev) => (prev === field ? null : field));
    };
    return { activeHelpField, setActiveHelpField, toggleHelp };
}

