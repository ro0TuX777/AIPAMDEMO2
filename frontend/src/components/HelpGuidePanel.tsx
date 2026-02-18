import React from "react";
import { getHelpEntry, getFieldTitle, HelpEntry } from "../data/settingsHelpData";

interface HelpGuidePanelProps {
    activeField: string | null;
    onClose: () => void;
    onNavigate: (field: string) => void;
}

const sectionColors: Record<string, string> = {
    "LLM Settings": "text-sky-400 bg-sky-400/10 border-sky-400/20",
    "Fine-Tuning": "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
    "Security Onion": "text-amber-400 bg-amber-400/10 border-amber-400/20",
    "Arkime": "text-violet-400 bg-violet-400/10 border-violet-400/20",
    "Storage": "text-rose-400 bg-rose-400/10 border-rose-400/20",
};

export const HelpGuidePanel: React.FC<HelpGuidePanelProps> = ({
    activeField,
    onClose,
    onNavigate,
}) => {
    const entry: HelpEntry | null = activeField ? getHelpEntry(activeField) : null;

    return (
        <div
            className={`help-guide-panel ${activeField ? "help-guide-panel--open" : ""}`}
            data-testid="help-guide-panel"
        >
            {/* Collapsed state — vertical label */}
            {!activeField && (
                <div className="flex items-center justify-center h-full">
                    <span className="text-xs text-slate-500 tracking-widest uppercase"
                        style={{ writingMode: "vertical-rl", textOrientation: "mixed" }}>
                        Click a setting label for help
                    </span>
                </div>
            )}

            {/* Expanded state */}
            {activeField && entry && (
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
                            data-testid="btn-close-help"
                        >
                            ×
                        </button>
                    </div>

                    {/* Description */}
                    <div className="mb-4">
                        <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                            Description
                        </h4>
                        <p className="text-sm text-slate-300 leading-relaxed">
                            {entry.description}
                        </p>
                    </div>

                    {/* Accepted Values */}
                    <div className="mb-4">
                        <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                            Accepted Values
                        </h4>
                        <div className="bg-slate-900/80 border border-slate-700/50 rounded px-2.5 py-2 text-xs text-slate-300 font-mono leading-relaxed">
                            {entry.acceptedValues}
                        </div>
                    </div>

                    {/* Dependencies */}
                    {entry.dependencies.length > 0 && (
                        <div className="mb-4">
                            <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                                Required Fields
                            </h4>
                            <p className="text-[11px] text-slate-400 mb-2">
                                These fields must also be configured for this setting to function end-to-end:
                            </p>
                            <ul className="space-y-1">
                                {entry.dependencies.map((dep) => (
                                    <li key={dep}>
                                        <button
                                            onClick={() => onNavigate(dep)}
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
                    )}

                    {entry.dependencies.length === 0 && (
                        <div className="mb-4">
                            <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                                Dependencies
                            </h4>
                            <p className="text-xs text-slate-500 italic">
                                This field has no dependencies — it works independently.
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
