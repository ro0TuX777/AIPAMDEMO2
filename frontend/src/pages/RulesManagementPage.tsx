import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  api,
  SuricataRuleItem,
  ParsedRule,
  ParsedRuleListResponse,
  RuleFileStats,
  CategoryStats,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";
import { TableSkeleton, SkeletonBar } from "../components/SkeletonLoader";

const SEVERITY_LABELS: Record<number, { label: string; color: string }> = {
  1: { label: "High", color: "text-red-400 bg-red-900/30" },
  2: { label: "Medium", color: "text-yellow-400 bg-yellow-900/30" },
  3: { label: "Low", color: "text-blue-400 bg-blue-900/30" },
};

const PAGE_SIZE = 50;

export const RulesManagementPage: React.FC = () => {
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const { addToast } = useToast();
  // ── File list state ──
  const [files, setFiles] = useState<SuricataRuleItem[]>([]);
  const [selectedFile, setSelectedFile] = useState<string>("");
  const [filesLoading, setFilesLoading] = useState(true);

  // ── Parsed rules state ──
  const [rules, setRules] = useState<ParsedRuleListResponse | null>(null);
  const [stats, setStats] = useState<RuleFileStats | null>(null);
  const [rulesLoading, setRulesLoading] = useState(false);

  // ── Filters ──
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<string>("");
  const [enabledFilter, setEnabledFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [offset, setOffset] = useState(0);

  // ── UI state ──
  const [toggling, setToggling] = useState<Set<number>>(new Set());
  const [expandedSid, setExpandedSid] = useState<number | null>(null);
  const [tab, setTab] = useState<"browse" | "raw">("browse");
  const [rawContent, setRawContent] = useState("");
  const [rawLoading, setRawLoading] = useState(false);
  const [rawSaving, setRawSaving] = useState(false);
  const searchTimeout = useRef<ReturnType<typeof setTimeout>>();

  // ── Load file list ──
  useEffect(() => {
    (async () => {
      setFilesLoading(true);
      try {
        const data = await api.listSuricataRules();
        setFiles(data);
        if (data.length > 0 && !selectedFile) {
          setSelectedFile(data[0].filename);
        }
      } catch (e) {
        console.error("Failed to load rule files:", e);
      } finally {
        setFilesLoading(false);
      }
    })();
  }, []);

  // ── Load stats when file changes ──
  useEffect(() => {
    if (!selectedFile) return;
    (async () => {
      try {
        const s = await api.getRuleFileStats(selectedFile);
        setStats(s);
      } catch (e) {
        console.error("Failed to load stats:", e);
      }
    })();
  }, [selectedFile]);

  // ── Load parsed rules ──
  const loadRules = useCallback(async () => {
    if (!selectedFile) return;
    setRulesLoading(true);
    try {
      const params: any = { offset, limit: PAGE_SIZE };
      if (search) params.search = search;
      if (category) params.category = category;
      if (enabledFilter !== "") params.enabled = enabledFilter === "true";
      if (severityFilter !== "") params.severity = parseInt(severityFilter);
      const data = await api.getParsedRules(selectedFile, params);
      setRules(data);
    } catch (e) {
      console.error("Failed to load parsed rules:", e);
    } finally {
      setRulesLoading(false);
    }
  }, [selectedFile, search, category, enabledFilter, severityFilter, offset]);

  useEffect(() => {
    if (tab === "browse") loadRules();
  }, [loadRules, tab]);

  // ── Debounced search ──
  const handleSearchChange = (val: string) => {
    setSearch(val);
    setOffset(0);
    clearTimeout(searchTimeout.current);
    searchTimeout.current = setTimeout(() => loadRules(), 300);
  };

  // ── Toggle single rule ──
  const handleToggle = async (sid: number, currentlyEnabled: boolean) => {
    setToggling((prev) => new Set(prev).add(sid));
    try {
      await api.toggleRules(selectedFile, { sids: [sid], enabled: !currentlyEnabled });
      await loadRules();
      // Refresh stats
      const s = await api.getRuleFileStats(selectedFile);
      setStats(s);
    } catch (e) {
      console.error("Toggle failed:", e);
      addToast({ severity: "high", title: "Failed to toggle rule" });
    } finally {
      setToggling((prev) => { const n = new Set(prev); n.delete(sid); return n; });
    }
  };

  // ── Toggle entire category ──
  const handleCategoryToggle = async (catName: string, enable: boolean) => {
    try {
      await api.toggleRules(selectedFile, { category: catName, enabled: enable });
      await loadRules();
      const s = await api.getRuleFileStats(selectedFile);
      setStats(s);
      addToast({ severity: "info", title: `Category "${catName}" ${enable ? "enabled" : "disabled"}`, duration: 3000 });
    } catch (e) {
      console.error("Category toggle failed:", e);
      addToast({ severity: "high", title: "Failed to toggle category" });
    }
  };

  // ── Raw editor ──
  const loadRaw = async () => {
    if (!selectedFile) return;
    setRawLoading(true);
    try {
      const r = await api.getSuricataRule(selectedFile);
      setRawContent(r.content || "");
    } catch (e) {
      console.error("Failed to load raw:", e);
    } finally {
      setRawLoading(false);
    }
  };

  const saveRaw = async () => {
    if (!selectedFile) return;
    setRawSaving(true);
    try {
      await api.updateSuricataRule(selectedFile, rawContent);
      const s = await api.getRuleFileStats(selectedFile);
      setStats(s);
      addToast({ severity: "info", title: "Rules saved", body: `${selectedFile} updated successfully.` });
    } catch (e) {
      console.error("Save failed:", e);
      addToast({ severity: "high", title: "Failed to save rules" });
    } finally {
      setRawSaving(false);
    }
  };

  const totalPages = rules ? Math.ceil(rules.total / PAGE_SIZE) : 0;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="flex flex-col h-[calc(100vh-100px)] space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className={`text-2xl font-bold ${labelHint("rules_management", activeHelpField)}`} onClick={() => toggleHelp("rules_management")}>Suricata Rule Management</h1>
        <div className="flex items-center gap-3">
          <select
            value={selectedFile}
            onChange={(e) => { setSelectedFile(e.target.value); setOffset(0); setCategory(""); setSearch(""); }}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-white text-sm"
          >
            {files.map((f) => (
              <option key={f.filename} value={f.filename}>{f.filename} ({(f.size_bytes / 1024 / 1024).toFixed(1)} MB)</option>
            ))}
          </select>
          <div className="flex rounded overflow-hidden border border-gray-700">
            <button onClick={() => setTab("browse")} className={`px-4 py-2 text-sm ${tab === "browse" ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>
              Browse Rules
            </button>
            <button onClick={() => { setTab("raw"); loadRaw(); }} className={`px-4 py-2 text-sm ${tab === "raw" ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>
              Raw Editor
            </button>
          </div>
        </div>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="flex gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex-1">
            <div className="text-2xl font-bold text-white">{stats.total_rules.toLocaleString()}</div>
            <div className="text-xs text-gray-500 uppercase tracking-wider">Total Rules</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex-1">
            <div className="text-2xl font-bold text-emerald-400">{stats.enabled.toLocaleString()}</div>
            <div className="text-xs text-gray-500 uppercase tracking-wider">Enabled</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex-1">
            <div className="text-2xl font-bold text-gray-500">{stats.disabled.toLocaleString()}</div>
            <div className="text-xs text-gray-500 uppercase tracking-wider">Disabled</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex-1">
            <div className="text-2xl font-bold text-purple-400">{stats.categories.length}</div>
            <div className="text-xs text-gray-500 uppercase tracking-wider">Categories</div>
          </div>
        </div>
      )}

      {tab === "browse" ? (
        <div className="flex flex-1 gap-4 overflow-hidden">
          {/* Category sidebar */}
          <div className="w-72 bg-gray-900 border border-gray-800 rounded-lg overflow-y-auto flex-shrink-0">
            <div className="p-3 border-b border-gray-800 font-semibold uppercase text-xs text-gray-500 tracking-wider">
              Categories
            </div>
            <div
              className={`px-3 py-2 cursor-pointer text-sm flex justify-between items-center hover:bg-gray-800 ${category === "" ? "bg-gray-800 border-l-2 border-blue-500 text-blue-400" : "text-gray-300"}`}
              onClick={() => { setCategory(""); setOffset(0); }}
            >
              <span>All Rules</span>
              <span className="text-xs text-gray-500">{stats?.total_rules.toLocaleString()}</span>
            </div>
            {stats?.categories.map((cat) => (
              <div
                key={cat.name}
                className={`px-3 py-2 cursor-pointer text-sm flex justify-between items-center group hover:bg-gray-800 ${category === cat.name ? "bg-gray-800 border-l-2 border-blue-500 text-blue-400" : "text-gray-300"}`}
                onClick={() => { setCategory(cat.name); setOffset(0); }}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="truncate">{cat.name}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-xs text-gray-500">{cat.total.toLocaleString()}</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleCategoryToggle(cat.name, cat.disabled > 0); }}
                    className="opacity-0 group-hover:opacity-100 text-xs px-1.5 py-0.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-300 transition-opacity"
                    title={cat.disabled > 0 ? "Enable all" : "Disable all"}
                  >
                    {cat.disabled > 0 ? "EN" : "DIS"}
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Main rules table */}
          <div className="flex-1 flex flex-col overflow-hidden bg-gray-900 border border-gray-800 rounded-lg">
            {/* Filters */}
            <div className="p-3 border-b border-gray-800 flex items-center gap-3">
              <input
                type="text"
                placeholder="Search by SID, message..."
                value={search}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm flex-1 max-w-md outline-none focus:border-blue-500"
              />
              <select value={enabledFilter} onChange={(e) => { setEnabledFilter(e.target.value); setOffset(0); }} className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-sm">
                <option value="">All States</option>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
              <select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); setOffset(0); }} className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-sm">
                <option value="">All Severities</option>
                <option value="1">High</option>
                <option value="2">Medium</option>
                <option value="3">Low</option>
              </select>
              {rules && (
                <span className="text-xs text-gray-500 ml-auto">
                  {rules.total.toLocaleString()} rules found
                </span>
              )}
            </div>


            {/* Table */}
            <div className="flex-1 overflow-y-auto">
              {rulesLoading ? (
                <div className="p-4"><TableSkeleton rows={8} cols={5} /></div>
              ) : rules && rules.items.length === 0 ? (
                <div className="p-8 text-center text-gray-500">No rules match your filters.</div>
              ) : (
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-gray-900 z-10">
                    <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
                      <th className="px-3 py-2 w-12">On</th>
                      <th className="px-3 py-2 w-20">SID</th>
                      <th className="px-3 py-2 w-16">Sev</th>
                      <th className="px-3 py-2">Message</th>
                      <th className="px-3 py-2 w-32">Category</th>
                      <th className="px-3 py-2 w-16">Proto</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules?.items.map((rule) => {
                      const sev = SEVERITY_LABELS[rule.severity] || SEVERITY_LABELS[3];
                      return (
                        <React.Fragment key={rule.sid}>
                          <tr
                            className={`border-b border-gray-800/50 hover:bg-gray-800/50 cursor-pointer transition-colors ${!rule.enabled ? "opacity-50" : ""} ${expandedSid === rule.sid ? "bg-gray-800/30" : ""}`}
                            onClick={() => setExpandedSid(expandedSid === rule.sid ? null : rule.sid)}
                          >
                            <td className="px-3 py-2">
                              <button
                                onClick={(e) => { e.stopPropagation(); handleToggle(rule.sid, rule.enabled); }}
                                disabled={toggling.has(rule.sid)}
                                className={`w-8 h-5 rounded-full relative transition-colors ${rule.enabled ? "bg-emerald-600" : "bg-gray-700"} ${toggling.has(rule.sid) ? "opacity-50" : ""}`}
                              >
                                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${rule.enabled ? "left-3.5" : "left-0.5"}`} />
                              </button>
                            </td>
                            <td className="px-3 py-2 font-mono text-xs text-gray-400">{rule.sid}</td>
                            <td className="px-3 py-2">
                              <span className={`text-xs px-1.5 py-0.5 rounded ${sev.color}`}>{sev.label}</span>
                            </td>
                            <td className="px-3 py-2 text-gray-200 truncate max-w-md" title={rule.msg}>{rule.msg}</td>
                            <td className="px-3 py-2 text-xs text-gray-500 truncate" title={rule.classtype}>{rule.classtype}</td>
                            <td className="px-3 py-2 text-xs text-gray-500 uppercase">{rule.protocol}</td>
                          </tr>
                          {expandedSid === rule.sid && (
                            <tr className="bg-gray-800/20">
                              <td colSpan={6} className="px-4 py-3">
                                <div className="text-xs space-y-1">
                                  <div><span className="text-gray-500">Action:</span> <span className="text-yellow-400">{rule.action}</span></div>
                                  <div><span className="text-gray-500">Source:</span> <span className="text-gray-300">{rule.src}</span> → <span className="text-gray-500">Dest:</span> <span className="text-gray-300">{rule.dst}</span></div>
                                  {rule.references.length > 0 && (
                                    <div><span className="text-gray-500">References:</span> <span className="text-blue-400">{rule.references.join(", ")}</span></div>
                                  )}
                                  <div className="mt-2">
                                    <pre className="bg-black/50 rounded p-2 text-gray-400 text-xs overflow-x-auto whitespace-pre-wrap break-all">{rule.raw}</pre>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Pagination */}
            {rules && totalPages > 1 && (
              <div className="p-3 border-t border-gray-800 flex items-center justify-between">
                <button
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                  disabled={offset === 0}
                  className="px-3 py-1 rounded bg-gray-800 text-gray-300 text-sm disabled:opacity-30 hover:bg-gray-700"
                >
                  ← Previous
                </button>
                <span className="text-xs text-gray-500">
                  Page {currentPage} of {totalPages.toLocaleString()} ({rules.total.toLocaleString()} rules)
                </span>
                <button
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                  disabled={offset + PAGE_SIZE >= rules.total}
                  className="px-3 py-1 rounded bg-gray-800 text-gray-300 text-sm disabled:opacity-30 hover:bg-gray-700"
                >
                  Next →
                </button>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Raw editor tab */
        <div className="flex-1 flex flex-col bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="p-3 border-b border-gray-800 flex items-center justify-between">
            <span className="font-mono text-emerald-400 text-sm">{selectedFile}</span>
            <button
              onClick={saveRaw}
              disabled={rawSaving}
              className="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-4 py-1.5 rounded text-sm transition-colors"
            >
              {rawSaving ? "Saving..." : "Save Changes"}
            </button>
          </div>
          {rawLoading ? (
            <div className="flex-1 p-4 space-y-3"><SkeletonBar className="h-3 w-full" /><SkeletonBar className="h-3 w-full" /><SkeletonBar className="h-3 w-4/5" /><SkeletonBar className="h-3 w-full" /><SkeletonBar className="h-3 w-3/4" /></div>
          ) : (
            <textarea
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              className="flex-1 bg-black text-gray-300 p-4 font-mono text-sm outline-none resize-none"
              placeholder="# Enter Suricata rules here..."
            />
          )}
        </div>
      )}
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};