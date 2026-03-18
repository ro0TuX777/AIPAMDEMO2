import React from "react";

interface MitreTechnique {
  id: string;
  name: string;
}

interface AttackChainItem {
  stage: string;
  description: string;
  evidence: string[];
  mitre_techniques: MitreTechnique[];
}

interface AttackChainVisualizationProps {
  attackChain: AttackChainItem[];
}

// Stage colors and icons for visualization
const stageConfig: Record<string, { color: string; bgColor: string; borderColor: string; icon: string }> = {
  initial_access: { color: "text-red-400", bgColor: "bg-red-500/10", borderColor: "border-red-500/30", icon: "IA" },
  execution: { color: "text-orange-400", bgColor: "bg-orange-500/10", borderColor: "border-orange-500/30", icon: "EX" },
  persistence: { color: "text-yellow-400", bgColor: "bg-yellow-500/10", borderColor: "border-yellow-500/30", icon: "PE" },
  privilege_escalation: { color: "text-amber-400", bgColor: "bg-amber-500/10", borderColor: "border-amber-500/30", icon: "PR" },
  defense_evasion: { color: "text-lime-400", bgColor: "bg-lime-500/10", borderColor: "border-lime-500/30", icon: "DE" },
  credential_access: { color: "text-green-400", bgColor: "bg-green-500/10", borderColor: "border-green-500/30", icon: "CA" },
  discovery: { color: "text-teal-400", bgColor: "bg-teal-500/10", borderColor: "border-teal-500/30", icon: "DI" },
  lateral_movement: { color: "text-cyan-400", bgColor: "bg-cyan-500/10", borderColor: "border-cyan-500/30", icon: "LM" },
  collection: { color: "text-blue-400", bgColor: "bg-blue-500/10", borderColor: "border-blue-500/30", icon: "CO" },
  command_and_control: { color: "text-indigo-400", bgColor: "bg-indigo-500/10", borderColor: "border-indigo-500/30", icon: "C2" },
  exfiltration: { color: "text-purple-400", bgColor: "bg-purple-500/10", borderColor: "border-purple-500/30", icon: "EF" },
  impact: { color: "text-pink-400", bgColor: "bg-pink-500/10", borderColor: "border-pink-500/30", icon: "IM" },
};

const getStageConfig = (stage: string) => {
  const normalized = stage.toLowerCase().replace(/[\s-]/g, "_");
  return stageConfig[normalized] || { 
    color: "text-slate-400", 
    bgColor: "bg-slate-500/10", 
    borderColor: "border-slate-500/30", 
    icon: "•" 
  };
};

const formatStageName = (stage: string) => {
  return stage
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
};

// Generate MITRE ATT&CK link
const getMitreLink = (techniqueId: string) => {
  // Handle sub-techniques (e.g., T1071.001 -> techniques/T1071/001)
  if (techniqueId.includes(".")) {
    const [base, sub] = techniqueId.split(".");
    return `https://attack.mitre.org/techniques/${base}/${sub}/`;
  }
  return `https://attack.mitre.org/techniques/${techniqueId}/`;
};

export const AttackChainVisualization: React.FC<AttackChainVisualizationProps> = ({ attackChain }) => {
  if (!attackChain || attackChain.length === 0) {
    return (
      <div className="text-slate-500 text-sm italic">
        No attack chain data available for this analysis.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Timeline header */}
      <div className="flex items-center gap-2 text-xs text-slate-500 uppercase tracking-wider mb-4">
        <span>Attack Timeline</span>
        <div className="flex-1 h-px bg-gradient-to-r from-slate-700 to-transparent"></div>
        <span>{attackChain.length} stages</span>
      </div>

      {/* Attack chain timeline */}
      <div className="relative">
        {/* Vertical timeline line */}
        <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-red-500 via-blue-500 to-purple-500 opacity-30"></div>

        {attackChain.map((item, index) => {
          const config = getStageConfig(item.stage);
          return (
            <div key={index} className="relative pl-16 pb-6 last:pb-0">
              {/* Timeline node */}
              <div className={`absolute left-4 w-5 h-5 rounded-full ${config.bgColor} ${config.borderColor} border-2 flex items-center justify-center text-xs`}>
                {config.icon}
              </div>

              {/* Stage card */}
              <div className={`${config.bgColor} ${config.borderColor} border rounded-lg p-4 hover:border-opacity-60 transition-colors`}>
                {/* Stage header */}
                <div className="flex items-center justify-between mb-2">
                  <h4 className={`font-semibold ${config.color}`}>
                    {formatStageName(item.stage)}
                  </h4>
                  <span className="text-xs text-slate-500">Stage {index + 1}</span>
                </div>

                {/* Description */}
                <p className="text-sm text-slate-300 mb-3">{item.description}</p>

                {/* Evidence */}
                {item.evidence && item.evidence.length > 0 && (
                  <div className="mb-3">
                    <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Evidence</div>
                    <ul className="text-xs text-slate-400 space-y-1">
                      {item.evidence.map((e, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-slate-600">•</span>
                          <span className="font-mono">{e}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* MITRE Techniques */}
                {item.mitre_techniques && item.mitre_techniques.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {item.mitre_techniques.map((tech, i) => (
                      <a
                        key={i}
                        href={getMitreLink(tech.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-1 bg-slate-800/50 border border-slate-700 rounded text-xs hover:bg-slate-700/50 hover:border-emerald-500/50 transition-colors group"
                        title={`View ${tech.id} on MITRE ATT&CK`}
                      >
                        <span className="font-mono text-emerald-400 group-hover:text-emerald-300">{tech.id}</span>
                        <span className="text-slate-400 ml-1.5">{tech.name}</span>
                        <span className="ml-1 opacity-0 group-hover:opacity-100 transition-opacity">↗</span>
                      </a>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

