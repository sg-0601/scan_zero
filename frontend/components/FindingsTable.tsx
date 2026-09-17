"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, ShieldAlert, AlertTriangle, Info, AlertCircle } from "lucide-react";
import RemediationCard from "./RemediationCard";

export interface Finding {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  category: string;
  tool: string;
  description: string;
  evidence?: any;
  remediation_code?: string;
  remediation_type?: string;
}

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("All");

  const severities = ["Critical", "High", "Medium", "Low", "Info"];
  
  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case "Critical": return { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/50", icon: ShieldAlert };
      case "High": return { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/50", icon: AlertTriangle };
      case "Medium": return { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/50", icon: AlertTriangle };
      case "Low": return { bg: "bg-whitelue-500/10", text: "text-blue-400", border: "border-blue-500/50", icon: Info };
      case "Info": default: return { bg: "bg-slate-500/10", text: "text-gray-500", border: "border-slate-500/50", icon: AlertCircle };
    }
  };

  const filtered = filter === "All" ? findings : findings.filter(f => f.severity === filter);

  // Group by severity for display order
  const sorted = [...filtered].sort((a, b) => severities.indexOf(a.severity) - severities.indexOf(b.severity));

  const counts = severities.map(sev => ({
    sev,
    count: findings.filter(f => f.severity === sev).length
  }));

  return (
    <div className="w-full mt-8">
      <div className="flex flex-wrap gap-2 mb-6">
        <button
          onClick={() => setFilter("All")}
          className={`px-4 py-2 rounded-lg text-sm font-medium border ${filter === "All" ? "bg-slate-700 text-gray-900 border-gray-300" : "bg-gray-100/50 text-gray-500 border-gray-200 hover:bg-gray-100"}`}
        >
          All ({findings.length})
        </button>
        {counts.map(({ sev, count }) => {
          if (count === 0) return null;
          const style = getSeverityStyle(sev);
          return (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-4 py-2 rounded-lg text-sm font-medium border flex items-center gap-2 ${filter === sev ? `${style.bg} ${style.text} ${style.border}` : "bg-gray-100/50 text-gray-500 border-gray-200 hover:bg-gray-100"}`}
            >
              <style.icon className="w-4 h-4" />
              {sev} ({count})
            </button>
          );
        })}
      </div>

      <div className="bg-[#1e293b] border border-gray-200 rounded-xl overflow-hidden">
        <div className="hidden md:grid grid-cols-12 gap-4 p-4 bg-gray-100/50 border-b border-gray-200 text-xs font-semibold text-gray-500 uppercase tracking-wider">
          <div className="col-span-1 text-center">Severity</div>
          <div className="col-span-6">Vulnerability</div>
          <div className="col-span-3">Category</div>
          <div className="col-span-2 text-right">Source Tool</div>
        </div>

        <div className="divide-y divide-gray-200/50">
          {sorted.length === 0 ? (
            <div className="p-8 text-center text-gray-400">No findings match the selected filter.</div>
          ) : (
            sorted.map((finding) => {
              const isExpanded = expandedId === finding.id;
              const style = getSeverityStyle(finding.severity);
              const Icon = style.icon;

              return (
                <div key={finding.id} className="group">
                  <div 
                    className="cursor-pointer grid grid-cols-1 md:grid-cols-12 gap-4 p-4 items-center hover:bg-gray-100/30 transition-colors"
                    onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  >
                    <div className="col-span-1 flex items-center justify-start md:justify-center gap-3">
                      <div className={`p-1.5 rounded-md ${style.bg} ${style.text} border ${style.border}`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <span className="md:hidden text-sm font-medium text-gray-600">{finding.severity}</span>
                    </div>
                    
                    <div className="col-span-6 flex items-center gap-3">
                      <div className="text-gray-500 group-hover:text-teal-600 transition-colors">
                        {isExpanded ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
                      </div>
                      <span className="text-sm font-semibold text-gray-800">{finding.title}</span>
                    </div>
                    
                    <div className="col-span-3 text-sm text-gray-500 flex items-center">
                      <span className="px-2.5 py-1 bg-gray-100 rounded-md border border-gray-200">
                        {finding.category}
                      </span>
                    </div>
                    
                    <div className="col-span-2 text-sm text-gray-400 md:text-right font-mono">
                      {finding.tool}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-6 bg-white/50 border-t border-gray-200/50 border-l-4" style={{ borderLeftColor: style.text.replace('text-', '') }}>
                      <div className="space-y-6">
                        <div>
                          <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Description</h4>
                          <p className="text-sm text-gray-600 leading-relaxed bg-gray-100/50 p-4 rounded-lg border border-gray-200/50">
                            {finding.description}
                          </p>
                        </div>

                        {finding.evidence && (
                          <div>
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Evidence</h4>
                            <pre className="text-xs font-mono text-emerald-400 bg-gray-50 p-4 rounded-lg border border-gray-200 overflow-x-auto">
                              {typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}
                            </pre>
                          </div>
                        )}

                        {finding.remediation_code && (
                          <div>
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Remediation</h4>
                            <RemediationCard 
                              title={`Fix: ${finding.title}`} 
                              description="Apply this configuration to remediate the vulnerability."
                              code={finding.remediation_code}
                              language={finding.remediation_type || "text"}
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
