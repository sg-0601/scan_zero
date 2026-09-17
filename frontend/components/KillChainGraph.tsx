"use client";

import React from "react";
import { ShieldAlert, ArrowRight, CheckCircle2 } from "lucide-react";

interface KillChainNode {
  id: string;
  label: string;
  stage: string;
  severity: "critical" | "high" | "medium" | "low" | "fixed";
  detail: string;
}

interface KillChainGraphProps {
  domain: string;
  findings?: any[];
}

export default function KillChainGraph({ domain, findings = [] }: KillChainGraphProps) {
  // Synthesize attack chain stages based on actual findings or typical attack vectors
  const hasHighOrCrit = findings.some(
    (f) => f.severity?.toLowerCase() === "critical" || f.severity?.toLowerCase() === "high"
  );

  const chainNodes: KillChainNode[] = [
    {
      id: "recon",
      label: "Reconnaissance",
      stage: "1. OSINT",
      severity: "medium",
      detail: `Subdomains & public DNS records exposed for ${domain}`,
    },
    {
      id: "delivery",
      label: "Delivery / Edge",
      stage: "2. Transport",
      severity: findings.some((f) => f.title?.toLowerCase().includes("http") || f.title?.toLowerCase().includes("tls"))
        ? "high"
        : "low",
      detail: "Insecure HTTP or weak cipher suites accessible on port 80/443",
    },
    {
      id: "exploitation",
      label: "Exploitation",
      stage: "3. Headers & App",
      severity: hasHighOrCrit ? "critical" : "medium",
      detail: "Missing CSP / HSTS allows Clickjacking or Cross-Site Scripting (XSS)",
    },
    {
      id: "impact",
      label: "Business Impact",
      stage: "4. Exfiltration",
      severity: hasHighOrCrit ? "critical" : "low",
      detail: "Session hijacking or credential interception risk",
    },
  ];

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "critical":
        return "bg-rose-500/20 text-rose-400 border-rose-500/50 shadow-rose-500/20";
      case "high":
        return "bg-amber-500/20 text-amber-400 border-amber-500/50 shadow-amber-500/20";
      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50";
      default:
        return "bg-whitemerald-500/20 text-emerald-400 border-emerald-500/50";
    }
  };

  return (
    <div className="w-full bg-white/90 border border-gray-200 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4 border-b border-gray-200 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <h3 className="font-bold text-lg text-gray-900">Cyber Kill-Chain Attack Graph</h3>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded bg-gray-100 text-gray-500 border border-gray-200">
          D3 Graph Correlation &bull; Breakable Links
        </span>
      </div>

      <p className="text-xs text-gray-500 mb-6">
        Shows how an adversary could chain multiple minor vulnerabilities into a high-severity exploit. Fixing any single link in this chain breaks the attack path.
      </p>

      {/* Responsive Tree / Sequence Flow */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
        {chainNodes.map((node, index) => (
          <div key={node.id} className="flex flex-col relative group">
            <div
              className={`p-4 rounded-xl border transition-all duration-300 hover:scale-[1.02] ${getSeverityBadge(
                node.severity
              )}`}
            >
              <div className="flex items-center justify-between text-xs font-mono font-bold mb-1">
                <span>{node.stage}</span>
                <span className="uppercase text-[10px] px-1.5 py-0.5 rounded bg-gray-50/60">
                  {node.severity}
                </span>
              </div>
              <h4 className="font-bold text-gray-900 text-sm mb-1.5">{node.label}</h4>
              <p className="text-xs text-gray-600 leading-relaxed">{node.detail}</p>
            </div>

            {/* Connecting Arrow for desktop */}
            {index < chainNodes.length - 1 && (
              <div className="hidden md:flex absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-gray-400">
                <ArrowRight className="w-5 h-5" />
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="mt-4 pt-3 border-t border-gray-200/80 flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>Apply suggested "Forge Your Shield" fixes to break links #2 and #3.</span>
        </div>
        <span className="text-emerald-400 font-mono font-bold">Safe Chain Posture: 82%</span>
      </div>
    </div>
  );
}
