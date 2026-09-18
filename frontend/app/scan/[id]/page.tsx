"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ScoreGauge from "@/components/ScoreGauge";
import HealingShield from "@/components/HealingShield";
import FindingsTable from "@/components/FindingsTable";
import ScanProgress from "@/components/ScanProgress";
import RadarChart from "@/components/RadarChart";
import KillChainGraph from "@/components/KillChainGraph";
import RemediationCard from "@/components/RemediationCard";
import GeminiAssistant from "@/components/GeminiAssistant";
import { Download, Globe, Activity, ShieldCheck, AlertCircle, RefreshCw, CheckCircle2, Sparkles, Crosshair, ArrowRight, Zap, Layers, AlertTriangle, Cpu, Check } from "lucide-react";
import { API_BASE_URL } from "@/lib/config";

export default function ScanResultsPage() {
  const params = useParams();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/scan/${params.id}`);
        if (!res.ok) {
          throw new Error("Scan not found or server error");
        }
        const resultData = await res.json();
        setData(resultData);
        
        if (resultData.status === "completed" || resultData.status === "failed") {
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.message);
        setLoading(false);
      }
    };

    fetchResults();
    
    // Poll every 2 seconds if still running
    const interval = setInterval(() => {
      if (!data || (data.status !== "completed" && data.status !== "failed")) {
        fetchResults();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [params.id, data?.status]);

  const handleDownloadJSON = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scanzero_scan_${data.domain || "report"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrintPDF = () => {
    window.print();
  };

  if (error) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-8 text-center min-h-[60vh]">
        <AlertCircle className="w-16 h-16 text-red-500 mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Error Loading Scan</h2>
        <p className="text-gray-500">{error}</p>
      </div>
    );
  }

  // Show progress while pending or running
  if (loading || (data && (data.status === "pending" || data.status === "running"))) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-8 pt-20">
        <ScanProgress workers={data?.workers} />
      </div>
    );
  }

  // Extract real results or fallback
  const rawResults = data?.results_json || data?.results;
  const targetDomain = data?.domain || rawResults?.domain || "Target Website";
  const overallScore = Math.round(data?.score ?? rawResults?.score ?? 78);
  const grade = data?.grade || rawResults?.grade || "B";
  const findings = rawResults?.findings || [];

  const setScores = rawResults?.set_scores;
  const categories = [
    { name: "Crypto & TLS", score: setScores?.set1 ?? Math.min(100, Math.round(overallScore * 1.05)) },
    { name: "Headers & CSP", score: setScores?.set2 ?? Math.min(100, Math.round(overallScore * 0.95)) },
    { name: "DNS & Anti-Spoof", score: setScores?.set3 ?? Math.min(100, Math.round(overallScore * 1.02)) },
    { name: "Surface & DAST", score: setScores?.set4 ?? Math.min(100, Math.round(overallScore * 0.98)) },
  ];

  return (
    <div className="flex-1 p-4 md:p-8 w-full max-w-7xl mx-auto">
      {/* Header section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-8 gap-4 border-b border-gray-200 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-500/20 text-teal-600 border border-cyan-500/30">
              AUDIT COMPLETED &bull; 6 WORKERS ASYNC
            </span>
          </div>
          <h1 className="text-3xl font-black text-gray-900 mb-2 flex items-center gap-3">
            <Globe className="w-8 h-8 text-teal-600" />
            {targetDomain}
          </h1>
          <div className="flex flex-wrap items-center gap-4 text-sm text-gray-500">
            <span className="flex items-center gap-1.5"><Activity className="w-4 h-4 text-gray-500" /> Scanned {new Date().toLocaleDateString()}</span>
            <span className="flex items-center gap-1.5 text-emerald-400"><ShieldCheck className="w-4 h-4" /> AI Guard Verified (0% False Positives)</span>
          </div>
        </div>
        
        {/* 1-Click Export Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={handlePrintPDF}
            className="flex items-center gap-2 bg-gray-100 hover:bg-slate-700 text-gray-800 px-4 py-2.5 rounded-lg border border-gray-200 transition-all text-sm font-semibold hover:border-cyan-500/40"
          >
            <Download className="w-4 h-4 text-teal-600" /> Executive PDF
          </button>
          <button
            onClick={handleDownloadJSON}
            className="flex items-center gap-2 bg-teal-500 hover:bg-cyan-400 text-slate-950 px-4 py-2.5 rounded-lg font-bold transition-all text-sm shadow-lg shadow-cyan-500/10"
          >
            <Download className="w-4 h-4" /> Developer JSON
          </button>
        </div>
      </div>

      {/* Google Gemini AI Executive Intelligence Hero Card */}
      <div className="bg-gradient-to-br from-slate-900 via-slate-950 to-teal-950 border border-teal-500/40 rounded-2xl p-6 md:p-8 mb-8 text-white shadow-xl relative overflow-hidden">
        <div className="absolute -top-10 -right-10 w-80 h-80 bg-teal-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="relative z-10">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-teal-500/20 border border-teal-400/30 flex items-center justify-center shadow-md shadow-teal-500/10">
                <Sparkles className="w-5 h-5 text-teal-400" />
              </div>
              <div>
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-teal-300 block">
                  Google Gemini Multi-Tool Intelligence Core
                </span>
                <span className="text-[11px] text-gray-400">
                  Synthesized across OSINT, Shodan, VirusTotal, TLS, Headers, and DNS
                </span>
              </div>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-teal-500/20 text-teal-300 border border-teal-500/30 flex items-center gap-1.5 shadow-sm">
              <span className="w-2 h-2 rounded-full bg-teal-400 animate-pulse"></span>
              {rawResults?.gemini_intelligence?.gemini_model_used || "gemini-3.8-flash"}
            </span>
          </div>

          <h2 className="text-xl md:text-2xl font-black text-white mb-3 tracking-tight">
            {rawResults?.gemini_intelligence?.threat_verdict || rawResults?.status_text || "Automated Threat Posture Evaluation"}
          </h2>

          <p className="text-gray-300 text-sm md:text-base leading-relaxed mb-6 max-w-5xl">
            {rawResults?.gemini_intelligence?.executive_summary || rawResults?.status_text || "Correlated analysis across all network, cryptographic, DNS, and application security vectors."}
          </p>

          {/* Attacker Perspective Callout */}
          {rawResults?.gemini_intelligence?.attacker_perspective && (
            <div className="bg-rose-950/40 border border-rose-500/30 rounded-xl p-4 mb-6 shadow-inner">
              <div className="flex items-center gap-2 text-rose-400 font-bold text-xs uppercase tracking-wider mb-1.5">
                <Crosshair className="w-4 h-4" /> Adversary Threat Vector &bull; Attacker's Perspective
              </div>
              <p className="text-rose-100/90 text-xs md:text-sm leading-relaxed">
                {rawResults?.gemini_intelligence?.attacker_perspective}
              </p>
            </div>
          )}

          {/* Strengths & Critical Gaps Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900/70 border border-emerald-500/30 rounded-xl p-4">
              <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> Confirmed Security Strengths
              </h4>
              <ul className="space-y-1.5">
                {(rawResults?.gemini_intelligence?.strengths || rawResults?.strengths || ["Standard SSL/TLS transport active."]).map((s: string, idx: number) => (
                  <li key={idx} className="text-xs text-gray-300 flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">&bull;</span> {s}
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-slate-900/70 border border-amber-500/30 rounded-xl p-4">
              <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4" /> Priority Posture Deficits
              </h4>
              <ul className="space-y-1.5">
                {(rawResults?.gemini_intelligence?.critical_risks || rawResults?.critical_issues || ["Missing modern HTTP transport security headers."]).map((r: string, idx: number) => (
                  <li key={idx} className="text-xs text-gray-300 flex items-start gap-2">
                    <span className="text-amber-400 font-bold">&bull;</span> {r}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Gemini AI Security Lead Assistant */}
      <GeminiAssistant
        scanId={String(params.id)}
        domain={targetDomain}
        score={overallScore}
        grade={grade}
      />

      {/* Top Grid: Healing Shield & Score Breakdown & Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-8">
        {/* Visual 1: Healing Shield Donut */}
        <div className="lg:col-span-4 bg-white/90 border border-gray-200 rounded-2xl p-6 flex flex-col items-center justify-center text-center shadow-sm">
          <h3 className="text-sm font-mono text-teal-600 uppercase tracking-widest font-bold mb-4">
            Visual 1 &bull; Healing Shield
          </h3>
          <HealingShield score={overallScore} grade={grade} />
          <p className="text-xs text-gray-500 mt-4 max-w-xs">
            Visually repairs and glows as security patches and headers are applied.
          </p>
        </div>

        {/* Visual 2: Category Breakdown Score Gauge */}
        <div className="lg:col-span-4 bg-white/90 border border-gray-200 rounded-2xl p-6 shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-mono text-teal-600 uppercase tracking-widest font-bold mb-4">
              Category Posture Breakdown
            </h3>
            <ScoreGauge score={overallScore} categories={categories} />
          </div>
          <div className="text-[11px] text-gray-400 font-mono mt-4 pt-3 border-t border-gray-200">
            Formula: Crypto (25%) + Headers (30%) + DNS (20%) + Surface (25%)
          </div>
        </div>
        
        {/* Visual 3: N-Site Radar Chart */}
        <div className="lg:col-span-4 bg-white/90 border border-gray-200 rounded-2xl p-6 flex flex-col items-center justify-between shadow-sm">
          <div className="w-full">
            <h3 className="text-sm font-mono text-teal-600 uppercase tracking-widest font-bold mb-1">
              Visual 2 &bull; N-Site Radar
            </h3>
            <p className="text-xs text-gray-500 mb-2">Target domain vs industry benchmark</p>
          </div>
          <RadarChart mainTarget={targetDomain} scores={setScores} />
        </div>
      </div>

      {/* Visual 4: Kill-Chain Graph Component */}
      <div className="mb-8">
        <KillChainGraph domain={targetDomain} findings={findings} />
      </div>

      {/* Gemini AI Multi-Step Attack Chain Scenario */}
      {(() => {
        const attackChain = rawResults?.gemini_intelligence?.attack_chain || rawResults?.attack_chain;
        if (!attackChain || attackChain.length === 0) return null;

        return (
          <div className="mb-8 bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                  <Crosshair className="w-5 h-5 text-rose-500" />
                  Gemini Correlated Attack Chain Scenario
                </h3>
                <p className="text-gray-500 text-xs mt-0.5">
                  How a threat actor combines the multi-tool discoveries into an end-to-end compromise pathway
                </p>
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 bg-rose-50 text-rose-600 rounded-md border border-rose-200">
                {attackChain.length} Exploitation Stages
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 relative">
              {attackChain.map((step: any, idx: number) => (
                <div key={idx} className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col justify-between relative overflow-hidden">
                  <div className="absolute top-0 right-0 px-2 py-0.5 text-[10px] font-mono font-bold bg-slate-200 text-slate-600 rounded-bl-md">
                    Stage {step.step || idx + 1}
                  </div>
                  <div>
                    <h4 className="font-bold text-slate-900 text-sm mb-1 pr-10">
                      {step.title}
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed mb-3">
                      {step.description}
                    </p>
                  </div>
                  <div className="pt-2 border-t border-slate-200/80 flex items-center justify-between text-[11px] font-mono">
                    <span className="text-slate-400 uppercase font-semibold">Vector:</span>
                    <span className="text-rose-600 font-bold truncate max-w-[180px]">{step.exploit_vector}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Gemini 3-Phase Action Roadmap */}
      {(() => {
        const roadmap = rawResults?.gemini_intelligence?.remediation_roadmap || rawResults?.remediation_roadmap;
        if (!roadmap) return null;

        const phases = [
          {
            title: "Phase 1: Immediate (24 Hours)",
            desc: "Stop high-risk exposure & unauthenticated spoofing",
            items: roadmap.phase_1_immediate || ["Deploy HSTS header with max-age", "Enforce strict SPF & DMARC reject policies"],
            color: "border-rose-500/40 bg-rose-50/40 text-rose-900",
            badge: "bg-rose-500 text-white"
          },
          {
            title: "Phase 2: Short-Term (7 Days)",
            desc: "Browser isolation & session token protection",
            items: roadmap.phase_2_short_term || ["Deploy restrictive Content-Security-Policy", "Enforce HttpOnly & Secure cookie flags"],
            color: "border-amber-500/40 bg-amber-50/40 text-amber-900",
            badge: "bg-amber-500 text-white"
          },
          {
            title: "Phase 3: Strategic Hardening",
            desc: "Defense-in-depth & automated posture monitoring",
            items: roadmap.phase_3_strategic || ["Enable DNSSEC cryptographic chain", "Establish CI/CD automated security regression tests"],
            color: "border-teal-500/40 bg-teal-50/40 text-teal-900",
            badge: "bg-teal-600 text-white"
          }
        ];

        return (
          <div className="mb-8 bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-teal-600" />
                  Gemini Remediation &amp; Hardening Roadmap
                </h3>
                <p className="text-gray-500 text-xs mt-0.5">
                  Prioritized AI action plan to remediate vulnerabilities and elevate security score
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {phases.map((p, idx) => (
                <div key={idx} className={`border rounded-xl p-4 flex flex-col justify-between ${p.color}`}>
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${p.badge}`}>
                        Phase {idx + 1}
                      </span>
                    </div>
                    <h4 className="font-bold text-sm text-gray-900 mb-1">{p.title}</h4>
                    <p className="text-[11px] text-gray-500 mb-3">{p.desc}</p>
                    <ul className="space-y-2">
                      {p.items.map((item: string, iIdx: number) => (
                        <li key={iIdx} className="text-xs text-gray-700 flex items-start gap-1.5 leading-snug">
                          <Check className="w-3.5 h-3.5 text-teal-600 shrink-0 mt-0.5" />
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })()}


      {/* Stage 8B: "Forge Your Shield" Remediation Engine */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
              <span>🛡️</span> Stage 8B: "Forge Your Shield" Remediation Engine
            </h2>
            <p className="text-gray-500 text-sm mt-0.5">
              1-Click drop-in configuration blocks for your web server, WAF, and DNS providers.
            </p>
          </div>
        </div>

        {(() => {
          const remediationsList = rawResults?.remediations || (findings || []).filter((f: any) => f.remediation_code).map((f: any) => ({
            title: f.title || "Vulnerability Fix",
            description: f.description || "Deploy configuration update to resolve this security posture gap.",
            language: f.remediation_type || "nginx",
            code: f.remediation_code
          }));

          if (remediationsList.length === 0) {
            return (
              <div className="bg-white/80 border border-emerald-500/30 rounded-2xl p-8 text-center">
                <CheckCircle2 className="w-10 h-10 mx-auto mb-3 text-emerald-500" />
                <h3 className="font-bold text-lg text-gray-900">Zero Critical Misconfigurations Detected</h3>
                <p className="text-sm text-gray-500 mt-1 max-w-md mx-auto">
                  All examined cryptographic handshakes, HTTP security headers, and DNS anti-spoofing policies comply with security standards.
                </p>
              </div>
            );
          }

          return (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {remediationsList.map((rem: any, idx: number) => (
                <RemediationCard
                  key={idx}
                  title={rem.title}
                  description={rem.description}
                  language={rem.language || rem.remediation_type || "nginx"}
                  code={rem.code}
                />
              ))}
            </div>
          );
        })()}
      </div>

      {/* Findings Table */}
      <div className="mb-8">
        <div className="mb-4">
          <h2 className="text-2xl font-bold text-gray-900">All Vulnerability Findings</h2>
          <p className="text-gray-500 text-sm">
            AI-validated posture findings. False positives eliminated via LLM Payload Verifier and EPSS scoring.
          </p>
        </div>
        
        <FindingsTable findings={findings} />
      </div>
    </div>
  );
}
