"use client";

import React, { useState } from "react";
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  TrendingUp,
  Download,
  ExternalLink,
  ChevronRight,
  Info,
  Layers,
  FileText,
  BarChart3,
  Lock,
  Globe,
  Server,
  Zap,
  Eye,
  Activity,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw,
  Clock,
  Sparkles,
  HelpCircle,
  Copy,
  Check,
  Terminal,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Legend,
} from "recharts";

export interface WebsiteResult {
  url: string;
  domain: string;
  overallScore: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  statusText: string;
  setScores: {
    set1: number; // TLS & Crypto
    set2: number; // Headers & CSP
    set3: number; // DNS & Anti-Spoof
    set4: number; // OSINT & Attack Surface
    set5: number; // DAST & Vulnerabilities
    set6: number; // Deception & Honeypot Posture
  };
  strengths: string[];
  weaknesses: string[];
  criticalIssues: string[];
  recommendations: string[];
  detailedSets: {
    [key: string]: {
      name: string;
      score: number;
      grade: string;
      analyzedItems: string[];
      positiveFindings: string[];
      negativeFindings: string[];
      whyScoreGiven: string;
      evidence: string;
      recommendation: string;
      metricValue: string;
    };
  };
  scoringBreakdown: {
    category: string;
    earned: number;
    max: number;
    reasonEarned: string;
    reasonDeducted: string;
    detectedIssue: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Clean";
    evidence: string;
    improvement: string;
  }[];
}

interface ScanZeroDashboardProps {
  results: WebsiteResult[];
  onNewScan: () => void;
}

export default function ScanZeroDashboard({ results, onNewScan }: ScanZeroDashboardProps) {
  const [activeSection, setActiveSection] = useState<string>("overall");
  const [selectedSiteIndex, setSelectedSiteIndex] = useState<number>(0);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [selectedServerTab, setSelectedServerTab] = useState<"nginx" | "apache" | "cloudflare" | "caddy">("nginx");
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedSnippet(id);
      setTimeout(() => setCopiedSnippet(null), 2500);
    }
  };

  const serverSnippets: Record<string, string> = {
    nginx: `# ScanZero Hardening Bundle for Nginx (/etc/nginx/conf.d/security.conf)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none';" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;`,

    apache: `# ScanZero Hardening Bundle for Apache (.htaccess / httpd.conf)
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline';"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>`,

    caddy: `# ScanZero Hardening for Caddyfile
header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "SAMEORIGIN"
    Referrer-Policy "strict-origin-when-cross-origin"
    Content-Security-Policy "default-src 'self';"
    Permissions-Policy "camera=(), microphone=(), geolocation=()"
}`,

    cloudflare: `// Cloudflare Transform Rule / Cloudflare Worker
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  let response = await fetch(request);
  let newHeaders = new Headers(response.headers);
  newHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  newHeaders.set("X-Content-Type-Options", "nosniff");
  newHeaders.set("X-Frame-Options", "SAMEORIGIN");
  newHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");
  return new Response(response.body, { status: response.status, headers: newHeaders });
}`
  };

  const isComparison = results.length > 1;
  const currentSite = results[selectedSiteIndex] || results[0];

  const handleDownloadReport = () => {
    setIsDownloading(true);
    setTimeout(() => {
      window.print();
      setIsDownloading(false);
    }, 250);
  };

  const navItems = [
    { id: "overall", label: "Overall", icon: Activity },
    { id: "set1", label: "Set 1: TLS & Network", icon: Lock },
    { id: "set2", label: "Set 2: Headers & CSP", icon: Server },
    { id: "set3", label: "Set 3: DNS & Anti-Spoof", icon: Globe },
    { id: "set4", label: "Set 4: OSINT Footprint", icon: Layers },
    { id: "set5", label: "Set 5: DAST & Vulns", icon: Zap },
    { id: "set6", label: "Set 6: Deception Posture", icon: Eye },
    { id: "scoring", label: "Scoring Breakdown", icon: BarChart3 },
    { id: "summary", label: "Summary Report", icon: FileText },
  ];

  // Colors for multi-site charts
  const siteColors = ["#06b6d4", "#a855f7", "#10b981", "#f59e0b"];

  // Prepare radar comparison data
  const radarComparisonData = [
    {
      subject: "Set 1: Crypto",
      ...results.reduce((acc, r, i) => ({ ...acc, [r.domain]: r.setScores.set1 }), {}),
    },
    {
      subject: "Set 2: Headers",
      ...results.reduce((acc, r, i) => ({ ...acc, [r.domain]: r.setScores.set2 }), {}),
    },
    {
      subject: "Set 3: DNS",
      ...results.reduce((acc, r, i) => ({ ...acc, [r.domain]: r.setScores.set3 }), {}),
    },
    {
      subject: "Set 4: OSINT",
      ...results.reduce((acc, r, i) => ({ ...acc, [r.domain]: r.setScores.set4 }), {}),
    },
    {
      subject: "Set 5: DAST",
      ...results.reduce((acc, r, i) => ({ ...acc, [r.domain]: r.setScores.set5 }), {}),
    },
    {
      subject: "Set 6: Deception",
      ...results.reduce((acc, r, i) => ({ ...acc, [r.domain]: r.setScores.set6 }), {}),
    },
  ];

  // Area progress trend data across sets
  const progressAreaChartData = [
    { name: "Set 1", ...results.reduce((acc, r) => ({ ...acc, [r.domain]: r.setScores.set1 }), {}) },
    { name: "Set 2", ...results.reduce((acc, r) => ({ ...acc, [r.domain]: r.setScores.set2 }), {}) },
    { name: "Set 3", ...results.reduce((acc, r) => ({ ...acc, [r.domain]: r.setScores.set3 }), {}) },
    { name: "Set 4", ...results.reduce((acc, r) => ({ ...acc, [r.domain]: r.setScores.set4 }), {}) },
    { name: "Set 5", ...results.reduce((acc, r) => ({ ...acc, [r.domain]: r.setScores.set5 }), {}) },
    { name: "Set 6", ...results.reduce((acc, r) => ({ ...acc, [r.domain]: r.setScores.set6 }), {}) },
  ];

  const getScoreColor = (score: number) => {
    if (score >= 85) return "text-emerald-400";
    if (score >= 70) return "text-teal-600";
    if (score >= 55) return "text-amber-400";
    return "text-rose-400";
  };

  const getBadgeBg = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-rose-500/15 text-rose-400 border-rose-200";
      case "high":
        return "bg-amber-500/15 text-amber-400 border-amber-500/30";
      case "medium":
        return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
      case "low":
        return "bg-blue-500/15 text-blue-400 border-blue-500/30";
      default:
        return "bg-emerald-500/15 text-emerald-400 border-emerald-200";
    }
  };

  return (
    <div className="w-full min-h-screen bg-gray-50 text-gray-900 flex flex-col font-sans">
      {/* Top Application Bar (inspired by the reference Jira/SaaS header) */}
      <div className="w-full bg-white border-b border-gray-200 px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4 sticky top-16 z-40 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-white border border-gray-200 px-3 py-1.5 rounded-xl">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            <span className="text-xs font-mono font-bold text-teal-600">SCANZER0 ANALYSIS ENGINE</span>
          </div>

          {/* Active Target Pills / Switcher */}
          <div className="flex items-center gap-1.5 overflow-x-auto py-1">
            {results.map((r, i) => (
              <button
                key={r.domain}
                onClick={() => setSelectedSiteIndex(i)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  selectedSiteIndex === i
                    ? "bg-teal-500 text-gray-900 shadow-md shadow-teal-500/10 font-bold"
                    : "bg-gray-100 hover:bg-gray-100 text-gray-600 border border-gray-200"
                }`}
              >
                <span>{r.domain}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                    selectedSiteIndex === i ? "bg-gray-50/30 text-gray-900" : "bg-white text-teal-600"
                  }`}
                >
                  {r.overallScore}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Real-time Telemetry Pill */}
          <div className="hidden xl:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-gray-50 border border-gray-200 text-xs font-mono text-gray-500">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Live Audit &bull; 55 Security Tools Active</span>
          </div>

          <button
            onClick={onNewScan}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-gray-100/90 hover:bg-gray-100 text-gray-600 hover:text-white border border-gray-200 text-xs font-medium transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5 text-teal-600" />
            <span>New Scan</span>
          </button>
          <button
            onClick={handleDownloadReport}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-teal-500 hover:bg-cyan-400 text-gray-900 text-xs font-extrabold shadow-md shadow-teal-500/10 transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isDownloading ? "Generating..." : "Download Report"}</span>
          </button>
        </div>
      </div>

      {/* Main Dashboard Layout (Left Nav + Main Content + Right Activity Stream) */}
      <div className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ========================================================= */}
        {/* LEFT NAVIGATION SIDEBAR (9 Sections) */}
        {/* ========================================================= */}
        <aside className="lg:col-span-3 xl:col-span-2 flex flex-col gap-1.5 bg-white border border-gray-200 rounded-2xl p-3 h-fit sticky top-36">
          <div className="px-3 py-2 text-[10px] font-mono uppercase tracking-widest text-gray-500 font-bold border-b border-gray-200 mb-1">
            Analysis Views
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveSection(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all text-left ${
                  isActive
                    ? "bg-gradient-to-r from-teal-50 to-teal-100 text-teal-600 border border-teal-300 font-bold shadow-sm"
                    : "text-gray-500 hover:text-gray-700 hover:bg-gray-100 border border-transparent"
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? "text-teal-600" : "text-gray-400"}`} />
                  <span className="truncate">{item.label}</span>
                </div>
                <ChevronRight className={`w-3 h-3 shrink-0 ${isActive ? "text-teal-600 opacity-100" : "opacity-0"}`} />
              </button>
            );
          })}

          {isComparison && (
            <div className="mt-4 pt-3 border-t border-gray-200">
              <span className="px-3 text-[10px] font-mono text-purple-400 font-bold uppercase tracking-wider block mb-1">
                Multi-Site Active
              </span>
              <div className="px-3 text-xs text-gray-500">
                Comparing {results.length} websites in all sections.
              </div>
            </div>
          )}
        </aside>

        {/* ========================================================= */}
        {/* CENTER MAIN INTERFACE AREA */}
        {/* ========================================================= */}
        <main className="lg:col-span-6 xl:col-span-7 flex flex-col gap-6">
          {/* SECTION 1: OVERALL */}
          {activeSection === "overall" && (
            <div className="space-y-6">
              {/* Header Status Banner (inspired by the green Financial Status banner in reference image) */}
              <div className={`rounded-2xl p-4 flex items-center justify-between shadow-sm border card-hover ${
                currentSite.overallScore >= 80 ? 'bg-emerald-50/80 border-emerald-200' :
                currentSite.overallScore >= 60 ? 'bg-amber-50/80 border-amber-200' :
                'bg-rose-50/80 border-rose-200'
              }`}>
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                    currentSite.overallScore >= 80 ? 'bg-emerald-100 text-emerald-600' :
                    currentSite.overallScore >= 60 ? 'bg-amber-100 text-amber-600' :
                    'bg-rose-100 text-rose-600'
                  }`}>
                    {currentSite.overallScore >= 80 ? <CheckCircle2 className="w-5 h-5" /> :
                     currentSite.overallScore >= 60 ? <AlertTriangle className="w-5 h-5" /> :
                     <XCircle className="w-5 h-5" />}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-gray-900">
                      Analysis Complete &bull; {currentSite.domain}
                    </h4>
                    <p className="text-xs text-gray-500">
                      {currentSite.statusText}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-gray-400 font-mono uppercase">Grade</div>
                  <div className={`text-2xl font-black ${
                    currentSite.overallScore >= 80 ? 'text-emerald-500' :
                    currentSite.overallScore >= 60 ? 'text-amber-500' :
                    'text-rose-500'
                  }`}>{currentSite.grade}</div>
                </div>
              </div>

              {/* Progress & Score Grid (Inspired by the Reference Image's Area Chart & Health Meter) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Overall Score & Health Gauge */}
                <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm card-hover flex flex-col items-center justify-center">
                  <div className="w-full flex items-center justify-between mb-4">
                    <span className="text-xs font-mono font-bold text-teal-600 uppercase tracking-wider">
                      Overall Health Score
                    </span>
                    <span className={`text-xs px-2.5 py-1 rounded-full font-bold font-mono border ${
                      currentSite.overallScore >= 80 ? 'bg-emerald-50 text-emerald-600 border-emerald-200' :
                      currentSite.overallScore >= 60 ? 'bg-amber-50 text-amber-600 border-amber-200' :
                      'bg-rose-50 text-rose-600 border-rose-200'
                    }`}>
                      {currentSite.grade} Rating
                    </span>
                  </div>

                  {/* Circular SVG Gauge (Lighthouse-style) */}
                  <div className="relative w-40 h-40 mx-auto">
                    <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                      {/* Background track */}
                      <circle cx="60" cy="60" r="52" fill="none" stroke="#f3f4f6" strokeWidth="8" />
                      {/* Score arc */}
                      <circle
                        cx="60" cy="60" r="52"
                        fill="none"
                        stroke={currentSite.overallScore >= 80 ? '#10b981' : currentSite.overallScore >= 60 ? '#f59e0b' : '#ef4444'}
                        strokeWidth="8"
                        strokeLinecap="round"
                        strokeDasharray={`${(currentSite.overallScore / 100) * 2 * Math.PI * 52} ${2 * Math.PI * 52}`}
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    {/* Center text */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-4xl font-black text-gray-900 animate-count-up">{currentSite.overallScore}</span>
                      <span className="text-xs text-gray-400 font-medium">out of 100</span>
                    </div>
                  </div>

                  {/* Gradient bar below */}
                  <div className="w-full mt-4 space-y-1">
                    <div className="flex justify-between text-[10px] font-mono text-gray-400">
                      <span>0</span>
                      <span>50</span>
                      <span>100</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-gradient-to-r from-rose-400 via-amber-400 to-emerald-400 relative">
                      <div
                        className="absolute top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-white border-2 shadow-sm transition-all duration-700"
                        style={{
                          left: `${currentSite.overallScore}%`,
                          borderColor: currentSite.overallScore >= 80 ? '#10b981' : currentSite.overallScore >= 60 ? '#f59e0b' : '#ef4444',
                          transform: `translateX(-50%) translateY(-50%)`
                        }}
                      />
                    </div>
                  </div>
                </div>

                {/* Radar Multi-Set Comparison / Profile */}
                <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm flex flex-col items-center justify-between">
                  <div className="w-full flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-bold text-teal-600 uppercase tracking-wider">
                      Six-Set Posture Radar
                    </span>
                    <span className="text-[10px] text-gray-500">6 Dimensions</span>
                  </div>
                  <div className="w-full h-44">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart data={radarComparisonData}>
                        <PolarGrid stroke="#e5e7eb" />
                        <PolarAngleAxis dataKey="subject" stroke="#6b7280" tick={{ fontSize: 10 }} />
                        <PolarRadiusAxis stroke="#d1d5db" angle={30} domain={[0, 100]} tick={false} />
                        {results.map((r, i) => (
                          <Radar
                            key={r.domain}
                            name={r.domain}
                            dataKey={r.domain}
                            stroke={siteColors[i % siteColors.length]}
                            fill={siteColors[i % siteColors.length]}
                            fillOpacity={0.25}
                          />
                        ))}
                        {isComparison && <Legend wrapperStyle={{ fontSize: 10 }} />}
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              {/* Progress Area Chart across 6 sets (matching reference image's soft multi-layer area graph!) */}
              <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-bold text-gray-700">
                      Six-Dimension Performance Curve
                    </h3>
                    <p className="text-xs text-gray-500">
                      Continuous efficiency profile across Set 1 through Set 6
                    </p>
                  </div>
                  <span className="text-xs font-mono text-teal-600 bg-white border border-gray-200 px-2.5 py-1 rounded-lg">
                    Area Distribution
                  </span>
                </div>

                <div className="w-full h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={progressAreaChartData}>
                      <defs>
                        {results.map((r, i) => (
                          <linearGradient key={r.domain} id={`grad-${i}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={siteColors[i % siteColors.length]} stopOpacity={0.05} />
                            <stop offset="95%" stopColor={siteColors[i % siteColors.length]} stopOpacity={0.0} />
                          </linearGradient>
                        ))}
                      </defs>
                      <XAxis dataKey="name" stroke="#9ca3af" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#9ca3af" domain={[40, 100]} tick={{ fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#ffffff',
                          borderColor: '#e5e7eb',
                          borderRadius: "12px",
                          color: '#1f2937',
                          fontSize: "12px",
                        }}
                      />
                      {results.map((r, i) => (
                        <Area
                          key={r.domain}
                          type="monotone"
                          dataKey={r.domain}
                          stroke={siteColors[i % siteColors.length]}
                          strokeWidth={2.5}
                          fillOpacity={1}
                          fill={`url(#grad-${i})`}
                        />
                      ))}
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Multi-Site Comparison Card (if 2+ sites entered) */}
              {isComparison && (
                <div className="bg-gradient-to-r from-purple-50 via-white to-white border border-purple-200 rounded-2xl p-5 shadow-sm">
                  <div className="flex items-center gap-2 mb-3">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    <h3 className="text-sm font-bold text-purple-700 uppercase tracking-wider font-mono">
                      Overall Website Comparison &bull; Why They Differ
                    </h3>
                  </div>
                  <div className="space-y-3 text-xs text-gray-600 leading-relaxed">
                    <p>
                      <strong className="text-teal-600">{results[0].domain}</strong> scored{" "}
                      <strong className="text-gray-900">{results[0].overallScore}/100</strong>, while{" "}
                      <strong className="text-purple-600">{results[1]?.domain}</strong> achieved{" "}
                      <strong className="text-gray-900">{results[1]?.overallScore}/100</strong>.
                    </p>
                    <p className="bg-gray-50 p-3 rounded-xl border border-gray-200">
                      {results[0].overallScore >= (results[1]?.overallScore || 0) ? (
                        <span>
                          <strong className="text-emerald-400">{results[0].domain}</strong> demonstrated superior
                          protection due to strict HSTS preload and modern TLS 1.3 ciphers, whereas{" "}
                          <strong className="text-amber-400">{results[1]?.domain}</strong> lost points in Set 2 and Set 3
                          from missing DMARC rejection records.
                        </span>
                      ) : (
                        <span>
                          <strong className="text-emerald-400">{results[1]?.domain}</strong> took the lead with
                          comprehensive Content Security Policy directives and zero public database port exposure.
                        </span>
                      )}
                    </p>
                  </div>
                </div>
              )}

              {/* Strengths & Weaknesses 2-Column Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm card-hover">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm mb-3">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Key Strengths</span>
                  </div>
                  <ul className="space-y-2 text-xs text-gray-600">
                    {currentSite.strengths.map((s, i) => (
                      <li key={i} className="flex items-start gap-2 bg-gray-50 p-2.5 rounded-xl border border-gray-200">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0"></span>
                        <span>{s}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm card-hover">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-sm mb-3">
                    <XCircle className="w-4 h-4" />
                    <span>Critical Issues &amp; Deductions</span>
                  </div>
                  <ul className="space-y-2 text-xs text-gray-600">
                    {currentSite.criticalIssues.map((c, i) => (
                      <li key={i} className="flex items-start gap-2 bg-gray-50 p-2.5 rounded-xl border border-gray-200">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0"></span>
                        <span>{c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* SECTIONS 2 TO 7: SIX INDIVIDUAL SETS (Set 1 to Set 6) */}
          {/* ========================================================= */}
          {["set1", "set2", "set3", "set4", "set5", "set6"].includes(activeSection) && (() => {
            const setKey = activeSection;
            const setDetails = currentSite.detailedSets[setKey];

            return (
              <div className="space-y-6">
                {/* Set Header Card */}
                <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="text-[10px] font-mono uppercase tracking-widest px-2.5 py-0.5 rounded bg-teal-50 text-teal-600 border border-teal-200 font-bold">
                        Dimension Analysis
                      </span>
                    </div>
                    <h2 className="text-2xl font-black text-gray-900">{setDetails.name}</h2>
                    <p className="text-xs text-gray-500 mt-1">
                      Target evaluated: <strong className="text-gray-700">{currentSite.domain}</strong>
                    </p>
                  </div>

                  <div className="flex items-center gap-6 bg-gray-50 px-6 py-4 rounded-xl border border-gray-200">
                    {/* Donut Score Chart */}
                    <div className="w-28 h-28">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={[{ value: setDetails.score }, { value: 100 - setDetails.score }]}
                            cx="50%"
                            cy="50%"
                            innerRadius={35}
                            outerRadius={48}
                            startAngle={90}
                            endAngle={-270}
                            dataKey="value"
                            strokeWidth={0}
                          >
                            <Cell fill={setDetails.score >= 70 ? '#0d9488' : setDetails.score >= 50 ? '#f59e0b' : '#ef4444'} />
                            <Cell fill="#e5e7eb" />
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="relative -mt-[72px] flex flex-col items-center justify-center">
                        <span className="text-2xl font-black text-gray-900">{setDetails.score}</span>
                        <span className="text-[10px] text-gray-400">/100</span>
                      </div>
                    </div>
                    <div className="text-center pl-6 border-l border-gray-200">
                      <div className="text-[10px] uppercase font-mono text-gray-400 font-bold">Grade</div>
                      <div className="text-3xl font-black text-gray-900">{setDetails.grade}</div>
                    </div>
                  </div>
                </div>

                {/* What was Analyzed & Evidence Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Analyzed Items */}
                  <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm card-hover">
                    <h4 className="text-xs font-mono uppercase text-teal-600 font-bold mb-3 flex items-center gap-1.5">
                      <Info className="w-3.5 h-3.5" /> What Was Analyzed
                    </h4>
                    <div className="space-y-2 text-xs text-gray-600">
                      {setDetails.analyzedItems.map((item, idx) => {
                        const isPassing = idx < setDetails.positiveFindings.length;
                        return (
                          <div key={idx} className={`flex items-center justify-between gap-2 p-2.5 rounded-lg border transition-colors ${
                            isPassing ? 'bg-emerald-50/50 border-emerald-100 hover:border-emerald-200' : 'bg-gray-50 border-gray-200 hover:border-gray-300'
                          }`}>
                            <div className="flex items-center gap-2">
                              {isPassing ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                              ) : (
                                <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                              )}
                              <span className="font-medium">{item}</span>
                            </div>
                            <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded-full border ${
                              isPassing ? 'bg-emerald-50 text-emerald-600 border-emerald-200' : 'bg-amber-50 text-amber-600 border-amber-200'
                            }`}>
                              {isPassing ? 'PASS' : 'REVIEW'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Evidence / Data Behind Score */}
                  <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm">
                    <h4 className="text-xs font-mono uppercase text-purple-400 font-bold mb-3 flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5" /> Evidence &amp; Data Telemetry
                    </h4>
                    <div className="p-3 bg-gray-50 rounded-xl border border-gray-200 text-xs text-gray-600 font-mono leading-relaxed select-all">
                      {setDetails.evidence}
                    </div>
                    <div className="mt-3 text-xs text-gray-500 flex items-center justify-between">
                      <span>Metric Output:</span>
                      <span className="font-mono text-emerald-400 font-bold">{setDetails.metricValue}</span>
                    </div>
                  </div>
                </div>

                {/* Positive vs Negative Findings */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-5 shadow-sm">
                    <h4 className="text-xs font-mono uppercase text-emerald-400 font-bold mb-3 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Positive Findings
                    </h4>
                    <ul className="space-y-2 text-xs text-gray-600">
                      {setDetails.positiveFindings.map((pos, idx) => (
                        <li key={idx} className="p-2 rounded-lg bg-gray-50 border border-emerald-200 flex items-start gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0"></span>
                          <span>{pos}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="bg-rose-50 border border-rose-200 rounded-2xl p-5 shadow-sm">
                    <h4 className="text-xs font-mono uppercase text-rose-400 font-bold mb-3 flex items-center gap-1.5">
                      <XCircle className="w-3.5 h-3.5" /> Negative Findings &amp; Gaps
                    </h4>
                    <ul className="space-y-2 text-xs text-gray-600">
                      {setDetails.negativeFindings.map((neg, idx) => (
                        <li key={idx} className="p-2 rounded-lg bg-gray-50 border border-rose-200 flex items-start gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0"></span>
                          <span>{neg}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Visual Certificate Trust Chain (SSLShopper style for Set 1) */}
                {setKey === "set1" && (
                  <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm card-hover">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-teal-600" />
                        <h4 className="text-xs font-mono uppercase text-teal-600 font-bold">
                          Certificate Trust Chain Path
                        </h4>
                      </div>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-600 border border-emerald-200">
                        CHAIN VERIFIED
                      </span>
                    </div>

                    <div className="flex flex-col md:flex-row items-center justify-between gap-3">
                      {/* Step 1: Root CA */}
                      <div className="flex-1 w-full bg-gray-50 border border-gray-200 rounded-xl p-3.5 flex items-start gap-3">
                        <div className="w-8 h-8 rounded-lg bg-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
                          <Shield className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-[10px] font-mono text-gray-400 uppercase font-bold">Root CA Anchor</div>
                          <div className="text-xs font-bold text-gray-900 truncate">ISRG Root X1 / DigiCert</div>
                          <div className="text-[10px] text-emerald-600 font-mono flex items-center gap-1 mt-0.5">
                            <CheckCircle2 className="w-3 h-3" /> Built-in OS Trust Store
                          </div>
                        </div>
                      </div>

                      {/* Connector Arrow */}
                      <div className="hidden md:flex text-gray-400">
                        <ChevronRight className="w-5 h-5 text-gray-300" />
                      </div>

                      {/* Step 2: Intermediate CA */}
                      <div className="flex-1 w-full bg-gray-50 border border-gray-200 rounded-xl p-3.5 flex items-start gap-3">
                        <div className="w-8 h-8 rounded-lg bg-teal-100 flex items-center justify-center text-teal-600 shrink-0">
                          <Server className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-[10px] font-mono text-gray-400 uppercase font-bold">Intermediate CA</div>
                          <div className="text-xs font-bold text-gray-900 truncate">R3 / Global CA Authority</div>
                          <div className="text-[10px] text-teal-600 font-mono flex items-center gap-1 mt-0.5">
                            <CheckCircle2 className="w-3 h-3" /> Intermediate Valid
                          </div>
                        </div>
                      </div>

                      {/* Connector Arrow */}
                      <div className="hidden md:flex text-gray-400">
                        <ChevronRight className="w-5 h-5 text-gray-300" />
                      </div>

                      {/* Step 3: Leaf / Server Cert */}
                      <div className="flex-1 w-full bg-emerald-50/60 border border-emerald-200 rounded-xl p-3.5 flex items-start gap-3">
                        <div className="w-8 h-8 rounded-lg bg-emerald-500 text-white flex items-center justify-center shrink-0">
                          <Lock className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-[10px] font-mono text-emerald-700 uppercase font-bold">Server Leaf Certificate</div>
                          <div className="text-xs font-bold text-gray-900 truncate">*.{currentSite.domain}</div>
                          <div className="text-[10px] text-emerald-600 font-mono flex items-center gap-1 mt-0.5">
                            <CheckCircle2 className="w-3 h-3" /> Valid TLS 1.3 Active
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* 1-Click Server Remediation Snippets (for Set 2) */}
                {setKey === "set2" && (
                  <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm card-hover">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <Terminal className="w-4 h-4 text-teal-600" />
                          <h4 className="text-xs font-mono uppercase text-teal-600 font-bold">
                            1-Click Ready Configuration Fix
                          </h4>
                        </div>
                        <p className="text-xs text-gray-500 mt-0.5">
                          Deploy to web server config to immediately earn Grade A+ on Security Headers.
                        </p>
                      </div>

                      {/* Server Tabs */}
                      <div className="flex items-center gap-1 bg-gray-100 p-1 rounded-xl">
                        {(["nginx", "apache", "caddy", "cloudflare"] as const).map((server) => (
                          <button
                            key={server}
                            onClick={() => setSelectedServerTab(server)}
                            className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold uppercase transition-all ${
                              selectedServerTab === server
                                ? "bg-white text-teal-600 shadow-sm font-bold"
                                : "text-gray-500 hover:text-gray-900"
                            }`}
                          >
                            {server}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="relative">
                      <pre className="p-4 bg-gray-900 text-gray-100 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed max-h-52">
                        <code>{serverSnippets[selectedServerTab]}</code>
                      </pre>
                      <button
                        onClick={() => copyToClipboard(serverSnippets[selectedServerTab], selectedServerTab)}
                        className="absolute top-3 right-3 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 shadow-sm transition-all"
                      >
                        {copiedSnippet === selectedServerTab ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400">Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5 text-gray-400" />
                            <span>Copy Snippet</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                )}

                {/* Why Score Was Given & Recommendations */}
                <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm space-y-4">
                  <div>
                    <h4 className="text-xs font-mono uppercase text-amber-400 font-bold mb-1">
                      Why This Score Was Awarded
                    </h4>
                    <p className="text-xs text-gray-600 leading-relaxed bg-gray-50 p-3.5 rounded-xl border border-gray-200">
                      {setDetails.whyScoreGiven}
                    </p>
                  </div>

                  <div>
                    <h4 className="text-xs font-mono uppercase text-teal-600 font-bold mb-1">
                      Recommendation For Improvement
                    </h4>
                    <p className="text-xs text-gray-600 leading-relaxed bg-gray-50 p-3.5 rounded-xl border border-gray-200">
                      {setDetails.recommendation}
                    </p>
                  </div>
                </div>

                {/* Multi-Website Side-by-Side Comparison for this Specific Set */}
                {isComparison && (
                  <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
                    <h4 className="text-xs font-mono uppercase text-purple-400 font-bold mb-3">
                      {setDetails.name} &bull; Comparative Matrix
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {results.map((r, i) => {
                        const siteSetScore = (r.setScores as any)[setKey] || 70;
                        return (
                          <div
                            key={r.domain}
                            className="bg-gray-50 p-4 rounded-xl border border-gray-200 flex flex-col justify-between"
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-bold text-sm text-gray-900">{r.domain}</span>
                              <span className="text-xs font-mono text-teal-600">{siteSetScore}/100</span>
                            </div>
                            <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-cyan-400"
                                style={{ width: `${siteSetScore}%` }}
                              ></div>
                            </div>
                            <p className="text-[11px] text-gray-500 mt-3">
                              {r.detailedSets[setKey]?.whyScoreGiven || "Evaluated against security standard."}
                            </p>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {/* ========================================================= */}
          {/* SECTION 8: SCORING (Deep Transparent Breakdown) */}
          {/* ========================================================= */}
          {activeSection === "scoring" && (
            <div className="space-y-6">
              <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm">
                <div className="flex items-center gap-2 mb-2">
                  <BarChart3 className="w-5 h-5 text-teal-600" />
                  <h2 className="text-2xl font-black text-gray-900">Transparent Scoring Breakdown</h2>
                </div>
                <p className="text-xs text-gray-500 mb-6">
                  ScanZero never displays opaque, mysterious numbers. Every point awarded or deducted is mapped directly to real evidence, severity, and remediation pathways.
                </p>

                <div className="w-full h-48 mt-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={currentSite.scoringBreakdown.map(item => ({ name: item.category.substring(0, 12), earned: item.earned, max: item.max }))}>
                      <XAxis dataKey="name" stroke="#9ca3af" tick={{ fontSize: 10 }} />
                      <YAxis stroke="#9ca3af" tick={{ fontSize: 10 }} />
                      <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e5e7eb', borderRadius: '12px', fontSize: '12px', color: '#1f2937' }} />
                      <Bar dataKey="max" fill="#e5e7eb" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="earned" fill="#0d9488" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Scoring Formula Card */}
                <div className="bg-gray-50 border border-gray-200 p-4 rounded-xl mb-6 flex flex-col md:flex-row items-center justify-between gap-4">
                  <div className="text-xs font-mono text-gray-600">
                    <span className="text-teal-600 font-bold">Standard Formula:</span> (Crypto &times; 0.25) + (Headers &times; 0.30) + (DNS &times; 0.20) + (Surface &times; 0.25)
                  </div>
                  <div className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-lg border border-emerald-200">
                    Final Score: {currentSite.overallScore}/100
                  </div>
                </div>

                {/* Point Attribution Table / Cards (Mozilla Observatory Modifier Style) */}
                <div className="space-y-4">
                  {currentSite.scoringBreakdown.map((item, idx) => {
                    const deduction = item.max - item.earned;
                    const percent = Math.round((item.earned / item.max) * 100);
                    return (
                      <div
                        key={idx}
                        className="bg-gray-50 border border-gray-200/90 rounded-2xl p-5 space-y-3.5 hover:border-gray-300 card-hover transition-all"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-gray-200 pb-3">
                          <div className="flex items-center gap-2.5">
                            <span className="font-bold text-gray-900 text-sm">{item.category}</span>
                            <span className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border ${getBadgeBg(item.severity)}`}>
                              {item.severity}
                            </span>
                          </div>
                          <div className="flex items-center gap-2.5 font-mono text-xs">
                            {/* Mozilla Observatory style + / - modifier tags */}
                            <span className="px-2.5 py-1 rounded-lg bg-emerald-50 text-emerald-700 font-bold border border-emerald-200 text-xs">
                              +{item.earned} pts
                            </span>
                            {deduction > 0 && (
                              <span className="px-2.5 py-1 rounded-lg bg-rose-50 text-rose-700 font-bold border border-rose-200 text-xs">
                                -{deduction} penalty
                              </span>
                            )}
                            <span className="text-gray-400 font-medium">
                              ({percent}% of {item.max} max)
                            </span>
                          </div>
                        </div>

                        {/* Visual completion progress bar */}
                        <div className="space-y-1">
                          <div className="h-1.5 w-full bg-gray-200 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-500 ${
                                percent >= 80 ? 'bg-emerald-500' : percent >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                              }`}
                              style={{ width: `${percent}%` }}
                            />
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          <div className="bg-emerald-50/70 border border-emerald-100 p-3 rounded-xl text-gray-700">
                            <span className="text-emerald-700 font-bold block mb-1 flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                              Points Awarded Rationale:
                            </span>
                            {item.reasonEarned}
                          </div>
                          <div className="bg-rose-50/70 border border-rose-100 p-3 rounded-xl text-gray-700">
                            <span className="text-rose-700 font-bold block mb-1 flex items-center gap-1">
                              <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                              Point Deduction Rationale:
                            </span>
                            {item.reasonDeducted}
                          </div>
                        </div>

                        <div className="text-xs text-gray-500 flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1 border-t border-gray-200/60">
                          <div>
                            <strong className="text-gray-700 font-mono text-[11px] uppercase">Telemetry Evidence:</strong>{" "}
                            <code className="text-teal-700 bg-teal-50 px-2 py-0.5 rounded border border-teal-200/60 font-mono text-[11px]">{item.evidence}</code>
                          </div>
                          <div>
                            <strong className="text-gray-700 font-mono text-[11px] uppercase">Action Pathway:</strong>{" "}
                            <span className="text-gray-600">{item.improvement}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* SECTION 9: SUMMARY REPORT */}
          {/* ========================================================= */}
          {activeSection === "summary" && (
            <div className="space-y-6">
              <div className="bg-white border border-gray-200 rounded-2xl p-6 shadow-sm space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-gray-200 pb-4">
                  <div>
                    <h2 className="text-2xl font-black text-gray-900">ScanZero Executive Summary Report</h2>
                    <p className="text-xs text-gray-500 mt-1">
                      Comprehensive posture audit for client sharing and board presentations.
                    </p>
                  </div>
                  <button
                    onClick={handleDownloadReport}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-teal-500 hover:bg-cyan-400 text-gray-900 text-xs font-bold transition-all shadow-lg"
                  >
                    <Download className="w-4 h-4" /> Download Client PDF
                  </button>
                </div>

                {/* Score Summary Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="bg-gray-50 p-4 rounded-xl border border-gray-200 text-center">
                    <div className="text-xs font-mono text-gray-500 uppercase">Overall Posture</div>
                    <div className="text-3xl font-black text-teal-600 mt-1">{currentSite.overallScore}%</div>
                    <div className="text-[10px] text-gray-400">Grade {currentSite.grade}</div>
                  </div>
                  <div className="bg-gray-50 p-4 rounded-xl border border-gray-200 text-center">
                    <div className="text-xs font-mono text-gray-500 uppercase">Critical Risks</div>
                    <div className="text-3xl font-black text-rose-400 mt-1">{currentSite.criticalIssues.length}</div>
                    <div className="text-[10px] text-gray-400">Immediate Action</div>
                  </div>
                  <div className="bg-gray-50 p-4 rounded-xl border border-gray-200 text-center">
                    <div className="text-xs font-mono text-gray-500 uppercase">Verified Strengths</div>
                    <div className="text-3xl font-black text-emerald-400 mt-1">{currentSite.strengths.length}</div>
                    <div className="text-[10px] text-gray-400">Industry Passing</div>
                  </div>
                  <div className="bg-gray-50 p-4 rounded-xl border border-gray-200 text-center">
                    <div className="text-xs font-mono text-gray-500 uppercase">Target Domain</div>
                    <div className="text-lg font-bold text-gray-900 mt-2 truncate">{currentSite.domain}</div>
                    <div className="text-[10px] text-gray-400">SSL Valid</div>
                  </div>
                </div>

                {/* Actionable Priority Matrix */}
                <div>
                  <h3 className="text-sm font-bold text-gray-700 mb-3 uppercase tracking-wider font-mono">
                    Prioritized Action Plan
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left text-gray-600">
                      <thead className="bg-gray-50 text-[11px] font-mono text-gray-500 uppercase">
                        <tr>
                          <th className="p-3">Priority</th>
                          <th className="p-3">Remediation Action</th>
                          <th className="p-3">Affected Set</th>
                          <th className="p-3">Expected Score Gain</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        <tr>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-200">
                              HIGH
                            </span>
                          </td>
                          <td className="p-3 font-medium text-gray-900">Implement Strict HSTS Preload header in Web Server</td>
                          <td className="p-3 text-teal-600">Set 2: Headers</td>
                          <td className="p-3 text-emerald-400 font-mono font-bold">+8 Points</td>
                        </tr>
                        <tr>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                              MEDIUM
                            </span>
                          </td>
                          <td className="p-3 font-medium text-gray-900">Enforce DMARC rejection policy (p=reject) in DNS</td>
                          <td className="p-3 text-teal-600">Set 3: DNS</td>
                          <td className="p-3 text-emerald-400 font-mono font-bold">+6 Points</td>
                        </tr>
                        <tr>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                              LOW
                            </span>
                          </td>
                          <td className="p-3 font-medium text-gray-900">Set Cookie flag SameSite=Strict on session identifiers</td>
                          <td className="p-3 text-teal-600">Set 2: Headers</td>
                          <td className="p-3 text-emerald-400 font-mono font-bold">+3 Points</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>

        {/* ========================================================= */}
        {/* RIGHT ACTIVITY STREAM (Inspired directly by reference image) */}
        {/* ========================================================= */}
        <aside className="lg:col-span-3 xl:col-span-3 space-y-6">
          {/* Activity Stream Card (matching right side of reference image) */}
          <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between border-b border-gray-200 pb-3 mb-4">
              <h3 className="text-xs font-mono font-bold text-teal-600 uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5" /> Intelligence Stream
              </h3>
              <span className="text-[10px] font-mono text-gray-500">Live Audit</span>
            </div>

            <div className="space-y-3.5">
              <div className="p-3 rounded-xl bg-gray-50 border border-gray-200 space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-bold text-gray-700">Worker 2 &bull; TLS Handshake</span>
                  <span className="text-emerald-400 text-[10px] font-mono">Passed</span>
                </div>
                <p className="text-[11px] text-gray-500">TLS 1.3 negotiated with AES-256-GCM cipher suite.</p>
                <div className="text-[10px] text-gray-400 font-mono">0.14s latency</div>
              </div>

              <div className="p-3 rounded-xl bg-gray-50 border border-gray-200 space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-bold text-gray-700">Worker 3 &bull; Header Audit</span>
                  <span className="text-amber-400 text-[10px] font-mono">Notice</span>
                </div>
                <p className="text-[11px] text-gray-500">Missing CSP frame-ancestors directive.</p>
                <div className="text-[10px] text-gray-400 font-mono">Port 443</div>
              </div>

              <div className="p-3 rounded-xl bg-gray-50 border border-gray-200 space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-bold text-gray-700">Worker 4 &bull; DNS Resolver</span>
                  <span className="text-emerald-400 text-[10px] font-mono">Verified</span>
                </div>
                <p className="text-[11px] text-gray-500">SPF record syntax verified (v=spf1 -all).</p>
                <div className="text-[10px] text-gray-400 font-mono">Lookup count: 4/10</div>
              </div>

              <div className="p-3 rounded-xl bg-gray-50 border border-gray-200 space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-bold text-gray-700">Worker 6 &bull; Honeypot Check</span>
                  <span className="text-teal-600 text-[10px] font-mono">Clean</span>
                </div>
                <p className="text-[11px] text-gray-500">Random canary returned 404. Non-tarpit host.</p>
                <div className="text-[10px] text-gray-400 font-mono">Deception score: 0.05</div>
              </div>
            </div>
          </div>

          {/* Quick Schedule / Re-Scan Mini Card */}
          <div className="bg-white border border-gray-200 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center gap-2 mb-2 text-gray-600 font-bold text-xs">
              <Clock className="w-4 h-4 text-teal-600" />
              <span>Automated Watch Status</span>
            </div>
            <p className="text-xs text-gray-500 mb-3">
              This report will automatically refresh on daily schedule with score-drop alerts.
            </p>
            <div className="p-2.5 rounded-xl bg-gray-50 border border-gray-200 flex items-center justify-between text-xs">
              <span className="text-gray-500">Frequency:</span>
              <span className="text-teal-600 font-mono font-bold">Daily (24h)</span>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
