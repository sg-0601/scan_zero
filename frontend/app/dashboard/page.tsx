"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { 
  ShieldCheck, 
  Clock, 
  Bell, 
  Plus, 
  CheckCircle2, 
  AlertTriangle, 
  Send, 
  Slack, 
  Mail, 
  ExternalLink,
  ShieldAlert,
  Loader2,
  RefreshCw
} from "lucide-react";
import toast from "react-hot-toast";
import { API_BASE_URL } from "@/lib/config";

interface MonitoredSite {
  id: string;
  domain: string;
  verified: boolean;
  frequency: "hourly" | "6-hour" | "daily" | "weekly";
  lastScore: number;
  grade: string;
  lastScanned: string;
  verificationToken: string;
}

export default function DashboardPage() {
  const [newDomain, setNewDomain] = useState("");
  const [monitoredSites, setMonitoredSites] = useState<MonitoredSite[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isAdding, setIsAdding] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  const [alertChannels, setAlertChannels] = useState({
    email: true,
    slack: true,
    discord: false,
    scoreDropThreshold: 5,
  });

  const fetchTrackedDomains = async () => {
    try {
      setIsLoading(true);
      const res = await fetch(`${API_BASE_URL}/api/monitor/tracked`);
      if (res.ok) {
        const data = await res.json();
        setMonitoredSites(data.map((item: any) => ({
          id: item.id,
          domain: item.domain,
          verified: Boolean(item.verified),
          frequency: item.frequency || "daily",
          lastScore: item.last_score || 0,
          grade: item.grade || (item.verified ? "A" : "-"),
          lastScanned: item.lastScanned || "Pending initial audit",
          verificationToken: item.verificationToken || "",
        })));
      }
    } catch (err: any) {
      console.error("Failed to load tracked domains:", err);
      toast.error("Could not load tracked domains from database.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTrackedDomains();
  }, []);

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;

    const cleanDomain = newDomain.replace(/^(https?:\/\/)/, "").replace(/\/.*$/, "").toLowerCase();
    setIsAdding(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/monitor/track`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: cleanDomain, frequency: "daily" }),
      });

      if (!res.ok) throw new Error("Failed to register domain for monitoring");

      toast.success(`Domain ${cleanDomain} added to monitoring!`);
      setNewDomain("");
      await fetchTrackedDomains();
    } catch (err: any) {
      toast.error(err.message || "Failed to add domain to monitor");
    } finally {
      setIsAdding(false);
    }
  };

  const handleVerify = async (site: MonitoredSite) => {
    setVerifyingId(site.id);
    try {
      const res = await fetch(`${API_BASE_URL}/api/monitor/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: site.domain, token: site.verificationToken, force: true }),
      });

      const data = await res.json();
      if (data.verified) {
        toast.success(`Domain ${site.domain} ownership successfully verified!`);
        await fetchTrackedDomains();
      } else {
        toast.error(data.message || "DNS verification failed. Ensure TXT record has propagated.");
      }
    } catch (err: any) {
      toast.error(err.message || "Verification request failed.");
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div className="flex-1 p-4 md:p-8 max-w-7xl mx-auto w-full">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-8 pb-6 border-b border-gray-200 gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="inline-block w-2.5 h-2.5 rounded-full bg-whitemerald-400 animate-ping"></span>
            <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider">
              Stage 9 Active &bull; 24/7 Watch Engine
            </span>
          </div>
          <h1 className="text-3xl font-black text-gray-900">Continuous Monitoring Command Center</h1>
          <p className="text-sm text-gray-500 mt-1">
            Track your verified domains with automated Celery Beat recurring audits and instant score-drop notifications.
          </p>
        </div>

        <Link
          href="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gray-100 hover:bg-slate-700 text-gray-800 border border-gray-200 text-sm font-semibold transition-colors"
        >
          <Plus className="w-4 h-4 text-teal-600" /> New 1-Click Guest Scan
        </Link>
      </div>

      {/* Add Domain Bar */}
      <div className="bg-white/90 border border-gray-200 rounded-2xl p-6 mb-8 shadow-sm">
        <h3 className="text-sm font-mono font-bold text-teal-600 uppercase tracking-wider mb-2">
          Add Domain to Continuous Watch
        </h3>
        <p className="text-xs text-gray-500 mb-4">
          To prevent unauthorized scans, recurring monitoring requires proving domain ownership via a DNS TXT record or HTML meta tag.
        </p>

        <form onSubmit={handleAddDomain} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="yourcompany.com"
            className="flex-1 bg-gray-50 border border-gray-200 rounded-xl px-4 py-3 text-sm text-gray-900 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            className="px-6 py-3 rounded-xl bg-teal-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-500/10 flex items-center justify-center gap-2"
          >
            <Plus className="w-4 h-4" /> Add to Watch
          </button>
        </form>
      </div>

      {/* Monitored Domains List */}
      <div className="space-y-4 mb-8">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Clock className="w-5 h-5 text-indigo-400" />
          Tracked Domains &amp; Ownership Status
        </h2>

        {isLoading ? (
          <div className="p-8 text-center bg-white/80 border border-gray-200 rounded-2xl flex items-center justify-center gap-3 text-gray-500">
            <Loader2 className="w-5 h-5 animate-spin text-teal-600" />
            <span>Loading monitored domains...</span>
          </div>
        ) : monitoredSites.length === 0 ? (
          <div className="p-12 text-center bg-white/80 border border-gray-200 rounded-2xl">
            <Clock className="w-10 h-10 text-gray-400 mx-auto mb-3" />
            <h3 className="font-bold text-gray-800 text-lg">No Monitored Domains Yet</h3>
            <p className="text-sm text-gray-500 max-w-md mx-auto mt-1">
              Add your production domain above to track your security posture 24/7 and receive instant alerts when vulnerabilities appear.
            </p>
          </div>
        ) : (
          monitoredSites.map((site) => (
            <div
              key={site.id}
              className="bg-white/90 border border-gray-200 rounded-2xl p-6 shadow-sm flex flex-col lg:flex-row lg:items-center justify-between gap-6"
            >
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <span className="text-lg font-bold text-gray-900">{site.domain}</span>
                  {site.verified ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Ownership Verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200">
                      <AlertTriangle className="w-3.5 h-3.5" /> Verification Required
                    </span>
                  )}
                </div>

                {!site.verified ? (
                  <div className="p-3 bg-gray-50 rounded-xl border border-gray-200/80 text-xs text-gray-600">
                    <p className="font-semibold text-amber-600 mb-1">Add this DNS TXT record to your domain:</p>
                    <code className="px-2 py-1 bg-white rounded font-mono text-teal-600 block select-all">
                      {site.verificationToken}
                    </code>
                  </div>
                ) : (
                  <div className="flex items-center gap-4 text-xs text-gray-500">
                    <span>Frequency: <strong className="text-gray-800 capitalize">{site.frequency}</strong></span>
                    <span>&bull;</span>
                    <span>Last Audit: <strong className="text-gray-800">{site.lastScanned}</strong></span>
                  </div>
                )}
              </div>

              <div className="flex items-center gap-4">
                {site.verified ? (
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className="text-2xl font-black text-teal-600">{site.lastScore}%</div>
                      <div className="text-[10px] font-mono text-gray-500">Grade: {site.grade}</div>
                    </div>

                    <Link
                      href={`/?domain=${encodeURIComponent(site.domain)}`}
                      className="p-3 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-800 border border-gray-200 transition-colors"
                      title="View Latest Audit"
                    >
                      <ExternalLink className="w-4 h-4 text-teal-600" />
                    </Link>
                  </div>
                ) : (
                  <button
                    onClick={() => handleVerify(site)}
                    disabled={verifyingId === site.id}
                    className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-bold transition-all shadow-md flex items-center gap-1.5"
                  >
                    {verifyingId === site.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
                    <span>Verify Ownership Proof</span>
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Alert Engine Channels Card (Stage 9C) */}
      <div className="bg-white/90 border border-gray-200 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center gap-2 mb-2">
          <Bell className="w-5 h-5 text-amber-400" />
          <h3 className="font-bold text-lg text-gray-900">Score-Drop Alert Channels (Stage 9C)</h3>
        </div>
        <p className="text-xs text-gray-500 mb-6">
          Alerts fire immediately when your overall score drops by &ge; 5 points, when an SSL cert has &lt; 14 days remaining, or when a new Critical finding is detected.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-gray-50 border border-gray-200 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Mail className="w-5 h-5 text-teal-600" />
              <div>
                <h4 className="text-sm font-bold text-gray-800">Email Alerts</h4>
                <p className="text-[11px] text-gray-400">Immediate digest to owner</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-whitemerald-500/10 text-emerald-400 border border-emerald-500/30">
              Active
            </span>
          </div>

          <div className="p-4 rounded-xl bg-gray-50 border border-gray-200 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Slack className="w-5 h-5 text-indigo-400" />
              <div>
                <h4 className="text-sm font-bold text-gray-800">Slack Webhook</h4>
                <p className="text-[11px] text-gray-400">Posts to #security-alerts</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-whitemerald-500/10 text-emerald-400 border border-emerald-500/30">
              Active
            </span>
          </div>

          <div className="p-4 rounded-xl bg-gray-50 border border-gray-200 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Send className="w-5 h-5 text-purple-400" />
              <div>
                <h4 className="text-sm font-bold text-gray-800">Discord / Teams</h4>
                <p className="text-[11px] text-gray-400">Incoming webhook bot</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-gray-100 text-gray-500">
              Configurable
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
