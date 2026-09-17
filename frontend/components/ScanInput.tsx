"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Plus, X, Loader2 } from "lucide-react";
import toast from "react-hot-toast";
import { API_BASE_URL } from "@/lib/config";

export default function ScanInput() {
  const [url, setUrl] = useState("");
  const [competitors, setCompetitors] = useState<string[]>([]);
  const [isExpanded, setIsExpanded] = useState(false);
  const [newCompetitor, setNewCompetitor] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleAddCompetitor = () => {
    if (!newCompetitor.trim()) return;
    if (competitors.length >= 5) {
      toast.error("Maximum 5 competitors allowed");
      return;
    }
    setCompetitors([...competitors, newCompetitor.trim()]);
    setNewCompetitor("");
  };

  const handleRemoveCompetitor = (index: number) => {
    setCompetitors(competitors.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      toast.error("Please enter a valid URL");
      return;
    }

    setIsLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), competitors }),
      });

      if (!res.ok) throw new Error("Failed to start scan");

      const data = await res.json();
      if (data.scan_id) {
        toast.success("Scan initiated successfully");
        router.push(`/scan/${data.scan_id}`);
      } else {
        throw new Error("Invalid response from server");
      }
    } catch (error) {
      console.error(error);
      toast.error("Failed to start scan. Ensure backend is running.");
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto">
      <form onSubmit={handleSubmit} className="relative group">
        <div className="absolute -inset-1 bg-gradient-to-r from-cyan-400 to-emerald-400 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
        <div className="relative flex flex-col md:flex-row items-center bg-white rounded-xl border border-gray-200/50 p-2 shadow-2xl">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter website URL (e.g., https://example.com)"
            className="w-full bg-transparent text-gray-900 placeholder-slate-500 px-6 py-4 outline-none text-lg"
            required
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading}
            className="w-full md:w-auto mt-2 md:mt-0 flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 text-slate-950 px-8 py-4 rounded-lg font-bold transition-all disabled:opacity-70 disabled:cursor-not-allowed whitespace-nowrap"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Initializing...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                SCAN NOW
              </>
            )}
          </button>
        </div>
      </form>

      <div className="mt-6 flex flex-col items-center">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-sm text-gray-500 hover:text-teal-600 flex items-center gap-1 transition-colors"
        >
          {isExpanded ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {isExpanded ? "Hide Competitors" : "Add Competitor URLs (Optional)"}
        </button>

        {isExpanded && (
          <div className="mt-4 w-full bg-gray-100/50 border border-gray-200 rounded-xl p-4 animate-in fade-in slide-in-from-top-4">
            <div className="flex gap-2">
              <input
                type="url"
                value={newCompetitor}
                onChange={(e) => setNewCompetitor(e.target.value)}
                placeholder="Competitor URL (e.g., https://competitor.com)"
                className="flex-1 bg-white border border-gray-200 rounded-lg px-4 py-2 text-sm text-gray-800 outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all"
                onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), handleAddCompetitor())}
              />
              <button
                type="button"
                onClick={handleAddCompetitor}
                className="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-lg text-sm transition-colors"
              >
                Add
              </button>
            </div>
            
            {competitors.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-2">
                {competitors.map((comp, idx) => (
                  <span
                    key={idx}
                    className="flex items-center gap-1 bg-cyan-900/30 text-teal-600 border border-cyan-800/50 px-3 py-1.5 rounded-full text-xs"
                  >
                    {comp}
                    <button
                      type="button"
                      onClick={() => handleRemoveCompetitor(idx)}
                      className="hover:text-red-400 ml-1"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
            <p className="text-xs text-gray-400 mt-3 text-center">
              Compare your security posture against up to 5 competitors.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
