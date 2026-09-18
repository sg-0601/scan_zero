"use client";

import { useEffect, useState } from "react";
import { Shield, Loader2, CheckCircle2, XCircle } from "lucide-react";
import { motion } from "framer-motion";

export interface WorkerStatus {
  id: string;
  name: string;
  status: "waiting" | "running" | "done" | "error";
  progress?: number;
}

export default function ScanProgress({ workers = [] }: { workers?: WorkerStatus[] }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const defaultWorkers: WorkerStatus[] = workers.length > 0 ? workers : [
    { id: "w1", name: "1. OSINT & Threat Intel (VT, Shodan, OTX)", status: elapsed > 2 ? "done" : "running" },
    { id: "w2", name: "2. TLS Cryptography & Ciphers", status: elapsed > 5 ? "done" : elapsed > 1 ? "running" : "waiting" },
    { id: "w3", name: "3. HTTP Security Headers & Cookies", status: elapsed > 8 ? "done" : elapsed > 3 ? "running" : "waiting" },
    { id: "w4", name: "4. DNS & Email Spoofing Defense", status: elapsed > 11 ? "done" : elapsed > 5 ? "running" : "waiting" },
    { id: "w5", name: "5. Active DAST Surface Probes", status: elapsed > 14 ? "done" : elapsed > 8 ? "running" : "waiting" },
    { id: "w6", name: "6. AI Multi-Vector Synthesis", status: elapsed > 15 ? "running" : "waiting" },
  ];

  const runningWorkers = defaultWorkers.filter(w => w.status === "running" || w.status === "done").length;
  const progressPercent = Math.round((runningWorkers / defaultWorkers.length) * 100);

  return (
    <div className="w-full max-w-4xl mx-auto flex flex-col items-center">
      <div className="relative w-40 h-40 mb-12 flex items-center justify-center">
        <div className="absolute inset-0 bg-teal-500/20 rounded-full animate-pulse-ring"></div>
        <div className="absolute inset-4 bg-teal-400/20 rounded-full animate-pulse-ring" style={{ animationDelay: "0.5s" }}></div>
        <div className="absolute inset-8 bg-emerald-500/20 rounded-full animate-pulse-ring" style={{ animationDelay: "1s" }}></div>
        <div className="relative z-10 w-20 h-20 bg-white rounded-2xl flex items-center justify-center shadow-sm border border-gray-200">
          <Shield className="w-10 h-10 text-teal-600" />
        </div>
      </div>

      <h2 className="text-2xl md:text-3xl font-bold text-gray-900 mb-4">
        Performing Deep Security Scan...
      </h2>
      <p className="text-gray-500 mb-8 font-mono text-sm">
        Elapsed time: {elapsed}s
      </p>

      <div className="w-full bg-gray-200 rounded-full h-3 mb-10 overflow-hidden border border-gray-300">
        <motion.div 
          className="h-full bg-gradient-to-r from-teal-500 to-emerald-400"
          initial={{ width: 0 }}
          animate={{ width: `${progressPercent}%` }}
          transition={{ duration: 0.5 }}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 w-full">
        {defaultWorkers.map((worker) => (
          <div key={worker.id} className="bg-gray-50 border border-gray-200 rounded-xl p-4 flex items-center justify-between shadow-sm">
            <span className="text-sm font-medium text-gray-800">{worker.name}</span>
            <div>
              {worker.status === "waiting" && <span className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Waiting</span>}
              {worker.status === "running" && <Loader2 className="w-5 h-5 text-teal-600 animate-spin" />}
              {worker.status === "done" && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
              {worker.status === "error" && <XCircle className="w-5 h-5 text-red-400" />}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
