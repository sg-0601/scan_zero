"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Lock, Mail, ArrowRight } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    // Save session locally and redirect to continuous monitoring dashboard
    setTimeout(() => {
      localStorage.setItem("scanzero_user", JSON.stringify({ email: email || "security@enterprise.com", loggedIn: true }));
      router.push("/dashboard");
    }, 600);
  };

  return (
    <div className="flex-1 flex items-center justify-center p-4 md:p-8 min-h-[80vh]">
      <div className="w-full max-w-md bg-white/90 border border-gray-200 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400" />
        
        <div className="text-center mb-8">
          <div className="inline-flex p-3 rounded-2xl bg-teal-500/10 border border-cyan-500/20 text-teal-600 mb-4">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-black text-gray-900">Site Owner Portal</h1>
          <p className="text-xs text-gray-500 mt-1.5">
            Login to verify domain ownership and activate 24/7 Continuous Watch & Score-Drop Alerts.
          </p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-mono font-bold text-gray-600 uppercase mb-1.5">
              Work Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@yourcompany.com"
                className="w-full bg-gray-50 border border-gray-200 rounded-xl px-10 py-3 text-sm text-gray-900 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono font-bold text-gray-600 uppercase mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-gray-50 border border-gray-200 rounded-xl px-10 py-3 text-sm text-gray-900 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 bg-gradient-to-r from-cyan-500 to-teal-400 hover:from-cyan-400 hover:to-teal-300 text-slate-950 font-extrabold py-3.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-500/10 active:scale-[0.98]"
          >
            {isLoading ? "Signing in..." : "Access Continuous Watch"}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-gray-200 text-center">
          <p className="text-xs text-gray-500">
            Just want a 1-time scan without an account?{" "}
            <Link href="/" className="text-teal-600 font-bold hover:underline">
              Use 1-Click Guest Scanner
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
