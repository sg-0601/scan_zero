"use client";

import Link from "next/link";
import { Shield, Sparkles, ArrowRight, Menu, X } from "lucide-react";
import { useState, useEffect } from "react";

export default function Header() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [scrollProgress, setScrollProgress] = useState(0);
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = totalHeight > 0 ? (window.scrollY / totalHeight) * 100 : 0;
      setScrollProgress(progress);
      setIsScrolled(window.scrollY > 10);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <header className={`sticky top-0 z-50 w-full backdrop-blur-xl border-b transition-all duration-300 ${
      isScrolled ? 'bg-white/95 border-gray-200 shadow-sm' : 'bg-white/80 border-transparent'
    }`}>
      {/* Scroll Progress Bar */}
      <div className="absolute bottom-0 left-0 h-[2px] bg-gradient-to-r from-cyan-500 via-teal-400 to-emerald-400 scroll-progress" style={{ width: `${scrollProgress}%` }} />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand Wordmark */}
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 via-teal-400 to-emerald-400 p-[1px] shadow-lg shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all group-hover:scale-105">
            <div className="w-full h-full bg-white rounded-[11px] flex items-center justify-center">
              <span className="font-black text-teal-500 text-base tracking-tighter">0</span>
            </div>
          </div>
          <div className="flex flex-col">
            <span className="font-black text-xl tracking-tight text-gray-900 flex items-center gap-1">
              Scan<span className="text-gradient">Zero</span>
            </span>
            <span className="text-[9px] font-mono uppercase tracking-widest text-gray-400 -mt-1 font-semibold">
              Deep Web Intelligence
            </span>
          </div>
        </Link>

        {/* Desktop Nav Items */}
        <nav className="hidden md:flex items-center gap-1">
          {[
            { href: "/", label: "Scanner" },
            { href: "#comparison-preview", label: "Compare Sites", isAnchor: true },
            { href: "#sets-info", label: "6-Set Framework", isAnchor: true },
            { href: "/dashboard", label: "Monitoring" },
          ].map((item) => (
            item.isAnchor ? (
              <button
                key={item.label}
                onClick={() => {
                  const el = document.getElementById(item.href.replace('#', ''));
                  if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                  }
                }}
                className="px-3.5 py-2 rounded-lg text-sm font-medium text-gray-500 hover:text-gray-900 hover:bg-gray-100/80 transition-all"
              >
                {item.label}
              </button>
            ) : (
              <Link key={item.label} href={item.href} className="px-3.5 py-2 rounded-lg text-sm font-medium text-gray-500 hover:text-gray-900 hover:bg-gray-100/80 transition-all">
                {item.label}
              </Link>
            )
          ))}
        </nav>

        {/* Right CTA */}
        <div className="hidden md:flex items-center gap-2">
          <Link
            href="/login"
            className="text-sm font-medium text-gray-500 hover:text-gray-900 px-4 py-2 rounded-lg hover:bg-gray-100/80 transition-all"
          >
            Sign In
          </Link>
          <button
            onClick={() => {
              const el = document.getElementById('search-hero');
              if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }
            }}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gray-900 hover:bg-gray-800 text-white font-semibold text-sm shadow-lg shadow-gray-900/10 hover:shadow-gray-900/20 transition-all active:scale-[0.98]"
          >
            <span>Start Free</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Mobile menu button */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100"
        >
          {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Nav Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-gray-200 bg-white/95 backdrop-blur-xl px-4 pt-3 pb-5 space-y-1">
          <Link href="/" onClick={() => setMobileMenuOpen(false)} className="block text-sm font-medium text-gray-700 py-2 px-3 rounded-lg hover:bg-gray-100">
            Scanner
          </Link>
          <button
            onClick={() => {
              setMobileMenuOpen(false);
              setTimeout(() => {
                const el = document.getElementById('comparison-preview');
                if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 100);
            }}
            className="block w-full text-left text-sm font-medium text-gray-700 py-2 px-3 rounded-lg hover:bg-gray-100"
          >
            Compare Sites
          </button>
          <button
            onClick={() => {
              setMobileMenuOpen(false);
              setTimeout(() => {
                const el = document.getElementById('sets-info');
                if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
              }, 100);
            }}
            className="block w-full text-left text-sm font-medium text-gray-700 py-2 px-3 rounded-lg hover:bg-gray-100"
          >
            6-Set Framework
          </button>
          <Link href="/dashboard" onClick={() => setMobileMenuOpen(false)} className="block text-sm font-medium text-gray-700 py-2 px-3 rounded-lg hover:bg-gray-100">
            Monitoring
          </Link>
          <Link href="/login" onClick={() => setMobileMenuOpen(false)} className="block text-sm font-medium text-gray-700 py-2 px-3 rounded-lg hover:bg-gray-100">
            Sign In
          </Link>
        </div>
      )}
    </header>
  );
}
