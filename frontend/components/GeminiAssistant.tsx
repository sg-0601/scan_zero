"use client";

import { useState, useRef, useEffect } from "react";
import { Sparkles, Send, Bot, User, Copy, Check, ChevronDown, ChevronUp, ShieldAlert, Terminal } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { API_BASE_URL } from "@/lib/config";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface GeminiAssistantProps {
  scanId: string;
  domain: string;
  score?: number;
  grade?: string;
}

export default function GeminiAssistant({ scanId, domain, score, grade }: GeminiAssistantProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: `Hello! I am your **Google Gemini Cyber Security Lead**. I've synthesized all telemetry from Shodan, VirusTotal, URLScan, AlienVault, SSL/TLS, DNS, and HTTP security headers for **${domain}**.\n\nYou can ask me anything about the scan results, attack chain scenarios, or request tailored configuration code (Nginx, Apache, Cloudflare, DNS).`
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const quickPrompts = [
    "🛡️ How do I remediate the critical findings?",
    "⚔️ Explain the attack chain in simple terms",
    "📝 Generate complete Nginx security headers",
    "📧 Is this domain vulnerable to email spoofing?",
  ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSend = async (textToSend?: string) => {
    const query = (textToSend || input).trim();
    if (!query || loading) return;

    const userMessage: Message = { role: "user", content: query };
    setMessages((prev) => [...prev, userMessage]);
    if (!textToSend) setInput("");
    setLoading(true);

    try {
      const historyPayload = messages.map((m) => ({
        role: m.role,
        content: m.content
      }));

      const res = await fetch(`${API_BASE_URL}/api/scan/${scanId}/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: query,
          history: historyPayload
        })
      });

      if (!res.ok) {
        throw new Error("Failed to get response from Gemini");
      }

      const data = await res.json();
      const assistantMessage: Message = {
        role: "assistant",
        content: data.answer || "I reviewed the scan data, but couldn't generate a specific response."
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `⚠️ *Communication issue with Gemini service: ${err.message}. Please ensure the backend is active.*`
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="bg-white border border-teal-500/30 rounded-2xl shadow-xl overflow-hidden mb-8 transition-all">
      {/* Header */}
      <div 
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="bg-gradient-to-r from-slate-900 via-slate-800 to-teal-950 p-4 md:p-5 flex items-center justify-between cursor-pointer border-b border-teal-500/20"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-teal-400 p-0.5 flex items-center justify-center shadow-lg shadow-teal-500/20">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-teal-400 animate-pulse" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-white font-bold text-base md:text-lg flex items-center gap-2">
                Ask Gemini &bull; AI Security Assistant
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-teal-500/20 text-teal-300 border border-teal-500/40">
                gemini-3.8-flash
              </span>
            </div>
            <p className="text-gray-400 text-xs mt-0.5">
              Trained on your multi-tool telemetry &bull; Interactive security Q&amp;A &amp; remediation
            </p>
          </div>
        </div>

        <button className="text-gray-400 hover:text-white transition-colors p-1">
          {isCollapsed ? <ChevronDown className="w-5 h-5" /> : <ChevronUp className="w-5 h-5" />}
        </button>
      </div>

      <AnimatePresence>
        {!isCollapsed && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="flex flex-col"
          >
            {/* Quick Prompt Chips */}
            <div className="p-3 md:px-5 bg-gray-50 border-b border-gray-100 flex items-center gap-2 overflow-x-auto no-scrollbar">
              <span className="text-[11px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Suggested:</span>
              {quickPrompts.map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSend(prompt)}
                  disabled={loading}
                  className="text-xs bg-white hover:bg-teal-50 text-gray-700 hover:text-teal-700 px-3 py-1.5 rounded-lg border border-gray-200 transition-all whitespace-nowrap font-medium shadow-xs disabled:opacity-50"
                >
                  {prompt}
                </button>
              ))}
            </div>

            {/* Chat Messages */}
            <div className="p-4 md:p-6 max-h-96 overflow-y-auto space-y-4 bg-slate-50/50">
              {messages.map((m, idx) => {
                const isAssistant = m.role === "assistant";
                return (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 ${isAssistant ? "" : "flex-row-reverse"}`}
                  >
                    <div
                      className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-white ${
                        isAssistant
                          ? "bg-gradient-to-tr from-cyan-600 to-teal-500 shadow-sm"
                          : "bg-slate-700"
                      }`}
                    >
                      {isAssistant ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
                    </div>

                    <div
                      className={`relative group max-w-[85%] md:max-w-[75%] rounded-2xl p-4 text-sm ${
                        isAssistant
                          ? "bg-white text-gray-800 border border-gray-200/80 shadow-sm"
                          : "bg-teal-600 text-white shadow-sm"
                      }`}
                    >
                      <div className="whitespace-pre-wrap leading-relaxed font-sans text-xs md:text-sm">
                        {m.content}
                      </div>

                      {isAssistant && (
                        <button
                          onClick={() => copyToClipboard(m.content, idx)}
                          title="Copy message"
                          className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity text-gray-400 hover:text-gray-700 p-1 bg-gray-50 rounded"
                        >
                          {copiedIndex === idx ? (
                            <Check className="w-3.5 h-3.5 text-teal-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}

              {loading && (
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-teal-500 flex items-center justify-center shrink-0 text-white shadow-sm">
                    <Sparkles className="w-4 h-4 animate-spin" />
                  </div>
                  <div className="bg-white border border-gray-200/80 rounded-2xl p-4 text-xs text-gray-500 flex items-center gap-2 shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-teal-500 animate-ping"></span>
                    Gemini is correlating scan findings and synthesizing response...
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="p-3 md:p-4 bg-white border-t border-gray-200 flex items-center gap-2"
            >
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={`Ask Gemini about ${domain}'s vulnerabilities, configuration, or attack vectors...`}
                disabled={loading}
                className="flex-1 bg-gray-50 border border-gray-200 focus:border-teal-500 focus:bg-white text-gray-900 px-4 py-2.5 rounded-xl text-sm outline-none transition-all"
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                className="bg-teal-600 hover:bg-teal-500 text-white p-2.5 rounded-xl font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm flex items-center justify-center"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
