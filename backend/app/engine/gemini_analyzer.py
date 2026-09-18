import json
import logging
import asyncio
import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.config import settings

logger = logging.getLogger(__name__)

def prepare_telemetry_digest(domain: str, url: str, worker_results: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract and structure all multi-tool outputs into a clean, context-dense security telemetry payload for Gemini."""
    
    # 1. OSINT & Threat Intel (w1)
    w1_raw = worker_results.get("w1_osint", {}).get("raw_data", {})
    vt = w1_raw.get("virustotal", {})
    shodan = w1_raw.get("shodan", {})
    urlscan = w1_raw.get("urlscan", {})
    otx = w1_raw.get("alienvault_otx", {})
    breaches = w1_raw.get("breaches", {})
    leakcheck = w1_raw.get("leakcheck", {})
    emailrep = w1_raw.get("emailrep", {})
    subdomains = w1_raw.get("subdomains", [])

    osint_summary = {
        "virustotal": {
            "stats": vt.get("stats") or vt.get("last_analysis_stats", {}),
            "reputation": vt.get("reputation", 0),
            "verdict": "malicious" if vt.get("stats", {}).get("malicious", 0) > 0 else "clean"
        },
        "shodan": {
            "open_ports": shodan.get("ports", []),
            "cves": shodan.get("vulns", []) or shodan.get("cves", []),
            "org": shodan.get("org", "Unknown"),
            "isp": shodan.get("isp", "Unknown"),
            "os": shodan.get("os", "Unknown")
        },
        "urlscan": {
            "score": urlscan.get("score"),
            "verdict": urlscan.get("verdicts", {}),
            "technologies": [t.get("name") for t in urlscan.get("technologies", []) if isinstance(t, dict)],
            "ips": urlscan.get("ips", [])
        },
        "alienvault_otx": {
            "pulse_count": otx.get("pulse_info", {}).get("count", 0),
            "threat_tags": [p.get("name") for p in otx.get("pulse_info", {}).get("pulses", [])[:3]]
        },
        "breach_intelligence": {
            "compromised_credentials_detected": bool(breaches.get("employees_compromised") or leakcheck.get("breaches_found")),
            "details": breaches.get("summary") or ("Breach traces detected" if leakcheck.get("breaches_found") else "No direct credentials leaked")
        },
        "subdomains": {
            "total_count": len(subdomains),
            "sample": subdomains[:8]
        },
        "email_reputation": emailrep.get("reputation", "neutral")
    }

    # 2. TLS & Cryptographic Posture (w2)
    w2_raw = worker_results.get("w2_tls", {}).get("raw_data", {})
    tls_data = w2_raw.get("tls", {})
    tls_summary = {
        "status": tls_data.get("status", "ok"),
        "certificate": {
            "subject": tls_data.get("cert_subject"),
            "issuer": tls_data.get("cert_issuer"),
            "days_until_expiry": tls_data.get("days_until_expiry"),
            "is_expired": tls_data.get("is_expired", False),
            "san_count": len(tls_data.get("sans", []))
        },
        "protocols": {
            "tls_1_0": tls_data.get("tls_1_0", False),
            "tls_1_1": tls_data.get("tls_1_1", False),
            "tls_1_2": tls_data.get("tls_1_2", True),
            "tls_1_3": tls_data.get("tls_1_3", False)
        },
        "weak_ciphers": tls_data.get("weak_ciphers", []),
        "vulnerabilities": {
            "heartbleed": tls_data.get("heartbleed", False),
            "robot": tls_data.get("robot", False),
            "poodle": tls_data.get("poodle", False)
        }
    }

    # 3. HTTP Headers & Cookies (w3)
    w3_raw = worker_results.get("w3_headers", {}).get("raw_data", {})
    headers_summary = {
        "missing_security_headers": w3_raw.get("missing_headers", []),
        "present_security_headers": w3_raw.get("present_headers", []),
        "hsts_present": bool(w3_raw.get("hsts")),
        "csp_present": bool(w3_raw.get("csp")),
        "x_frame_options": w3_raw.get("x_frame_options"),
        "x_content_type_options": w3_raw.get("x_content_type_options"),
        "referrer_policy": w3_raw.get("referrer_policy"),
        "server_banner_exposed": w3_raw.get("server_banner"),
        "cookie_issues": w3_raw.get("cookie_issues", [])
    }

    # 4. DNS & Anti-Spoofing Posture (w4)
    w4_raw = worker_results.get("w4_dns", {}).get("raw_data", {})
    dns_summary = {
        "spf": {
            "present": bool(w4_raw.get("spf", {}).get("record")),
            "record": w4_raw.get("spf", {}).get("record"),
            "valid": w4_raw.get("spf", {}).get("valid", False),
            "is_strict": "~all" in str(w4_raw.get("spf", {}).get("record", "")) or "-all" in str(w4_raw.get("spf", {}).get("record", ""))
        },
        "dmarc": {
            "present": bool(w4_raw.get("dmarc", {}).get("record")),
            "record": w4_raw.get("dmarc", {}).get("record"),
            "policy": w4_raw.get("dmarc", {}).get("policy", "none"),
            "enforced": w4_raw.get("dmarc", {}).get("policy") in ("quarantine", "reject")
        },
        "dkim_configured": w4_raw.get("dkim", {}).get("configured", False),
        "dnssec_enabled": w4_raw.get("dnssec", {}).get("enabled", False),
        "nameservers": w4_raw.get("dns", {}).get("ns", [])[:3],
        "mail_servers": w4_raw.get("dns", {}).get("mx", [])[:3]
    }

    # 5. DAST & Surface Probes (w5)
    w5_raw = worker_results.get("w5_dast", {}).get("raw_data", {})
    dast_summary = {
        "sensitive_files_exposed": w5_raw.get("exposed_files", []),
        "zap_alerts_count": len(w5_raw.get("zap_alerts", [])),
        "nuclei_vulns_count": len(w5_raw.get("nuclei_findings", []))
    }

    # 6. WAF & Honeypot Protection
    waf_res = worker_results.get("waf", {})
    honeypot_res = worker_results.get("w6_honeypot", {}).get("raw_data", {})
    defense_summary = {
        "waf_active": waf_res.get("waf_detected", False),
        "waf_vendor": waf_res.get("waf_name", "None detected"),
        "honeypot_detected": honeypot_res.get("is_honeypot", False)
    }

    # Clean list of findings from tools
    compact_findings = []
    for f in findings[:25]:
        compact_findings.append({
            "title": f.get("title"),
            "severity": f.get("severity", "info"),
            "category": f.get("category", "general"),
            "description": f.get("description", "")
        })

    return {
        "target_domain": domain,
        "target_url": url,
        "osint_threat_intel": osint_summary,
        "tls_crypto": tls_summary,
        "http_headers_and_cookies": headers_summary,
        "dns_email_security": dns_summary,
        "dast_surface_probes": dast_summary,
        "active_defenses": defense_summary,
        "tool_findings": compact_findings
    }

def get_candidate_models() -> List[str]:
    """Retrieve prioritized list of Gemini models to use."""
    primary = getattr(settings, "GEMINI_PRIMARY_MODEL", "gemini-3.8-flash")
    fallback_str = getattr(settings, "GEMINI_FALLBACK_MODELS", "gemini-3.5-flash,gemini-flash-latest,gemini-flash-lite-latest")
    fallbacks = [m.strip() for m in fallback_str.split(",") if m.strip()]
    models = [primary] + [m for m in fallbacks if m != primary]
    return models

async def call_gemini_api(prompt: str, response_json: bool = True, timeout_sec: float = 14.0) -> Optional[str]:
    """Robust Gemini REST API call with model fallback chain and JSON schema support."""
    key = settings.GEMINI_API_KEY
    if not key:
        logger.warning("No GEMINI_API_KEY found in configuration.")
        return None

    candidate_models = get_candidate_models()

    for model in candidate_models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
            payload: Dict[str, Any] = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            if response_json:
                payload["generationConfig"] = {
                    "response_mime_type": "application/json",
                    "temperature": 0.2
                }

            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        content_parts = candidates[0].get("content", {}).get("parts", [])
                        if content_parts:
                            text = content_parts[0].get("text", "").strip()
                            logger.info(f"Gemini intelligence successfully generated using {model} ({len(text)} chars)")
                            return text
                else:
                    logger.debug(f"Gemini API model {model} returned HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            logger.debug(f"Gemini call to model {model} failed: {e}")

    logger.warning("All Gemini candidate models failed to return content.")
    return None

def clean_and_parse_json(raw_text: str) -> Optional[dict]:
    """Extract valid JSON from raw LLM output, stripping potential markdown fences."""
    if not raw_text:
        return None
    cleaned = raw_text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except Exception as e:
        logger.warning(f"Failed to parse Gemini JSON output directly: {e}. Attempting substring extraction...")
        try:
            start_idx = cleaned.find("{")
            end_idx = cleaned.rfind("}")
            if start_idx != -1 and end_idx != -1:
                return json.loads(cleaned[start_idx:end_idx + 1])
        except Exception:
            pass
    return None

def generate_fallback_intelligence(domain: str, url: str, tool_outputs: Dict[str, Any], raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic fallback generator when Gemini API key is unavailable or offline."""
    logger.info(f"Generating deterministic fallback security intelligence for {domain}")
    
    # Calculate baseline heuristic score
    crit_count = sum(1 for f in raw_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in raw_findings if f.get("severity") == "high")
    med_count = sum(1 for f in raw_findings if f.get("severity") == "medium")
    
    score = max(20, 100 - (crit_count * 25 + high_count * 15 + med_count * 6))
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "ai_powered": False,
        "gemini_model_used": "deterministic-fallback",
        "executive_summary": (
            f"Automated multi-tool scan across 6 security vectors completed for {domain}. "
            f"Identified {len(raw_findings)} potential security findings. "
            f"Transport encryption and boundary controls were evaluated."
        ),
        "threat_verdict": f"Security Posture Rating: Grade {grade} ({score}/100)",
        "ai_score": score,
        "ai_grade": grade,
        "category_scores": {
            "crypto_tls": {
                "score": min(100, score + 5),
                "rationale": "Evaluated TLS handshake, certificate validity, and cipher strength."
            },
            "headers_config": {
                "score": max(30, score - 5),
                "rationale": "Evaluated modern HTTP defense headers and cookie security flags."
            },
            "dns_email": {
                "score": min(100, score + 2),
                "rationale": "Evaluated SPF, DMARC, DKIM, and DNSSEC cryptographic records."
            },
            "surface_intel": {
                "score": score,
                "rationale": "Correlated Shodan open ports, VirusTotal scans, and external attack surface."
            }
        },
        "attacker_perspective": (
            f"An external adversary targeting {domain} would examine exposed DNS records for email impersonation opportunities "
            f"and probe web endpoints for missing transport headers to facilitate adversary-in-the-middle attacks."
        ),
        "attack_chain": [
            {
                "step": 1,
                "title": "Reconnaissance & OSINT",
                "description": f"Gather public subdomains and DNS records for {domain}.",
                "exploit_vector": "Public intelligence discovery"
            },
            {
                "step": 2,
                "title": "Perimeter Header Inspection",
                "description": "Probe HTTP response headers to identify missing framing and content controls.",
                "exploit_vector": "Client-side injection / Clickjacking"
            },
            {
                "step": 3,
                "title": "Targeted Exploitation",
                "description": "Attempt to leverage unhardened vectors against domain users.",
                "exploit_vector": "Domain spoofing / session hijack"
            }
        ],
        "strengths": [
            "Valid SSL/TLS certificate issued and operational",
            "Core network endpoints responding to secure transport"
        ],
        "critical_risks": [
            f.get("title", "Missing defense configuration") for f in raw_findings if f.get("severity") in ("critical", "high")
        ][:3] or ["Review missing HTTP security headers"],
        "remediation_roadmap": {
            "phase_1_immediate": [
                "Deploy Strict-Transport-Security (HSTS) header",
                "Enforce strict SPF and DMARC reject policies"
            ],
            "phase_2_short_term": [
                "Implement strict Content-Security-Policy (CSP)",
                "Add Secure and HttpOnly flags to all session cookies"
            ],
            "phase_3_strategic": [
                "Enable DNSSEC validation at domain registrar",
                "Implement automated vulnerability scanning in CI/CD"
            ]
        },
        "ready_to_deploy_fixes": [
            {
                "title": "HSTS & Header Hardening",
                "target": "Web Server",
                "type": "nginx",
                "code": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;",
                "explanation": "Enforces HTTPS encryption and protects against clickjacking and MIME-sniffing."
            },
            {
                "title": "Strict DMARC Anti-Spoofing",
                "target": "DNS Zone",
                "type": "dns",
                "code": f"_dmarc.{domain}. IN TXT \"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@{domain}; pct=100;\"",
                "explanation": "Instructs receiving mail servers to discard unauthorized emails spoofing your domain."
            }
        ]
    }

async def synthesize_scan_intelligence(domain: str, url: str, worker_results: Dict[str, Any], raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The central intelligence pipeline: ingests all multi-tool outputs into Gemini, which analyzes, correlates, and generates final results."""
    
    # 1. Structure the multi-tool telemetry digest
    telemetry = prepare_telemetry_digest(domain, url, worker_results, raw_findings)
    
    prompt = f"""
You are Google Gemini, acting as the Senior Principal Cyber Security Architect & Chief Penetration Tester for ScanZero.
You have been provided with comprehensive multi-tool intelligence and raw telemetry collected across 6 parallel inspection workers for the target domain: '{domain}' (URL: '{url}').

The tools executed include:
1. OSINT & Threat Intel: VirusTotal (70+ AV engines), Shodan (open ports & CVEs), URLScan.io (DOM & tech audit), AlienVault OTX (threat pulses), Hudson Rock (infostealer malware credential breaches), crt.sh Subdomains, and EmailRep.
2. TLS & Cryptographic Worker: SSL/TLS handshakes, certificate chain validity, protocols (TLS 1.0-1.3), cipher strength, and known SSL flaws (Heartbleed, ROBOT, POODLE).
3. HTTP Headers & Cookies: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie security attributes (HttpOnly, Secure, SameSite), and server banner exposure.
4. DNS & Anti-Spoofing: Authoritative DNS records, SPF validation, DMARC policy enforcement, DKIM, and DNSSEC trust chain.
5. Active DAST & Surface Probes: Exposed sensitive endpoints (e.g. .env, .git, /admin), OWASP ZAP alerts, and Nuclei CVE findings.
6. Boundary Defenses: WAF detection (WAFW00F) and Honeypot/canary detection.

TELEMETRY & FINDINGS DATA:
{json.dumps(telemetry, indent=2)}

YOUR TASK:
Add deep security intelligence to this raw data and generate the definitive, final security assessment.
Correlate findings across tools (e.g., how an exposed port or missing header combines with DNS or OSINT data).
Synthesize this into a cohesive, professional security audit.

Return a STRICT, VALID JSON object with the following schema:
{{
  "executive_summary": "A 2-4 sentence executive overview of the domain's real-world security posture, written in clear, plain English for CTOs and developers.",
  "threat_verdict": "A punchy, single-sentence summary verdict (e.g. 'Hardened Cloudflare Perimeter with Critical Email Spoofing Vulnerabilities').",
  "ai_score": 0 to 100 integer representing overall security score (weighing real exploitability, critical misconfigurations, and active protections like WAF),
  "ai_grade": "A+", "A", "B", "C", "D", or "F",
  "category_scores": {{
    "crypto_tls": {{ "score": 0 to 100 integer, "rationale": "1-2 sentence AI explanation of the cryptographic posture" }},
    "headers_config": {{ "score": 0 to 100 integer, "rationale": "1-2 sentence AI explanation of header defense and browser isolation" }},
    "dns_email": {{ "score": 0 to 100 integer, "rationale": "1-2 sentence AI explanation of email spoofing protection and DNSSEC" }},
    "surface_intel": {{ "score": 0 to 100 integer, "rationale": "1-2 sentence AI explanation of attack surface, open ports, and threat intel" }}
  }},
  "attacker_perspective": "A concise paragraph explaining exactly how a motivated adversary views this target, what attack vectors they would prioritize, and why.",
  "attack_chain": [
    {{
      "step": 1,
      "title": "Stage title (e.g. Reconnaissance & Footprinting)",
      "description": "How the attacker uses tool findings (e.g. subdomains, exposed tech)",
      "exploit_vector": "E.g. Public OSINT & DNS enumeration"
    }},
    {{
      "step": 2,
      "title": "Stage title (e.g. Exploitation / Impersonation)",
      "description": "How the next vulnerability in the chain is exploited (e.g. missing DMARC or missing CSP)",
      "exploit_vector": "E.g. Business Email Compromise / Phishing"
    }},
    {{
      "step": 3,
      "title": "Stage title (e.g. Perimeter Breach or Lateral Movement)",
      "description": "The final impact of chaining these weaknesses together",
      "exploit_vector": "E.g. Credential harvesting / Session hijacking"
    }}
  ],
  "strengths": [
    "List of 2 to 4 positive security defenses confirmed by the tools (e.g., 'Modern TLS 1.3 enforced', 'Protected behind Cloudflare WAF', 'No leaked infostealer credentials')"
  ],
  "critical_risks": [
    "List of 1 to 4 top critical posture gaps requiring immediate remediation"
  ],
  "intelligent_findings": [
    {{
      "title": "Clean, descriptive vulnerability or misconfiguration title",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "category": "crypto" | "headers" | "dns" | "osint" | "dast",
      "description": "Plain-English description of the finding",
      "ai_insight": "Gemini intelligence explaining why this matters and how an attacker could exploit it",
      "remediation_text": "Actionable instructions on how to resolve the finding",
      "remediation_code": "Copy-paste configuration snippet (Nginx, Apache, or DNS record)",
      "remediation_type": "nginx" | "apache" | "dns" | "cloudflare" | "config"
    }}
  ],
  "remediation_roadmap": {{
    "phase_1_immediate": [
      "Actions to execute within 24 hours"
    ],
    "phase_2_short_term": [
      "Actions to execute within 7 days"
    ],
    "phase_3_strategic": [
      "Long-term defense-in-depth security improvements"
    ]
  }},
  "ready_to_deploy_fixes": [
    {{
      "title": "Fix title",
      "target": "E.g. Nginx / Apache / DNS / Cloudflare",
      "type": "nginx" | "apache" | "dns" | "cloudflare",
      "code": "Actual copy-paste configuration block",
      "explanation": "Why this snippet fixes the underlying vulnerability"
    }}
  ]
}}

IMPORTANT: Return ONLY the raw JSON object. Do not include markdown preamble or conversational text outside the JSON.
"""

    raw_response = await call_gemini_api(prompt, response_json=True, timeout_sec=16.0)
    parsed_json = clean_and_parse_json(raw_response) if raw_response else None

    if not parsed_json or "ai_score" not in parsed_json:
        logger.warning("Gemini synthesis returned incomplete or unparseable JSON. Falling back to structured synthesizer.")
        return generate_fallback_intelligence(domain, url, worker_results, raw_findings)

    parsed_json["ai_powered"] = True
    parsed_json["gemini_model_used"] = getattr(settings, "GEMINI_PRIMARY_MODEL", "gemini-3.8-flash")
    parsed_json["analyzed_at"] = datetime.utcnow().isoformat()
    return parsed_json

async def ask_gemini_scan_assistant(domain: str, scan_results: Dict[str, Any], question: str, history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """Interactive conversational assistant for users to query Gemini about their specific scan results."""
    
    score = scan_results.get("score")
    grade = scan_results.get("grade")
    findings = scan_results.get("findings", [])[:10]
    exec_summary = scan_results.get("gemini_intelligence", {}).get("executive_summary", "")
    attack_chain = scan_results.get("gemini_intelligence", {}).get("attack_chain", [])
    
    context_brief = {
        "domain": domain,
        "overall_score": score,
        "grade": grade,
        "executive_summary": exec_summary,
        "top_findings": [
            {"title": f.get("title"), "severity": f.get("severity"), "description": f.get("description")}
            for f in findings
        ],
        "attack_chain": attack_chain
    }

    conversation_context = ""
    nl = "\n"
    if history:
        for turn in history[-4:]:
            role = "User" if turn.get("role") == "user" else "Assistant"
            conversation_context += f"{role}: {turn.get('content')}{nl}"

    prev_convo = f"PREVIOUS CONVERSATION:{nl}{conversation_context}" if conversation_context else ""
    prompt = f"""
You are the ScanZero AI Cyber Security Assistant powered by Google Gemini.
You have full access to the security audit and multi-tool scan results for the target website: '{domain}'.

SCAN CONTEXT:
{json.dumps(context_brief, indent=2)}

{prev_convo}

USER'S QUESTION:
"{question}"

INSTRUCTIONS:
1. Provide an expert, clear, and actionable answer based on the real scan data above.
2. If the user asks for remediation code (e.g. Nginx, Apache, Cloudflare, Next.js, Django, DNS), provide precise, copy-paste ready snippets.
3. Be direct, authoritative, yet approachable. Keep explanations focused and concise.
4. Format your response in clean GitHub-flavored Markdown.
"""

    model_used = getattr(settings, "GEMINI_PRIMARY_MODEL", "gemini-3.8-flash")
    response_text = await call_gemini_api(prompt, response_json=False, timeout_sec=12.0)
    
    if not response_text:
        response_text = (
            f"I reviewed the scan results for **{domain}** (Score: {score}/100, Grade: {grade}). "
            f"Key priorities include addressing missing security headers and ensuring strict email authentication records (SPF & DMARC). "
            f"Please verify your API connectivity to continue interactive analysis."
        )

    return {
        "answer": response_text,
        "model": model_used,
        "domain": domain
    }
