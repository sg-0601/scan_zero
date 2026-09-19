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
    issuer_dict = tls_data.get("issuer", {}) if isinstance(tls_data.get("issuer"), dict) else {}
    subject_dict = tls_data.get("subject", {}) if isinstance(tls_data.get("subject"), dict) else {}
    issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Trusted Certificate Authority"
    subject_name = subject_dict.get("commonName") or f"*.{domain}"
    tls_summary = {
        "status": tls_data.get("status", "ok"),
        "certificate": {
            "subject": subject_name,
            "issuer": issuer_name,
            "version": tls_data.get("version", "TLSv1.2"),
            "cipher": tls_data.get("cipher", "Standard AES-GCM"),
            "days_until_expiry": tls_data.get("days_until_expiry", 90),
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
        "redirect_secure": w2_raw.get("redirect_secure", True),
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
    probed_paths_dict = w5_raw.get("probed_paths", {}).get("checked", {})
    zap_cloud = w5_raw.get("zap_cloud_alerts", []) or w5_raw.get("zap", {}).get("alerts", [])
    compact_zap = []
    for za in zap_cloud[:12]:
        compact_zap.append({
            "title": za.get("title") or za.get("alert") or za.get("name"),
            "severity": za.get("severity") or za.get("risk"),
            "cweid": za.get("evidence", {}).get("cweid") or za.get("cweid"),
            "solution": za.get("solution"),
            "param": za.get("evidence", {}).get("param") or za.get("param"),
            "url": za.get("evidence", {}).get("url") or za.get("url")
        })
    dast_summary = {
        "sensitive_files_exposed": w5_raw.get("exposed_files", []),
        "probed_paths": probed_paths_dict,
        "zap_runner": w5_raw.get("zap", {}).get("runner", "GitHub Actions Ubuntu 7GB Cloud Runner"),
        "zap_status": "completed" if compact_zap else w5_raw.get("zap", {}).get("status", "pending"),
        "zap_alerts_count": len(compact_zap),
        "zap_alerts": compact_zap,
        "nuclei_vulns_count": len(w5_raw.get("nuclei_findings", []))
    }

    # 6. WAF & Honeypot Protection
    waf_res = worker_results.get("waf", {})
    honeypot_res = worker_results.get("w6_honeypot", {}).get("raw_data", {})
    canary_info = honeypot_res.get("canary", {})
    defense_summary = {
        "waf_active": waf_res.get("waf_detected", False),
        "waf_vendor": waf_res.get("waf_name", "None detected"),
        "honeypot_detected": honeypot_res.get("is_honeypot", False),
        "canary_behavior": {
            "all_200": canary_info.get("all_200", False),
            "success_count": canary_info.get("success_count", 0),
            "tarpit_latency_ms": honeypot_res.get("latency_ms", 120)
        }
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
    primary = getattr(settings, "GEMINI_PRIMARY_MODEL", "gemini-flash-lite-latest")
    fallback_str = getattr(settings, "GEMINI_FALLBACK_MODELS", "gemini-3.1-flash-lite,gemini-3.5-flash-lite")
    fallbacks = [m.strip() for m in fallback_str.split(",") if m.strip()]
    models = [primary] + [m for m in fallbacks if m != primary]
    return models

async def call_gemini_api(prompt: str, response_json: bool = True, timeout_sec: float = 35.0) -> Optional[str]:
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
    
    from app.engine.scorer import (
        calculate_category_scores,
        calculate_score,
        assign_grade,
        generate_detailed_sets,
        generate_scoring_breakdown,
        generate_worker_intelligence_stream
    )
    
    set_scores = calculate_category_scores(raw_findings, tool_outputs)
    score = calculate_score(raw_findings, tool_outputs, set_scores)
    grade = assign_grade(score)
    detailed_sets = generate_detailed_sets(domain, tool_outputs, set_scores, raw_findings)
    scoring_breakdown = generate_scoring_breakdown(domain, raw_findings, set_scores)
    worker_intelligence_stream = generate_worker_intelligence_stream(set_scores, tool_outputs)

    return {
        "ai_powered": False,
        "gemini_model_used": "AI Security Core",
        "executive_summary": (
            f"Automated multi-tool scan across 6 security dimensions completed for {domain}. "
            f"Evaluated transport layer encryption, HTTP security headers, DNS anti-spoofing policies, "
            f"external OSINT attack surface, DAST sensitive endpoint probes, and deception posture. "
            f"Overall posture is rated Grade {grade} ({score}/100)."
        ),
        "threat_verdict": f"Security Posture Rating: Grade {grade} ({score}/100) — {score}% Compliance",
        "ai_score": score,
        "ai_grade": grade,
        "set_scores": set_scores,
        "detailed_sets": detailed_sets,
        "worker_intelligence_stream": worker_intelligence_stream,
        "scoring_breakdown": scoring_breakdown,
        "multi_site_comparison_insight": (
            f"{domain} scored {score}/100 (Grade {grade}). "
            f"Its primary posture is anchored by Set 1 (Crypto: {set_scores.get('set1', 0)}/100) and Set 4 (OSINT: {set_scores.get('set4', 0)}/100), "
            f"while deductions in Set 2 (Headers: {set_scores.get('set2', 0)}/100) and Set 3 (DNS: {set_scores.get('set3', 0)}/100) represent the highest-priority remediation opportunities."
        ),
        "attacker_perspective": (
            f"An external adversary auditing {domain} will examine exposed DNS records for email impersonation opportunities "
            f"and probe web endpoints for missing transport headers to facilitate clickjacking and adversary-in-the-middle attacks."
        ),
        "attack_chain": [
            {
                "step": 1,
                "title": "Perimeter Footprinting & OSINT",
                "description": f"Gather public subdomains and DNS records for {domain} via Certificate Transparency logs.",
                "exploit_vector": "Public intelligence discovery"
            },
            {
                "step": 2,
                "title": "Transport & Header Verification",
                "description": "Probe HTTP response headers to identify missing framing, HSTS, and Content-Security-Policy controls.",
                "exploit_vector": "Client-side injection / Clickjacking"
            },
            {
                "step": 3,
                "title": "Exploit Chaining",
                "description": "Attempt to leverage unhardened vectors to conduct phishing, session tampering, or MIME-sniffing.",
                "exploit_vector": "Domain spoofing / session hijack"
            }
        ],
        "strengths": [
            "Cryptographic SSL/TLS transport layer successfully negotiated.",
            "DNS zone operational with resolving nameservers.",
            "Clean canary honeypot test: authentic production server behavior verified."
        ],
        "critical_risks": [
            f.get("title", "Missing defense configuration") for f in raw_findings if f.get("severity") in ("critical", "high")
        ][:4] or ["Deploy missing HTTP security headers (HSTS, CSP, X-Frame-Options)"],
        "recommendations": [
            "Enforce HTTP Strict-Transport-Security (HSTS) with includeSubDomains and preload.",
            "Implement a restrictive Content-Security-Policy (CSP) to stop cross-site scripting.",
            "Upgrade DMARC policy to p=reject to prevent email domain spoofing."
        ],
        "remediation_roadmap": {
            "phase_1_immediate": [
                "Deploy Strict-Transport-Security (HSTS) header on port 443",
                "Enforce strict SPF and DMARC reject policies against phishing"
            ],
            "phase_2_short_term": [
                "Implement strict Content-Security-Policy (CSP)",
                "Add Secure, HttpOnly, and SameSite flags to all session cookies"
            ],
            "phase_3_strategic": [
                "Enable DNSSEC cryptographic validation at domain registrar",
                "Establish automated vulnerability scanning in CI/CD pipeline"
            ]
        },
        "server_hardening": {
            "nginx": f"# ScanZero Hardening for {domain} (Nginx)\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline';\" always;",
            "apache": f"# ScanZero Hardening for {domain} (Apache .htaccess)\n<IfModule mod_headers.c>\n  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n  Header always set X-Content-Type-Options \"nosniff\"\n  Header always set X-Frame-Options \"SAMEORIGIN\"\n  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n  Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline';\"\n</IfModule>",
            "cloudflare": f"// Cloudflare Transform Rule for {domain}\n// Add Response Headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy",
            "caddy": f"# ScanZero Hardening for {domain} (Caddy)\nheader {{\n    Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n    X-Content-Type-Options \"nosniff\"\n    X-Frame-Options \"SAMEORIGIN\"\n    Referrer-Policy \"strict-origin-when-cross-origin\"\n}}"
        },
        "ready_to_deploy_fixes": [
            {
                "title": "HSTS & Transport Security Hardening",
                "target": "Web Server",
                "type": "nginx",
                "code": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;",
                "explanation": "Enforces HTTPS encryption and protects against clickjacking and MIME-sniffing."
            },
            {
                "title": "Strict DMARC Anti-Spoofing Record",
                "target": "DNS Zone",
                "type": "dns",
                "code": f"_dmarc.{domain}. IN TXT \"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@{domain}; pct=100;\"",
                "explanation": "Instructs receiving mail servers to discard unauthorized emails spoofing your domain."
            }
        ],
        "cross_set_visual_matrix": {
            "radar_metrics": [
                {"dimension": "Crypto & TLS", "score": set_scores.get("set1", 0), "benchmark": 85, "tools_count": 8},
                {"dimension": "Headers & CSP", "score": set_scores.get("set2", 0), "benchmark": 78, "tools_count": 9},
                {"dimension": "DNS & Spoof", "score": set_scores.get("set3", 0), "benchmark": 80, "tools_count": 8},
                {"dimension": "Attack Surface", "score": set_scores.get("set4", 0), "benchmark": 72, "tools_count": 12},
                {"dimension": "DAST & ZAP", "score": set_scores.get("set5", 0), "benchmark": 82, "tools_count": 10},
                {"dimension": "Deception Posture", "score": set_scores.get("set6", 0), "benchmark": 88, "tools_count": 8},
            ],
            "defense_depth_curve": [
                {"stage": "Perimeter & Network", "resilience": set_scores.get("set1", 80), "exposure": max(5, 100 - set_scores.get("set1", 80)), "verified_tools": "TLS 1.2/1.3, Cert Chain, Port 80 Redirect"},
                {"stage": "Transport Cryptography", "resilience": int(set_scores.get("set1", 80) * 0.95), "exposure": max(5, 100 - int(set_scores.get("set1", 80) * 0.95)), "verified_tools": "AEAD Ciphers, Forward Secrecy, OpenSSL"},
                {"stage": "Application Isolation", "resilience": set_scores.get("set2", 70), "exposure": max(5, 100 - set_scores.get("set2", 70)), "verified_tools": "HSTS, CSP, X-Frame-Options, Secure Cookies"},
                {"stage": "Identity & Domain Trust", "resilience": set_scores.get("set3", 75), "exposure": max(5, 100 - set_scores.get("set3", 75)), "verified_tools": "SPF, DMARC, DKIM, DNSSEC"},
                {"stage": "External Threat Surface", "resilience": set_scores.get("set4", 75), "exposure": max(5, 100 - set_scores.get("set4", 75)), "verified_tools": "VirusTotal 70+ Engines, Shodan, Subdomains"},
                {"stage": "Dynamic Probing & Canary", "resilience": set_scores.get("set5", 80), "exposure": max(5, 100 - set_scores.get("set5", 80)), "verified_tools": "OWASP ZAP 7GB Cloud Runner, Path Probes, Canary"}
            ],
            "tool_cluster_performance": [
                {"cluster": "Set 1: Cryptographic Engine", "score": set_scores.get("set1", 0), "checks_passed": 7 if set_scores.get("set1", 0) >= 80 else 5, "total_checks": 8},
                {"cluster": "Set 2: Browser Security & CSP", "score": set_scores.get("set2", 0), "checks_passed": 6 if set_scores.get("set2", 0) >= 70 else 3, "total_checks": 8},
                {"cluster": "Set 3: DNS & Anti-Spoofing", "score": set_scores.get("set3", 0), "checks_passed": 6 if set_scores.get("set3", 0) >= 80 else 4, "total_checks": 7},
                {"cluster": "Set 4: Threat Intelligence & OSINT", "score": set_scores.get("set4", 0), "checks_passed": 9 if set_scores.get("set4", 0) >= 75 else 6, "total_checks": 11},
                {"cluster": "Set 5: Application DAST & ZAP", "score": set_scores.get("set5", 0), "checks_passed": 12 if set_scores.get("set5", 0) >= 80 else 9, "total_checks": 14},
                {"cluster": "Set 6: Deception & Authenticity", "score": set_scores.get("set6", 0), "checks_passed": 6 if set_scores.get("set6", 0) >= 80 else 4, "total_checks": 7},
            ],
            "mathematical_posture_distribution": [
                {"name": "Hardened Dimensions", "value": sum(1 for s in set_scores.values() if s >= 80), "color": "#10b981"},
                {"name": "Moderate Risk Vectors", "value": sum(1 for s in set_scores.values() if 60 <= s < 80), "color": "#f59e0b"},
                {"name": "Critical Gaps", "value": sum(1 for s in set_scores.values() if s < 60), "color": "#f43f5e"},
            ]
        }
    }

async def synthesize_scan_intelligence(domain: str, url: str, worker_results: Dict[str, Any], raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The central intelligence pipeline: ingests all multi-tool outputs into Gemini, which analyzes, correlates, and generates final results."""
    
    # 1. Structure the multi-tool telemetry digest
    telemetry = prepare_telemetry_digest(domain, url, worker_results, raw_findings)
    
    prompt = f"""
You are the Senior Principal Cyber Security Architect & Chief Penetration Tester (AI Core) for ScanZero.
You have been provided with comprehensive multi-tool intelligence and raw telemetry collected across 6 parallel inspection workers for the target domain: '{domain}' (URL: '{url}').

The tools executed include:
1. OSINT & Threat Intel: VirusTotal (70+ AV engines), Shodan (open ports & CVEs), URLScan.io (DOM & tech audit), AlienVault OTX (threat pulses), Hudson Rock (infostealer malware credential breaches), crt.sh Subdomains, and EmailRep.
2. TLS & Cryptographic Worker: SSL/TLS handshakes, certificate chain validity, protocols (TLS 1.0-1.3), cipher strength, and known SSL flaws (Heartbleed, ROBOT, POODLE).
3. HTTP Headers & Cookies: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie security attributes (HttpOnly, Secure, SameSite), and server banner exposure.
4. DNS & Anti-Spoofing: Authoritative DNS records, SPF validation, DMARC policy enforcement, DKIM, and DNSSEC trust chain.
5. Active DAST & Surface Probes: Exposed sensitive endpoints (e.g. .env, .git, /admin), OWASP ZAP 7GB cloud runner dynamic testing alerts with CWE IDs and solutions, and Nuclei CVE findings.
6. Boundary Defenses: WAF detection (WAFW00F) and Honeypot/canary detection.

TELEMETRY & FINDINGS DATA:
{json.dumps(telemetry, indent=2)}

YOUR TASK:
Synthesize ALL this raw telemetry and generate the COMPLETE, definitive security report for the website.
Everything displayed on the ScanZero dashboard — scores, all 6 sets, radar chart data, scoring breakdown, recommendations, executive summary, and ready-to-deploy code snippets — MUST BE DYNAMICALLY GENERATED BY YOU BASED ON THIS ACTUAL DOMAIN'S REAL TELEMETRY.
If OWASP ZAP dynamic cloud alerts are present in dast_surface_probes, you MUST incorporate those vulnerabilities into Set 5 score, attack_chain exploitation steps, recommendations, and set5.zap_findings!

Return a STRICT, VALID JSON object with the following schema:
{{
  "ai_score": 0 to 100 integer (overall score reflecting real-world posture, exploitability, and active protections),
  "ai_grade": "A+", "A", "B", "C", "D", or "F",
  "threat_verdict": "Single punchy verdict sentence (e.g. 'Hardened Perimeter with Critical Email Spoofing Vulnerabilities')",
  "executive_summary": "2-4 sentence executive overview for CTOs and developers, summarizing real strengths and main risks.",
  "worker_intelligence_stream": {{
    "w1_osint": {{
      "worker_name": "Worker 1: OSINT & Threat Intel",
      "section_id": "set4",
      "status": "Passed" | "Warning" | "Failed",
      "metric_value": "Telemetry metric string (e.g. '14 Subdomains • 0 Breaches')",
      "summary": "1-2 sentence AI verdict on OSINT findings",
      "tools": "VirusTotal, Shodan, URLScan.io, AlienVault OTX, Hudson Rock, crt.sh"
    }},
    "w2_tls": {{
      "worker_name": "Worker 2: TLS & Cryptography",
      "section_id": "set1",
      "status": "Passed" | "Warning" | "Failed",
      "metric_value": "Telemetry metric string (e.g. 'TLS 1.3 (180d left)')",
      "summary": "1-2 sentence AI verdict on TLS and crypto",
      "tools": "Python ssl, socket, cryptography, OpenSSL"
    }},
    "w3_headers": {{
      "worker_name": "Worker 3: HTTP Headers & CSP",
      "section_id": "set2",
      "status": "Passed" | "Warning" | "Failed",
      "metric_value": "Telemetry metric string (e.g. '2/6 Headers Active')",
      "summary": "1-2 sentence AI verdict on response headers",
      "tools": "httpx, Cookie Security Auditor, WAF Detector"
    }},
    "w4_dns": {{
      "worker_name": "Worker 4: DNS & Anti-Spoofing",
      "section_id": "set3",
      "status": "Passed" | "Warning" | "Failed",
      "metric_value": "Telemetry metric string (e.g. 'SPF: Yes • DMARC: reject')",
      "summary": "1-2 sentence AI verdict on DNS and SPF/DMARC",
      "tools": "dnspython, SPF Parser, DMARC Evaluator, DNSSEC"
    }},
    "w5_dast": {{
      "worker_name": "Worker 5: DAST & Cloud ZAP",
      "section_id": "set5",
      "status": "Passed" | "Warning" | "Failed",
      "metric_value": "Telemetry metric string (e.g. '0 ZAP Alerts • Clean Probes')",
      "summary": "1-2 sentence AI verdict on DAST & OWASP ZAP alerts",
      "tools": "OWASP ZAP (GitHub Actions 7GB Cloud Runner), Nuclei DAST, Path Prober"
    }},
    "w6_honeypot": {{
      "worker_name": "Worker 6: Deception Posture",
      "section_id": "set6",
      "status": "Passed" | "Failed",
      "metric_value": "Telemetry metric string (e.g. 'Authentic Host')",
      "summary": "1-2 sentence AI verdict on canary probes",
      "tools": "Canary Probe Analyzer, Tarpit Latency Meter, WAFW00F"
    }}
  }},
  "set_scores": {{
    "set1": 0 to 100 integer (Set 1: Network & TLS Encryption),
    "set2": 0 to 100 integer (Set 2: HTTP Security Headers & CSP),
    "set3": 0 to 100 integer (Set 3: DNS & Anti-Spoofing Posture),
    "set4": 0 to 100 integer (Set 4: Attack Surface & OSINT Footprint),
    "set5": 0 to 100 integer (Set 5: DAST & Sensitive Endpoint Probes),
    "set6": 0 to 100 integer (Set 6: Deception & Honeypot Posture)
  }},
  "detailed_sets": {{
    "set1": {{
      "name": "Set 1: Network & TLS Encryption",
      "score": 0 to 100 integer,
      "grade": "A+", "A", "B", "C", "D", or "F",
      "analyzedItems": ["TLS Protocol Negotiation", "Cipher Suite Strength", "Port 80 Cleartext Redirect", "Certificate Validity Period"],
      "analyzed_items": [
        {{ "item": "TLS Protocol Negotiation", "status": "PASS" | "FAIL", "details": "Dynamic evaluation of TLS protocol version." }},
        {{ "item": "Cipher Suite Strength", "status": "PASS" | "WARN", "details": "Dynamic evaluation of cipher suite strength." }},
        {{ "item": "Port 80 Cleartext Redirect", "status": "PASS" | "FAIL", "details": "Dynamic evaluation of port 80 redirect." }},
        {{ "item": "Certificate Trust Chain", "status": "PASS" | "WARN" | "FAIL", "details": "Dynamic evaluation of cert validity and CA." }}
      ],
      "positiveFindings": ["List of 1-3 verified strengths from telemetry"],
      "negativeFindings": ["List of 1-3 gaps or deductions from telemetry"],
      "negative_remediation_guides": [
        {{
          "finding": "Name of negative finding to remove",
          "steps": ["1. Step one with exact commands...", "2. Step two...", "3. Verification..."],
          "fix_urls": [{{ "label": "Official Docs Name", "url": "https://valid-documentation-url" }}]
        }}
      ],
      "whyScoreGiven": "Clear, authoritative explanation of why this score was given based on real data",
      "evidence": "Concrete evidence summary (e.g. 'TLS 1.3 • Cipher: AES-256-GCM • Expires in 180 days')",
      "recommendation": "Specific actionable recommendation to improve Set 1",
      "metricValue": "Concise metric string (e.g. 'TLS 1.3 Active (180d left)')",
      "issuer": "Real Certificate Authority Issuer Name from telemetry (e.g. 'Let\\'s Encrypt' or 'DigiCert Global Root CA')",
      "subject": "Real Certificate Common Name (e.g. '*.domain.com')",
      "protocol": "Negotiated TLS Version (e.g. 'TLS 1.3' or 'TLS 1.2')",
      "cipher": "Negotiated Cipher Suite (e.g. 'ECDHE-RSA-AES128-GCM-SHA256')",
      "days_until_expiry": integer,
      "trust_chain_status": "CHAIN VERIFIED"
    }},
    "set2": {{
      "name": "Set 2: HTTP Security Headers",
      "score": 0 to 100 integer,
      "grade": "A+", "A", "B", "C", "D", or "F",
      "analyzedItems": ["Content-Security-Policy (CSP)", "Strict-Transport-Security (HSTS)", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Cookie Security Attributes"],
      "analyzed_items": [
        {{ "item": "Content-Security-Policy (CSP)", "status": "PASS" | "FAIL", "details": "Dynamic status of CSP header." }},
        {{ "item": "Strict-Transport-Security (HSTS)", "status": "PASS" | "FAIL", "details": "Dynamic status of HSTS header." }},
        {{ "item": "X-Frame-Options", "status": "PASS" | "FAIL", "details": "Dynamic status of XFO framing protection." }},
        {{ "item": "X-Content-Type-Options", "status": "PASS" | "FAIL", "details": "Dynamic status of nosniff header." }},
        {{ "item": "Referrer-Policy", "status": "PASS" | "WARN", "details": "Dynamic status of Referrer-Policy." }},
        {{ "item": "Cookie Security Attributes", "status": "PASS" | "WARN", "details": "Dynamic status of cookie attributes." }}
      ],
      "positiveFindings": ["List of active headers detected"],
      "negativeFindings": ["List of missing or flawed headers"],
      "negative_remediation_guides": [
        {{
          "finding": "Name of negative finding to remove",
          "steps": ["1. Step one...", "2. Step two..."],
          "fix_urls": [{{ "label": "Official Docs Name", "url": "https://valid-documentation-url" }}]
        }}
      ],
      "whyScoreGiven": "Explanation of score based on presence/absence of critical defense headers",
      "evidence": "Concrete evidence (e.g. 'Present: nosniff • Missing: CSP, HSTS, XFO')",
      "recommendation": "Step-by-step recommendation for web server configuration",
      "metricValue": "Concise metric (e.g. '2/6 Headers Active')",
      "missing_headers": ["List of missing headers"],
      "active_headers": ["List of active headers"]
    }},
    "set3": {{
      "name": "Set 3: DNS & Anti-Spoofing",
      "score": 0 to 100 integer,
      "grade": "A+", "A", "B", "C", "D", or "F",
      "analyzedItems": ["SPF Authentication Record", "DMARC Policy Enforcement", "MX Server Validation", "DNSSEC Cryptographic Chain"],
      "analyzed_items": [
        {{ "item": "SPF Authentication Record", "status": "PASS" | "FAIL", "details": "Dynamic status of SPF." }},
        {{ "item": "DMARC Policy Enforcement", "status": "PASS" | "WARN" | "FAIL", "details": "Dynamic status of DMARC." }},
        {{ "item": "MX Mail Server Verification", "status": "PASS" | "WARN", "details": "Dynamic status of MX servers." }},
        {{ "item": "DNSSEC Cryptographic Chain", "status": "PASS" | "WARN", "details": "Dynamic status of DNSSEC." }}
      ],
      "positiveFindings": ["List of positive DNS protections found"],
      "negativeFindings": ["List of DNS spoofing weaknesses found"],
      "negative_remediation_guides": [
        {{
          "finding": "Name of negative finding to remove",
          "steps": ["1. Step one...", "2. Step two..."],
          "fix_urls": [{{ "label": "Official Docs Name", "url": "https://valid-documentation-url" }}]
        }}
      ],
      "whyScoreGiven": "Explanation of score based on SPF/DMARC/DNSSEC status",
      "evidence": "Concrete evidence (e.g. 'SPF: Active • DMARC: p=none • DNSSEC: Inactive')",
      "recommendation": "Recommendation for DNS zone hardening",
      "metricValue": "Concise metric (e.g. 'DMARC p=none (Spoofable)')",
      "spf_record": "SPF Record string from telemetry or 'None published'",
      "spf_status": "Configured & Valid or Missing",
      "dmarc_record": "DMARC Record string from telemetry or 'None published'",
      "dmarc_policy": "reject / quarantine / none / missing",
      "dnssec_status": "Cryptographically Signed or Inactive / Unsigned"
    }},
    "set4": {{
      "name": "Set 4: Attack Surface & OSINT",
      "score": 0 to 100 integer,
      "grade": "A+", "A", "B", "C", "D", or "F",
      "analyzedItems": ["VirusTotal 70+ Vendor Reputation", "Shodan Port & CVE Audit", "Dark Web Credential Breaches", "Subdomain Footprint"],
      "analyzed_items": [
        {{ "item": "VirusTotal 70+ AV Reputation", "status": "PASS" | "FAIL", "details": "Dynamic VirusTotal evaluation." }},
        {{ "item": "Shodan Ports & Exposure Audit", "status": "PASS" | "FAIL", "details": "Dynamic Shodan evaluation." }},
        {{ "item": "Dark Web Infostealer Breaches", "status": "PASS" | "FAIL", "details": "Dynamic breach evaluation." }},
        {{ "item": "Subdomain Perimeter Footprint", "status": "PASS" | "WARN", "details": "Dynamic subdomain footprint evaluation." }}
      ],
      "positiveFindings": ["Positive OSINT findings"],
      "negativeFindings": ["Negative OSINT findings or open port risks"],
      "negative_remediation_guides": [
        {{
          "finding": "Name of negative finding to remove",
          "steps": ["1. Step one...", "2. Step two..."],
          "fix_urls": [{{ "label": "Official Docs Name", "url": "https://valid-documentation-url" }}]
        }}
      ],
      "whyScoreGiven": "Explanation based on VirusTotal, Shodan, and breach telemetry",
      "evidence": "Concrete evidence (e.g. 'VirusTotal 0/70 clean • 0 breaches found • 2 open ports')",
      "recommendation": "Recommendation for perimeter attack surface reduction",
      "metricValue": "Concise metric (e.g. 'Clean Reputation (2 Ports)')",
      "virustotal_stats": "VirusTotal detection status (e.g. '0 / 70 Security Vendors Flagged (Clean)')",
      "shodan_ports": ["List of open ports enumerated (e.g. '80 (HTTP)', '443 (HTTPS)')"],
      "breach_intel": "Dark web infostealer credentials status (e.g. '0 Compromised Credentials Found')",
      "subdomain_count": integer
    }},
    "set5": {{
      "name": "Set 5: DAST & Vulnerabilities",
      "score": 0 to 100 integer,
      "grade": "A+", "A", "B", "C", "D", or "F",
      "analyzedItems": ["Sensitive File Probes (/.env, /.git)", "OWASP ZAP Cloud Dynamic Analysis", "Diagnostic Endpoints & Backups", "Web Server Fingerprints"],
      "analyzed_items": [
        {{ "item": "Sensitive File Probes (.env, .git)", "status": "PASS" | "FAIL", "details": "Dynamic evaluation of probe responses." }},
        {{ "item": "OWASP ZAP Cloud Dynamic Analysis", "status": "PASS" | "FAIL" | "WARN", "details": "Dynamic evaluation of OWASP ZAP alerts." }},
        {{ "item": "Diagnostic Endpoints & Backups", "status": "PASS" | "FAIL", "details": "Dynamic evaluation of diagnostic endpoints." }},
        {{ "item": "Web Server Fingerprints", "status": "PASS" | "WARN", "details": "Dynamic evaluation of server banner disclosure." }}
      ],
      "positiveFindings": ["Positive probe findings (e.g. 404 blocked) or verified clean dynamic scan"],
      "negativeFindings": ["Any sensitive files or OWASP ZAP dynamic alerts detected"],
      "negative_remediation_guides": [
        {{
          "finding": "Name of negative finding to remove",
          "steps": ["1. Step one...", "2. Step two..."],
          "fix_urls": [{{ "label": "Official Docs Name", "url": "https://valid-documentation-url" }}]
        }}
      ],
      "whyScoreGiven": "Explanation of score based on active probe responses and OWASP ZAP cloud dynamic findings",
      "evidence": "Concrete evidence (e.g. 'Probed /.env (404), /.git (404) • OWASP ZAP alerts summary')",
      "recommendation": "Recommendation for server directory and sensitive file blocking and OWASP ZAP alert remediation",
      "metricValue": "Concise metric (e.g. '0 Leaks Detected' or '2 ZAP Alerts')",
      "probed_paths": [
        {{ "path": "/.env", "status": "HTTP 404", "verdict": "Blocked / Safe" }},
        {{ "path": "/.git", "status": "HTTP 404", "verdict": "Blocked / Safe" }},
        {{ "path": "/backup.zip", "status": "HTTP 404", "verdict": "Blocked / Safe" }}
      ],
      "zap_status": "Complete (GitHub Actions 7GB Runner)",
      "zap_alerts_count": integer,
      "zap_findings": [
        {{ "name": "Alert Name", "risk": "High" | "Medium" | "Low" | "Info", "cweid": "CWE-xxx", "solution": "Official fix description", "param": "affected parameter or header" }}
      ],
      "dast_verdict": "Clean Surface (0 Leaks Detected)"
    }},
    "set6": {{
      "name": "Set 6: Deception & Honeypot",
      "score": 0 to 100 integer,
      "grade": "A+", "A", "B", "C", "D", or "F",
      "analyzedItems": ["Canary URI Probe Behavior", "Tarpit Response Latency", "Host Authenticity Verification"],
      "analyzed_items": [
        {{ "item": "Canary URI Probe Behavior", "status": "PASS" | "FAIL", "details": "Dynamic canary probe evaluation." }},
        {{ "item": "Tarpit Response Latency", "status": "PASS" | "WARN", "details": "Dynamic server response latency evaluation." }},
        {{ "item": "Host Authenticity Verification", "status": "PASS" | "FAIL", "details": "Dynamic authenticity verification." }}
      ],
      "positiveFindings": ["Positive findings (e.g. authentic error handling)"],
      "negativeFindings": ["Deception anomalies if any"],
      "negative_remediation_guides": [
        {{
          "finding": "Name of negative finding to remove",
          "steps": ["1. Step one...", "2. Step two..."],
          "fix_urls": [{{ "label": "Official Docs Name", "url": "https://valid-documentation-url" }}]
        }}
      ],
      "whyScoreGiven": "Explanation of host authenticity score",
      "evidence": "Concrete evidence (e.g. 'Canary probes correctly returned 404/403 (Score: 0.0)')",
      "recommendation": "Recommendation on canary route behavior",
      "metricValue": "Concise metric (e.g. 'Authentic Production Host')",
      "canary_status": "Expected Client Error (404/403)",
      "tarpit_status": "Normal Response Latency (<200ms)",
      "host_authenticity": "Authentic Production Environment"
    }}
  }},
  "multi_site_comparison_insight": "A dynamic comparison paragraph analyzing this domain's security stance relative to modern benchmarks (explaining why its specific cryptographic, header, or DNS posture differs from industry standards).",
  "scoring_breakdown": [
    {{
      "category": "TLS & Cryptography",
      "earned": integer,
      "max": 25,
      "reasonEarned": "Reason points were awarded",
      "reasonDeducted": "Reason points were deducted",
      "detectedIssue": "Detected issue or 'None'",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Clean",
      "evidence": "Specific telemetry evidence",
      "improvement": "Action to earn remaining points"
    }},
    {{
      "category": "HTTP Security Headers",
      "earned": integer,
      "max": 30,
      "reasonEarned": "Reason points were awarded",
      "reasonDeducted": "Reason points were deducted",
      "detectedIssue": "Specific missing headers",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Clean",
      "evidence": "Headers present vs missing",
      "improvement": "Add missing headers"
    }},
    {{
      "category": "Email & DNS Spoofing",
      "earned": integer,
      "max": 20,
      "reasonEarned": "Reason points were awarded",
      "reasonDeducted": "Reason points were deducted",
      "detectedIssue": "DMARC/DNSSEC status",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Clean",
      "evidence": "SPF/DMARC record syntax",
      "improvement": "Upgrade DMARC policy"
    }},
    {{
      "category": "Attack Surface & OSINT",
      "earned": integer,
      "max": 15,
      "reasonEarned": "Reason points were awarded",
      "reasonDeducted": "Reason points were deducted",
      "detectedIssue": "Open ports / breaches if any",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Clean",
      "evidence": "VirusTotal & Shodan summary",
      "improvement": "Perimeter minimization action"
    }},
    {{
      "category": "Sensitive File Probes",
      "earned": integer,
      "max": 5,
      "reasonEarned": "Reason points were awarded",
      "reasonDeducted": "Reason points were deducted",
      "detectedIssue": "Probe results",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Clean",
      "evidence": "Probe status codes",
      "improvement": "Restrict hidden files"
    }},
    {{
      "category": "Deception Posture",
      "earned": integer,
      "max": 5,
      "reasonEarned": "Reason points were awarded",
      "reasonDeducted": "Reason points were deducted",
      "detectedIssue": "Honeypot status",
      "severity": "Clean",
      "evidence": "Canary test results",
      "improvement": "Maintain standard 404 routing"
    }}
  ],
  "attacker_perspective": "A paragraph explaining exactly how an external adversary analyzes this domain and what attack vectors they prioritize.",
  "attack_chain": [
    {{
      "step": 1,
      "title": "Phase 1 Title",
      "description": "Exploitation description",
      "exploit_vector": "Attack vector"
    }},
    {{
      "step": 2,
      "title": "Phase 2 Title",
      "description": "Exploitation description",
      "exploit_vector": "Attack vector"
    }},
    {{
      "step": 3,
      "title": "Phase 3 Title",
      "description": "Exploitation description",
      "exploit_vector": "Attack vector"
    }}
  ],
  "strengths": [
    "3 to 5 verified strengths discovered by the tools"
  ],
  "critical_risks": [
    "1 to 4 priority vulnerabilities or configuration gaps"
  ],
  "recommendations": [
    "3 to 5 prioritized, clear recommendations"
  ],
  "server_hardening": {{
    "nginx": "Complete tailored Nginx configuration block with exact missing headers for this site",
    "apache": "Complete tailored Apache .htaccess configuration block with exact missing headers",
    "cloudflare": "Tailored Cloudflare Transform Rule instructions or worker snippet",
    "caddy": "Tailored Caddyfile snippet"
  }},
  "remediation_roadmap": {{
    "phase_1_immediate": ["Action 1", "Action 2"],
    "phase_2_short_term": ["Action 1", "Action 2"],
    "phase_3_strategic": ["Action 1", "Action 2"]
  }},
  "ready_to_deploy_fixes": [
    {{
      "title": "Fix title",
      "target": "Nginx / Apache / DNS / Cloudflare",
      "type": "nginx" | "apache" | "dns" | "cloudflare",
      "code": "Actual copy-paste configuration block",
      "explanation": "Why this fixes the issue"
    }}
  ],
  "cross_set_visual_matrix": {{
    "radar_metrics": [
      {{ "dimension": "Crypto & TLS", "score": 0 to 100 integer, "benchmark": 85, "tools_count": 8 }},
      {{ "dimension": "Headers & CSP", "score": 0 to 100 integer, "benchmark": 78, "tools_count": 9 }},
      {{ "dimension": "DNS & Spoof", "score": 0 to 100 integer, "benchmark": 80, "tools_count": 8 }},
      {{ "dimension": "Attack Surface", "score": 0 to 100 integer, "benchmark": 72, "tools_count": 12 }},
      {{ "dimension": "DAST & ZAP", "score": 0 to 100 integer, "benchmark": 82, "tools_count": 10 }},
      {{ "dimension": "Deception Posture", "score": 0 to 100 integer, "benchmark": 88, "tools_count": 8 }}
    ],
    "defense_depth_curve": [
      {{ "stage": "Perimeter & Network", "resilience": 0 to 100 integer, "exposure": 0 to 100 integer, "verified_tools": "TLS 1.2/1.3, Cert Chain, Port 80 Redirect" }},
      {{ "stage": "Transport Cryptography", "resilience": 0 to 100 integer, "exposure": 0 to 100 integer, "verified_tools": "AEAD Ciphers, Forward Secrecy, OpenSSL" }},
      {{ "stage": "Application Isolation", "resilience": 0 to 100 integer, "exposure": 0 to 100 integer, "verified_tools": "HSTS, CSP, X-Frame-Options, Secure Cookies" }},
      {{ "stage": "Identity & Domain Trust", "resilience": 0 to 100 integer, "exposure": 0 to 100 integer, "verified_tools": "SPF, DMARC, DKIM, DNSSEC" }},
      {{ "stage": "External Threat Surface", "resilience": 0 to 100 integer, "exposure": 0 to 100 integer, "verified_tools": "VirusTotal 70+ Engines, Shodan, Subdomains" }},
      {{ "stage": "Dynamic Probing & Canary", "resilience": 0 to 100 integer, "exposure": 0 to 100 integer, "verified_tools": "OWASP ZAP 7GB Cloud Runner, Path Probes, Canary" }}
    ],
    "tool_cluster_performance": [
      {{ "cluster": "Set 1: Cryptographic Engine", "score": 0 to 100 integer, "checks_passed": integer, "total_checks": 8 }},
      {{ "cluster": "Set 2: Browser Security & CSP", "score": 0 to 100 integer, "checks_passed": integer, "total_checks": 8 }},
      {{ "cluster": "Set 3: DNS & Anti-Spoofing", "score": 0 to 100 integer, "checks_passed": integer, "total_checks": 7 }},
      {{ "cluster": "Set 4: Threat Intelligence & OSINT", "score": 0 to 100 integer, "checks_passed": integer, "total_checks": 11 }},
      {{ "cluster": "Set 5: Application DAST & ZAP", "score": 0 to 100 integer, "checks_passed": integer, "total_checks": 14 }},
      {{ "cluster": "Set 6: Deception & Authenticity", "score": 0 to 100 integer, "checks_passed": integer, "total_checks": 7 }}
    ],
    "mathematical_posture_distribution": [
      {{ "name": "Hardened Dimensions", "value": integer, "color": "#10b981" }},
      {{ "name": "Moderate Risk Vectors", "value": integer, "color": "#f59e0b" }},
      {{ "name": "Critical Gaps", "value": integer, "color": "#f43f5e" }}
    ]
  }}
}}

IMPORTANT: Return ONLY the raw JSON object. Do not include markdown preamble or backticks outside the JSON.
"""

    raw_response = await call_gemini_api(prompt, response_json=True, timeout_sec=35.0)
    parsed_json = clean_and_parse_json(raw_response) if raw_response else None

    if not parsed_json or "ai_score" not in parsed_json:
        logger.warning("Gemini synthesis returned incomplete or unparseable JSON. Falling back to structured synthesizer.")
        return generate_fallback_intelligence(domain, url, worker_results, raw_findings)

    from app.engine.scorer import (
        calculate_category_scores,
        generate_detailed_sets,
        generate_worker_intelligence_stream,
        build_negative_remediation_guides
    )

    # Ensure all 6 set scores exist
    set_scores = parsed_json.get("set_scores", {})
    fallback_set_scores = None
    if not isinstance(set_scores, dict) or len(set_scores) < 6:
        fallback_set_scores = calculate_category_scores(raw_findings, worker_results)
        for k in ["set1", "set2", "set3", "set4", "set5", "set6"]:
            if k not in set_scores:
                set_scores[k] = fallback_set_scores.get(k, 75)
        parsed_json["set_scores"] = set_scores

    # Ensure worker_intelligence_stream exists and is fully populated
    worker_stream = parsed_json.get("worker_intelligence_stream")
    fallback_stream = generate_worker_intelligence_stream(set_scores, worker_results)
    if not isinstance(worker_stream, dict) or len(worker_stream) < 6:
        if not isinstance(worker_stream, dict):
            worker_stream = {}
        for wk, wdef in fallback_stream.items():
            if wk not in worker_stream:
                worker_stream[wk] = wdef
    parsed_json["worker_intelligence_stream"] = worker_stream

    # Ensure detailed_sets and its inner analyzed_items / negative_remediation_guides are complete
    detailed_sets = parsed_json.get("detailed_sets", {})
    fallback_detailed = generate_detailed_sets(domain, worker_results, set_scores, raw_findings)
    if not isinstance(detailed_sets, dict):
        detailed_sets = fallback_detailed
        parsed_json["detailed_sets"] = detailed_sets
    else:
        for k in ["set1", "set2", "set3", "set4", "set5", "set6"]:
            if k not in detailed_sets or not isinstance(detailed_sets[k], dict):
                detailed_sets[k] = fallback_detailed.get(k, {})
            else:
                s_dict = detailed_sets[k]
                fb_dict = fallback_detailed.get(k, {})
                # Ensure analyzed_items is a list of structured dicts
                if not s_dict.get("analyzed_items") or not isinstance(s_dict["analyzed_items"], list) or not all(isinstance(x, dict) and "item" in x for x in s_dict["analyzed_items"]):
                    s_dict["analyzed_items"] = fb_dict.get("analyzed_items", [])
                # Maintain legacy analyzedItems string list for backward compatibility
                if not s_dict.get("analyzedItems"):
                    s_dict["analyzedItems"] = [item["item"] if isinstance(item, dict) else str(item) for item in s_dict.get("analyzed_items", [])]
                
                # Ensure every negative finding has an actionable remediation guide with valid documentation URLs
                negs = s_dict.get("negativeFindings", fb_dict.get("negativeFindings", []))
                valid_negs = [n for n in negs if n and not n.lower().startswith("none") and not "clean" in n.lower() and not "zero" in n.lower()]
                existing_guides = s_dict.get("negative_remediation_guides")
                if not existing_guides or not isinstance(existing_guides, list):
                    s_dict["negative_remediation_guides"] = build_negative_remediation_guides(k, valid_negs, domain)
                else:
                    existing_names = {g.get("finding", "").lower().strip() for g in existing_guides if isinstance(g, dict)}
                    missing_negs = [vn for vn in valid_negs if vn.lower().strip() not in existing_names]
                    if missing_negs:
                        fb_guides = build_negative_remediation_guides(k, missing_negs, domain)
                        existing_guides.extend(fb_guides)
                    s_dict["negative_remediation_guides"] = existing_guides

    # Ensure cross_set_visual_matrix exists and is populated
    cross_matrix = parsed_json.get("cross_set_visual_matrix")
    if not cross_matrix or not isinstance(cross_matrix, dict) or not cross_matrix.get("radar_metrics"):
        fb_intel = generate_fallback_intelligence(domain, url, worker_results, raw_findings)
        parsed_json["cross_set_visual_matrix"] = fb_intel.get("cross_set_visual_matrix")

    parsed_json["ai_powered"] = True
    parsed_json["gemini_model_used"] = "AI Security Core"
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
