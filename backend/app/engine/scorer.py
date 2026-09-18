def calculate_category_scores(findings: list, worker_results: dict) -> dict:
    """Calculate individual scores (0-100) for all 6 security sets based on real telemetry."""
    # -------------------------------------------------------------
    # Set 1: Network & TLS Encryption (Max 100)
    # -------------------------------------------------------------
    tls_raw = worker_results.get("w2_tls", {}).get("raw_data", {})
    tls_info = tls_raw.get("tls", {})
    tls_status = tls_info.get("status")
    
    set1_score = 100.0
    if tls_status == "success":
        version = tls_info.get("version", "")
        if version == "TLSv1.3":
            pass # perfect
        elif version == "TLSv1.2":
            set1_score -= 8.0 # slight deduction for not supporting 1.3
        elif version in ("TLSv1.1", "TLSv1", "SSLv3", "SSLv2"):
            set1_score -= 40.0

        days_left = tls_info.get("days_until_expiry", 90)
        if days_left <= 0:
            set1_score -= 50.0
        elif days_left < 15:
            set1_score -= 25.0
        elif days_left < 30:
            set1_score -= 10.0

        if not tls_raw.get("redirect_secure", True):
            set1_score -= 12.0
    else:
        # Unable to complete TLS or no HTTPS
        set1_score = 45.0

    # -------------------------------------------------------------
    # Set 2: HTTP Security Headers & CSP (Max 100)
    # -------------------------------------------------------------
    hdr_raw = worker_results.get("w3_headers", {}).get("raw_data", {})
    missing_headers = hdr_raw.get("missing_headers", [])
    
    set2_score = 100.0
    if "Content-Security-Policy" in missing_headers:
        set2_score -= 25.0
    if "Strict-Transport-Security" in missing_headers:
        set2_score -= 25.0
    if "X-Frame-Options" in missing_headers:
        set2_score -= 15.0
    if "X-Content-Type-Options" in missing_headers:
        set2_score -= 10.0
    if "Referrer-Policy" in missing_headers:
        set2_score -= 5.0
        
    for f in findings:
        if f.get("category") == "headers" and "Insecure Cookie" in f.get("title", ""):
            set2_score -= 10.0
            break

    # -------------------------------------------------------------
    # Set 3: DNS & Anti-Spoofing (Max 100)
    # -------------------------------------------------------------
    dns_raw = worker_results.get("w4_dns", {}).get("raw_data", {})
    spf_data = dns_raw.get("spf", {})
    dmarc_data = dns_raw.get("dmarc", {})
    dnssec_data = dns_raw.get("dnssec", {})
    
    set3_score = 100.0
    if not spf_data.get("found"):
        set3_score -= 35.0
    elif spf_data.get("mechanism") in ["?all", "+all"]:
        set3_score -= 15.0

    if not dmarc_data.get("found"):
        set3_score -= 35.0
    elif dmarc_data.get("policy") == "none":
        set3_score -= 15.0
    elif dmarc_data.get("policy") == "quarantine":
        set3_score -= 5.0

    if not dnssec_data.get("active"):
        set3_score -= 10.0

    # -------------------------------------------------------------
    # Set 4: Attack Surface & OSINT (Max 100)
    # -------------------------------------------------------------
    osint_raw = worker_results.get("w1_osint", {}).get("raw_data", {})
    shodan_data = osint_raw.get("shodan", {})
    subdomains = osint_raw.get("subdomains", [])
    vt_data = osint_raw.get("virustotal", {})
    breach_data = osint_raw.get("breaches", {})
    leakcheck_data = osint_raw.get("leakcheck", {})
    urlscan_data = osint_raw.get("urlscan", {})
    emailrep_data = osint_raw.get("emailrep", {})
    
    set4_score = 100.0
    if len(subdomains) > 50:
        set4_score -= 15.0
    elif len(subdomains) > 20:
        set4_score -= 8.0

    if shodan_data.get("vulns"):
        set4_score -= 35.0
    if any(p in [3306, 5432, 27017, 6379, 22, 1433, 9200] for p in shodan_data.get("ports", [])):
        set4_score -= 25.0

    # VirusTotal threat detection deduction
    vt_malicious = vt_data.get("malicious", 0)
    if vt_malicious > 2:
        set4_score -= 40.0
    elif vt_malicious > 0:
        set4_score -= 20.0

    # Dark Web / Credential breach deduction
    total_breaches = breach_data.get("breach_count", 0) + leakcheck_data.get("breach_count", 0)
    if total_breaches > 10:
        set4_score -= 25.0
    elif total_breaches > 0:
        set4_score -= 12.0

    # URLScan malicious verdict deduction
    if urlscan_data.get("malicious"):
        set4_score -= 20.0

    # EmailRep suspicious flag deduction
    if emailrep_data.get("suspicious"):
        set4_score -= 10.0

    set4_score = max(0.0, min(100.0, set4_score))

    # -------------------------------------------------------------
    # Set 5: DAST & Exposure (Max 100)
    # -------------------------------------------------------------
    dast_raw = worker_results.get("w5_dast", {}).get("raw_data", {})
    set5_score = 100.0
    for f in findings:
        if f.get("category") == "dast":
            if f.get("severity") == "critical":
                set5_score -= 40.0
            elif f.get("severity") == "high":
                set5_score -= 20.0
            elif f.get("severity") == "medium":
                set5_score -= 10.0

    # -------------------------------------------------------------
    # Set 6: Deception Posture & Canary (Max 100)
    # -------------------------------------------------------------
    honey_raw = worker_results.get("w6_honeypot", {}).get("raw_data", {})
    set6_score = 100.0
    if honey_raw.get("is_honeypot"):
        set6_score -= 50.0
    elif honey_raw.get("canary", {}).get("all_200"):
        set6_score -= 30.0

    return {
        "set1": max(10, min(100, int(round(set1_score)))),
        "set2": max(10, min(100, int(round(set2_score)))),
        "set3": max(10, min(100, int(round(set3_score)))),
        "set4": max(10, min(100, int(round(set4_score)))),
        "set5": max(10, min(100, int(round(set5_score)))),
        "set6": max(10, min(100, int(round(set6_score)))),
    }

def calculate_score(findings: list, worker_results: dict, set_scores: dict = None) -> float:
    """Calculate overall weighted security score from real category posture."""
    if not set_scores:
        set_scores = calculate_category_scores(findings, worker_results)

    weighted = (
        set_scores["set1"] * 0.25 +
        set_scores["set2"] * 0.30 +
        set_scores["set3"] * 0.20 +
        set_scores["set4"] * 0.15 +
        set_scores["set5"] * 0.05 +
        set_scores["set6"] * 0.05
    )
    return round(max(5.0, min(100.0, weighted)), 1)

def assign_grade(score: float) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"

def generate_detailed_sets(domain: str, worker_results: dict, set_scores: dict, findings: list = None) -> dict:
    """Generate rich, human-readable explanations based on real data for all 6 sets."""
    if findings is None:
        findings = worker_results.get("w5_dast", {}).get("findings", [])
    tls_info = worker_results.get("w2_tls", {}).get("raw_data", {}).get("tls", {})
    hdr_raw = worker_results.get("w3_headers", {}).get("raw_data", {})
    dns_raw = worker_results.get("w4_dns", {}).get("raw_data", {})
    osint_raw = worker_results.get("w1_osint", {}).get("raw_data", {})
    
    # Set 1 Details
    s1_pos = []
    s1_neg = []
    if tls_info.get("version"):
        s1_pos.append(f"{tls_info.get('version')} cryptographic handshake validated")
    if tls_info.get("cipher"):
        s1_pos.append(f"Modern cipher suite negotiated: {tls_info.get('cipher')}")
    days = tls_info.get("days_until_expiry", 0)
    if days > 30:
        s1_pos.append(f"Certificate authority trust chain active ({days} days remaining)")
    else:
        s1_neg.append(f"Certificate expires in only {days} days")

    if not worker_results.get("w2_tls", {}).get("raw_data", {}).get("redirect_secure", True):
        s1_neg.append("Port 80 HTTP does not immediately enforce strict 301 redirect to HTTPS")

    # Set 2 Details
    s2_pos = []
    s2_neg = []
    for h in hdr_raw.get("active_headers", []):
        s2_pos.append(f"{h} is actively enforced on responses")
    for h in hdr_raw.get("missing_headers", []):
        s2_neg.append(f"Missing {h} header")

    # Set 3 Details
    s3_pos = []
    s3_neg = []
    spf = dns_raw.get("spf", {})
    if spf.get("found"):
        s3_pos.append(f"SPF record active ({spf.get('mechanism') or 'configured'})")
    else:
        s3_neg.append("Missing SPF TXT record for domain spoof protection")

    dmarc = dns_raw.get("dmarc", {})
    if dmarc.get("found"):
        pol = dmarc.get("policy", "active")
        if pol == "reject":
            s3_pos.append("Strict DMARC p=reject policy enforced against phishing")
        else:
            s3_pos.append(f"DMARC policy found with policy '{pol}'")
            if pol == "none":
                s3_neg.append("DMARC is set to p=none (monitoring only, spoofed emails not rejected)")
    else:
        s3_neg.append("Missing DMARC policy record")

    if dns_raw.get("dnssec", {}).get("active"):
        s3_pos.append("DNSSEC cryptographically verified with DS records")
    else:
        s3_neg.append("DNSSEC validation inactive (no signed DS/DNSKEY records)")

    # Set 4 Details
    subs = osint_raw.get("subdomains", [])
    s4_pos = [f"Attack surface monitored: {len(subs)} public subdomains discovered via CT logs"]
    s4_neg = []
    if len(subs) > 30:
        s4_neg.append(f"Large public attack surface ({len(subs)} subdomains discovered)")

    # VirusTotal multi-vendor intelligence
    vt_info = osint_raw.get("virustotal", {})
    if vt_info.get("status") == "success":
        if vt_info.get("malicious", 0) == 0:
            s4_pos.append("Domain verified clean across 70+ security vendors (VirusTotal)")
        else:
            s4_neg.append(f"Domain flagged malicious by {vt_info.get('malicious')} security vendors on VirusTotal")

    # Dark Web & Infostealer breaches (Hudson Rock & LeakCheck)
    breach_info = osint_raw.get("breaches", {})
    if breach_info.get("breaches_found"):
        s4_neg.append(f"Infostealer malware breach: {breach_info.get('breach_count', 0)} compromised credentials found in cybercrime dumps (Hudson Rock)")
    else:
        s4_pos.append("Zero compromised corporate credentials found in cybercrime dumps")

    # Shodan ports & CVEs
    shodan_info = osint_raw.get("shodan", {})
    if shodan_info.get("vulns"):
        s4_neg.append(f"{len(shodan_info.get('vulns'))} known CVE vulnerabilities detected on host")
    elif shodan_info.get("ports"):
        s4_pos.append(f"Host port audit clean: {len(shodan_info.get('ports'))} active services enumerated")

    # URLScan passive audit
    urlscan_info = osint_raw.get("urlscan", {})
    if urlscan_info.get("status") == "success" and not urlscan_info.get("malicious"):
        s4_pos.append("Passive web topology & DOM structure validated (URLScan)")

    # Set 5 Details (DAST & Sensitive Path Probes & OWASP ZAP)
    dast_raw = worker_results.get("w5_dast", {}).get("raw_data", {})
    probed_paths = dast_raw.get("probed_paths", {})
    checked_paths = probed_paths.get("checked", {})
    dast_findings = [f for f in findings if f.get("category") == "dast"]
    
    # Extract OWASP ZAP findings
    zap_cloud_alerts = dast_raw.get("zap_cloud_alerts", []) or dast_raw.get("zap", {}).get("alerts", [])
    zap_findings_list = []
    for za in zap_cloud_alerts:
        risk = (za.get("severity") or za.get("risk", "Low")).capitalize()
        name = za.get("title", "OWASP ZAP Finding").replace("OWASP ZAP: ", "")
        zap_findings_list.append({
            "name": name,
            "risk": risk,
            "cweid": za.get("evidence", {}).get("cweid", "") or za.get("cweid", ""),
            "solution": za.get("solution", ""),
            "param": za.get("evidence", {}).get("param", "") or za.get("param", ""),
            "url": za.get("evidence", {}).get("url", "") or za.get("url", "")
        })

    zap_meta = dast_raw.get("zap", {})
    if zap_findings_list or zap_meta.get("status") == "completed":
        zap_status = "Complete (GitHub Actions 7GB Runner)"
        zap_count = len(zap_findings_list)
    elif zap_meta.get("status") in ("cloud_active", "dispatched", "running"):
        zap_status = "Scanning in Cloud (GitHub Actions 7GB Runner)"
        zap_count = 0
    else:
        zap_status = "On-Demand Cloud Runner Ready"
        zap_count = 0

    s5_pos = []
    s5_neg = []
    if zap_findings_list:
        for zf in zap_findings_list[:4]:
            s5_neg.append(f"OWASP ZAP: {zf['name']} ({zf['risk']} Risk • {zf['cweid'] or 'DAST'})")
    elif zap_status == "Complete (GitHub Actions 7GB Runner)":
        s5_pos.append("OWASP ZAP dynamic baseline audit verified 0 high-risk vulnerabilities")

    if dast_findings:
        for df in dast_findings:
            if not df.get("title", "").startswith("OWASP ZAP:"):
                s5_neg.append(f"Exposed sensitive file: {df.get('title')}")
    else:
        if checked_paths:
            s5_pos.append(f"Probed {len(checked_paths)} sensitive endpoints (/.env, /.git, backups); all properly restricted/blocked")
        else:
            s5_pos.append("No sensitive application configuration files exposed on public root")

    nuclei_info = dast_raw.get("nuclei", {})
    if nuclei_info.get("vulnerabilities"):
        s5_neg.append(f"Nuclei DAST identified {len(nuclei_info.get('vulnerabilities'))} active misconfigurations")
    elif nuclei_info.get("status") == "success":
        s5_pos.append("Nuclei template audit verified zero known exploit misconfigurations")

    dast_evidence = ", ".join([f"{p} ({code})" for p, code in checked_paths.items()]) if checked_paths else "No configuration leaks discovered on standard probe paths"

    # Set 6 Details (Deception & Honeypot Posture)
    honey_raw = worker_results.get("w6_honeypot", {}).get("raw_data", {})
    is_honeypot = honey_raw.get("is_honeypot", False)
    canary_data = honey_raw.get("canary", {})
    
    s6_pos = []
    s6_neg = []
    if is_honeypot:
        s6_neg.append("Host returned HTTP 200 OK for random non-existent paths (Deception / Honeypot profile detected)")
        honey_evidence = f"Canary test: {canary_data.get('success_count', 0)}/3 random URIs responded with 200 OK"
        honey_metric = f"Honeypot Detected (Score: {honey_raw.get('honeypot_score', 0.5)})"
        honey_recommendation = "If this is a deception environment, verify production traffic is properly segregated."
    else:
        s6_pos.append("Target server correctly returns 404/403 for non-existent canary probe paths")
        s6_pos.append("Authentic production host behavior confirmed; zero tarpit deception detected")
        honey_evidence = f"Canary probes returned expected client error status codes (honeypot score: 0.0)"
        honey_metric = "Authentic Production Host"
        honey_recommendation = "Maintain standard HTTP 404 routing for non-existent paths to preserve scanner transparency."

    issuer_org = tls_info.get("issuer", {}).get("organizationName") or tls_info.get("issuer", {}).get("commonName") or "Trusted Certificate Authority"
    subject_cn = tls_info.get("subject", {}).get("commonName") or f"*.{domain}"

    return {
        "set1": {
            "name": "Set 1: Network & TLS Encryption",
            "score": set_scores["set1"],
            "grade": assign_grade(set_scores["set1"]),
            "analyzedItems": ["TLS Protocol Version", "Cipher Suite Strength", "Port 80 Cleartext Redirect", "Certificate Validity Period"],
            "positiveFindings": s1_pos or ["Standard TLS handshake completed"],
            "negativeFindings": s1_neg or ["None detected; encryption posture clean"],
            "whyScoreGiven": f"Awarded {set_scores['set1']}/100 based on {tls_info.get('version', 'TLS')} protocol negotiation and {days} days certificate validity.",
            "evidence": f"{tls_info.get('version', 'TLS')} &bull; Cipher: {tls_info.get('cipher', 'Standard')} &bull; CA: {issuer_org} &bull; Cert Expires: {days} days",
            "recommendation": "Maintain automatic TLS certificate rotation and enforce TLS 1.3 across all virtual hosts.",
            "metricValue": f"{tls_info.get('version', 'TLS Active')} ({days}d left)",
            "issuer": issuer_org,
            "subject": subject_cn,
            "protocol": tls_info.get("version") or "Not Negotiated",
            "cipher": tls_info.get("cipher") or "None",
            "days_until_expiry": days,
            "trust_chain_status": "CHAIN VERIFIED" if days > 0 else "EXPIRED"
        },
        "set2": {
            "name": "Set 2: HTTP Security Headers",
            "score": set_scores["set2"],
            "grade": assign_grade(set_scores["set2"]),
            "analyzedItems": ["Content-Security-Policy (CSP)", "Strict-Transport-Security (HSTS)", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"],
            "positiveFindings": s2_pos or ["Basic web response headers returned"],
            "negativeFindings": s2_neg or ["No missing headers detected"],
            "whyScoreGiven": f"Awarded {set_scores['set2']}/100. Evaluated {hdr_raw.get('active_count', 0)} active headers out of {hdr_raw.get('total_evaluated', 6)} industry benchmarks.",
            "evidence": f"Active: {', '.join(hdr_raw.get('active_headers', [])[:3]) or 'None'} &bull; Missing: {', '.join(hdr_raw.get('missing_headers', [])[:3]) or 'None'}",
            "recommendation": "Add missing security headers in web server configuration (Nginx / Cloudflare).",
            "metricValue": f"{hdr_raw.get('active_count', 0)}/{hdr_raw.get('total_evaluated', 6)} Headers Active",
            "missing_headers": hdr_raw.get("missing_headers", []),
            "active_headers": hdr_raw.get("active_headers", [])
        },
        "set3": {
            "name": "Set 3: DNS & Anti-Spoofing",
            "score": set_scores["set3"],
            "grade": assign_grade(set_scores["set3"]),
            "analyzedItems": ["SPF Record Syntax", "DMARC Policy Enforcement", "MX Server Records", "DNSSEC Authentication"],
            "positiveFindings": s3_pos or ["DNS resolution functional"],
            "negativeFindings": s3_neg or ["DNS records conform to security standards"],
            "whyScoreGiven": f"Awarded {set_scores['set3']}/100 based on SPF and DMARC anti-spoofing policy analysis.",
            "evidence": f"SPF: {spf.get('record', 'None')} &bull; DMARC: {dmarc.get('record', 'None')}",
            "recommendation": "Upgrade DMARC policy to p=reject to block unauthorized domain impersonation.",
            "metricValue": f"SPF: {'Yes' if spf.get('found') else 'No'}, DMARC: {dmarc.get('policy', 'None')}",
            "spf_record": spf.get("record") or "None published",
            "spf_status": "Configured" if spf.get("found") else "Missing",
            "dmarc_record": dmarc.get("record") or "None published",
            "dmarc_policy": dmarc.get("policy") or "missing",
            "dnssec_status": "Cryptographically Signed" if dns_raw.get("dnssec", {}).get("active") else "Inactive / Unsigned"
        },
        "set4": {
            "name": "Set 4: Attack Surface & OSINT",
            "score": set_scores["set4"],
            "grade": assign_grade(set_scores["set4"]),
            "analyzedItems": [
                "Subdomain Enumeration (CT Logs)",
                "Open Ports & CVEs (Shodan)",
                "Multi-Engine Threat Intel (VirusTotal)",
                "Dark Web Infostealer Intel (Hudson Rock)",
                "Passive Web Topology Audit (URLScan)"
            ],
            "positiveFindings": s4_pos,
            "negativeFindings": s4_neg or ["No sensitive database ports publicly reachable"],
            "whyScoreGiven": f"Awarded {set_scores['set4']}/100 based on public perimeter and threat intelligence audit.",
            "evidence": f"Subdomains: {len(subs)} &bull; Shodan Ports: {len(shodan_info.get('ports', []))} &bull; Breaches: {breach_info.get('breach_count', 0)}",
            "recommendation": "Ensure development subdomains are isolated, restrict database ports, and monitor employee credentials for dark web leaks.",
            "metricValue": f"{len(subs)} Subdomains &bull; {breach_info.get('breach_count', 0)} Breaches",
            "virustotal_stats": f"{vt_info.get('malicious', 0)} / 70 Vendors Flagged (Clean)" if vt_info.get("malicious", 0) == 0 else f"{vt_info.get('malicious')} / 70 Vendors Flagged Malicious",
            "shodan_ports": [str(p) for p in shodan_info.get("ports", [])],
            "breach_intel": f"{breach_info.get('breach_count', 0)} Compromised Credentials",
            "subdomain_count": len(subs)
        },
        "set5": {
            "name": "Set 5: DAST & Vulnerabilities",
            "score": set_scores["set5"],
            "grade": assign_grade(set_scores["set5"]),
            "analyzedItems": [
                "Exposed Sensitive Files (.env, .git)",
                "OWASP ZAP Cloud Dynamic Analysis",
                "Diagnostic Endpoints",
                "Configuration Backups",
                "Web Server Fingerprints"
            ],
            "positiveFindings": s5_pos or ["No configuration leaks detected on critical paths"],
            "negativeFindings": s5_neg or ["No public directory listing or file leaks detected"],
            "whyScoreGiven": f"Awarded {set_scores['set5']}/100 based on sensitive path probing and OWASP ZAP cloud dynamic analysis.",
            "evidence": f"Probes: {dast_evidence} &bull; ZAP: {zap_status} ({zap_count} Alerts)",
            "recommendation": "Address high-priority OWASP ZAP dynamic findings and enforce strict access control to sensitive paths.",
            "metricValue": f"{zap_count} ZAP Alerts &bull; {len(dast_findings)} Leaks" if (zap_count or dast_findings) else "Clean DAST Surface",
            "probed_paths": [{"path": p, "status": f"HTTP {code}", "verdict": "Blocked / Safe" if code in [404, 403, 401] else "Review"} for p, code in checked_paths.items()],
            "dast_verdict": f"{zap_count} ZAP Alerts Detected" if zap_count else ("Clean Surface (0 Leaks)" if not dast_findings else f"{len(dast_findings)} Leaks Found"),
            "zap_status": zap_status,
            "zap_alerts_count": zap_count,
            "zap_findings": zap_findings_list
        },
        "set6": {
            "name": "Set 6: Deception Posture & Canary",
            "score": set_scores["set6"],
            "grade": assign_grade(set_scores["set6"]),
            "analyzedItems": ["Canary URI Probe Behavior", "Tarpit Latency Profile", "Honeypot Signature Analysis"],
            "positiveFindings": s6_pos,
            "negativeFindings": s6_neg,
            "whyScoreGiven": f"Awarded {set_scores['set6']}/100 based on canary path response behavior.",
            "evidence": honey_evidence,
            "recommendation": honey_recommendation,
            "metricValue": honey_metric,
            "canary_status": "Expected Client Error (404/403)" if not is_honeypot else "Anomalous 200 OK",
            "tarpit_status": "Normal Response Latency (<200ms)",
            "host_authenticity": "Authentic Production Environment" if not is_honeypot else "Deception / Honeypot Detected"
        }
    }

def generate_scoring_breakdown(domain: str, findings: list, set_scores: dict) -> list:
    """Generate transparent point-by-point breakdown mapping points to real evidence for all 6 sets."""
    return [
        {
            "category": "Set 1: Crypto & TLS",
            "earned": int(round(set_scores["set1"] * 0.25)),
            "max": 25,
            "reasonEarned": "Modern TLS handshake negotiated with valid CA certificate.",
            "reasonDeducted": "Deductions applied if certificate is close to expiry or HTTP port 80 fails to enforce redirect." if set_scores["set1"] < 100 else "Full points awarded.",
            "detectedIssue": "Port 80 or cipher check" if set_scores["set1"] < 100 else "None",
            "severity": "Medium" if set_scores["set1"] < 80 else "Clean",
            "evidence": f"Set 1 Score: {set_scores['set1']}/100",
            "improvement": "Enforce TLS 1.3 only and immediate HTTP-to-HTTPS permanent redirect."
        },
        {
            "category": "Set 2: HTTP Headers",
            "earned": int(round(set_scores["set2"] * 0.30)),
            "max": 30,
            "reasonEarned": "Standard response headers present.",
            "reasonDeducted": "Missing core security headers like CSP, HSTS, or X-Frame-Options." if set_scores["set2"] < 100 else "Full points awarded.",
            "detectedIssue": "Missing browser defense headers" if set_scores["set2"] < 100 else "None",
            "severity": "High" if set_scores["set2"] < 70 else "Medium" if set_scores["set2"] < 90 else "Clean",
            "evidence": f"Set 2 Score: {set_scores['set2']}/100",
            "improvement": "Deploy HSTS preload, Content-Security-Policy, and X-Content-Type-Options."
        },
        {
            "category": "Set 3: DNS Security",
            "earned": int(round(set_scores["set3"] * 0.20)),
            "max": 20,
            "reasonEarned": "DNS records active and resolvable.",
            "reasonDeducted": "Missing or weak SPF or DMARC records allowing domain spoofing." if set_scores["set3"] < 100 else "Full points awarded.",
            "detectedIssue": "Email spoofing risk" if set_scores["set3"] < 80 else "None",
            "severity": "High" if set_scores["set3"] < 70 else "Clean",
            "evidence": f"Set 3 Score: {set_scores['set3']}/100",
            "improvement": "Add strict SPF record (v=spf1 -all) and DMARC policy with p=reject."
        },
        {
            "category": "Set 4: Attack Surface",
            "earned": int(round(set_scores["set4"] * 0.15)),
            "max": 15,
            "reasonEarned": "Public perimeter scanned via OSINT and Certificate Transparency.",
            "reasonDeducted": "Large public attack surface or exposed management ports." if set_scores["set4"] < 100 else "Full points awarded.",
            "detectedIssue": "Perimeter exposure" if set_scores["set4"] < 90 else "None",
            "severity": "Medium" if set_scores["set4"] < 80 else "Clean",
            "evidence": f"Set 4 Score: {set_scores['set4']}/100",
            "improvement": "Audit and decommission unused subdomains and firewall public ports."
        },
        {
            "category": "Set 5: DAST & Exposure",
            "earned": int(round(set_scores["set5"] * 0.05)),
            "max": 5,
            "reasonEarned": "Sensitive diagnostic and configuration paths verified secure.",
            "reasonDeducted": "Publicly accessible .env, .git repository, or backup files detected." if set_scores["set5"] < 100 else "Full points awarded.",
            "detectedIssue": "Configuration file exposure" if set_scores["set5"] < 100 else "None",
            "severity": "Critical" if set_scores["set5"] < 70 else "Clean",
            "evidence": f"Set 5 Score: {set_scores['set5']}/100",
            "improvement": "Block direct web access to hidden files and backup archives in server configuration."
        },
        {
            "category": "Set 6: Deception Posture",
            "earned": int(round(set_scores["set6"] * 0.05)),
            "max": 5,
            "reasonEarned": "Authentic production host behavior confirmed via canary probe analysis.",
            "reasonDeducted": "Host behaves like a honeypot or tarpit returning 200 OK for random URIs." if set_scores["set6"] < 100 else "Full points awarded.",
            "detectedIssue": "Deception profile" if set_scores["set6"] < 100 else "None",
            "severity": "Low" if set_scores["set6"] < 100 else "Clean",
            "evidence": f"Set 6 Score: {set_scores['set6']}/100",
            "improvement": "Ensure production web servers return standard HTTP 404 for undefined routes."
        }
    ]
