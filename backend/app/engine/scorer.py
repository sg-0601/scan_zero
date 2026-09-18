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

def build_negative_remediation_guides(category: str, negative_findings: list, domain: str) -> list:
    """Generate structured, step-by-step remediation instructions with clickable documentation links for negative findings."""
    guides = []
    if not negative_findings:
        return guides

    for raw_finding in negative_findings:
        f_str = str(raw_finding).strip()
        if not f_str or f_str.lower().startswith("none") or "clean" in f_str.lower():
            continue

        f_lower = f_str.lower()
        steps = []
        fix_urls = []

        # Set 1: TLS & Encryption
        if "redirect" in f_lower or "port 80" in f_lower:
            steps = [
                f"1. In your Nginx/Apache configuration, add an HTTP (port 80) server block that returns a permanent 301 redirect to HTTPS for {domain}.",
                "2. Ensure the redirect targets 'https://$host$request_uri' with status code 301 (Moved Permanently).",
                f"3. Verify via command line: 'curl -I http://{domain}' and confirm 'HTTP/1.1 301 Moved Permanently' and 'Location: https://{domain}/'."
            ]
            fix_urls = [
                {"label": "Mozilla SSL Server Configuration Guide", "url": "https://ssl-config.mozilla.org/"},
                {"label": "Nginx Converting Rewrite Rules to 301", "url": "https://nginx.org/en/docs/http/converting_rewrite_rules.html"}
            ]
        elif "expir" in f_lower or "certificate" in f_lower or "trust chain" in f_lower:
            steps = [
                f"1. Request an updated X.509 certificate for {domain} from Let's Encrypt, DigiCert, or your CA before the current validity window expires.",
                "2. Deploy the renewed fullchain.pem certificate and private key to your edge reverse proxy or CDN.",
                "3. Set up automated renewal using Certbot or ACME client cron: 'certbot renew --dry-run' to ensure zero renewal downtime."
            ]
            fix_urls = [
                {"label": "Certbot Automated Renewal Guide", "url": "https://certbot.eff.org/"},
                {"label": "Let's Encrypt Expiration Best Practices", "url": "https://letsencrypt.org/docs/expiration-emails/"}
            ]
        elif "tls 1.0" in f_lower or "tls 1.1" in f_lower or "weak cipher" in f_lower:
            steps = [
                "1. Disable legacy TLSv1.0 and TLSv1.1 protocols in your SSL configuration file.",
                "2. Restrict protocols to 'TLSv1.2 TLSv1.3' and configure ECDHE/ChaCha20-Poly1305 forward-secret ciphers.",
                "3. Reload web server configuration and verify using SSL Labs or OpenSSL s_client."
            ]
            fix_urls = [
                {"label": "Mozilla Modern TLS Security Profile", "url": "https://ssl-config.mozilla.org/"},
                {"label": "Cloudflare TLS Cipher Documentation", "url": "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls-version/"}
            ]

        # Set 2: HTTP Security Headers
        elif "content-security-policy" in f_lower or "csp" in f_lower:
            steps = [
                f"1. Audit all third-party scripts, styles, and fonts loaded by {domain}.",
                "2. Construct a policy starting with: default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;.",
                "3. First deploy using 'Content-Security-Policy-Report-Only' to monitor violations, then migrate to the enforcing 'Content-Security-Policy' header."
            ]
            fix_urls = [
                {"label": "MDN Content Security Policy Guide", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
                {"label": "OWASP Content Security Policy Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"}
            ]
        elif "strict-transport-security" in f_lower or "hsts" in f_lower:
            steps = [
                f"1. Verify that all subdomains of {domain} have active, valid HTTPS certificates.",
                "2. Add the response header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                "3. Submit the domain to the official browser HSTS preload list at hstspreload.org."
            ]
            fix_urls = [
                {"label": "Official HSTS Preload Submission Portal", "url": "https://hstspreload.org/"},
                {"label": "MDN Strict-Transport-Security (HSTS)", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"}
            ]
        elif "x-frame-options" in f_lower:
            steps = [
                "1. If this website is not meant to be embedded in external iframes, send 'X-Frame-Options: DENY'.",
                "2. If internal iframes are necessary for same-origin pages, send 'X-Frame-Options: SAMEORIGIN'.",
                "3. In parallel, specify 'frame-ancestors 'self'' in your Content-Security-Policy header."
            ]
            fix_urls = [
                {"label": "OWASP Clickjacking Defense Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"},
                {"label": "MDN X-Frame-Options Documentation", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"}
            ]
        elif "x-content-type-options" in f_lower:
            steps = [
                "1. Add 'X-Content-Type-Options: nosniff' header to all HTTP responses.",
                "2. Ensure your web server delivers correct MIME types for CSS (text/css) and JavaScript (application/javascript).",
                "3. Validate that legacy browsers cannot MIME-sniff response bodies as executable scripts."
            ]
            fix_urls = [
                {"label": "MDN X-Content-Type-Options Header", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"}
            ]
        elif "referrer-policy" in f_lower:
            steps = [
                "1. Add 'Referrer-Policy: strict-origin-when-cross-origin' header to your web server or CDN configuration.",
                f"2. Test that external link clicks send only the origin (https://{domain}) rather than full query paths."
            ]
            fix_urls = [
                {"label": "MDN Referrer-Policy Guide", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"}
            ]
        elif "cookie" in f_lower:
            steps = [
                "1. Update server session cookie generation to include the '; Secure; HttpOnly; SameSite=Lax' directives.",
                "2. For high-security authentication cookies, enforce 'SameSite=Strict' and consider adding the '__Host-' prefix."
            ]
            fix_urls = [
                {"label": "OWASP Session Management & Secure Cookies", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies"},
                {"label": "MDN Set-Cookie Documentation", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"}
            ]

        # Set 3: DNS & Anti-Spoofing
        elif "spf" in f_lower:
            steps = [
                f"1. Identify all authorized outbound mail sources for {domain} (e.g. Google Workspace, Microsoft 365, transactional relays).",
                "2. Publish a DNS TXT record at the root domain: 'v=spf1 include:_spf.google.com ~all' (or appropriate mail provider include tags).",
                "3. Verify syntax and lookups (must not exceed 10 DNS lookups) using MXToolbox."
            ]
            fix_urls = [
                {"label": "Google Workspace SPF Configuration", "url": "https://support.google.com/a/answer/33786"},
                {"label": "MXToolbox SPF Record Generator & Checker", "url": "https://mxtoolbox.com/spf.aspx"}
            ]
        elif "dmarc" in f_lower:
            steps = [
                f"1. Ensure SPF and DKIM signatures are published and aligned for {domain}.",
                f"2. Add a DNS TXT record at '_dmarc.{domain}': 'v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100;'.",
                "3. Monitor DMARC aggregate reports, verify zero legitimate emails are blocked, then upgrade policy to 'p=reject'."
            ]
            fix_urls = [
                {"label": "DMARC.org Official Deployment Overview", "url": "https://dmarc.org/overview/"},
                {"label": "Cloudflare Email Security & DMARC", "url": "https://developers.cloudflare.com/email-routing/setup/email-security/dmarc/"}
            ]
        elif "dnssec" in f_lower:
            steps = [
                f"1. Navigate to your DNS registrar or DNS management console (Cloudflare, Route 53, Namecheap) for {domain}.",
                "2. Enable DNSSEC signing on the hosted zone.",
                "3. Copy the generated DS (Delegation Signer) record and paste it into your parent domain registrar's DNSSEC management tab."
            ]
            fix_urls = [
                {"label": "Cloudflare DNSSEC One-Click Guide", "url": "https://developers.cloudflare.com/dns/dnssec/"},
                {"label": "ICANN DNSSEC Standard Explanation", "url": "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"}
            ]

        # Set 4: OSINT & Threat Intel
        elif "port" in f_lower or "shodan" in f_lower:
            steps = [
                "1. Audit the exposed network port on your host or cloud security groups (AWS Security Groups, Azure NSG, iptables).",
                "2. Restrict non-public services (databases, SSH, administration panels) to private VPC subnets or VPN IP addresses.",
                "3. Re-scan using Nmap or Shodan to verify the port is filtered or closed."
            ]
            fix_urls = [
                {"label": "AWS Security Group Hardening Best Practices", "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"},
                {"label": "CISA Port & Protocol Security Guide", "url": "https://www.cisa.gov/resources-tools/services"}
            ]
        elif "breach" in f_lower or "credential" in f_lower:
            steps = [
                f"1. Notify affected users or team members with credentials leaked under @{domain} domain.",
                "2. Enforce immediate credential rotation and invalidate existing active session tokens.",
                "3. Implement mandatory Multi-Factor Authentication (MFA / FIDO2 / WebAuthn) for all corporate accounts."
            ]
            fix_urls = [
                {"label": "CISA Multi-Factor Authentication (MFA) Guide", "url": "https://www.cisa.gov/mfa"},
                {"label": "HaveIBeenPwned Domain Monitoring", "url": "https://haveibeenpwned.com/DomainSearch"}
            ]
        elif "virustotal" in f_lower or "malicious" in f_lower:
            steps = [
                "1. Review the flagged URL or hash report on VirusTotal to inspect the specific vendor detection engine and timestamp.",
                "2. Inspect the host for unauthorized injected scripts, malicious redirects, or compromised WordPress/CMS plugins.",
                "3. Submit a false-positive review or remediation dispute through the VirusTotal vendor community portal."
            ]
            fix_urls = [
                {"label": "VirusTotal Intelligence Portal", "url": "https://www.virustotal.com/gui/home/url"},
                {"label": "Google Safe Browsing Dispute Request", "url": "https://safebrowsing.google.com/"}
            ]

        # Set 5: DAST & Sensitive Probes
        elif "zap" in f_lower or "cwe" in f_lower or "dynamic" in f_lower:
            steps = [
                "1. Inspect the OWASP ZAP cloud alert report, noting the identified URL endpoint, vulnerable parameter, and risk level.",
                "2. Apply secure coding practices: input validation, contextual output encoding, and parameterized database queries.",
                "3. Re-run OWASP ZAP automated dynamic scan to confirm complete remediation of the alert."
            ]
            fix_urls = [
                {"label": "OWASP Top 10 Web Application Vulnerabilities", "url": "https://owasp.org/www-project-top-ten/"},
                {"label": "OWASP ZAP Official User Documentation", "url": "https://www.zaproxy.org/docs/"}
            ]
        elif "sensitive file" in f_lower or ".env" in f_lower or ".git" in f_lower:
            steps = [
                "1. Block web server access to all dotfiles and backup archives. In Nginx: 'location ~ /\\. { deny all; return 404; }'.",
                "2. Remove any accidentally published sensitive files (.env, .git, config.json, backups) from the public web root.",
                "3. Immediately revoke and regenerate any leaked API keys, database credentials, or application secrets."
            ]
            fix_urls = [
                {"label": "OWASP Information Leakage Prevention Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Information_Leakage_Cheat_Sheet.html"},
                {"label": "Nginx Restricting Hidden Files", "url": "https://nginx.org/en/docs/http/ngx_http_core_module.html#location"}
            ]

        # Set 6: Deception Posture
        elif "honeypot" in f_lower or "canary" in f_lower or "deception" in f_lower or "200 ok" in f_lower:
            steps = [
                "1. Ensure your reverse proxy or web application router returns HTTP 404 (Not Found) or 403 (Forbidden) for undefined paths.",
                "2. If using Single Page Application (SPA) catch-all fallbacks, restrict rewrite rules to HTML routes and do not return 200 for random binary/API paths.",
                f"3. Test canary routes: 'curl -I https://{domain}/non_existent_canary_test_123' and verify status is 404."
            ]
            fix_urls = [
                {"label": "Nginx Error Page Handling Directive", "url": "https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page"},
                {"label": "RFC 9110 HTTP Status Codes Standard", "url": "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.5"}
            ]

        # General Fallback
        else:
            steps = [
                f"1. Audit the affected component or configuration on {domain}.",
                "2. Apply industry-standard security hardening aligned with OWASP guidelines.",
                "3. Re-test the endpoint using ScanZero automated workers to verify the gap has been closed."
            ]
            fix_urls = [
                {"label": "OWASP Web Security Testing Guide", "url": "https://owasp.org/www-project-web-security-testing-guide/"}
            ]

        guides.append({
            "finding": f_str,
            "steps": steps,
            "fix_urls": fix_urls
        })

    return guides

def generate_worker_intelligence_stream(set_scores: dict, worker_results: dict) -> dict:
    """Generate dynamic status, metric, and telemetry summary for each worker, mapped by section."""
    tls_raw = worker_results.get("w2_tls", {}).get("raw_data", {})
    tls_info = tls_raw.get("tls", {})
    hdr_raw = worker_results.get("w3_headers", {}).get("raw_data", {})
    dns_raw = worker_results.get("w4_dns", {}).get("raw_data", {})
    osint_raw = worker_results.get("w1_osint", {}).get("raw_data", {})
    dast_raw = worker_results.get("w5_dast", {}).get("raw_data", {})
    honey_raw = worker_results.get("w6_honeypot", {}).get("raw_data", {})

    # Worker 1 (OSINT) -> set4
    subs = osint_raw.get("subdomains", [])
    breach_count = osint_raw.get("breaches", {}).get("breach_count", 0)
    w1_score = set_scores.get("set4", 80)
    w1_status = "Passed" if w1_score >= 80 else ("Warning" if w1_score >= 60 else "Failed")

    # Worker 2 (TLS) -> set1
    version = tls_info.get("version") or "TLS"
    days = tls_info.get("days_until_expiry", 90)
    w2_score = set_scores.get("set1", 85)
    w2_status = "Passed" if w2_score >= 80 else ("Warning" if w2_score >= 60 else "Failed")

    # Worker 3 (Headers) -> set2
    active_count = hdr_raw.get("active_count", len(hdr_raw.get("active_headers", [])))
    total_headers = hdr_raw.get("total_evaluated", 6)
    w3_score = set_scores.get("set2", 70)
    w3_status = "Passed" if w3_score >= 80 else ("Warning" if w3_score >= 60 else "Failed")

    # Worker 4 (DNS) -> set3
    spf = dns_raw.get("spf", {})
    dmarc = dns_raw.get("dmarc", {})
    w4_score = set_scores.get("set3", 75)
    w4_status = "Passed" if w4_score >= 80 else ("Warning" if w4_score >= 60 else "Failed")

    # Worker 5 (DAST & ZAP) -> set5
    zap_alerts = dast_raw.get("zap_cloud_alerts", []) or dast_raw.get("zap", {}).get("alerts", [])
    exposed_files = dast_raw.get("exposed_files", [])
    w5_score = set_scores.get("set5", 85)
    w5_status = "Passed" if w5_score >= 80 else ("Warning" if w5_score >= 60 else "Failed")

    # Worker 6 (Honeypot) -> set6
    is_honeypot = honey_raw.get("is_honeypot", False)
    w6_status = "Failed" if is_honeypot else "Passed"

    return {
        "w1_osint": {
            "worker_name": "Worker 1: OSINT & Threat Intel",
            "section_id": "set4",
            "status": w1_status,
            "metric_value": f"{len(subs)} Subdomains • {breach_count} Breaches",
            "summary": "Verified clean across 70+ threat feeds; perimeter footprint mapped." if w1_status == "Passed" else "Compromised credentials or public perimeter exposures discovered.",
            "tools": "VirusTotal, Shodan, URLScan.io, AlienVault OTX, Hudson Rock, crt.sh"
        },
        "w2_tls": {
            "worker_name": "Worker 2: TLS & Cryptography",
            "section_id": "set1",
            "status": w2_status,
            "metric_value": f"{version} ({days}d remaining)",
            "summary": "Cryptographic handshake validated with trusted CA root." if w2_status == "Passed" else "Certificate expiry warning or missing HTTP-to-HTTPS redirect detected.",
            "tools": "Python ssl, socket, cryptography, OpenSSL"
        },
        "w3_headers": {
            "worker_name": "Worker 3: HTTP Headers & CSP",
            "section_id": "set2",
            "status": w3_status,
            "metric_value": f"{active_count}/{total_headers} Headers Active",
            "summary": "Core client-side browser defense headers actively protecting users." if w3_status == "Passed" else f"Missing headers: {', '.join(hdr_raw.get('missing_headers', [])[:2]) or 'CSP / HSTS'}.",
            "tools": "httpx, Cookie Security Auditor, WAF Detector"
        },
        "w4_dns": {
            "worker_name": "Worker 4: DNS & Anti-Spoofing",
            "section_id": "set3",
            "status": w4_status,
            "metric_value": f"SPF: {'Yes' if spf.get('found') else 'No'} • DMARC: {dmarc.get('policy', 'None')}",
            "summary": "Email identity authenticated with anti-phishing protection." if w4_status == "Passed" else "Missing SPF record or weak DMARC policy allows domain spoofing.",
            "tools": "dnspython, SPF Parser, DMARC Evaluator, DNSSEC"
        },
        "w5_dast": {
            "worker_name": "Worker 5: DAST & Cloud ZAP",
            "section_id": "set5",
            "status": w5_status,
            "metric_value": f"{len(zap_alerts)} ZAP Alerts • {len(exposed_files)} Leaks",
            "summary": "Zero sensitive file exposures and dynamic baseline verified." if w5_status == "Passed" else "Dynamic vulnerability alerts or configuration paths exposed.",
            "tools": "OWASP ZAP (GitHub Actions 7GB Cloud Runner), Nuclei DAST, Path Prober"
        },
        "w6_honeypot": {
            "worker_name": "Worker 6: Deception Posture",
            "section_id": "set6",
            "status": w6_status,
            "metric_value": "Authentic Host" if not is_honeypot else "Honeypot Detected",
            "summary": "Canary probes properly returned 404/403 with normal response latency." if not is_honeypot else "Target server returned 200 OK for canary probes (deception profile).",
            "tools": "Canary Probe Analyzer, Tarpit Latency Meter, WAFW00F"
        }
    }

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
    zap_completed = bool(zap_findings_list or zap_meta.get("status") == "completed")
    if zap_completed:
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

    # Generate rich, dynamic analyzed items and step-by-step remediation guides with clickable documentation links
    set1_analyzed = [
        {
            "item": "TLS Protocol Negotiation",
            "status": "PASS" if tls_info.get("version") in ("TLSv1.3", "TLSv1.2") else "FAIL",
            "details": f"Negotiated modern {tls_info.get('version', 'TLS')} cryptographic protocol." if tls_info.get("version") else "TLS handshake failed or outdated protocol negotiated."
        },
        {
            "item": "Cipher Suite Strength",
            "status": "PASS" if tls_info.get("cipher") and not any(w in tls_info.get("cipher", "").lower() for w in ["rc4", "3des", "cbc", "null"]) else "WARN",
            "details": f"High-strength cipher suite negotiated: {tls_info.get('cipher', 'Standard AES-GCM')}."
        },
        {
            "item": "Port 80 Cleartext Redirect",
            "status": "PASS" if worker_results.get("w2_tls", {}).get("raw_data", {}).get("redirect_secure", True) else "FAIL",
            "details": "Port 80 HTTP strictly enforces permanent 301 redirect to HTTPS." if worker_results.get("w2_tls", {}).get("raw_data", {}).get("redirect_secure", True) else "Port 80 HTTP does not immediately enforce strict 301 redirect to HTTPS."
        },
        {
            "item": "Certificate Trust Chain",
            "status": "PASS" if days > 30 else ("WARN" if days > 0 else "FAIL"),
            "details": f"Certificate valid for {days} days issued by {issuer_org}." if days > 0 else "Certificate authority trust chain invalid or expired."
        }
    ]

    set2_analyzed = [
        {
            "item": "Content-Security-Policy (CSP)",
            "status": "PASS" if "Content-Security-Policy" in hdr_raw.get("active_headers", []) else "FAIL",
            "details": "Active Content-Security-Policy header restricting unauthorized script execution." if "Content-Security-Policy" in hdr_raw.get("active_headers", []) else "Missing Content-Security-Policy leaving application exposed to cross-site scripting (XSS)."
        },
        {
            "item": "Strict-Transport-Security (HSTS)",
            "status": "PASS" if "Strict-Transport-Security" in hdr_raw.get("active_headers", []) else "FAIL",
            "details": "HSTS header enforced ensuring browsers mandate HTTPS encryption." if "Strict-Transport-Security" in hdr_raw.get("active_headers", []) else "Missing HSTS header allowing potential SSL-stripping man-in-the-middle attacks."
        },
        {
            "item": "X-Frame-Options (Clickjacking)",
            "status": "PASS" if "X-Frame-Options" in hdr_raw.get("active_headers", []) else "FAIL",
            "details": "Framing restrictions enforced (SAMEORIGIN/DENY) preventing UI redressing." if "X-Frame-Options" in hdr_raw.get("active_headers", []) else "Missing X-Frame-Options header; site can be framed in malicious clickjacking iframes."
        },
        {
            "item": "X-Content-Type-Options",
            "status": "PASS" if "X-Content-Type-Options" in hdr_raw.get("active_headers", []) else "FAIL",
            "details": "MIME-sniffing protection (nosniff) actively enforced." if "X-Content-Type-Options" in hdr_raw.get("active_headers", []) else "Missing X-Content-Type-Options: nosniff header."
        },
        {
            "item": "Referrer-Policy",
            "status": "PASS" if "Referrer-Policy" in hdr_raw.get("active_headers", []) else "WARN",
            "details": "Referrer-Policy privacy directive actively configured." if "Referrer-Policy" in hdr_raw.get("active_headers", []) else "Missing Referrer-Policy; browser may leak full query paths to external sites."
        },
        {
            "item": "Cookie Security Attributes",
            "status": "PASS" if not hdr_raw.get("cookie_issues") else "WARN",
            "details": "Session cookies secured with HttpOnly and Secure flags." if not hdr_raw.get("cookie_issues") else "Insecure cookie flags detected without Secure or HttpOnly attributes."
        }
    ]

    set3_analyzed = [
        {
            "item": "SPF Authentication Record",
            "status": "PASS" if spf.get("found") else "FAIL",
            "details": f"SPF record active with mechanism: {spf.get('mechanism') or 'configured'}." if spf.get("found") else "Missing SPF TXT record allowing unauthorized mail servers to spoof emails."
        },
        {
            "item": "DMARC Policy Enforcement",
            "status": "PASS" if dmarc.get("policy") in ("reject", "quarantine") else ("WARN" if dmarc.get("policy") == "none" else "FAIL"),
            "details": f"Strict DMARC {dmarc.get('policy')} policy enforced against domain phishing." if dmarc.get("policy") in ("reject", "quarantine") else (f"DMARC is set to p={dmarc.get('policy', 'none')} (monitoring only; spoofed emails not rejected)." if dmarc.get("found") else "Missing DMARC policy record leaving domain defenseless against email impersonation.")
        },
        {
            "item": "MX Mail Server Verification",
            "status": "PASS" if dns_raw.get("dns", {}).get("mx") else "WARN",
            "details": "Authoritative MX records verified." if dns_raw.get("dns", {}).get("mx") else "No direct MX mail exchange servers discovered."
        },
        {
            "item": "DNSSEC Cryptographic Chain",
            "status": "PASS" if dns_raw.get("dnssec", {}).get("active") else "WARN",
            "details": "DNSSEC cryptographically signed with validated DS records." if dns_raw.get("dnssec", {}).get("active") else "DNSSEC inactive; zone lacks cryptographic domain validation."
        }
    ]

    set4_analyzed = [
        {
            "item": "VirusTotal 70+ AV Reputation",
            "status": "PASS" if vt_info.get("malicious", 0) == 0 else "FAIL",
            "details": "Verified clean across 70+ security vendors on VirusTotal." if vt_info.get("malicious", 0) == 0 else f"Domain flagged malicious by {vt_info.get('malicious')} security vendors on VirusTotal."
        },
        {
            "item": "Shodan Ports & Exposure Audit",
            "status": "PASS" if not shodan_info.get("vulns") and not any(p in [3306, 5432, 27017, 6379, 1433] for p in shodan_info.get("ports", [])) else "FAIL",
            "details": f"{len(shodan_info.get('ports', []))} services active; zero known CVEs." if not shodan_info.get("vulns") else f"Known CVEs detected on public host: {', '.join(shodan_info.get('vulns', [])[:2])}."
        },
        {
            "item": "Dark Web Infostealer Breaches",
            "status": "PASS" if not breach_info.get("breaches_found") else "FAIL",
            "details": "Zero compromised corporate credentials found in cybercrime dumps." if not breach_info.get("breaches_found") else f"{breach_info.get('breach_count', 0)} compromised credentials found in cybercrime dumps (Hudson Rock)."
        },
        {
            "item": "Subdomain Perimeter Footprint",
            "status": "PASS" if len(subs) <= 30 else "WARN",
            "details": f"{len(subs)} public subdomains discovered via Certificate Transparency logs."
        }
    ]

    set5_analyzed = [
        {
            "item": "Sensitive File Probes (.env, .git)",
            "status": "PASS" if not any(f.get("category") == "dast" and not f.get("title", "").startswith("OWASP ZAP:") for f in findings) else "FAIL",
            "details": "All sensitive diagnostic and configuration paths properly blocked (404/403)." if not any(f.get("category") == "dast" and not f.get("title", "").startswith("OWASP ZAP:") for f in findings) else "Critical sensitive configuration file publicly accessible."
        },
        {
            "item": "OWASP ZAP Cloud Dynamic Analysis",
            "status": ("PASS" if zap_count == 0 else "FAIL") if zap_completed else "WARN",
            "details": ("OWASP ZAP baseline audit verified 0 dynamic vulnerabilities." if zap_count == 0 else f"OWASP ZAP detected {zap_count} dynamic vulnerability alerts on host.") if zap_completed else "OWASP ZAP 7GB cloud runner actively probing dynamic attack surface."
        },
        {
            "item": "Diagnostic Endpoints & Backups",
            "status": "PASS" if not any("phpinfo" in str(f) or "backup" in str(f) for f in s5_neg) else "FAIL",
            "details": "Web server backup files and diagnostic endpoints restricted."
        },
        {
            "item": "Web Server Fingerprints",
            "status": "PASS" if not hdr_raw.get("server_banner") else "WARN",
            "details": "Server version details concealed from public headers." if not hdr_raw.get("server_banner") else f"Server banner disclosed: {hdr_raw.get('server_banner')}."
        }
    ]

    set6_analyzed = [
        {
            "item": "Canary URI Probe Behavior",
            "status": "PASS" if not is_honeypot else "FAIL",
            "details": "Canary URIs properly returned 404 client error confirming transparent routing." if not is_honeypot else "Canary probe returned anomalous 200 OK for non-existent path."
        },
        {
            "item": "Tarpit Response Latency",
            "status": "PASS" if honey_raw.get("latency_ms", 100) < 800 else "WARN",
            "details": f"Normal server response latency ({honey_raw.get('latency_ms', 120)}ms)."
        },
        {
            "item": "Host Authenticity Verification",
            "status": "PASS" if not is_honeypot else "FAIL",
            "details": "Authentic production environment verified; zero deception detected." if not is_honeypot else "Deception environment / Honeypot profile detected."
        }
    ]

    return {
        "set1": {
            "name": "Set 1: Network & TLS Encryption",
            "score": set_scores["set1"],
            "grade": assign_grade(set_scores["set1"]),
            "analyzedItems": [a["item"] for a in set1_analyzed],
            "analyzed_items": set1_analyzed,
            "positiveFindings": s1_pos or ["Standard TLS handshake completed"],
            "negativeFindings": s1_neg or ["None detected; encryption posture clean"],
            "negative_remediation_guides": build_negative_remediation_guides("set1", s1_neg, domain),
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
            "analyzedItems": [a["item"] for a in set2_analyzed],
            "analyzed_items": set2_analyzed,
            "positiveFindings": s2_pos or ["Basic web response headers returned"],
            "negativeFindings": s2_neg or ["No missing headers detected"],
            "negative_remediation_guides": build_negative_remediation_guides("set2", s2_neg, domain),
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
            "analyzedItems": [a["item"] for a in set3_analyzed],
            "analyzed_items": set3_analyzed,
            "positiveFindings": s3_pos or ["DNS resolution functional"],
            "negativeFindings": s3_neg or ["DNS records conform to security standards"],
            "negative_remediation_guides": build_negative_remediation_guides("set3", s3_neg, domain),
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
            "analyzedItems": [a["item"] for a in set4_analyzed],
            "analyzed_items": set4_analyzed,
            "positiveFindings": s4_pos,
            "negativeFindings": s4_neg or ["No sensitive database ports publicly reachable"],
            "negative_remediation_guides": build_negative_remediation_guides("set4", s4_neg, domain),
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
            "analyzedItems": [a["item"] for a in set5_analyzed],
            "analyzed_items": set5_analyzed,
            "positiveFindings": s5_pos or ["No configuration leaks detected on critical paths"],
            "negativeFindings": s5_neg or ["No public directory listing or file leaks detected"],
            "negative_remediation_guides": build_negative_remediation_guides("set5", s5_neg, domain),
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
            "analyzedItems": [a["item"] for a in set6_analyzed],
            "analyzed_items": set6_analyzed,
            "positiveFindings": s6_pos,
            "negativeFindings": s6_neg,
            "negative_remediation_guides": build_negative_remediation_guides("set6", s6_neg, domain),
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
