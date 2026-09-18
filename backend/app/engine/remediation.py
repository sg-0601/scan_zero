def generate_fixes(findings: list) -> list:
    """Generate specific, copy-paste ready remediation code for each security finding."""
    for f in findings:
        title = f.get("title", "").lower()
        desc = f.get("description", "").lower()
        cat = f.get("category", "").lower()
        evidence = f.get("evidence", {})
        
        # 1. HSTS
        if "strict-transport-security" in title or "hsts" in title:
            f["remediation_text"] = "Add HTTP Strict-Transport-Security (HSTS) with a 1-year max-age and preload parameter."
            f["remediation_code"] = (
                "# Nginx:\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n"
                "# Apache (.htaccess / httpd.conf):\n"
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
            )
            f["remediation_type"] = "nginx"

        # 2. CSP (Content-Security-Policy)
        elif "content-security-policy" in title or "csp" in title:
            f["remediation_text"] = "Deploy a Content-Security-Policy restricting scripts to self and trusted origins."
            f["remediation_code"] = (
                "# Nginx:\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'self';\" always;\n\n"
                "# Apache:\n"
                "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline'; frame-ancestors 'self';\""
            )
            f["remediation_type"] = "nginx"

        # 3. X-Frame-Options (Clickjacking)
        elif "x-frame-options" in title or "clickjacking" in title:
            f["remediation_text"] = "Set X-Frame-Options to SAMEORIGIN or DENY to prevent iframe embedding clickjacking attacks."
            f["remediation_code"] = (
                "# Nginx:\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;\n\n"
                "# Apache:\n"
                "Header always set X-Frame-Options \"SAMEORIGIN\""
            )
            f["remediation_type"] = "nginx"

        # 4. X-Content-Type-Options
        elif "x-content-type-options" in title or "nosniff" in title:
            f["remediation_text"] = "Set X-Content-Type-Options: nosniff to stop browsers from MIME-sniffing away from declared types."
            f["remediation_code"] = (
                "# Nginx:\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n\n"
                "# Apache:\n"
                "Header always set X-Content-Type-Options \"nosniff\""
            )
            f["remediation_type"] = "nginx"

        # 5. Referrer-Policy
        elif "referrer-policy" in title:
            f["remediation_text"] = "Enforce Referrer-Policy strict-origin-when-cross-origin to protect sensitive URLs."
            f["remediation_code"] = (
                "# Nginx:\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n"
                "# Apache:\n"
                "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
            )
            f["remediation_type"] = "nginx"

        # 6. Insecure Cookies
        elif "cookie" in title:
            f["remediation_text"] = "Add Secure, HttpOnly, and SameSite=Lax flags to all session and tracking cookies."
            f["remediation_code"] = (
                "# Set-Cookie response header standard format:\n"
                "Set-Cookie: session_id=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Lax;\n\n"
                "# Nginx proxy cookie flag modifier:\n"
                "proxy_cookie_flags ~* httponly secure samesite=lax;"
            )
            f["remediation_type"] = "nginx"

        # 7. SPF (Sender Policy Framework)
        elif "spf" in title:
            f["remediation_text"] = "Publish a strict SPF TXT record in your authoritative DNS zone to prevent spoofing."
            f["remediation_code"] = (
                "; DNS TXT Record (Replace mail.example.com with your authorized sending IP/MX):\n"
                "@    IN    TXT    \"v=spf1 mx a include:_spf.google.com ~all\""
            )
            f["remediation_type"] = "dns"

        # 8. DMARC
        elif "dmarc" in title:
            f["remediation_text"] = "Publish or upgrade your DMARC policy to p=quarantine or p=reject with aggregate reporting."
            f["remediation_code"] = (
                "; DNS TXT Record at _dmarc host:\n"
                "_dmarc    IN    TXT    \"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@yourdomain.com; pct=100; adkim=r; aspf=r\""
            )
            f["remediation_type"] = "dns"

        # 9. DNSSEC
        elif "dnssec" in title:
            f["remediation_text"] = "Enable DNSSEC signing in your DNS provider (Cloudflare, Route53, or registrar) and publish the DS record."
            f["remediation_code"] = (
                "# Enable DNSSEC in registrar/DNS provider:\n"
                "1. Turn on DNSSEC in DNS management panel (e.g. Cloudflare -> DNS -> Enable DNSSEC)\n"
                "2. Copy the DS Record Key Tag, Algorithm, and Digest to domain registrar"
            )
            f["remediation_type"] = "text"

        # 10. TLS / SSL Certificate Expiry / Deprecated TLS
        elif "tls" in title or "ssl" in title or "expired" in title:
            f["remediation_text"] = "Enforce modern TLS 1.2 and TLS 1.3 only, and automate certificate renewal via Certbot / ACME."
            f["remediation_code"] = (
                "# Nginx SSL Hardening Configuration:\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\n"
                "ssl_prefer_server_ciphers off;\n\n"
                "# Renew certificates automatically via Certbot:\n"
                "certbot renew --dry-run"
            )
            f["remediation_type"] = "nginx"

        # 11. Cleartext HTTP Redirect
        elif "cleartext" in title or "redirect" in title or "port 80" in title:
            f["remediation_text"] = "Configure port 80 to permanently redirect all requests to HTTPS with HTTP 301."
            f["remediation_code"] = (
                "# Nginx Port 80 Redirect:\n"
                "server {\n"
                "    listen 80 default_server;\n"
                "    server_name _;\n"
                "    return 301 https://$host$request_uri;\n"
                "}"
            )
            f["remediation_type"] = "nginx"

        # 12. Exposed Sensitive Files (.env, .git, etc.)
        elif "exposed" in title and (".env" in desc or ".git" in desc or "backup" in desc):
            f["remediation_text"] = "Block direct HTTP access to dotfiles (.env, .git) and server backups in web server configuration."
            f["remediation_code"] = (
                "# Nginx block rule for hidden files and backups:\n"
                "location ~ /\\.(?!well-known).* {\n"
                "    deny all;\n"
                "    access_log off;\n"
                "    log_not_found off;\n"
                "}\n"
                "location ~* \\.(bak|config|sql|tar|zip|gz)$ {\n"
                "    deny all;\n"
                "}"
            )
            f["remediation_type"] = "nginx"

        # 13. Sensitive Database / Management Ports Exposed
        elif "ports" in title or "port" in title:
            ports = evidence.get("exposed_ports", [3306, 5432, 27017, 6379, 22])
            f["remediation_text"] = f"Firewall exposed database/management ports ({ports}) using UFW / iptables or cloud security groups."
            f["remediation_code"] = (
                "# Linux UFW Firewall Rules:\n" +
                "\n".join([f"sudo ufw deny {p}/tcp  # Block external access to port {p}" for p in ports[:4]]) +
                "\n\n# Or allow only specific administrative jump host IP:\n"
                "sudo ufw allow from <TRUSTED_ADMIN_IP> to any port 22 proto tcp"
            )
            f["remediation_type"] = "shell"

        # 14. Known CVEs
        elif "cve" in title:
            cves = evidence.get("cves", [])
            f["remediation_text"] = f"Patch and update affected server services immediately for detected CVEs ({', '.join(cves[:3])})."
            f["remediation_code"] = (
                "# Update host OS packages:\n"
                "sudo apt-get update && sudo apt-get --only-upgrade install <package-name>\n"
                "# Or rebuild and update Docker base images:\n"
                "docker compose build --no-cache && docker compose up -d"
            )
            f["remediation_type"] = "shell"

        # 15. VirusTotal Malicious Classification
        elif "virustotal" in title or "malicious domain" in title:
            f["remediation_text"] = "Submit false positive dispute or clean infected web assets flagged by security vendors."
            f["remediation_code"] = (
                "# Verify web server for unauthorized injected webshells or phishing pages:\n"
                "find /var/www -type f -name '*.php' -exec grep -Hn 'eval(base64_decode' {} \\;\n\n"
                "# Submit domain dispute on VirusTotal: https://www.virustotal.com/gui/contact-us"
            )
            f["remediation_type"] = "shell"

        # 16. Dark Web / Infostealer Credential Leaks
        elif "breach" in title or "infostealer" in title or "leak" in title:
            f["remediation_text"] = "Enforce immediate password resets and mandate FIDO2 / TOTP Multi-Factor Authentication for all corporate accounts."
            f["remediation_code"] = (
                "# Action Checklist:\n"
                "1. Force enterprise-wide password reset for affected domain users.\n"
                "2. Enable mandatory Multi-Factor Authentication (MFA/2FA) on SSO and admin portals.\n"
                "3. Invalidate all active session tokens and refresh secrets."
            )
            f["remediation_type"] = "text"

        # 17. OWASP ZAP Dynamic Findings
        elif "owasp zap" in title or cat == "dast":
            zap_sol = f.get("solution") or "Review and address OWASP dynamic vulnerability alert."
            f["remediation_text"] = zap_sol[:200]
            f["remediation_code"] = (
                f"# OWASP ZAP Cloud Advisory:\n"
                f"# Title: {f.get('title')}\n"
                f"# Solution: {zap_sol}\n"
                f"# Reference CWE: {evidence.get('cweid', 'N/A')}"
            )
            f["remediation_type"] = "text"

        else:
            f["remediation_text"] = "Review server security configuration and follow OWASP best practices."
            f["remediation_code"] = (
                "# General Server Hardening Reference:\n"
                "# https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
            )
            f["remediation_type"] = "text"

    return findings
