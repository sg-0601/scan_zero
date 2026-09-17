import asyncio
import socket
import httpx
import shodan
from app.workers.base import BaseWorker
from app.config import settings

class OsintWorker(BaseWorker):
    name = "w1_osint"
    category = "osint"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        # 1. Subdomain Enumeration (crt.sh — 100% Free, No Key)
        subdomains = await self.subdomain_enum(domain)
        raw_data["subdomains"] = subdomains
        if len(subdomains) > 20:
            findings.append({
                "title": "Large Attack Surface Discovered",
                "description": f"Found {len(subdomains)} public subdomains for {domain}. Staging/internal environments should be isolated behind a VPN.",
                "severity": "medium",
                "evidence": {"subdomain_count": len(subdomains), "sample": subdomains[:5]}
            })

        # 2. Shodan Infrastructure & Port Audit (Free InternetDB fallback)
        shodan_data = await self.shodan_lookup(domain)
        raw_data["shodan"] = shodan_data
        if shodan_data and "vulns" in shodan_data and shodan_data["vulns"]:
            findings.append({
                "title": "Exposed Known CVE Vulnerabilities (Shodan)",
                "description": f"Shodan detected {len(shodan_data['vulns'])} publicly exploitable CVEs on this host.",
                "severity": "critical",
                "evidence": {"cves": shodan_data["vulns"], "ports": shodan_data.get("ports", [])}
            })
        elif shodan_data and "ports" in shodan_data and any(p in [3306, 5432, 27017, 6379, 22] for p in shodan_data.get("ports", [])):
            exposed_db_ports = [p for p in shodan_data.get("ports", []) if p in [3306, 5432, 27017, 6379, 22]]
            findings.append({
                "title": "Sensitive Management / Database Ports Publicly Exposed",
                "description": f"Ports {exposed_db_ports} are reachable from the public internet without firewall restriction.",
                "severity": "high",
                "evidence": {"exposed_ports": exposed_db_ports}
            })

        # 3. EmailRep Domain Reputation (100% Free, No Key)
        emailrep_data = await self.emailrep_lookup(domain)
        raw_data["emailrep"] = emailrep_data
        if emailrep_data.get("suspicious"):
            findings.append({
                "title": "Domain Flagged as Suspicious by EmailRep",
                "description": f"EmailRep reputation engine flagged {domain} as suspicious with low reputation score.",
                "severity": "medium",
                "evidence": emailrep_data
            })

        # 4. URLScan Passive Scan (100% Free, No Key for search)
        urlscan_data = await self.urlscan_lookup(domain)
        raw_data["urlscan"] = urlscan_data
        if urlscan_data.get("malicious"):
            findings.append({
                "title": "Domain Flagged as Malicious by URLScan Community",
                "description": f"URLScan.io community scans have flagged resources on {domain} as potentially malicious.",
                "severity": "high",
                "evidence": urlscan_data
            })

        # 5. Dark Web & Breach Intel (Hudson Rock Cavalier — 100% Free, No Key)
        breach_data = await self.check_breaches(domain)
        raw_data["breaches"] = breach_data
        if breach_data and breach_data.get("breaches_found"):
            findings.append({
                "title": "Dark Web / Credential Breach Matches Found",
                "description": f"Domain {domain} was identified in known compromised database dumps.",
                "severity": "high",
                "evidence": breach_data
            })

        # 6. GitHub Leaked Secrets Check (Free, No Key for basic search)
        github_data = await self.github_leak_check(domain)
        raw_data["github"] = github_data
        if github_data.get("leaks_detected"):
            findings.append({
                "title": "Potential Leaked Secrets in Public GitHub Repositories",
                "description": f"Detected public code references matching {domain} containing potential API keys or database configs.",
                "severity": "critical",
                "evidence": {"total_matches": github_data.get("total_count", 0)}
            })

        return {"findings": findings, "raw_data": raw_data}

    async def subdomain_enum(self, domain: str) -> list:
        """Query Certificate Transparency logs for public subdomains. (Free, No Key)"""
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub and "*" not in sub and domain in sub:
                                subdomains.add(sub)
                    return sorted(list(subdomains))
        except Exception:
            pass
        return []

    async def shodan_lookup(self, domain: str) -> dict:
        """Query Shodan API for open ports, OS, and vulnerabilities, with InternetDB fallback."""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            
            # 1. Try with authenticated Shodan API Key if configured
            if settings.SHODAN_API_KEY:
                try:
                    api = shodan.Shodan(settings.SHODAN_API_KEY)
                    host = await loop.run_in_executor(None, api.host, ip)
                    if host and host.get("ports"):
                        return {
                            "ip": host.get("ip_str", ip),
                            "os": host.get("os", "Unknown"),
                            "ports": host.get("ports", []),
                            "vulns": list(host.get("vulns", {}).keys()) if isinstance(host.get("vulns"), dict) else host.get("vulns", []),
                            "source": "Shodan API (Key Authenticated)"
                        }
                except Exception:
                    pass

            # 2. Free Shodan InternetDB Fallback (100% Free & Unlimited, No Key Required)
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(f"https://internetdb.shodan.io/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": data.get("ip", ip),
                        "ports": data.get("ports", []),
                        "vulns": data.get("cves", []),
                        "hostnames": data.get("hostnames", []),
                        "source": "Shodan InternetDB (Free Engine)"
                    }
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "skipped", "reason": "No host intelligence available"}

    async def emailrep_lookup(self, domain: str) -> dict:
        """Query EmailRep.io for domain reputation intelligence. (Free, No Key)"""
        try:
            email = f"info@{domain}"
            headers = {"User-Agent": "ScanZero-OSINT", "Accept": "application/json"}
            async with httpx.AsyncClient(headers=headers, timeout=5.0) as client:
                resp = await client.get(f"https://emailrep.io/{email}")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "status": "success",
                        "reputation": data.get("reputation", "unknown"),
                        "suspicious": data.get("suspicious", False),
                        "references": data.get("references", 0),
                        "details": {
                            "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                            "spam": data.get("details", {}).get("spam", False),
                            "data_breach": data.get("details", {}).get("data_breach", False),
                            "credentials_leaked": data.get("details", {}).get("credentials_leaked", False),
                        },
                        "source": "EmailRep.io (Free)"
                    }
                elif resp.status_code == 429:
                    return {"status": "rate_limited", "source": "EmailRep.io"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        return {"status": "no_data"}

    async def urlscan_lookup(self, domain: str) -> dict:
        """Query URLScan.io search API for passive intelligence. (Free, No Key for search)"""
        try:
            headers = {"User-Agent": "ScanZero-OSINT"}
            async with httpx.AsyncClient(headers=headers, timeout=6.0) as client:
                resp = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=3")
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    if results:
                        latest = results[0]
                        verdicts = latest.get("verdicts", {}).get("overall", {})
                        return {
                            "status": "success",
                            "total_scans": data.get("total", 0),
                            "malicious": verdicts.get("malicious", False),
                            "score": verdicts.get("score", 0),
                            "categories": verdicts.get("categories", []),
                            "latest_scan_url": latest.get("result", ""),
                            "page_title": latest.get("page", {}).get("title", ""),
                            "page_ip": latest.get("page", {}).get("ip", ""),
                            "source": "URLScan.io (Free)"
                        }
                    return {"status": "success", "total_scans": 0, "source": "URLScan.io (Free)"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        return {"status": "no_data"}

    async def check_breaches(self, domain: str) -> dict:
        """Check free breach intelligence via Hudson Rock Cavalier API. (Free, No Key)"""
        try:
            headers = {"User-Agent": "ScanZero-OSINT"}
            async with httpx.AsyncClient(headers=headers, timeout=4.0) as client:
                resp = await client.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}")
                if resp.status_code == 200:
                    data = resp.json()
                    comp_employees = data.get("employees_compromised") or 0
                    comp_users = data.get("users_compromised") or 0
                    total = comp_employees + comp_users
                    if total > 0:
                        return {
                            "breaches_found": True,
                            "breach_count": total,
                            "compromised_employees": comp_employees,
                            "compromised_users": comp_users,
                            "source": "Hudson Rock Cybercrime Intelligence (Free)"
                        }
        except Exception:
            pass

        return {"breaches_found": False}

    async def github_leak_check(self, domain: str) -> dict:
        """Search public GitHub repositories for potential leaked secrets mentioning domain."""
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            async with httpx.AsyncClient(headers=headers, timeout=6.0) as client:
                query = f'"{domain}" AND (password OR secret_key OR API_KEY)'
                resp = await client.get(f"https://api.github.com/search/code?q={query}")
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    return {"leaks_detected": total > 0, "total_count": total}
        except Exception:
            pass
        return {"leaks_detected": False}
