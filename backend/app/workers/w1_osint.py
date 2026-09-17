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

        # 1. Subdomain Enumeration (crt.sh & Subfinder)
        subdomains = await self.subdomain_enum(domain)
        raw_data["subdomains"] = subdomains
        if len(subdomains) > 20:
            findings.append({
                "title": "Large Attack Surface Discovered",
                "description": f"Found {len(subdomains)} public subdomains for {domain}. Staging/internal environments should be isolated behind a VPN.",
                "severity": "medium",
                "evidence": {"subdomain_count": len(subdomains), "sample": subdomains[:5]}
            })

        # 2. Shodan Infrastructure & Port Audit
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

        # 3. Censys Cloud & Certificate Audit
        censys_data = await self.censys_lookup(domain)
        raw_data["censys"] = censys_data
        if censys_data and censys_data.get("services"):
            raw_data["cloud_services"] = censys_data.get("services")

        # 4. Dark Web & Breach Intel (HIBP)
        breach_data = await self.check_breaches(domain)
        raw_data["breaches"] = breach_data
        if breach_data and breach_data.get("breaches_found"):
            findings.append({
                "title": "Dark Web / Credential Breach Matches Found",
                "description": f"Domain {domain} was identified in known compromised database dumps.",
                "severity": "high",
                "evidence": breach_data
            })

        # 5. GitHub Leaked Secrets Check
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
        """Query Certificate Transparency logs for public subdomains."""
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
        """Query Shodan API for open ports, OS, and vulnerabilities."""
        if not settings.SHODAN_API_KEY:
            return {"status": "skipped", "reason": "No SHODAN_API_KEY provided."}

        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            
            api = shodan.Shodan(settings.SHODAN_API_KEY)
            host = await loop.run_in_executor(None, api.host, ip)
            return {
                "ip": host.get("ip_str"),
                "os": host.get("os", "Unknown"),
                "ports": host.get("ports", []),
                "vulns": list(host.get("vulns", {}).keys()) if isinstance(host.get("vulns"), dict) else host.get("vulns", [])
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def censys_lookup(self, domain: str) -> dict:
        """Query Censys Search API for cloud assets."""
        if not settings.CENSYS_API_ID or not settings.CENSYS_API_SECRET:
            return {"status": "skipped", "reason": "No CENSYS_API_ID provided."}

        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            auth = (settings.CENSYS_API_ID, settings.CENSYS_API_SECRET)
            
            async with httpx.AsyncClient(auth=auth, timeout=8.0) as client:
                resp = await client.get(f"https://search.censys.io/api/v2/hosts/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    services = [s.get("service_name") for s in data.get("result", {}).get("services", []) if s.get("service_name")]
                    return {"services": services, "autonomous_system": data.get("result", {}).get("autonomous_system", {})}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        return {"status": "no_data"}

    async def check_breaches(self, domain: str) -> dict:
        """Query Have I Been Pwned API if key is provided, or check breach indices."""
        if not settings.HIBP_API_KEY:
            return {"status": "skipped", "reason": "No HIBP_API_KEY provided."}

        try:
            headers = {
                "hibp-api-key": settings.HIBP_API_KEY,
                "user-agent": "ScanZero-Scanner"
            }
            async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
                resp = await client.get(f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}")
                if resp.status_code == 200:
                    breaches = resp.json()
                    return {
                        "breaches_found": len(breaches) > 0,
                        "breach_count": len(breaches),
                        "breaches": [b.get("Name") for b in breaches]
                    }
        except Exception as e:
            return {"status": "error", "error": str(e)}
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
