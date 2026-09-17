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

        # 3. Censys Cloud & Certificate Audit (New Censys Platform API)
        censys_data = await self.censys_lookup(domain)
        raw_data["censys"] = censys_data
        if censys_data and censys_data.get("services"):
            raw_data["cloud_services"] = censys_data.get("services")

        # 4. IntelX Free Tier Threat & OSINT Search
        intelx_data = await self.intelx_lookup(domain)
        raw_data["intelx"] = intelx_data
        if intelx_data and intelx_data.get("records_found", 0) > 0:
            raw_data["intelx_records"] = intelx_data.get("records_found")

        # 5. Dark Web & Breach Intel (HIBP & Hudson Rock)
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
                    # If key has no credits or rate-limits, fall through to free InternetDB
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

    async def censys_lookup(self, domain: str) -> dict:
        """Query new Censys Platform API using Bearer Token authentication."""
        if not settings.CENSYS_API_TOKEN:
            return {"status": "skipped", "reason": "No CENSYS_API_TOKEN provided."}

        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            
            headers = {
                "Authorization": f"Bearer {settings.CENSYS_API_TOKEN}",
                "User-Agent": "ScanZero-Scanner",
                "Accept": "application/json"
            }
            
            # Censys Platform Host Search API
            async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
                resp = await client.get(f"https://search.censys.io/api/v2/hosts/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    services = [s.get("service_name") for s in data.get("result", {}).get("services", []) if s.get("service_name")]
                    return {
                        "services": services,
                        "autonomous_system": data.get("result", {}).get("autonomous_system", {}),
                        "source": "Censys Platform API"
                    }
                elif resp.status_code in (401, 403):
                    return {"status": "skipped", "reason": f"Censys Platform API authorization notice (HTTP {resp.status_code})."}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        return {"status": "no_data"}

    async def intelx_lookup(self, domain: str) -> dict:
        """Query IntelX Free Tier API endpoint (https://free.intelx.io/) with x-key header."""
        if not settings.INTELX_API_KEY:
            return {"status": "skipped", "reason": "No INTELX_API_KEY provided."}

        try:
            base_url = "https://free.intelx.io/"
            search_url = f"{base_url}phonebook/search"
            headers = {
                "x-key": settings.INTELX_API_KEY,
                "User-Agent": "ScanZero-Scanner",
                "Content-Type": "application/json"
            }
            payload = {
                "term": domain,
                "maxresults": 20,
                "media": 0,
                "target": 1,
                "timeout": 5
            }

            async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
                resp = await client.post(search_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    search_id = data.get("id")
                    if search_id:
                        res_url = f"{base_url}phonebook/search/result?id={search_id}&limit=20"
                        res_resp = await client.get(res_url)
                        if res_resp.status_code == 200:
                            res_data = res_resp.json()
                            selectors = res_data.get("selectors", [])
                            return {
                                "status": "success",
                                "records_found": len(selectors),
                                "sample": [s.get("selectorvalue") for s in selectors[:5]],
                                "source": "IntelX Free Platform API"
                            }
                    return {"status": "success", "records_found": 0}
                elif resp.status_code in (401, 403):
                    return {"status": "skipped", "reason": f"IntelX Free API authorization notice (HTTP {resp.status_code})."}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        return {"status": "no_data"}

    async def check_breaches(self, domain: str) -> dict:
        """Query Have I Been Pwned API if key is provided, or check free breach intelligence."""
        # 1. HIBP with Key
        if settings.HIBP_API_KEY:
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
                            "breaches": [b.get("Name") for b in breaches],
                            "source": "Have I Been Pwned API"
                        }
            except Exception as e:
                return {"status": "error", "error": str(e)}

        # 2. Free Dark Web Breach Intelligence Fallback (Hudson Rock Cavalier API)
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
