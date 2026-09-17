import asyncio
import socket
import httpx
import shodan
import logging
from app.workers.base import BaseWorker
from app.config import settings

logger = logging.getLogger(__name__)

class OsintWorker(BaseWorker):
    name = "w1_osint"
    category = "osint"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        # -------------------------------------------------------------
        # Execute all 9 Threat & OSINT Engines in Parallel via asyncio.gather
        # -------------------------------------------------------------
        results = await asyncio.gather(
            self.subdomain_enum(domain),
            self.shodan_lookup(domain),
            self.virustotal_lookup(domain),
            self.urlscan_lookup(domain),
            self.leakcheck_lookup(domain),
            self.alienvault_otx_lookup(domain),
            self.check_breaches(domain),
            self.emailrep_lookup(domain),
            self.github_leak_check(domain),
            return_exceptions=True
        )

        (
            subdomains_res,
            shodan_res,
            vt_res,
            urlscan_res,
            leakcheck_res,
            otx_res,
            breach_res,
            emailrep_res,
            github_res
        ) = [r if not isinstance(r, Exception) else {} for r in results]

        # 1. Subdomains (crt.sh)
        subdomains = subdomains_res if isinstance(subdomains_res, list) else []
        raw_data["subdomains"] = subdomains
        if len(subdomains) > 20:
            findings.append({
                "title": "Large Attack Surface Discovered",
                "description": f"Found {len(subdomains)} public subdomains for {domain}. Staging or administrative subdomains should be protected behind zero-trust access.",
                "severity": "medium",
                "evidence": {"subdomain_count": len(subdomains), "sample": subdomains[:5]}
            })

        # 2. Shodan Infrastructure & Open Ports
        shodan_data = shodan_res if isinstance(shodan_res, dict) else {}
        raw_data["shodan"] = shodan_data
        if shodan_data.get("vulns"):
            findings.append({
                "title": "Exposed Known CVE Vulnerabilities (Shodan)",
                "description": f"Detected {len(shodan_data['vulns'])} publicly exploitable CVEs on this host.",
                "severity": "critical",
                "evidence": {"cves": shodan_data["vulns"], "ports": shodan_data.get("ports", [])}
            })
        elif shodan_data.get("ports") and any(p in [3306, 5432, 27017, 6379, 22, 1433, 9200] for p in shodan_data.get("ports", [])):
            exposed_db_ports = [p for p in shodan_data.get("ports", []) if p in [3306, 5432, 27017, 6379, 22, 1433, 9200]]
            findings.append({
                "title": "Sensitive Management / Database Ports Publicly Exposed",
                "description": f"Ports {exposed_db_ports} are reachable from the public internet without firewall restriction.",
                "severity": "high",
                "evidence": {"exposed_ports": exposed_db_ports}
            })

        # 3. VirusTotal Threat Intelligence (Censys Alternative)
        vt_data = vt_res if isinstance(vt_res, dict) else {}
        raw_data["virustotal"] = vt_data
        if vt_data.get("malicious", 0) > 0:
            findings.append({
                "title": "Malicious Domain Classification (VirusTotal)",
                "description": f"Domain {domain} is flagged as malicious or suspicious by {vt_data.get('malicious')} security vendors on VirusTotal.",
                "severity": "critical" if vt_data.get("malicious", 0) > 2 else "high",
                "evidence": {
                    "malicious_engines": vt_data.get("malicious"),
                    "suspicious_engines": vt_data.get("suspicious", 0),
                    "reputation": vt_data.get("reputation", 0)
                }
            })

        # 4. URLScan.io Passive Audit (IntelX Alternative)
        urlscan_data = urlscan_res if isinstance(urlscan_res, dict) else {}
        raw_data["urlscan"] = urlscan_data
        if urlscan_data.get("malicious"):
            findings.append({
                "title": "Threat Flagged by URLScan Community Audit",
                "description": f"URLScan analysis detected suspicious or malicious web behavior on {domain}.",
                "severity": "high",
                "evidence": urlscan_data
            })

        # 5. LeakCheck Credential Leak Intelligence (DeHashed Alternative)
        leakcheck_data = leakcheck_res if isinstance(leakcheck_res, dict) else {}
        raw_data["leakcheck"] = leakcheck_data
        if leakcheck_data.get("breaches_found"):
            findings.append({
                "title": "Compromised Credentials Detected (LeakCheck)",
                "description": f"Domain {domain} was found in {leakcheck_data.get('breach_count', 0)} compromised database dumps.",
                "severity": "high",
                "evidence": leakcheck_data
            })

        # 6. AlienVault OTX Threat Pulses (Censys / Asset Intelligence Alternative)
        otx_data = otx_res if isinstance(otx_res, dict) else {}
        raw_data["alienvault_otx"] = otx_data
        if otx_data.get("pulse_count", 0) > 0:
            findings.append({
                "title": "Active Threat Indicators in AlienVault OTX",
                "description": f"Domain {domain} has {otx_data.get('pulse_count')} reported threat pulses in AlienVault Open Threat Exchange.",
                "severity": "medium",
                "evidence": otx_data
            })

        # 7. Hudson Rock Cavalier Cybercrime & Infostealer Intel (HIBP Alternative - 100% Free)
        breach_data = breach_res if isinstance(breach_res, dict) else {}
        raw_data["breaches"] = breach_data
        if breach_data.get("breaches_found"):
            findings.append({
                "title": "Infostealer Malware Credential Compromise (Hudson Rock)",
                "description": (
                    f"Cybercrime logs confirm {breach_data.get('compromised_employees', 0)} employee accounts "
                    f"and {breach_data.get('compromised_users', 0)} user accounts compromised by infostealer malware."
                ),
                "severity": "high",
                "evidence": breach_data
            })

        # 8. EmailRep Domain Reputation
        emailrep_data = emailrep_res if isinstance(emailrep_res, dict) else {}
        raw_data["emailrep"] = emailrep_data
        if emailrep_data.get("suspicious"):
            findings.append({
                "title": "Domain Flagged as Suspicious by EmailRep",
                "description": f"EmailRep reputation engine flagged {domain} as suspicious with poor domain trust.",
                "severity": "medium",
                "evidence": emailrep_data
            })

        # 9. GitHub Leaked Secrets
        github_data = github_res if isinstance(github_res, dict) else {}
        raw_data["github"] = github_data
        if github_data.get("leaks_detected"):
            findings.append({
                "title": "Potential Leaked Secrets in Public GitHub Repositories",
                "description": f"Detected public code references matching {domain} containing potential API keys or database configs.",
                "severity": "critical",
                "evidence": {"total_matches": github_data.get("total_count", 0)}
            })

        return {"findings": findings, "raw_data": raw_data}

    # =========================================================================
    # Engine 1: Subdomain Enumeration (crt.sh - Zero Key)
    # =========================================================================
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
        except Exception as e:
            logger.debug(f"crt.sh lookup skipped: {e}")
        return []

    # =========================================================================
    # Engine 2: Shodan & InternetDB (Authenticated + Zero Key Fallback)
    # =========================================================================
    async def shodan_lookup(self, domain: str) -> dict:
        """Query Shodan API with free InternetDB fallback."""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)

            # 1. Try authenticated Shodan API Key if configured
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

    # =========================================================================
    # Engine 3: VirusTotal API v3 (World #1 Free Alternative to Censys)
    # Free Tier: 500 requests/day, 4 req/min, free at virustotal.com
    # =========================================================================
    async def virustotal_lookup(self, domain: str) -> dict:
        """Query Google VirusTotal API for multi-vendor domain security audit."""
        if not settings.VIRUSTOTAL_API_KEY:
            return {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY not configured"}

        try:
            headers = {
                "x-apikey": settings.VIRUSTOTAL_API_KEY,
                "User-Agent": "ScanZero-ThreatIntel"
            }
            async with httpx.AsyncClient(headers=headers, timeout=7.0) as client:
                resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}")
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "status": "success",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": data.get("reputation", 0),
                        "categories": data.get("categories", {}),
                        "popularity": data.get("popularity_ranks", {}),
                        "source": "VirusTotal API v3 (Free Tier)"
                    }
                elif resp.status_code in (401, 403):
                    logger.warning("VirusTotal API Key invalid or unverified")
                    return {"status": "skipped", "reason": "VirusTotal auth failed"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "no_data"}

    # =========================================================================
    # Engine 4: URLScan.io Deep Web Scanner (World #1 Free Alternative to IntelX)
    # Free Tier: 5,000 public searches/scans/month, free at urlscan.io
    # =========================================================================
    async def urlscan_lookup(self, domain: str) -> dict:
        """Query URLScan.io search API for deep passive web intelligence."""
        try:
            headers = {"User-Agent": "ScanZero-OSINT"}
            if settings.URLSCAN_API_KEY:
                headers["API-Key"] = settings.URLSCAN_API_KEY

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
                            "page_server": latest.get("page", {}).get("server", ""),
                            "source": "URLScan.io Intelligence (Free Engine)"
                        }
                    return {"status": "success", "total_scans": 0, "source": "URLScan.io"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "no_data"}

    # =========================================================================
    # Engine 5: LeakCheck API (Free Alternative to DeHashed)
    # Free tier available at leakcheck.io
    # =========================================================================
    async def leakcheck_lookup(self, domain: str) -> dict:
        """Query LeakCheck API for compromised domain databases."""
        if not settings.LEAKCHECK_API_KEY:
            return {"status": "skipped", "reason": "LEAKCHECK_API_KEY not configured"}

        try:
            headers = {
                "X-API-Key": settings.LEAKCHECK_API_KEY,
                "User-Agent": "ScanZero-Scanner"
            }
            async with httpx.AsyncClient(headers=headers, timeout=6.0) as client:
                resp = await client.get(f"https://leakcheck.io/api/v2/query/{domain}?type=domain")
                if resp.status_code == 200:
                    data = resp.json()
                    entries = data.get("result", [])
                    return {
                        "status": "success",
                        "breaches_found": len(entries) > 0,
                        "breach_count": len(entries),
                        "sources": [e.get("source") for e in entries[:5] if e.get("source")],
                        "source": "LeakCheck Breach Intelligence"
                    }
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "no_data"}

    # =========================================================================
    # Engine 6: AlienVault OTX (Open Threat Exchange - 100% Free Community)
    # Free at otx.alienvault.com
    # =========================================================================
    async def alienvault_otx_lookup(self, domain: str) -> dict:
        """Query AT&T AlienVault OTX for community threat pulses."""
        if not settings.OTX_API_KEY:
            return {"status": "skipped", "reason": "OTX_API_KEY not configured"}

        try:
            headers = {
                "X-OTX-API-KEY": settings.OTX_API_KEY,
                "User-Agent": "ScanZero-ThreatPulse"
            }
            async with httpx.AsyncClient(headers=headers, timeout=6.0) as client:
                resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    count = pulse_info.get("count", 0)
                    pulses = [p.get("name") for p in pulse_info.get("pulses", [])[:3] if p.get("name")]
                    return {
                        "status": "success",
                        "pulse_count": count,
                        "threat_pulses": pulses,
                        "alexa_rank": data.get("alexa", "Unknown"),
                        "source": "AlienVault OTX (Free Community)"
                    }
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "no_data"}

    # =========================================================================
    # Engine 7: Hudson Rock Cavalier (100% Free Infostealer & Breach Intel - HIBP Alternative)
    # Zero Key Required! Unrestricted research endpoint
    # =========================================================================
    async def check_breaches(self, domain: str) -> dict:
        """Query Hudson Rock Cybercrime Intelligence for infostealer malware compromises."""
        try:
            headers = {"User-Agent": "ScanZero-OSINT"}
            async with httpx.AsyncClient(headers=headers, timeout=5.0) as client:
                resp = await client.get(
                    f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    comp_employees = data.get("employees_compromised") or 0
                    comp_users = data.get("users_compromised") or 0
                    total = comp_employees + comp_users
                    return {
                        "breaches_found": total > 0,
                        "breach_count": total,
                        "compromised_employees": comp_employees,
                        "compromised_users": comp_users,
                        "source": "Hudson Rock Cybercrime Intelligence (Zero-Key Free)"
                    }
        except Exception as e:
            logger.debug(f"Hudson rock lookup failed: {e}")

        return {"breaches_found": False}

    # =========================================================================
    # Engine 8: EmailRep.io Domain Reputation (Zero Key Free)
    # =========================================================================
    async def emailrep_lookup(self, domain: str) -> dict:
        """Query EmailRep.io for domain reputation intelligence."""
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
                        "source": "EmailRep.io (Zero-Key Free)"
                    }
                elif resp.status_code == 429:
                    return {"status": "rate_limited", "source": "EmailRep.io"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "no_data"}

    # =========================================================================
    # Engine 9: GitHub Leaked Secrets & Config Search (Zero Key Free)
    # =========================================================================
    async def github_leak_check(self, domain: str) -> dict:
        """Search public GitHub repositories for potential leaked secrets mentioning domain."""
        try:
            headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "ScanZero-CodeAudit"}
            async with httpx.AsyncClient(headers=headers, timeout=5.0) as client:
                query = f'"{domain}" AND (password OR secret_key OR API_KEY)'
                resp = await client.get(f"https://api.github.com/search/code?q={query}")
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    return {"leaks_detected": total > 0, "total_count": total}
        except Exception:
            pass
        return {"leaks_detected": False}
