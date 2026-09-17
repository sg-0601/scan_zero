import asyncio
import subprocess
import shutil
import json
from app.workers.base import BaseWorker
from app.config import settings

class DastWorker(BaseWorker):
    name = "w5_dast"
    category = "dast"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        # 1. Native DAST Surface & Sensitive Path Probes
        native_dast = await self.probe_sensitive_paths(url)
        raw_data["probed_paths"] = native_dast

        for finding in native_dast.get("findings", []):
            findings.append(finding)

        # 2. Nuclei Scan (if binary available)
        nuclei_res = await self.nuclei_scan(url)
        raw_data["nuclei"] = nuclei_res
        
        for vuln in nuclei_res.get("vulnerabilities", []):
            findings.append({
                "title": f"Nuclei: {vuln.get('info', {}).get('name', 'Unknown')}",
                "description": vuln.get('info', {}).get('description', 'No description.'),
                "severity": vuln.get('info', {}).get('severity', 'info'),
                "evidence": {"template": vuln.get('template-id')}
            })

        # 3. OWASP ZAP Scan (if daemon running)
        zap_res = await self.zap_scan(url)
        raw_data["zap"] = zap_res
        if zap_res.get("status") == "connected" and zap_res.get("alerts"):
            for a in zap_res.get("alerts", [])[:5]:
                findings.append({
                    "title": f"OWASP ZAP: {a.get('alert', 'Vulnerability Detected')}",
                    "description": a.get('description', 'Detected by OWASP ZAP dynamic analysis.')[:200],
                    "severity": a.get('risk', 'Low').lower(),
                    "category": "dast",
                    "evidence": {"param": a.get('param'), "url": a.get('url')}
                })

        return {"findings": findings, "raw_data": raw_data}

    async def probe_sensitive_paths(self, base_url: str) -> dict:
        import httpx
        clean_url = base_url.rstrip("/")
        findings = []
        checks = [
            {"path": "/.env", "severity": "critical", "title": "Exposed Environment Configuration File (.env)", "desc": "Publicly accessible .env file containing potential database credentials or API secrets."},
            {"path": "/.git/HEAD", "severity": "critical", "title": "Exposed Git Repository Source (.git/HEAD)", "desc": "Publicly accessible .git folder allows complete extraction of application source code."},
            {"path": "/wp-config.php.bak", "severity": "high", "title": "Exposed Backup Configuration File", "desc": "Web server backup files exposed to direct HTTP requests."},
            {"path": "/phpinfo.php", "severity": "medium", "title": "Exposed PHP Diagnostics (phpinfo)", "desc": "Detailed server environment variables and internal IP addresses exposed."},
        ]

        checked_paths = {}
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=5.0) as client:
                for c in checks:
                    test_url = f"{clean_url}{c['path']}"
                    try:
                        resp = await client.get(test_url)
                        checked_paths[c["path"]] = resp.status_code
                        # Only flag if returns 200 with meaningful content
                        if resp.status_code == 200 and len(resp.content) > 5:
                            # Verify not a soft 404 HTML page
                            content_type = resp.headers.get("content-type", "").lower()
                            content_sample = resp.text[:100].lower()
                            if "text/html" not in content_type or "ref: refs/" in content_sample or "db_" in content_sample or "php" in content_sample:
                                findings.append({
                                    "title": c["title"],
                                    "description": c["desc"],
                                    "severity": c["severity"],
                                    "category": "dast",
                                    "evidence": {"url": test_url, "status_code": resp.status_code}
                                })
                    except Exception:
                        checked_paths[c["path"]] = "timeout/error"

        except Exception as e:
            return {"status": "error", "error": str(e), "findings": findings}

        return {"status": "completed", "checked": checked_paths, "findings": findings}

    async def nuclei_scan(self, url: str) -> dict:
        if not shutil.which("nuclei"):
            return {"status": "skipped", "reason": "nuclei not installed"}
            
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-target", url, "-je", "nuclei_out.json",
                "-t", "technologies,misconfiguration", # use lightweight templates
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            # Read output
            results = []
            try:
                with open("nuclei_out.json", "r") as f:
                    for line in f:
                        if line.strip():
                            results.append(json.loads(line))
            except FileNotFoundError:
                pass
                
            return {"status": "success", "vulnerabilities": results}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def zap_scan(self, url: str) -> dict:
        """Query OWASP ZAP API if running for live DAST alerts."""
        if not settings.ZAP_API_URL:
            return {"status": "skipped", "reason": "No ZAP_API_URL configured"}

        try:
            import httpx
            base = settings.ZAP_API_URL.rstrip("/")
            api_key = settings.ZAP_API_KEY
            version_url = f"{base}/JSON/core/view/version/?apikey={api_key}"
            async with httpx.AsyncClient(timeout=3.0) as client:
                v_resp = await client.get(version_url)
                if v_resp.status_code == 200:
                    alerts_url = f"{base}/JSON/alert/view/alerts/?apikey={api_key}&baseurl={url}&count=10"
                    a_resp = await client.get(alerts_url)
                    if a_resp.status_code == 200:
                        alerts = a_resp.json().get("alerts", [])
                        return {"status": "connected", "zap_version": v_resp.json().get("version"), "alerts_count": len(alerts), "alerts": alerts}
                    return {"status": "connected", "zap_version": v_resp.json().get("version"), "alerts_count": 0}
        except Exception:
            pass

        return {"status": "offline", "reason": "ZAP daemon container not reachable on port 8080"}
