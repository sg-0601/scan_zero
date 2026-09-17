import httpx
import time
import asyncio
from app.workers.base import BaseWorker

class HoneypotWorker(BaseWorker):
    name = "w6_honeypot"
    category = "honeypot"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        honeypot_score = 0.0

        # Canary URI Test
        canary_res = await self.canary_uri_test(url)
        raw_data["canary"] = canary_res
        if canary_res.get("all_200"):
            honeypot_score += 0.5
            findings.append({
                "title": "Suspicious URI Handling (Possible Honeypot)",
                "description": "Server returned 200 OK for random non-existent paths.",
                "severity": "info",
                "evidence": {}
            })

        raw_data["honeypot_score"] = honeypot_score
        raw_data["is_honeypot"] = honeypot_score >= 0.5

        return {"findings": findings, "raw_data": raw_data}

    async def canary_uri_test(self, url: str) -> dict:
        uris = [f"{url}/a8f9ds7v68s", f"{url}/zcxvbm1234", f"{url}/.env.bak.xyz"]
        success_count = 0
        try:
            async with httpx.AsyncClient(verify=False) as client:
                for uri in uris:
                    resp = await client.get(uri, timeout=5)
                    if resp.status_code == 200:
                        success_count += 1
            
            return {"all_200": success_count == len(uris), "success_count": success_count}
        except Exception as e:
            return {"error": str(e)}
