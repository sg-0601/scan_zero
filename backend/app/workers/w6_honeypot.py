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
        if canary_res.get("all_200") and not canary_res.get("is_spa_routing"):
            honeypot_score += 0.5
            findings.append({
                "title": "Suspicious URI Handling (Possible Honeypot)",
                "description": "Server returned 200 OK for random non-existent paths (deception profile detected).",
                "severity": "info",
                "evidence": {}
            })
        elif canary_res.get("is_spa_routing"):
            findings.append({
                "title": "Client-Side SPA Routing Detected (Authentic Host)",
                "description": "Target server serves a standard Single Page Application (SPA) HTML shell for catch-all paths; verified authentic host.",
                "severity": "info",
                "evidence": {"spa_shell_detected": True}
            })

        raw_data["honeypot_score"] = honeypot_score
        raw_data["is_honeypot"] = honeypot_score >= 0.5

        return {"findings": findings, "raw_data": raw_data}

    async def canary_uri_test(self, url: str) -> dict:
        uris = [f"{url}/a8f9ds7v68s", f"{url}/zcxvbm1234", f"{url}/.env.bak.xyz"]
        try:
            async with httpx.AsyncClient(verify=False, timeout=3.5) as client:
                async def _probe(uri):
                    try:
                        resp = await client.get(uri)
                        is_200 = resp.status_code == 200
                        ctype = resp.headers.get("content-type", "").lower()
                        text_sample = resp.text[:2500].lower() if is_200 else ""
                        is_spa_shell = is_200 and ("text/html" in ctype) and any(
                            marker in text_sample for marker in [
                                "<!doctype html", "<html", "id=\"__next\"", "id=\"root\"", "id=\"app\"",
                                "react-root", "window.__next_data__", "vite", "webpack"
                            ]
                        )
                        return {"is_200": is_200, "is_spa": is_spa_shell}
                    except Exception:
                        return {"is_200": False, "is_spa": False}

                results = await asyncio.gather(*[_probe(u) for u in uris], return_exceptions=True)
                valid_results = [r for r in results if isinstance(r, dict)]
                success_count = sum(1 for r in valid_results if r.get("is_200"))
                spa_count = sum(1 for r in valid_results if r.get("is_spa"))
                all_200 = (success_count == len(uris)) and len(uris) > 0
                is_spa_routing = all_200 and (spa_count >= 2)
                return {
                    "all_200": all_200,
                    "success_count": success_count,
                    "is_spa_routing": is_spa_routing
                }
        except Exception as e:
            return {"error": str(e), "is_spa_routing": False}
