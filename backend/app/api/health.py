import os
import time
import asyncio
from fastapi import APIRouter
import httpx
from app.config import settings

router = APIRouter()


@router.get("/health/apis")
async def check_apis_health(domain: str = "cloudflare.com"):
    """
    Live diagnostic endpoint to verify operational readiness and authentication
    for all threat intelligence and OSINT APIs.
    """
    tasks = {
        "virustotal": _check_vt(domain),
        "urlscan": _check_urlscan(domain),
        "alienvault_otx": _check_otx(domain),
        "shodan": _check_shodan(),
        "shodan_internetdb": _check_internetdb(),
        "gemini": _check_gemini(),
        "hudson_rock": _check_hudson_rock(domain),
        "crt_sh": _check_crt_sh(domain),
        "cisa_kev": _check_cisa_kev(),
        "first_epss": _check_epss(),
        "leakcheck": _check_leakcheck(domain),
        "github_cloud_zap": _check_github_cloud_zap(),
    }

    results = {}
    for name, coro in zip(tasks.keys(), await asyncio.gather(*tasks.values())):
        results[name] = coro

    operational_count = sum(1 for v in results.values() if v.get("status") == "operational")
    total_count = len(results)

    return {
        "status": "operational" if operational_count == total_count else "degraded",
        "timestamp": time.time(),
        "total_apis": total_count,
        "operational_count": operational_count,
        "apis": results,
    }


async def _check_vt(domain: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "message": "Key not configured"}
    start = time.perf_counter()
    try:
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, "User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}")
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            return {"status": "operational", "latency_ms": latency, "http_code": 200}
        return {"status": "error", "latency_ms": latency, "http_code": resp.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_urlscan(domain: str) -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-HealthCheck"}
        if settings.URLSCAN_API_KEY:
            headers["API-Key"] = settings.URLSCAN_API_KEY
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "degraded", "latency_ms": latency, "http_code": resp.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_otx(domain: str) -> dict:
    if not settings.OTX_API_KEY:
        return {"status": "skipped", "message": "Key not configured"}
    start = time.perf_counter()
    try:
        headers = {"X-OTX-API-KEY": settings.OTX_API_KEY, "User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "error", "latency_ms": latency, "http_code": resp.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_shodan() -> dict:
    if not settings.SHODAN_API_KEY:
        return {"status": "skipped", "message": "Key not configured"}
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"https://api.shodan.io/api-info?key={settings.SHODAN_API_KEY}")
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            return {"status": "operational", "latency_ms": latency, "plan": resp.json().get("plan")}
        return {"status": "error", "latency_ms": latency, "http_code": resp.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_internetdb() -> dict:
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get("https://internetdb.shodan.io/1.1.1.1")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "degraded", "latency_ms": latency}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_gemini() -> dict:
    if not settings.GEMINI_API_KEY:
        return {"status": "skipped", "message": "Key not configured"}
    start = time.perf_counter()
    models = [settings.GEMINI_PRIMARY_MODEL, "gemini-3.5-flash", "gemini-flash-latest", "gemini-flash-lite-latest"]
    for model in models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.GEMINI_API_KEY}"
            payload = {"contents": [{"parts": [{"text": "Reply: OK"}]}]}
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(url, json=payload)
            latency = int((time.perf_counter() - start) * 1000)
            if resp.status_code == 200:
                return {"status": "operational", "latency_ms": latency, "model": model}
        except Exception:
            pass
    return {"status": "error", "message": "All Gemini models unreachable"}


async def _check_hudson_rock(domain: str) -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "degraded", "latency_ms": latency}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_crt_sh(domain: str) -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://crt.sh/?q={domain}&output=json")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "degraded", "latency_ms": latency}
    except Exception:
        return {"status": "degraded", "message": "Upstream CT log server latency"}


async def _check_cisa_kev() -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "degraded", "latency_ms": latency}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_epss() -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get("https://api.first.org/data/v1/epss?cve=CVE-2021-44228")
        latency = int((time.perf_counter() - start) * 1000)
        return {"status": "operational" if resp.status_code == 200 else "degraded", "latency_ms": latency}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_leakcheck(domain: str) -> dict:
    if not settings.LEAKCHECK_API_KEY:
        return {"status": "skipped", "message": "Key not configured"}
    start = time.perf_counter()
    try:
        headers = {"X-API-Key": settings.LEAKCHECK_API_KEY, "User-Agent": "ScanZero-HealthCheck"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://leakcheck.io/api/v2/query/{domain}?type=domain")
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code in (200, 403):
            return {"status": "operational", "latency_ms": latency, "note": "Key authenticated"}
        return {"status": "error", "latency_ms": latency, "http_code": resp.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


async def _check_github_cloud_zap() -> dict:
    if not settings.GITHUB_TOKEN:
        return {"status": "skipped", "message": "GITHUB_TOKEN not configured"}
    start = time.perf_counter()
    try:
        repo = settings.GITHUB_REPO or "sg-0601/scan_zero"
        headers = {
            "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ScanZero-HealthCheck"
        }
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/actions/workflows/zap-ondemand.yml")
        latency = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            wf = resp.json()
            return {
                "status": "operational",
                "latency_ms": latency,
                "workflow": wf.get("name", "On-Demand ZAP Scanner"),
                "state": wf.get("state", "active"),
                "runner": "Ubuntu 7GB Cloud Runner",
                "repo": repo
            }
        return {"status": "error", "latency_ms": latency, "http_code": resp.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}
