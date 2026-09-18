import asyncio
import logging
import json
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

async def verify_with_llm(finding: dict, evidence: dict) -> bool:
    """Ask Gemini if this is a genuine vulnerability using clean async REST API."""
    if not settings.GEMINI_API_KEY:
        return False
        
    models = [settings.GEMINI_PRIMARY_MODEL, "gemini-3.5-flash", "gemini-flash-latest", "gemini-flash-lite-latest"]
    for model in models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.GEMINI_API_KEY}"
            prompt = (
                f"Given this security finding: '{finding.get('title')}' and evidence: {json.dumps(evidence)}. "
                "Is this a genuine security vulnerability or likely a false positive? Reply only with 'GENUINE' or 'FALSE_POSITIVE'."
            )
            payload = {
                "contents": [
                    {
                        "parts": [{"text": prompt}]
                    }
                ]
            }
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    return "FALSE_POSITIVE" in text
                else:
                    logger.debug(f"Gemini API model {model} returned status {resp.status_code}")
        except Exception as e:
            logger.debug(f"LLM verification on {model} skipped: {e}")

async def check_epss(cve_id: str) -> float:
    """Query FIRST.org EPSS API for exploit probability score."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("data", [])
                if items:
                    return float(items[0].get("epss", 0.5))
    except Exception:
        pass
    return 0.5

# In-memory cached CISA KEV catalog
_cisa_kev_cache = set()
_cisa_kev_loaded = False

async def load_cisa_kev() -> set:
    """Fetch and cache official CISA Known Exploited Vulnerabilities catalog."""
    global _cisa_kev_cache, _cisa_kev_loaded
    if _cisa_kev_loaded and _cisa_kev_cache:
        return _cisa_kev_cache

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                _cisa_kev_cache = {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
                _cisa_kev_loaded = True
                logger.info(f"Loaded {len(_cisa_kev_cache)} CISA KEV catalog entries")
    except Exception as e:
        logger.debug(f"CISA KEV fetch skipped: {e}")
        
    return _cisa_kev_cache

async def check_cisa_kev(cve_id: str) -> bool:
    """Check if a CVE is listed in the CISA Known Exploited Vulnerabilities catalog."""
    if not cve_id:
        return False
    kev_set = await load_cisa_kev()
    return cve_id.strip().upper() in kev_set

async def filter_findings(findings: list) -> list:
    """Run critical findings through LLM verification and enrich CVEs with EPSS + CISA KEV."""
    if not findings:
        return []

    # 1. Enrich any CVE findings with real FIRST.org EPSS scores and CISA KEV status
    for f in findings:
        cves = f.get("evidence", {}).get("cves", [])
        if isinstance(cves, list) and cves:
            first_cve = str(cves[0])
            epss = await check_epss(first_cve)
            is_kev = await check_cisa_kev(first_cve)
            f["epss_score"] = epss
            f["cisa_kev"] = is_kev
            f["evidence"]["epss_score"] = epss
            f["evidence"]["cisa_kev"] = is_kev

    # 2. Parallel LLM Verification for top Critical/High findings
    candidates = [f for f in findings if f.get("severity") in ("critical", "high")][:3]
    
    async def _check(f):
        try:
            is_fp = await asyncio.wait_for(verify_with_llm(f, f.get("evidence", {})), timeout=4.0)
            f["is_false_positive"] = is_fp
        except Exception:
            f["is_false_positive"] = False

    if settings.GEMINI_API_KEY and candidates:
        await asyncio.gather(*[_check(f) for f in candidates], return_exceptions=True)

    for f in findings:
        if "is_false_positive" not in f:
            f["is_false_positive"] = False

    return findings
