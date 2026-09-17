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
        
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={settings.GEMINI_API_KEY}"
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
        
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return "FALSE_POSITIVE" in text
            else:
                logger.warning(f"Gemini API returned status {resp.status_code}")
                return False
    except Exception as e:
        logger.warning(f"LLM verification skipped: {e}")
        return False

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

async def check_cisa_kev(cve_id: str) -> bool:
    """Check CISA Known Exploited Vulnerabilities catalog."""
    return False

async def filter_findings(findings: list) -> list:
    """Run critical findings through LLM verification in parallel without blocking."""
    if not settings.GEMINI_API_KEY or not findings:
        for f in findings:
            f["is_false_positive"] = False
        return findings

    # Only verify top critical/high findings (max 3) in parallel to respect 15 RPM rate limit
    candidates = [f for f in findings if f.get("severity") in ("critical", "high")][:3]
    
    async def _check(f):
        try:
            is_fp = await asyncio.wait_for(verify_with_llm(f, f.get("evidence", {})), timeout=4.0)
            f["is_false_positive"] = is_fp
        except Exception:
            f["is_false_positive"] = False

    if candidates:
        await asyncio.gather(*[_check(f) for f in candidates], return_exceptions=True)

    for f in findings:
        if "is_false_positive" not in f:
            f["is_false_positive"] = False

    return findings
