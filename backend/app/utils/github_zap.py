import httpx
import logging
from datetime import datetime
from typing import Dict, Any
from app.config import settings

logger = logging.getLogger(__name__)

async def trigger_github_zap(target_url: str, scan_id: str) -> Dict[str, Any]:
    """
    Trigger GitHub Actions workflow to run OWASP ZAP on-demand in the cloud.
    Executes in a dedicated 7 GB RAM runner without loading the Render container.
    """
    if not settings.GITHUB_TOKEN:
        logger.debug("GITHUB_TOKEN not configured - skipping on-demand GitHub ZAP runner")
        return {
            "dispatched": False,
            "status": "skipped",
            "reason": "GITHUB_TOKEN not configured in .env",
            "target_url": target_url,
            "scan_id": scan_id
        }

    repo = settings.GITHUB_REPO or "sg-0601/scan_zero"
    workflow_id = "zap-ondemand.yml"
    url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/dispatches"

    callback_url = ""
    if settings.BACKEND_PUBLIC_URL:
        callback_url = f"{settings.BACKEND_PUBLIC_URL.rstrip('/')}/api/scan/zap-callback"

    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ScanZero-App"
    }

    payload = {
        "ref": "main",
        "inputs": {
            "target_url": target_url,
            "scan_id": scan_id,
            "callback_url": callback_url
        }
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 204):
                logger.info(f"[ZAP-CLOUD] Successfully triggered GitHub Actions ZAP runner for {target_url} (scan_id: {scan_id})")
                return {
                    "dispatched": True,
                    "status": "dispatched",
                    "target_url": target_url,
                    "scan_id": scan_id,
                    "repo": repo,
                    "workflow": workflow_id,
                    "runner": "GitHub Actions Ubuntu 7GB Cloud Runner",
                    "callback_url": callback_url,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                logger.warning(f"[ZAP-CLOUD] GitHub Actions dispatch returned HTTP {resp.status_code}: {resp.text}")
                return {
                    "dispatched": False,
                    "status": "error",
                    "status_code": resp.status_code,
                    "error": resp.text,
                    "target_url": target_url,
                    "scan_id": scan_id
                }
    except Exception as e:
        logger.error(f"[ZAP-CLOUD] Failed to dispatch GitHub Actions ZAP workflow: {e}")
        return {
            "dispatched": False,
            "status": "error",
            "error": str(e),
            "target_url": target_url,
            "scan_id": scan_id
        }

