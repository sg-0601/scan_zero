from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.future import select
from typing import Dict
from pydantic import BaseModel
from datetime import datetime
import uuid
import logging

from app.models.database import AsyncSessionLocal
from app.models.scan import ScanResult
from app.models.memory_store import MEMORY_SCANS
from app.utils.url_validator import validate_url
from app.engine.cache import get_cached_scan

logger = logging.getLogger(__name__)

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    competitors: list[str] = []
    force: bool = False

async def start_scan_task(scan_id: uuid.UUID, domain: str, url: str):
    scan_id_str = str(scan_id)
    try:
        from app.engine.dispatcher import run_scan
        await run_scan(scan_id_str, domain, url)
    except Exception as e:
        logger.error(f"Error in start_scan_task for {domain}: {e}", exc_info=True)
        if scan_id_str in MEMORY_SCANS:
            MEMORY_SCANS[scan_id_str]["status"] = "failed"
            MEMORY_SCANS[scan_id_str]["results_json"] = {
                "error": f"Scan failed during processing: {str(e)}",
                "domain_unreachable": False,
            }

@router.post("/scan")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    val_res = validate_url(request.url)
    if not val_res["valid"]:
        raise HTTPException(status_code=400, detail=val_res["error"])
        
    domain = val_res["domain"]
    url = val_res["url"]
    
    # Check cache if not forcing fresh scan
    if not request.force:
        cached = await get_cached_scan(domain)
        if cached:
            return {"scan_id": cached.get("scan_id"), "status": "completed", "cached": True}
        
    scan_id = uuid.uuid4()
    scan_id_str = str(scan_id)

    # 1. In-memory storage (Always available & instantaneous)
    MEMORY_SCANS[scan_id_str] = {
        "id": scan_id_str,
        "target_url": url,
        "domain": domain,
        "status": "pending",
        "score": None,
        "grade": None,
        "results_json": None,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
    }

    # 2. Try DB if available
    try:
        async with AsyncSessionLocal() as session:
            new_scan = ScanResult(
                id=scan_id,
                target_url=url,
                domain=domain,
                status="pending"
            )
            session.add(new_scan)
            await session.commit()
    except Exception as e:
        logger.warning(f"Database write skipped (running in resilient memory mode): {e}")

    # Dispatch background task
    background_tasks.add_task(start_scan_task, scan_id, domain, url)
    
    return {"scan_id": scan_id_str, "status": "pending", "cached": False}

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan_data = None

    # 1. Try DB first
    try:
        uid = uuid.UUID(scan_id)
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(ScanResult).where(ScanResult.id == uid))
            scan = result.scalar_one_or_none()
            if scan:
                scan_data = {
                    "id": str(scan.id),
                    "status": scan.status,
                    "domain": scan.domain,
                    "score": scan.score,
                    "grade": scan.grade,
                    "results_json": scan.results_json,
                }
    except Exception:
        pass
        
    # 2. Fallback to memory store
    if not scan_data and scan_id in MEMORY_SCANS:
        mem = MEMORY_SCANS[scan_id]
        scan_data = {
            "id": mem["id"],
            "status": mem["status"],
            "domain": mem["domain"],
            "score": mem.get("score"),
            "grade": mem.get("grade"),
            "results_json": mem.get("results_json"),
        }

    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return scan_data

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    status = None
    try:
        uid = uuid.UUID(scan_id)
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(ScanResult).where(ScanResult.id == uid))
            scan = result.scalar_one_or_none()
            if scan:
                status = scan.status
    except Exception:
        pass

    if not status and scan_id in MEMORY_SCANS:
        status = MEMORY_SCANS[scan_id].get("status")
        
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    progress = 100 if status == "completed" else 50 if status == "running" else 0
    return {
        "status": status,
        "progress": progress
    }

active_connections: Dict[str, WebSocket] = {}

@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    active_connections[scan_id] = websocket
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        if scan_id in active_connections:
            del active_connections[scan_id]

class AskGeminiRequest(BaseModel):
    question: str
    history: list[dict] = []

@router.post("/scan/{scan_id}/ask")
async def ask_scan_gemini(scan_id: str, req: AskGeminiRequest):
    """Allow user to query Google Gemini directly about this scan's findings and remediation."""
    scan_data = None
    try:
        uid = uuid.UUID(scan_id)
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(ScanResult).where(ScanResult.id == uid))
            scan = result.scalar_one_or_none()
            if scan and scan.results_json:
                scan_data = scan.results_json
    except Exception:
        pass

    if not scan_data and scan_id in MEMORY_SCANS:
        scan_data = MEMORY_SCANS[scan_id].get("results_json")

    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan results not ready or scan not found")

    domain = scan_data.get("domain", "Target Website")
    from app.engine.gemini_analyzer import ask_gemini_scan_assistant
    answer_data = await ask_gemini_scan_assistant(domain, scan_data, req.question, req.history)
    return answer_data

