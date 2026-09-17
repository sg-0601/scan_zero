from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.future import select
from typing import Dict
from pydantic import BaseModel, HttpUrl
import uuid

from app.models.database import AsyncSessionLocal
from app.models.scan import ScanResult
from app.utils.url_validator import validate_url
from app.engine.cache import get_cached_scan

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    competitors: list[str] = []
    force: bool = False

# Mock dispatcher for this api endpoint setup
async def start_scan_task(scan_id: uuid.UUID, domain: str, url: str):
    from app.engine.dispatcher import run_scan
    await run_scan(str(scan_id), domain, url)

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
        
    # Create DB entry
    async with AsyncSessionLocal() as session:
        new_scan = ScanResult(
            target_url=url,
            domain=domain,
            status="pending"
        )
        session.add(new_scan)
        await session.commit()
        await session.refresh(new_scan)
        scan_id = new_scan.id
        
    # Dispatch task
    background_tasks.add_task(start_scan_task, scan_id, domain, url)
    
    return {"scan_id": str(scan_id), "status": "pending", "cached": False}

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    try:
        uid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_id")
        
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ScanResult).where(ScanResult.id == uid))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        return {
            "id": scan.id,
            "status": scan.status,
            "domain": scan.domain,
            "score": scan.score,
            "grade": scan.grade,
            "results_json": scan.results_json,
            # We would typically join findings here
        }

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    try:
        uid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_id")
        
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(ScanResult).where(ScanResult.id == uid))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        # Simplistic progress for now
        progress = 100 if scan.status == "completed" else 50 if scan.status == "running" else 0
        
        return {
            "status": scan.status,
            "progress": progress
        }

active_connections: Dict[str, WebSocket] = {}

@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    active_connections[scan_id] = websocket
    try:
        while True:
            # wait for messages or just keep alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        if scan_id in active_connections:
            del active_connections[scan_id]
