from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.future import select
from typing import Dict
from pydantic import BaseModel
from datetime import datetime
import asyncio
import uuid
import logging

from app.models.database import AsyncSessionLocal
from app.models.scan import ScanResult
from app.models.memory_store import MEMORY_SCANS
from app.utils.url_validator import validate_url
from app.engine.cache import get_cached_scan, set_cached_scan

logger = logging.getLogger(__name__)

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    competitors: list[str] = []
    force: bool = False

async def start_scan_task(scan_id: uuid.UUID, domain: str, url: str):
    scan_id_str = str(scan_id)
    try:
        # Asynchronously trigger GitHub Actions ZAP runner if configured
        try:
            from app.utils.github_zap import trigger_github_zap
            asyncio.create_task(trigger_github_zap(url, scan_id_str))
        except Exception as zap_err:
            logger.debug(f"GitHub ZAP runner trigger skipped: {zap_err}")

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

@router.post("/scan/zap-callback")
async def zap_callback(payload: dict):
    """
    Webhook callback endpoint invoked by GitHub Actions ZAP runner upon completion.
    Asynchronously merges cloud-scanned DAST alerts into the live scan record,
    re-synthesizes full intelligence via Google Gemini AI, and updates all dashboards.
    """
    import re
    scan_id = payload.get("scan_id")
    if not scan_id:
        raise HTTPException(status_code=400, detail="Missing scan_id in payload")

    report = payload.get("report", {})
    zap_findings = []

    # Parse ZAP JSON site alerts (support both list and single dict)
    sites = report.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    elif not isinstance(sites, list):
        sites = []

    raw_alerts = []
    for s in sites:
        if isinstance(s, dict):
            alerts = s.get("alerts", [])
            if isinstance(alerts, list):
                raw_alerts.extend(alerts)

    # Also support top-level alerts if reported directly
    if isinstance(report.get("alerts"), list):
        raw_alerts.extend(report.get("alerts"))

    for a in raw_alerts:
        risk_str = a.get("riskdesc", a.get("risk", "Low"))
        severity = risk_str.split()[0].lower() if risk_str else "low"
        if severity not in ["critical", "high", "medium", "low", "info"]:
            severity = "low"
        
        # Clean HTML tags from description and solution if present
        clean_desc = re.sub(r'<[^>]+>', '', a.get("desc") or a.get("description", "Identified by OWASP ZAP cloud dynamic analysis."))
        clean_sol = re.sub(r'<[^>]+>', '', a.get("solution") or "")

        cwe_raw = str(a.get("cweid") or "")
        cwe_formatted = f"CWE-{cwe_raw}" if cwe_raw and not cwe_raw.startswith("CWE") else cwe_raw

        zap_findings.append({
            "title": f"OWASP ZAP: {a.get('name') or a.get('alert', 'Security Finding')}",
            "description": clean_desc[:250],
            "severity": severity,
            "category": "dast",
            "solution": clean_sol[:250],
            "evidence": {
                "param": a.get("param", ""),
                "url": a.get("url", ""),
                "cweid": cwe_formatted,
                "instances": len(a.get("instances", [])) if isinstance(a.get("instances"), list) else 0
            }
        })

    from app.engine.scoring import (
        calculate_score,
        assign_grade,
        calculate_category_scores,
        generate_detailed_sets,
        generate_scoring_breakdown
    )
    from app.engine.remediation import generate_fixes
    from app.engine.gemini_analyzer import synthesize_scan_intelligence

    # Identify target domain and url from memory or DB
    domain = "target.com"
    url = f"https://{domain}"
    existing_r_json = None

    if scan_id in MEMORY_SCANS:
        scan_mem = MEMORY_SCANS[scan_id]
        domain = scan_mem.get("domain", domain)
        url = scan_mem.get("target_url", url)
        existing_r_json = scan_mem.get("results_json")

    # If not found in memory, try DB
    if not existing_r_json:
        try:
            uid = uuid.UUID(scan_id)
            async with AsyncSessionLocal() as session:
                stmt = select(ScanResult).where(ScanResult.id == uid)
                db_res = await session.execute(stmt)
                scan = db_res.scalar_one_or_none()
                if scan and scan.results_json:
                    existing_r_json = scan.results_json
                    domain = scan.domain or domain
                    url = scan.target_url or url
        except Exception as e:
            logger.debug(f"DB lookup in zap_callback: {e}")

    if not isinstance(existing_r_json, dict):
        existing_r_json = {}

    r_json = dict(existing_r_json)

    # 1. Merge findings (replace old ZAP findings if any)
    current_findings = [f for f in r_json.get("findings", []) if not f.get("title", "").startswith("OWASP ZAP:")]
    combined_findings = current_findings + zap_findings
    remediated_findings = generate_fixes(combined_findings)
    r_json["findings"] = remediated_findings

    # 2. Update worker raw results with ZAP cloud findings
    worker_raw = r_json.setdefault("raw_results", {})
    w5_dict = worker_raw.setdefault("w5_dast", {}).setdefault("raw_data", {})
    w5_dict["zap_cloud_alerts"] = zap_findings
    w5_dict["zap_alerts_count"] = len(zap_findings)
    w5_dict["zap"] = {
        "status": "completed",
        "runner": "GitHub Actions Ubuntu 7GB Cloud Runner",
        "alerts_count": len(zap_findings),
        "timestamp": datetime.utcnow().isoformat()
    }

    # 3. Mathematical baseline recalculation
    base_set_scores = calculate_category_scores(remediated_findings, worker_raw)
    base_score = calculate_score(remediated_findings, worker_raw, base_set_scores)
    base_grade = assign_grade(base_score)
    base_detailed = generate_detailed_sets(domain, worker_raw, base_set_scores, remediated_findings)
    base_breakdown = generate_scoring_breakdown(domain, remediated_findings, base_set_scores)

    # 4. Feed ZAP report to Google Gemini AI for synthesis
    logger.info(f"[ZAP-CALLBACK] Feeding {len(zap_findings)} OWASP ZAP alerts for {domain} into Google Gemini AI...")
    gemini_intel = None
    try:
        gemini_intel = await synthesize_scan_intelligence(domain, url, worker_raw, remediated_findings)
    except Exception as g_err:
        logger.warning(f"[ZAP-CALLBACK] Gemini intelligence re-synthesis failed: {g_err}")

    # Harmonize with Gemini or fallback
    final_score = base_score
    final_grade = base_grade
    final_set_scores = dict(base_set_scores)
    final_detailed = dict(base_detailed)
    final_breakdown = base_breakdown
    final_status_text = r_json.get("status_text", "")
    final_strengths = r_json.get("strengths", [])
    final_critical = r_json.get("critical_issues", [])
    final_recs = r_json.get("recommendations", [])
    final_hardening = r_json.get("server_hardening", {})

    if gemini_intel:
        if gemini_intel.get("ai_score") is not None:
            final_score = int(gemini_intel["ai_score"])
            final_grade = gemini_intel.get("ai_grade") or assign_grade(final_score)
        final_status_text = gemini_intel.get("threat_verdict") or final_status_text
        final_strengths = gemini_intel.get("strengths") or final_strengths
        final_critical = gemini_intel.get("critical_risks") or final_critical
        if gemini_intel.get("recommendations"):
            final_recs = gemini_intel["recommendations"]
        final_hardening = gemini_intel.get("server_hardening") or final_hardening

        g_set_scores = gemini_intel.get("set_scores", {})
        if isinstance(g_set_scores, dict) and g_set_scores:
            for k in ["set1", "set2", "set3", "set4", "set5", "set6"]:
                if k in g_set_scores:
                    final_set_scores[k] = int(g_set_scores[k])

        g_detailed = gemini_intel.get("detailed_sets", {})
        if isinstance(g_detailed, dict) and g_detailed:
            for k, v in g_detailed.items():
                if isinstance(v, dict):
                    final_detailed[k] = v

        if gemini_intel.get("scoring_breakdown"):
            final_breakdown = gemini_intel["scoring_breakdown"]

    # Ensure Set 5 has explicit ZAP cloud runner fields
    if "set5" in final_detailed:
        final_detailed["set5"]["zap_status"] = "Complete (GitHub Actions 7GB Runner)"
        final_detailed["set5"]["zap_alerts_count"] = len(zap_findings)
        final_detailed["set5"]["zap_findings"] = base_detailed.get("set5", {}).get("zap_findings", [])

    r_json["score"] = final_score
    r_json["grade"] = final_grade
    r_json["set_scores"] = final_set_scores
    r_json["detailed_sets"] = final_detailed
    r_json["scoring_breakdown"] = final_breakdown
    r_json["status_text"] = final_status_text
    r_json["strengths"] = final_strengths
    r_json["critical_issues"] = final_critical
    r_json["recommendations"] = final_recs
    r_json["server_hardening"] = final_hardening
    r_json["zap_completed"] = True
    r_json["zap_alerts_count"] = len(zap_findings)
    r_json["zap_alerts"] = zap_findings
    if gemini_intel:
        r_json["gemini_intelligence"] = gemini_intel
        r_json["executive_summary"] = gemini_intel.get("executive_summary")
        r_json["attacker_perspective"] = gemini_intel.get("attacker_perspective")
        r_json["attack_chain"] = gemini_intel.get("attack_chain") or []
        r_json["remediation_roadmap"] = gemini_intel.get("remediation_roadmap") or {}

    # 5. Update in-memory store
    if scan_id in MEMORY_SCANS:
        MEMORY_SCANS[scan_id]["score"] = final_score
        MEMORY_SCANS[scan_id]["grade"] = final_grade
        MEMORY_SCANS[scan_id]["results_json"] = r_json

    # 6. Update database
    try:
        uid = uuid.UUID(scan_id)
        async with AsyncSessionLocal() as session:
            stmt = select(ScanResult).where(ScanResult.id == uid)
            db_res = await session.execute(stmt)
            scan = db_res.scalar_one_or_none()
            if scan:
                scan.score = final_score
                scan.grade = final_grade
                scan.results_json = r_json
                scan.findings_count = len(remediated_findings)
                scan.critical_count = len([f for f in remediated_findings if f.get("severity") == "critical"])
                scan.high_count = len([f for f in remediated_findings if f.get("severity") == "high"])
                scan.medium_count = len([f for f in remediated_findings if f.get("severity") == "medium"])
                scan.low_count = len([f for f in remediated_findings if f.get("severity") == "low"])
                await session.commit()
    except Exception as e:
        logger.warning(f"ZAP callback DB update skipped: {e}")

    # 7. Update Cache
    await set_cached_scan(domain, r_json)

    logger.info(f"[ZAP-CALLBACK] Successfully processed {len(zap_findings)} ZAP findings and re-synthesized Gemini intelligence for scan {scan_id}")
    return {
        "status": "success",
        "scan_id": scan_id,
        "alerts_merged": len(zap_findings),
        "score": final_score,
        "grade": final_grade,
        "gemini_re_synthesized": gemini_intel is not None
    }


