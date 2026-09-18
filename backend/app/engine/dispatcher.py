import asyncio
import logging
from datetime import datetime
from uuid import UUID

from app.workers.w1_osint import OsintWorker
from app.workers.w2_tls import TlsWorker
from app.workers.w3_headers import HeadersWorker
from app.workers.w4_dns import DnsWorker
from app.workers.w5_dast import DastWorker
from app.workers.w6_honeypot import HoneypotWorker

from app.engine.ai_guard import filter_findings
from app.engine.scoring import (
    calculate_score,
    assign_grade,
    calculate_category_scores,
    generate_detailed_sets,
    generate_scoring_breakdown
)
from app.engine.remediation import generate_fixes
from app.engine.gemini_analyzer import synthesize_scan_intelligence
from app.engine.cache import set_cached_scan
from app.models.database import AsyncSessionLocal
from app.models.scan import ScanResult
from app.models.memory_store import MEMORY_SCANS
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

async def run_scan(scan_id: str, domain: str, url: str) -> dict:
    """Run all workers in parallel and aggregate results."""
    # Mark running in memory store
    if scan_id in MEMORY_SCANS:
        MEMORY_SCANS[scan_id]["status"] = "running"

    # 1. Initialize Workers
    workers = [
        OsintWorker(),
        TlsWorker(),
        HeadersWorker(),
        DnsWorker(),
        DastWorker(),
        HoneypotWorker()
    ]
    
    # 2 & 3. Run in parallel with timeout handling inside worker execution
    tasks = [worker.execute(domain, url) for worker in workers]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 4 & 5. Collect and Merge Results
    all_findings = []
    worker_results_dict = {}
    
    for w, res in zip(workers, results):
        if isinstance(res, Exception):
            logger.error(f"Worker {w.name} failed with exception: {res}")
            continue
            
        worker_results_dict[w.name] = res
        all_findings.extend(res.get("findings", []))
        
    # 0. WAF Detection via WAFW00F
    try:
        from app.utils.stealth import detect_waf
        waf_res = await asyncio.get_event_loop().run_in_executor(None, detect_waf, domain)
        worker_results_dict["waf"] = waf_res
        if waf_res.get("waf_detected"):
            all_findings.append({
                "title": f"Web Application Firewall Active ({waf_res.get('waf_name', 'Active')})",
                "description": f"Domain is protected by {waf_res.get('waf_name', 'WAF')}, shielding backend infrastructure from direct exploit payloads.",
                "severity": "info",
                "category": "headers",
                "evidence": waf_res
            })
    except Exception as e:
        logger.debug(f"WAF detection skipped: {e}")

    # --- Unreachable Domain Detection ---
    # Check if the key connectivity workers all failed or errored
    tls_status = worker_results_dict.get("w2_tls", {}).get("status", "missing")
    headers_status = worker_results_dict.get("w3_headers", {}).get("status", "missing")
    headers_has_error = bool(worker_results_dict.get("w3_headers", {}).get("raw_data", {}).get("error"))
    tls_has_error = worker_results_dict.get("w2_tls", {}).get("raw_data", {}).get("tls", {}).get("status") == "error"
    
    # Domain is unreachable if:
    # 1. TLS worker is missing/errored AND headers worker is missing/errored, OR
    # 2. Both connectivity workers returned but both had connection errors
    connectivity_failed = False
    if (tls_status in ("error", "timeout", "missing") and headers_status in ("error", "timeout", "missing")):
        connectivity_failed = True
    elif (tls_has_error and (headers_has_error or headers_status in ("error", "timeout", "missing"))):
        connectivity_failed = True
    elif (headers_has_error and tls_has_error):
        connectivity_failed = True
    
    if connectivity_failed:
        logger.warning(f"Domain {domain} is unreachable - all connectivity workers failed")
        error_result = {
            "scan_id": scan_id,
            "domain": domain,
            "url": url,
            "error": f"Domain '{domain}' is unreachable or not responding. The website may be offline, the domain may not exist, or it may be blocking our scan.",
            "domain_unreachable": True,
            "completed_at": datetime.utcnow().isoformat()
        }

        # Update memory store
        if scan_id in MEMORY_SCANS:
            MEMORY_SCANS[scan_id].update({
                "status": "failed",
                "score": 0,
                "grade": "N/A",
                "results_json": error_result,
                "completed_at": datetime.utcnow().isoformat()
            })

        # Update DB if available
        try:
            async with AsyncSessionLocal() as session:
                uid = UUID(scan_id)
                stmt = select(ScanResult).where(ScanResult.id == uid)
                db_res = await session.execute(stmt)
                scan = db_res.scalar_one_or_none()
                if scan:
                    scan.status = "failed"
                    scan.score = 0
                    scan.grade = "N/A"
                    scan.results_json = error_result
                    scan.completed_at = datetime.utcnow()
                    await session.commit()
        except Exception as e:
            logger.warning(f"DB update skipped (memory store updated): {e}")

        return error_result

    # 6. Honeypot Gate
    is_honeypot = worker_results_dict.get("w6_honeypot", {}).get("raw_data", {}).get("is_honeypot", False)
    if is_honeypot:
        logger.warning(f"Honeypot detected for {domain}")
        
    # 7. AI Guard (EPSS and CISA KEV enrichment)
    filtered_findings = await filter_findings(all_findings)
    remediated_findings = generate_fixes(filtered_findings)
    
    # 8. Baseline Heuristic Scoring (used as robust mathematical baseline)
    set_scores = calculate_category_scores(remediated_findings, worker_results_dict)
    score = calculate_score(remediated_findings, worker_results_dict, set_scores)
    grade = assign_grade(score)
    detailed_sets = generate_detailed_sets(domain, worker_results_dict, set_scores)
    scoring_breakdown = generate_scoring_breakdown(domain, remediated_findings, set_scores)

    # 9. Google Gemini Multi-Tool Intelligence Synthesis Engine
    logger.info(f"Passing multi-tool telemetry for {domain} into Google Gemini Intelligence Engine...")
    try:
        gemini_intel = await synthesize_scan_intelligence(domain, url, worker_results_dict, remediated_findings)
    except Exception as e:
        logger.error(f"Gemini intelligence synthesis encountered exception: {e}", exc_info=True)
        from app.engine.gemini_analyzer import generate_fallback_intelligence
        gemini_intel = generate_fallback_intelligence(domain, url, worker_results_dict, remediated_findings)

    # 10. Harmonize Final Results with Gemini's AI Intelligence
    if gemini_intel:
        if "ai_score" in gemini_intel and gemini_intel.get("ai_score") is not None:
            score = int(gemini_intel["ai_score"])
            grade = gemini_intel.get("ai_grade") or assign_grade(score)
        
        status_text = gemini_intel.get("threat_verdict") or (
            "Hardened against web attacks. Superior cryptographic posture and email defenses." if score >= 80 else
            "Moderate security posture. Review recommended security headers and email enforcement." if score >= 60 else
            "Elevated risk surface. Missing critical transport layer defenses and baseline headers."
        )
        
        strengths = gemini_intel.get("strengths") or ["Core transport encryption verified."]
        critical_issues = gemini_intel.get("critical_risks") or []
        
        cat_scores = gemini_intel.get("category_scores", {})
        if cat_scores:
            set_scores = {
                "set1": cat_scores.get("crypto_tls", {}).get("score", set_scores.get("set1", 80)),
                "set2": cat_scores.get("headers_config", {}).get("score", set_scores.get("set2", 70)),
                "set3": cat_scores.get("dns_email", {}).get("score", set_scores.get("set3", 75)),
                "set4": cat_scores.get("surface_intel", {}).get("score", set_scores.get("set4", 80)),
            }

        # Enrich findings with Gemini AI Insights and tailored remediation
        intel_map = {f.get("title", "").lower().strip(): f for f in gemini_intel.get("intelligent_findings", [])}
        for rf in remediated_findings:
            title_key = rf.get("title", "").lower().strip()
            matched = intel_map.get(title_key)
            if matched:
                rf["ai_insight"] = matched.get("ai_insight")
                if matched.get("remediation_code") and not rf.get("remediation_code"):
                    rf["remediation_code"] = matched.get("remediation_code")
                    rf["remediation_type"] = matched.get("remediation_type", "nginx")

    recommendations = [f.get("remediation_text") for f in remediated_findings if f.get("remediation_text") and "Consult" not in f.get("remediation_text")]
    if not recommendations:
        recommendations = [
            "Add HTTP Strict-Transport-Security (HSTS) with preload directive.",
            "Deploy Content-Security-Policy (CSP) restricting script execution.",
            "Upgrade DMARC policy to p=reject to eliminate domain impersonation."
        ]
    
    # Ready-to-deploy fixes from Gemini or findings
    ready_fixes = gemini_intel.get("ready_to_deploy_fixes", []) if gemini_intel else []
    if not ready_fixes:
        ready_fixes = [
            {
                "title": f.get("title", "Fix Configuration"),
                "target": "Web Server",
                "type": f.get("remediation_type", "nginx"),
                "code": f.get("remediation_code", ""),
                "explanation": f.get("description", "")
            }
            for f in remediated_findings if f.get("remediation_code")
        ]

    final_result_data = {
        "scan_id": scan_id,
        "domain": domain,
        "url": url,
        "score": score,
        "grade": grade,
        "status_text": status_text,
        "set_scores": set_scores,
        "strengths": strengths or ["Basic network connectivity verified."],
        "weaknesses": critical_issues or ["No immediate exploit vectors detected."],
        "critical_issues": critical_issues,
        "recommendations": recommendations,
        "detailed_sets": detailed_sets,
        "scoring_breakdown": scoring_breakdown,
        "findings": remediated_findings,
        "remediations": ready_fixes,
        "raw_results": worker_results_dict,
        "gemini_intelligence": gemini_intel,
        "executive_summary": gemini_intel.get("executive_summary") if gemini_intel else None,
        "attacker_perspective": gemini_intel.get("attacker_perspective") if gemini_intel else None,
        "attack_chain": gemini_intel.get("attack_chain") if gemini_intel else [],
        "remediation_roadmap": gemini_intel.get("remediation_roadmap") if gemini_intel else {},
        "completed_at": datetime.utcnow().isoformat()
    }

    # 10. Update Memory Store
    if scan_id in MEMORY_SCANS:
        MEMORY_SCANS[scan_id].update({
            "status": "completed",
            "score": score,
            "grade": grade,
            "results_json": final_result_data,
            "completed_at": datetime.utcnow().isoformat()
        })
    
    # 11. Update DB if available
    try:
        async with AsyncSessionLocal() as session:
            uid = UUID(scan_id)
            stmt = select(ScanResult).where(ScanResult.id == uid)
            db_res = await session.execute(stmt)
            scan = db_res.scalar_one_or_none()
            
            if scan:
                scan.status = "completed"
                scan.score = score
                scan.grade = grade
                scan.results_json = final_result_data
                scan.completed_at = datetime.utcnow()
                
                # Update counts
                scan.findings_count = len(remediated_findings)
                scan.critical_count = len([f for f in remediated_findings if f.get("severity") == "critical"])
                scan.high_count = len([f for f in remediated_findings if f.get("severity") == "high"])
                scan.medium_count = len([f for f in remediated_findings if f.get("severity") == "medium"])
                scan.low_count = len([f for f in remediated_findings if f.get("severity") == "low"])
                
                await session.commit()
    except Exception as e:
        logger.warning(f"DB update skipped (memory store updated): {e}")
            
    # 12. Cache
    await set_cached_scan(domain, final_result_data)
    
    return final_result_data
