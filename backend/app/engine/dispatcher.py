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
from app.engine.scorer import (
    calculate_score,
    assign_grade,
    calculate_category_scores,
    generate_detailed_sets,
    generate_scoring_breakdown
)
from app.engine.remediation import generate_fixes
from app.engine.cache import set_cached_scan
from app.models.database import AsyncSessionLocal
from app.models.scan import ScanResult
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

async def run_scan(scan_id: str, domain: str, url: str) -> dict:
    """Run all workers in parallel and aggregate results."""
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
        # Update DB with failed status
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
        return error_result

    # 6. Honeypot Gate
    is_honeypot = worker_results_dict.get("w6_honeypot", {}).get("raw_data", {}).get("is_honeypot", False)
    if is_honeypot:
        # We might want to stop early or flag the scan heavily
        logger.warning(f"Honeypot detected for {domain}")
        
    # 7. AI Guard
    filtered_findings = await filter_findings(all_findings)
    
    # 8. Multi-Set Scoring Engine
    set_scores = calculate_category_scores(filtered_findings, worker_results_dict)
    score = calculate_score(filtered_findings, worker_results_dict, set_scores)
    grade = assign_grade(score)
    detailed_sets = generate_detailed_sets(domain, worker_results_dict, set_scores)
    scoring_breakdown = generate_scoring_breakdown(domain, filtered_findings, set_scores)

    # 9. Remediation Engine
    remediated_findings = generate_fixes(filtered_findings)

    # Strengths & Weaknesses extraction
    strengths = []
    tls_info = worker_results_dict.get("w2_tls", {}).get("raw_data", {}).get("tls", {})
    if tls_info.get("version") == "TLSv1.3":
        strengths.append("TLS 1.3 enforced with modern forward-secret cipher suites.")
    elif tls_info.get("version") == "TLSv1.2":
        strengths.append("TLS 1.2 encryption active with valid cryptographic certificates.")
    days = tls_info.get("days_until_expiry", 0)
    if days > 30:
        strengths.append(f"Valid Certificate Authority trust chain ({days} days remaining).")

    dns_raw = worker_results_dict.get("w4_dns", {}).get("raw_data", {})
    if dns_raw.get("spf", {}).get("found"):
        strengths.append("Sender Policy Framework (SPF) active to restrict email spoofing.")
    if dns_raw.get("dmarc", {}).get("found"):
        strengths.append(f"DMARC email policy active ({dns_raw.get('dmarc', {}).get('policy', '')}).")
    if dns_raw.get("dnssec", {}).get("active"):
        strengths.append("DNSSEC cryptographic trust chain verified.")
    if not worker_results_dict.get("w6_honeypot", {}).get("raw_data", {}).get("is_honeypot"):
        strengths.append("Clean honeypot test: Authentic production server behavior confirmed.")

    weaknesses = [f.get("title") for f in filtered_findings if f.get("severity") in ["medium", "high", "critical"]][:5]
    critical_issues = [f.get("title") for f in filtered_findings if f.get("severity") in ["high", "critical"]]
    recommendations = [f.get("remediation_text") for f in remediated_findings if f.get("remediation_text") and f.get("remediation_text") != "Consult standard security guidelines."][:4]
    if not recommendations:
        recommendations = [
            "Add HTTP Strict-Transport-Security (HSTS) with preload directive.",
            "Deploy Content-Security-Policy (CSP) restricting script execution.",
            "Upgrade DMARC policy to p=reject to eliminate domain impersonation."
        ]

    status_text = (
        "Hardened against web attacks. Superior cryptographic posture and email defenses."
        if score >= 80 else
        "Moderate risk posture. Missing critical browser security headers and email enforcement."
        if score >= 60 else
        "High vulnerability surface. Urgent remediation required for exposed ports and protocols."
    )

    final_result_data = {
        "scan_id": scan_id,
        "domain": domain,
        "url": url,
        "score": score,
        "grade": grade,
        "status_text": status_text,
        "set_scores": set_scores,
        "strengths": strengths or ["Basic network connectivity verified."],
        "weaknesses": weaknesses or ["No significant security warnings detected."],
        "critical_issues": critical_issues,
        "recommendations": recommendations,
        "detailed_sets": detailed_sets,
        "scoring_breakdown": scoring_breakdown,
        "findings": remediated_findings,
        "raw_results": worker_results_dict,
        "completed_at": datetime.utcnow().isoformat()
    }
    
    # 10. Update DB
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
            
    # 11. Cache
    await set_cached_scan(domain, final_result_data)
    
    return final_result_data
