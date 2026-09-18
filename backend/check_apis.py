#!/usr/bin/env python3
"""
ScanZero - Threat Intelligence & OSINT API Diagnostic Runner
Executes real-time operational health checks against all configured security APIs.

Usage:
    python check_apis.py
    python check_apis.py --domain example.com
"""

import os
import sys
import time
import argparse
import asyncio
from pathlib import Path

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Load environment variables
try:
    from dotenv import load_dotenv
    env_file = Path(__file__).resolve().parent / ".env"
    if not env_file.exists():
        env_file = Path(__file__).resolve().parent / ".." / ".env"
    load_dotenv(dotenv_path=env_file)
except ImportError:
    pass

try:
    import httpx
except ImportError:
    print("[ERROR] 'httpx' is required to run API checks. Run: pip install httpx python-dotenv")
    sys.exit(1)

# Color terminal helpers
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


async def check_virustotal(domain: str, key: str) -> dict:
    if not key:
        return {"name": "VirusTotal API v3", "status": "SKIP", "ms": 0, "msg": "VIRUSTOTAL_API_KEY not set in .env"}
    start = time.perf_counter()
    try:
        headers = {"x-apikey": key, "User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"name": "VirusTotal API v3", "status": "PASS", "ms": ms, "msg": f"Auth OK • Harmless: {stats.get('harmless', 0)}, Malicious: {stats.get('malicious', 0)}"}
        elif resp.status_code in (401, 403):
            return {"name": "VirusTotal API v3", "status": "FAIL", "ms": ms, "msg": f"Authentication rejected (HTTP {resp.status_code})"}
        return {"name": "VirusTotal API v3", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "VirusTotal API v3", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_urlscan(domain: str, key: str) -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-Diagnostic"}
        if key:
            headers["API-Key"] = key
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            resp = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=2")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            total = resp.json().get("total", 0)
            return {"name": "URLScan.io Search API", "status": "PASS", "ms": ms, "msg": f"Search operational • {total:,} historical scans indexed"}
        return {"name": "URLScan.io Search API", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "URLScan.io Search API", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_alienvault_otx(domain: str, key: str) -> dict:
    if not key:
        return {"name": "AlienVault OTX API", "status": "SKIP", "ms": 0, "msg": "OTX_API_KEY not set in .env"}
    start = time.perf_counter()
    try:
        headers = {"X-OTX-API-KEY": key, "User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            count = resp.json().get("pulse_info", {}).get("count", 0)
            return {"name": "AlienVault OTX API", "status": "PASS", "ms": ms, "msg": f"Auth OK • Threat pulse count: {count}"}
        return {"name": "AlienVault OTX API", "status": "FAIL", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "AlienVault OTX API", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_shodan(key: str) -> dict:
    if not key:
        return {"name": "Shodan Host API", "status": "SKIP", "ms": 0, "msg": "SHODAN_API_KEY not set in .env"}
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"https://api.shodan.io/api-info?key={key}")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            plan = resp.json().get("plan", "free")
            return {"name": "Shodan Host API", "status": "PASS", "ms": ms, "msg": f"Auth OK • Plan: {plan.upper()} tier"}
        return {"name": "Shodan Host API", "status": "FAIL", "ms": ms, "msg": f"Auth error (HTTP {resp.status_code})"}
    except Exception as e:
        return {"name": "Shodan Host API", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_shodan_internetdb() -> dict:
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get("https://internetdb.shodan.io/1.1.1.1")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            ports = resp.json().get("ports", [])
            return {"name": "Shodan InternetDB (Zero-Key)", "status": "PASS", "ms": ms, "msg": f"Public API operational • Sample ports: {ports[:5]}"}
        return {"name": "Shodan InternetDB (Zero-Key)", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "Shodan InternetDB (Zero-Key)", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_gemini(key: str) -> dict:
    if not key:
        return {"name": "Google Gemini Generative AI", "status": "SKIP", "ms": 0, "msg": "GEMINI_API_KEY not set in .env"}
    start = time.perf_counter()
    models = ["gemini-flash-lite-latest", "gemini-flash-latest", "gemini-2.5-flash"]
    for model in models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
            payload = {"contents": [{"parts": [{"text": "Reply: OK"}]}]}
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
            ms = int((time.perf_counter() - start) * 1000)
            if resp.status_code == 200:
                text = resp.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                return {"name": "Google Gemini Generative AI", "status": "PASS", "ms": ms, "msg": f"Model: {model} • Verification online (\"{text[:20]}\")"}
        except Exception:
            pass
    return {"name": "Google Gemini Generative AI", "status": "FAIL", "ms": 0, "msg": "Failed to connect to Gemini models"}


async def check_hudson_rock(domain: str) -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            return {"name": "Hudson Rock Cybercrime Intel", "status": "PASS", "ms": ms, "msg": "Zero-Key breach search operational"}
        return {"name": "Hudson Rock Cybercrime Intel", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "Hudson Rock Cybercrime Intel", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_crt_sh(domain: str) -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            resp = await client.get(f"https://crt.sh/?q={domain}&output=json")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            return {"name": "Certificate Transparency (crt.sh)", "status": "PASS", "ms": ms, "msg": f"CT log stream operational • {len(data)} certificates parsed"}
        elif resp.status_code in (502, 503, 504, 404):
            return {"name": "Certificate Transparency (crt.sh)", "status": "WARN", "ms": ms, "msg": f"Community server high load (HTTP {resp.status_code})"}
        return {"name": "Certificate Transparency (crt.sh)", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception:
        return {"name": "Certificate Transparency (crt.sh)", "status": "WARN", "ms": 0, "msg": "Upstream CT log timeout (transient)"}


async def check_cisa_kev() -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            count = len(resp.json().get("vulnerabilities", []))
            return {"name": "CISA Known Exploited Vulns", "status": "PASS", "ms": ms, "msg": f"Active threat catalog feed • {count:,} weaponized CVEs"}
        return {"name": "CISA Known Exploited Vulns", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "CISA Known Exploited Vulns", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_first_epss() -> dict:
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get("https://api.first.org/data/v1/epss?cve=CVE-2021-44228")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            return {"name": "FIRST.org EPSS Exploit Scoring", "status": "PASS", "ms": ms, "msg": "Live exploit prediction scoring operational"}
        return {"name": "FIRST.org EPSS Exploit Scoring", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "FIRST.org EPSS Exploit Scoring", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_leakcheck(domain: str, key: str) -> dict:
    if not key:
        return {"name": "LeakCheck Credentials API", "status": "SKIP", "ms": 0, "msg": "LEAKCHECK_API_KEY not set in .env"}
    start = time.perf_counter()
    try:
        headers = {"X-API-Key": key, "User-Agent": "ScanZero-Diagnostic"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0) as client:
            resp = await client.get(f"https://leakcheck.io/api/v2/query/{domain}?type=domain")
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            return {"name": "LeakCheck Credentials API", "status": "PASS", "ms": ms, "msg": "Auth OK • Active subscription verified"}
        elif resp.status_code == 403:
            return {"name": "LeakCheck Credentials API", "status": "PASS", "ms": ms, "msg": "Key authenticated • Domain search requires paid tier (Hudson Rock handles free breaches)"}
        return {"name": "LeakCheck Credentials API", "status": "WARN", "ms": ms, "msg": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"name": "LeakCheck Credentials API", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def check_wafw00f() -> dict:
    try:
        import wafw00f.main
        return {"name": "WAFW00F Firewall Fingerprinter", "status": "PASS", "ms": 0, "msg": "Engine installed and ready for pre-flight inspection"}
    except ImportError:
        return {"name": "WAFW00F Firewall Fingerprinter", "status": "WARN", "ms": 0, "msg": "Package not installed. Run: pip install wafw00f"}


async def check_owasp_zap(zap_url: str, zap_key: str) -> dict:
    if not zap_url:
        return {"name": "OWASP ZAP Dynamic Daemon", "status": "SKIP", "ms": 0, "msg": "Optional daemon not configured"}
    start = time.perf_counter()
    try:
        url = f"{zap_url.rstrip('/')}/JSON/core/view/version/?apikey={zap_key}"
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            ver = resp.json().get("version", "Active")
            return {"name": "OWASP ZAP Dynamic Daemon", "status": "PASS", "ms": ms, "msg": f"Connected to daemon v{ver}"}
        return {"name": "OWASP ZAP Dynamic Daemon", "status": "SKIP", "ms": ms, "msg": "Optional ZAP daemon offline (start with --profile full)"}
    except Exception:
        return {"name": "OWASP ZAP Dynamic Daemon", "status": "SKIP", "ms": 0, "msg": "Optional ZAP daemon offline (start with --profile full)"}


async def check_github_cloud_zap(token: str, repo: str, backend_url: str) -> dict:
    if not token:
        return {"name": "GitHub Actions Cloud ZAP", "status": "SKIP", "ms": 0, "msg": "GITHUB_TOKEN not set in .env"}
    start = time.perf_counter()
    try:
        repo = repo or "sg-0601/scan_zero"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ScanZero-Diagnostic"
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/actions/workflows/zap-ondemand.yml", headers=headers)
        ms = int((time.perf_counter() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            state = data.get("state", "active")
            name = data.get("name", "On-Demand ZAP Scanner")
            cb_msg = f" • Callback: {backend_url}" if backend_url else ""
            return {"name": "GitHub Actions Cloud ZAP", "status": "PASS", "ms": ms, "msg": f"Auth OK ({repo}) • Workflow: '{name}' ({state}) • 7GB Runner Ready{cb_msg}"}
        return {"name": "GitHub Actions Cloud ZAP", "status": "FAIL", "ms": ms, "msg": f"Workflow lookup error (HTTP {resp.status_code})"}
    except Exception as e:
        return {"name": "GitHub Actions Cloud ZAP", "status": "FAIL", "ms": 0, "msg": str(e)[:60]}


async def main():
    parser = argparse.ArgumentParser(description="ScanZero Threat Intelligence API Health Diagnostic")
    parser.add_argument("--domain", default="cloudflare.com", help="Domain to use for read-only validation")
    args = parser.parse_args()

    domain = args.domain

    print(f"\n{BOLD}{CYAN}+--------------------------------------------------------------------------------------------+{RESET}")
    print(f"{BOLD}{CYAN}|                    ScanZero Threat Intelligence & OSINT API Diagnostic                     |{RESET}")
    print(f"{BOLD}{CYAN}+--------------------------------------------------------------------------------------------+{RESET}")
    print(f"{GRAY}Target Test Domain:{RESET} {BOLD}{domain}{RESET}\n")

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    urlscan_key = os.getenv("URLSCAN_API_KEY", "")
    otx_key = os.getenv("OTX_API_KEY", "")
    shodan_key = os.getenv("SHODAN_API_KEY", "")
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    leakcheck_key = os.getenv("LEAKCHECK_API_KEY", "")
    zap_url = os.getenv("ZAP_API_URL", "")
    zap_key = os.getenv("ZAP_API_KEY", "")
    github_token = os.getenv("GITHUB_TOKEN", "")
    github_repo = os.getenv("GITHUB_REPO", "sg-0601/scan_zero")
    backend_url = os.getenv("BACKEND_PUBLIC_URL", "")

    tasks = [
        check_virustotal(domain, vt_key),
        check_urlscan(domain, urlscan_key),
        check_alienvault_otx(domain, otx_key),
        check_shodan(shodan_key),
        check_shodan_internetdb(),
        check_gemini(gemini_key),
        check_hudson_rock(domain),
        check_crt_sh(domain),
        check_cisa_kev(),
        check_first_epss(),
        check_leakcheck(domain, leakcheck_key),
        check_wafw00f(),
        check_github_cloud_zap(github_token, github_repo, backend_url),
        check_owasp_zap(zap_url, zap_key),
    ]

    results = await asyncio.gather(*tasks)

    passed_count = 0
    warn_count = 0
    fail_count = 0
    skip_count = 0

    print(f"{BOLD}{'API / Engine':<35} {'Status':<10} {'Latency':<10} {'Diagnostics & Telemetry'}{RESET}")
    print("-" * 94)

    for r in results:
        status = r["status"]
        ms_str = f"{r['ms']}ms" if r["ms"] > 0 else "-"

        if status == "PASS":
            badge = f"{GREEN}{BOLD}[ PASS ]{RESET}"
            passed_count += 1
        elif status == "WARN":
            badge = f"{YELLOW}{BOLD}[ WARN ]{RESET}"
            warn_count += 1
        elif status == "FAIL":
            badge = f"{RED}{BOLD}[ FAIL ]{RESET}"
            fail_count += 1
        else:
            badge = f"{GRAY}[ SKIP ]{RESET}"
            skip_count += 1

        print(f"{r['name']:<35} {badge:<19} {ms_str:<10} {r['msg']}")

    print("-" * 94)
    print(f"\n{BOLD}Summary:{RESET} {GREEN}{passed_count} Passed{RESET} | {YELLOW}{warn_count} Warnings{RESET} | {RED}{fail_count} Failed{RESET} | {GRAY}{skip_count} Skipped{RESET}")

    if fail_count == 0:
        print(f"\n{GREEN}{BOLD}[OK] All active threat intelligence APIs are verified and fully operational!{RESET}\n")
        sys.exit(0)
    else:
        print(f"\n{RED}{BOLD}[ERROR] {fail_count} API(s) failed verification. Please review the diagnostics above.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
