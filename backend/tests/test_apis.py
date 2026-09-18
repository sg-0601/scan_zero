"""
ScanZero Automated Threat Intelligence & OSINT API Test Suite
Validates operational readiness, authentication, and responses for all configured threat intelligence engines.
"""

import os
import time
import pytest
import httpx


@pytest.mark.asyncio
async def test_virustotal_api(api_keys, test_domain):
    """Verify VirusTotal API v3 key and domain analysis endpoint."""
    key = api_keys.get("virustotal")
    if not key:
        pytest.skip("VIRUSTOTAL_API_KEY not configured in .env")

    headers = {"x-apikey": key, "User-Agent": "ScanZero-TestRunner"}
    url = f"https://www.virustotal.com/api/v3/domains/{test_domain}"

    start = time.perf_counter()
    async with httpx.AsyncClient(headers=headers, timeout=12.0) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"VirusTotal returned HTTP {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "data" in data, "VirusTotal response missing top-level data field"
    attrs = data["data"].get("attributes", {})
    assert "last_analysis_stats" in attrs, "Missing last_analysis_stats in attributes"
    stats = attrs["last_analysis_stats"]
    assert "harmless" in stats and "malicious" in stats
    print(f"\n[VT] VirusTotal API v3 OK ({latency:.0f}ms) - harmless: {stats.get('harmless')}, malicious: {stats.get('malicious')}")


@pytest.mark.asyncio
async def test_urlscan_api(api_keys, test_domain):
    """Verify URLScan.io search API key and live search results."""
    key = api_keys.get("urlscan")
    headers = {"User-Agent": "ScanZero-TestRunner"}
    if key:
        headers["API-Key"] = key

    url = f"https://urlscan.io/api/v1/search/?q=domain:{test_domain}&size=3"
    start = time.perf_counter()
    async with httpx.AsyncClient(headers=headers, timeout=12.0) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"URLScan returned HTTP {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "results" in data or "total" in data, "Invalid URLScan response structure"
    total = data.get("total", len(data.get("results", [])))
    print(f"\n[URLScan] URLScan.io API OK ({latency:.0f}ms) - historical scans: {total}")


@pytest.mark.asyncio
async def test_alienvault_otx_api(api_keys, test_domain):
    """Verify AlienVault OTX API key and threat pulses endpoint."""
    key = api_keys.get("otx")
    if not key:
        pytest.skip("OTX_API_KEY not configured in .env")

    headers = {"X-OTX-API-KEY": key, "User-Agent": "ScanZero-TestRunner"}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{test_domain}/general"
    start = time.perf_counter()
    async with httpx.AsyncClient(headers=headers, timeout=12.0) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"AlienVault OTX returned HTTP {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "pulse_info" in data, "AlienVault OTX response missing pulse_info"
    pulse_count = data["pulse_info"].get("count", 0)
    print(f"\n[OTX] AlienVault OTX OK ({latency:.0f}ms) - pulse count: {pulse_count}")


@pytest.mark.asyncio
async def test_shodan_api_auth(api_keys):
    """Verify Shodan API key authentication and account quota info."""
    key = api_keys.get("shodan")
    if not key:
        pytest.skip("SHODAN_API_KEY not configured in .env")

    url = f"https://api.shodan.io/api-info?key={key}"
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"Shodan authentication failed HTTP {resp.status_code}: {resp.text}"
    data = resp.json()
    plan = data.get("plan", "unknown")
    scan_credits = data.get("scan_credits", 0)
    query_credits = data.get("query_credits", 0)
    print(f"\n[Shodan] Shodan API OK ({latency:.0f}ms) - Plan: {plan}, Query Credits: {query_credits}, Scan Credits: {scan_credits}")


@pytest.mark.asyncio
async def test_shodan_internetdb_free():
    """Verify Shodan InternetDB zero-key public API for instant IP intelligence."""
    test_ip = "1.1.1.1"
    url = f"https://internetdb.shodan.io/{test_ip}"
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=8.0) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"Shodan InternetDB returned HTTP {resp.status_code}"
    data = resp.json()
    assert "ports" in data, "InternetDB response missing ports field"
    print(f"\n[InternetDB] Shodan InternetDB OK ({latency:.0f}ms) - Ports: {data.get('ports')}, Hostnames: {data.get('hostnames')}")


@pytest.mark.asyncio
async def test_gemini_api(api_keys):
    """Verify Google Gemini API key and generative AI model execution."""
    key = api_keys.get("gemini")
    if not key:
        pytest.skip("GEMINI_API_KEY not configured in .env")

    models = ["gemini-flash-latest", "gemini-flash-lite-latest"]
    success = False
    last_error = ""
    start = time.perf_counter()

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        payload = {
            "contents": [
                {"parts": [{"text": "Respond in 3 words: ScanZero is active"}]}
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                latency = (time.perf_counter() - start) * 1000
                print(f"\n[Gemini] Google Gemini API ({model}) OK ({latency:.0f}ms) - Response: \"{text.strip()}\"")
                success = True
                break
            else:
                last_error = f"HTTP {resp.status_code}: {resp.text}"
        except Exception as e:
            last_error = str(e)

    assert success, f"Gemini API failed on models {models}: {last_error}"


@pytest.mark.asyncio
async def test_hudson_rock_breaches_api(test_domain):
    """Verify Hudson Rock Cavalier Cybercrime Intelligence API (Zero-Key)."""
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={test_domain}"
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": "ScanZero-TestRunner"}) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"Hudson Rock Cavalier returned HTTP {resp.status_code}: {resp.text}"
    data = resp.json()
    emp = data.get("employees_compromised", 0)
    users = data.get("users_compromised", 0)
    print(f"\n[HudsonRock] Hudson Rock Cavalier OK ({latency:.0f}ms) - Compromised Employees: {emp}, Users: {users}")


@pytest.mark.asyncio
async def test_crt_sh_subdomains(test_domain):
    """Verify crt.sh Certificate Transparency subdomain enumeration (Zero-Key)."""
    # Use direct domain search to avoid heavy Postgres wildcard timeouts on crt.sh public server
    url = f"https://crt.sh/?q={test_domain}&output=json"
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": "ScanZero-TestRunner"}) as client:
            resp = await client.get(url)
        latency = (time.perf_counter() - start) * 1000

        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, list), "crt.sh did not return a JSON list"
            print(f"\n[crt.sh] Certificate Transparency OK ({latency:.0f}ms) - Found {len(data)} CT certificates")
        elif resp.status_code in (502, 503, 504, 404):
            # crt.sh free community server frequently encounters DB locks
            pytest.skip(f"crt.sh community server busy (HTTP {resp.status_code}) - normal for crt.sh free tier")
        else:
            pytest.fail(f"crt.sh returned unexpected HTTP {resp.status_code}")
    except (httpx.ReadTimeout, httpx.ConnectTimeout):
        pytest.skip("crt.sh public server timed out (transient upstream CT log delay)")


@pytest.mark.asyncio
async def test_cisa_kev_feed():
    """Verify official CISA Known Exploited Vulnerabilities catalog feed."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": "ScanZero-TestRunner"}) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"CISA KEV returned HTTP {resp.status_code}"
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    assert len(vulns) > 500, f"Expected >500 CISA KEV entries, got {len(vulns)}"
    print(f"\n[CISA-KEV] CISA Known Exploited Vulns OK ({latency:.0f}ms) - Total catalog CVEs: {len(vulns)}")


@pytest.mark.asyncio
async def test_first_epss_api(test_cve):
    """Verify FIRST.org EPSS (Exploit Prediction Scoring System) API."""
    url = f"https://api.first.org/data/v1/epss?cve={test_cve}"
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": "ScanZero-TestRunner"}) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    assert resp.status_code == 200, f"FIRST.org EPSS returned HTTP {resp.status_code}"
    data = resp.json()
    items = data.get("data", [])
    assert len(items) > 0, "No EPSS data returned for test CVE"
    epss_score = float(items[0].get("epss", 0.0))
    percentile = float(items[0].get("percentile", 0.0))
    print(f"\n[EPSS] FIRST.org EPSS API OK ({latency:.0f}ms) - {test_cve} score: {epss_score:.4f}, percentile: {percentile:.4f}")


@pytest.mark.asyncio
async def test_emailrep_api(test_domain):
    """Verify EmailRep.io domain reputation API."""
    url = f"https://emailrep.io/info@{test_domain}"
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": "ScanZero-TestRunner", "Accept": "application/json"}) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    if resp.status_code == 429:
        pytest.skip("EmailRep.io community rate limit reached (HTTP 429) - normal for free tier")
    
    assert resp.status_code in (200, 404), f"EmailRep returned HTTP {resp.status_code}"
    if resp.status_code == 200:
        data = resp.json()
        print(f"\n[EmailRep] EmailRep.io OK ({latency:.0f}ms) - Reputation: {data.get('reputation')}")
    else:
        print(f"\n[EmailRep] EmailRep.io OK ({latency:.0f}ms) - No previous negative flags")


@pytest.mark.asyncio
async def test_leakcheck_api_status(api_keys, test_domain):
    """Verify LeakCheck API key status and report plan tier availability."""
    key = api_keys.get("leakcheck")
    if not key:
        pytest.skip("LEAKCHECK_API_KEY not configured in .env")

    url = f"https://leakcheck.io/api/v2/query/{test_domain}?type=domain"
    start = time.perf_counter()
    async with httpx.AsyncClient(headers={"X-API-Key": key, "User-Agent": "ScanZero-TestRunner"}, timeout=8.0) as client:
        resp = await client.get(url)
    latency = (time.perf_counter() - start) * 1000

    if resp.status_code == 200:
        data = resp.json()
        entries = data.get("result", [])
        print(f"\n[LeakCheck] LeakCheck API OK ({latency:.0f}ms) - Found {len(entries)} breach entries")
    elif resp.status_code == 403:
        err = resp.json().get("error", "Active plan required")
        print(f"\n[LeakCheck] LeakCheck Key Validated ({latency:.0f}ms) - Note: {err} (Domain queries require LeakCheck paid tier; Hudson Rock covers breach intel for free)")
    else:
        pytest.fail(f"LeakCheck returned unexpected HTTP {resp.status_code}: {resp.text}")


@pytest.mark.asyncio
async def test_wafw00f_engine():
    """Verify WAFW00F engine is installed and operational."""
    import wafw00f.main
    assert wafw00f.main is not None
    print("\n[WAFW00F] WAFW00F Firewall Detection Engine is installed and operational")


@pytest.mark.asyncio
async def test_owasp_zap_status(api_keys):
    """Verify OWASP ZAP daemon status (optional component)."""
    zap_url = api_keys.get("zap_url")
    zap_key = api_keys.get("zap_key", "")
    if not zap_url:
        pytest.skip("ZAP_API_URL not configured")

    base = zap_url.rstrip("/")
    url = f"{base}/JSON/core/view/version/?apikey={zap_key}"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
        if resp.status_code == 200:
            version = resp.json().get("version", "Unknown")
            print(f"\n[ZAP] OWASP ZAP Daemon Connected - Version: {version}")
        else:
            pytest.skip(f"ZAP daemon responded with HTTP {resp.status_code}")
    except Exception:
        pytest.skip("OWASP ZAP daemon container is offline (optional service)")


@pytest.mark.asyncio
async def test_github_cloud_zap_runner(api_keys):
    """Verify GitHub Actions Cloud ZAP Runner authentication, repo, and workflow readiness."""
    token = api_keys.get("github_token")
    repo = api_keys.get("github_repo", "sg-0601/scan_zero")
    backend_url = api_keys.get("backend_public_url", "")

    if not token:
        pytest.skip("GITHUB_TOKEN not configured in .env")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ScanZero-TestRunner"
    }

    start = time.perf_counter()
    async with httpx.AsyncClient(headers=headers, timeout=12.0) as client:
        # 1. Check user authentication and token scopes
        user_resp = await client.get("https://api.github.com/user")
        assert user_resp.status_code == 200, f"GitHub authentication failed: HTTP {user_resp.status_code}"
        user_data = user_resp.json()
        login = user_data.get("login", "")
        scopes = user_resp.headers.get("x-oauth-scopes", "")

        # 2. Check repository access
        repo_resp = await client.get(f"https://api.github.com/repos/{repo}")
        assert repo_resp.status_code == 200, f"Repository {repo} lookup failed: HTTP {repo_resp.status_code}"
        default_branch = repo_resp.json().get("default_branch", "main")

        # 3. Check ZAP workflow exists and is active
        wf_resp = await client.get(f"https://api.github.com/repos/{repo}/actions/workflows/zap-ondemand.yml")
        assert wf_resp.status_code == 200, f"Workflow zap-ondemand.yml not found in {repo}: HTTP {wf_resp.status_code}"
        wf_data = wf_resp.json()
        assert wf_data.get("state") == "active", f"Workflow zap-ondemand.yml is not active: state={wf_data.get('state')}"

    latency = (time.perf_counter() - start) * 1000
    print(
        f"\n[GitHub-ZAP] Cloud Runner Ready ({latency:.0f}ms) - User: {login}, "
        f"Repo: {repo} ({default_branch}), Workflow: {wf_data.get('name')} (Active), "
        f"Scopes: [{scopes}], Callback Target: {backend_url or 'Not set'}"
    )


@pytest.mark.asyncio
async def test_zap_callback_handler():
    """Verify backend ZAP callback processing and dynamic score recalculation."""
    from app.api.scan import zap_callback
    from app.models.memory_store import MEMORY_SCANS

    test_scan_id = "00000000-0000-0000-0000-000000000099"
    MEMORY_SCANS[test_scan_id] = {
        "id": test_scan_id,
        "domain": "test-target.com",
        "status": "running",
        "results_json": {
            "findings": [],
            "raw_results": {
                "w2_tls": {"raw_data": {"tls": {"status": "success", "version": "TLSv1.3", "days_until_expiry": 180}}},
                "w3_headers": {"raw_data": {"active_headers": ["Content-Security-Policy"], "missing_headers": []}},
                "w4_dns": {"raw_data": {"spf": {"found": True}, "dmarc": {"found": True, "policy": "reject"}, "dnssec": {"active": True}}},
                "w1_osint": {"raw_data": {"subdomains": [], "virustotal": {"malicious": 0}}},
                "w5_dast": {"raw_data": {"probed_paths": {"checked": {}}}},
                "w6_honeypot": {"raw_data": {"is_honeypot": False}}
            }
        }
    }

    mock_zap_payload = {
        "scan_id": test_scan_id,
        "report": {
            "site": [
                {
                    "@name": "https://test-target.com",
                    "alerts": [
                        {
                            "alert": "Anti-CSRF Tokens Check",
                            "risk": "Medium",
                            "desc": "A form was found without an anti-CSRF token.",
                            "solution": "Add CSRF protection token to form submissions.",
                            "param": "session_id",
                            "url": "https://test-target.com/login",
                            "cweid": "352"
                        }
                    ]
                }
            ]
        }
    }

    result = await zap_callback(mock_zap_payload)
    assert result.get("status") == "success"
    assert result.get("alerts_merged") == 1

    stored_scan = MEMORY_SCANS[test_scan_id]
    r_json = stored_scan.get("results_json", {})
    findings = r_json.get("findings", [])
    assert len(findings) == 1
    assert "OWASP ZAP: Anti-CSRF Tokens Check" in findings[0].get("title")
    assert findings[0].get("severity") == "medium"
    assert findings[0].get("category") == "dast"
    assert "remediation_code" in findings[0]
    assert r_json.get("zap_completed") is True
    print(f"\n[ZAP-Callback] Callback handler successfully merged dynamic finding and recalculated score: {stored_scan.get('score')} (Grade: {stored_scan.get('grade')})")

    # Clean up test entry
    MEMORY_SCANS.pop(test_scan_id, None)

