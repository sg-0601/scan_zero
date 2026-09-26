import httpx
from app.workers.base import BaseWorker

class HeadersWorker(BaseWorker):
    name = "w3_headers"
    category = "headers"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12.0) as client:
                resp = await client.get(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_data["headers"] = dict(resp.headers)
                raw_data["status_code"] = resp.status_code

                active_headers = []
                missing_headers = []

                # 1. Content-Security-Policy
                csp = headers.get("content-security-policy")
                if not csp:
                    missing_headers.append("Content-Security-Policy")
                    findings.append({
                        "title": "Missing Content-Security-Policy (CSP)",
                        "description": "Content-Security-Policy restricts which resources (scripts, images, styles) can be loaded, mitigating XSS.",
                        "severity": "medium",
                        "category": "headers",
                        "evidence": {"header": "Content-Security-Policy", "status": "Not Found"}
                    })
                else:
                    active_headers.append("Content-Security-Policy")
                    if "unsafe-inline" in csp.lower():
                        findings.append({
                            "title": "CSP Allows Unsafe Inline Scripts",
                            "description": "Content-Security-Policy permits 'unsafe-inline' which reduces protection against Cross-Site Scripting (XSS).",
                            "severity": "low",
                            "category": "headers",
                            "evidence": {"csp_directive": "'unsafe-inline' found in policy"}
                        })

                # 2. Strict-Transport-Security (HSTS)
                hsts = headers.get("strict-transport-security")
                if not hsts:
                    missing_headers.append("Strict-Transport-Security")
                    findings.append({
                        "title": "Missing HTTP Strict Transport Security (HSTS)",
                        "description": "Forces browsers to only interact with this website via HTTPS, eliminating SSL-stripping attack vectors.",
                        "severity": "high",
                        "category": "headers",
                        "evidence": {"header": "Strict-Transport-Security", "status": "Not Found"}
                    })
                else:
                    active_headers.append("Strict-Transport-Security")
                    hsts_lower = hsts.lower()
                    if "preload" not in hsts_lower:
                        findings.append({
                            "title": "HSTS Missing Preload Directive",
                            "description": "The HSTS header lacks the 'preload' flag for browser HSTS preload list inclusion.",
                            "severity": "low",
                            "category": "headers",
                            "evidence": {"hsts_value": hsts}
                        })

                # 3. X-Frame-Options
                xfo = headers.get("x-frame-options")
                if not xfo and ("frame-ancestors" not in (csp or "").lower()):
                    missing_headers.append("X-Frame-Options")
                    findings.append({
                        "title": "Missing X-Frame-Options (Clickjacking Risk)",
                        "description": "Allows other websites to embed this site inside an iframe, creating clickjacking vulnerability risks.",
                        "severity": "medium",
                        "category": "headers",
                        "evidence": {"header": "X-Frame-Options", "status": "Not Found"}
                    })
                else:
                    active_headers.append("X-Frame-Options")

                # 4. X-Content-Type-Options
                xcto = headers.get("x-content-type-options")
                if not xcto or xcto.lower() != "nosniff":
                    missing_headers.append("X-Content-Type-Options")
                    findings.append({
                        "title": "Missing X-Content-Type-Options: nosniff",
                        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
                        "severity": "low",
                        "category": "headers",
                        "evidence": {"header": "X-Content-Type-Options", "status": xcto or "Not Found"}
                    })
                else:
                    active_headers.append("X-Content-Type-Options")

                # 5. Referrer-Policy
                ref = headers.get("referrer-policy")
                if not ref:
                    missing_headers.append("Referrer-Policy")
                    findings.append({
                        "title": "Missing Referrer-Policy",
                        "description": "Governs which referrer information, sent in the Referer header, should be included with requests.",
                        "severity": "low",
                        "category": "headers",
                        "evidence": {"header": "Referrer-Policy", "status": "Not Found"}
                    })
                else:
                    active_headers.append("Referrer-Policy")

                # 6. Permissions-Policy
                perm = headers.get("permissions-policy")
                if not perm:
                    missing_headers.append("Permissions-Policy")
                else:
                    active_headers.append("Permissions-Policy")

                # 7. Cookie security flags check
                cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
                cookies_present = len(cookies) > 0
                insecure_cookies = []
                for c in cookies:
                    c_lower = c.lower()
                    if "secure" not in c_lower or "httponly" not in c_lower:
                        insecure_cookies.append(c.split(";")[0])
                if cookies_present and insecure_cookies:
                    findings.append({
                        "title": "Insecure Cookie Flags (Missing Secure or HttpOnly)",
                        "description": f"Cookies {insecure_cookies[:2]} lack Secure or HttpOnly flags, exposing them to XSS or eavesdropping.",
                        "severity": "medium",
                        "category": "headers",
                        "evidence": {"insecure_cookies": insecure_cookies}
                    })

                # 8. Server Banner & Technology Fingerprinting (OWASP Info Leakage)
                server_banner = headers.get("server")
                x_powered_by = headers.get("x-powered-by")

                if server_banner and any(c.isdigit() for c in server_banner):
                    findings.append({
                        "title": f"Server Version Disclosed ({server_banner})",
                        "description": f"Server header discloses software and exact version details ('{server_banner}'), assisting attackers with CVE targeting.",
                        "severity": "low",
                        "category": "headers",
                        "evidence": {"server": server_banner}
                    })

                if x_powered_by:
                    findings.append({
                        "title": f"Application Framework Fingerprint Disclosed (X-Powered-By: {x_powered_by})",
                        "description": f"The X-Powered-By header discloses backend runtime/framework ('{x_powered_by}').",
                        "severity": "low",
                        "category": "headers",
                        "evidence": {"x_powered_by": x_powered_by}
                    })

                raw_data["active_headers"] = active_headers
                raw_data["missing_headers"] = missing_headers
                raw_data["active_count"] = len(active_headers)
                raw_data["total_evaluated"] = len(active_headers) + len(missing_headers)
                raw_data["server_header"] = server_banner or "Hidden / Not Disclosed"
                raw_data["server_banner"] = server_banner
                raw_data["x_powered_by"] = x_powered_by
                raw_data["cookies_present"] = cookies_present
                raw_data["csp_has_frame_ancestors"] = "frame-ancestors" in (csp or "").lower()

        except Exception as e:
            raw_data["error"] = str(e)

        return {"findings": findings, "raw_data": raw_data}
