import asyncio
import socket
import ssl
from datetime import datetime
import httpx
from app.workers.base import BaseWorker

class TlsWorker(BaseWorker):
    name = "w2_tls"
    category = "tls"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        # 1. Check Cleartext HTTP Redirect
        redirect_secure = await self.check_cleartext_redirect(domain)
        raw_data["redirect_secure"] = redirect_secure
        if not redirect_secure:
            findings.append({
                "title": "Insecure HTTP connection allowed",
                "description": "Port 80 is open but does not enforce an immediate redirect to HTTPS.",
                "severity": "medium",
                "evidence": {"port": 80, "protocol": "HTTP"}
            })

        # 2. Native TLS & Certificate Audit
        tls_data = await self.tls_audit(domain)
        raw_data["tls"] = tls_data

        if tls_data.get("status") == "success":
            tls_version = tls_data.get("version", "")
            cipher = tls_data.get("cipher", "")
            days_left = tls_data.get("days_until_expiry", 999)

            # Check TLS version
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                findings.append({
                    "title": f"Deprecated {tls_version} Detected",
                    "description": f"The target supports {tls_version}, which is deprecated and susceptible to downgrade attacks.",
                    "severity": "critical",
                    "evidence": {"tls_version": tls_version}
                })

            # Check certificate expiry
            if days_left <= 0:
                findings.append({
                    "title": "SSL Certificate Has Expired",
                    "description": "The TLS certificate for this domain has expired, causing browser security warnings.",
                    "severity": "critical",
                    "evidence": {"days_until_expiry": days_left}
                })
            elif days_left < 15:
                findings.append({
                    "title": "SSL Certificate Expiring Soon",
                    "description": f"The TLS certificate expires in {days_left} days. Renew immediately.",
                    "severity": "high",
                    "evidence": {"days_until_expiry": days_left}
                })
            elif days_left < 30:
                findings.append({
                    "title": "SSL Certificate Approaching Expiration",
                    "description": f"The TLS certificate expires in {days_left} days.",
                    "severity": "medium",
                    "evidence": {"days_until_expiry": days_left}
                })
        else:
            findings.append({
                "title": "TLS Connection Audit Incomplete",
                "description": tls_data.get("error", "Unable to establish direct TLS handshake on port 443."),
                "severity": "info",
                "evidence": {"error": tls_data.get("error")}
            })

        return {"findings": findings, "raw_data": raw_data}

    async def check_cleartext_redirect(self, domain: str) -> bool:
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
                resp = await client.get(f"http://{domain}", timeout=5.0)
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location.startswith("https://"):
                        return True
            return False
        except Exception:
            # If port 80 is closed or refuses connections, that is inherently safe
            return True

    async def tls_audit(self, domain: str) -> dict:
        """Perform native, zero-dependency TLS handshake and certificate validation."""
        def _sync_audit():
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=6.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        version = ssock.version()
                        cipher = ssock.cipher()

                        # Parse expiry date
                        not_after_str = cert.get("notAfter", "")
                        days_left = 365
                        if not_after_str:
                            # Format: 'May 15 12:00:00 2026 GMT'
                            expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expire_dt - datetime.utcnow()).days

                        return {
                            "status": "success",
                            "version": version,
                            "cipher": cipher[0] if cipher else "Unknown",
                            "bits": cipher[2] if cipher and len(cipher) > 2 else 0,
                            "issuer": dict(x[0] for x in cert.get("issuer", ())),
                            "subject": dict(x[0] for x in cert.get("subject", ())),
                            "expires": not_after_str,
                            "days_until_expiry": days_left
                        }
            except Exception as e:
                return {"status": "error", "error": str(e)}

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_audit)
