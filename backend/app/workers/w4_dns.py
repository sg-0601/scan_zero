import dns.resolver
import asyncio
from app.workers.base import BaseWorker

class DnsWorker(BaseWorker):
    name = "w4_dns"
    category = "dns"

    async def run(self, domain: str, url: str) -> dict:
        findings = []
        raw_data = {}

        loop = asyncio.get_event_loop()

        # 1. SPF Check
        spf_data = await loop.run_in_executor(None, self.check_spf, domain)
        raw_data["spf"] = spf_data
        if not spf_data.get("found"):
            findings.append({
                "title": "Missing SPF (Sender Policy Framework) Record",
                "description": "No SPF TXT record was discovered. Mail servers cannot verify whether outgoing emails legitimately originate from your servers.",
                "severity": "high",
                "category": "dns",
                "evidence": {"domain": domain, "spf": "None"}
            })
        elif spf_data.get("mechanism") in ["?all", "+all"]:
            findings.append({
                "title": "Permissive SPF Record Allowed",
                "description": f"The SPF record ends with '{spf_data.get('mechanism')}', allowing unauthorized servers to spoof your domain.",
                "severity": "medium",
                "category": "dns",
                "evidence": {"record": spf_data.get("record")}
            })

        # 2. DMARC Check
        dmarc_data = await loop.run_in_executor(None, self.check_dmarc, domain)
        raw_data["dmarc"] = dmarc_data
        if not dmarc_data.get("found"):
            findings.append({
                "title": "Missing DMARC Record",
                "description": "No DMARC policy published. Attackers can forge phishing emails appearing from your brand without receiving bounce reports.",
                "severity": "high",
                "category": "dns",
                "evidence": {"domain": f"_dmarc.{domain}", "dmarc": "None"}
            })
        elif dmarc_data.get("policy") == "none":
            findings.append({
                "title": "DMARC Policy Set to 'none' (Monitoring Only)",
                "description": "DMARC policy is currently set to 'p=none'. Unauthenticated spoofed emails will still be delivered to users' inboxes.",
                "severity": "medium",
                "category": "dns",
                "evidence": {"record": dmarc_data.get("record"), "policy": "none"}
            })

        # 3. MX Records Check
        mx_data = await loop.run_in_executor(None, self.check_mx, domain)
        raw_data["mx"] = mx_data

        # 4. DNSSEC Check
        dnssec_data = await loop.run_in_executor(None, self.check_dnssec, domain)
        raw_data["dnssec"] = dnssec_data
        if not dnssec_data.get("active"):
            findings.append({
                "title": "DNSSEC Validation Inactive",
                "description": "Domain lacks cryptographically signed DNSSEC records, exposing DNS lookups to cache-poisoning / MITM spoofing.",
                "severity": "low",
                "category": "dns",
                "evidence": {"dnssec": "No DS or DNSKEY records found"}
            })

        return {"findings": findings, "raw_data": raw_data}

    def check_spf(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    mechanism = "-all" if "-all" in txt else "~all" if "~all" in txt else "?all" if "?all" in txt else "none"
                    return {"found": True, "record": txt, "mechanism": mechanism}
            return {"found": False}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def check_dmarc(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    policy = "reject" if "p=reject" in txt else "quarantine" if "p=quarantine" in txt else "none" if "p=none" in txt else "unknown"
                    return {"found": True, "record": txt, "policy": policy}
            return {"found": False}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def check_mx(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            records = [str(r.exchange).rstrip('.') for r in answers]
            return {"has_mx": len(records) > 0, "records": records[:3]}
        except Exception:
            return {"has_mx": False, "records": []}

    def check_dnssec(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(domain, 'DS')
            return {"active": len(answers) > 0}
        except Exception:
            return {"active": False}
