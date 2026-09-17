def generate_fixes(findings: list) -> list:
    """Generate appropriate fix code for each finding."""
    for f in findings:
        title = f.get("title", "").lower()
        
        if "hsts" in title:
            f["remediation_text"] = "Add Strict-Transport-Security header."
            f["remediation_code"] = generate_nginx_config(f)
        elif "spf" in title:
            f["remediation_text"] = "Add SPF record to DNS."
            f["remediation_code"] = generate_dns_records(f)
        else:
            f["remediation_text"] = "Consult standard security guidelines."
            f["remediation_code"] = ""
            
    return findings

def generate_nginx_config(finding: dict) -> str:
    return "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"

def generate_apache_config(finding: dict) -> str:
    return "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'"

def generate_dns_records(finding: dict) -> str:
    return 'v=spf1 mx a -all'

def generate_cloudflare_waf(finding: dict) -> str:
    return "{}"
