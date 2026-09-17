import re
from urllib.parse import urlparse

def validate_url(url: str) -> dict:
    """Validate URL format, add https:// if missing, extract domain."""
    if not url:
        return {"valid": False, "url": "", "domain": "", "error": "URL cannot be empty."}

    original_url = url
    if not re.match(r'^https?://', url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return {"valid": False, "url": url, "domain": "", "error": "Invalid URL format."}
            
        # Basic regex to check domain validity
        if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain) and domain != "localhost":
             return {"valid": False, "url": url, "domain": domain, "error": "Invalid domain format."}
             
        return {"valid": True, "url": url, "domain": domain, "error": None}
    except Exception as e:
        return {"valid": False, "url": original_url, "domain": "", "error": str(e)}
