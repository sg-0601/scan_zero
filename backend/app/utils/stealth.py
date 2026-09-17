import subprocess
import shutil

def detect_waf(domain: str) -> dict:
    """Detect WAF using wafw00f."""
    result = {"waf_detected": None, "waf_name": None, "details": "wafw00f not installed or failed."}
    
    if not shutil.which("wafw00f"):
        return result
        
    try:
        # Run wafw00f
        proc = subprocess.run(
            ["wafw00f", domain],
            capture_output=True,
            text=True,
            timeout=15
        )
        output = proc.stdout.lower()
        
        if "is behind" in output and "waf" in output:
            result["waf_detected"] = True
            # Simple heuristic to extract WAF name
            lines = output.split('\n')
            for line in lines:
                if "is behind" in line:
                    result["waf_name"] = line.split("is behind")[-1].strip()
                    break
            result["details"] = "WAF detected."
        elif "no waf detected" in output:
            result["waf_detected"] = False
            result["details"] = "No WAF detected."
            
    except Exception as e:
        result["details"] = f"Error running WAF detection: {str(e)}"
        
    return result
