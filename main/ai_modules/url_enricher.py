import hashlib
import requests
from urllib.parse import urlparse

def get_favicon_hash(url):
    try:
        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        r = requests.get(favicon_url, timeout=2, stream=True)
        if r.status_code == 200:
            return hashlib.md5(r.content).hexdigest()
    except Exception:
        pass
    return None

def enrich_url(domain):
    result = {
        "final_url": None,
        "redirects": 0,
        "status_code": None,
        "content_length": None,
        "favicon_hash": None,
        "meta_score": 0.0
    }
    try:
        r = requests.get(f"http://{domain}", timeout=3, allow_redirects=True)
        result["final_url"] = r.url
        result["redirects"] = len(r.history)
        result["status_code"] = r.status_code
        result["content_length"] = len(r.content)
        result["favicon_hash"] = get_favicon_hash(r.url)
        if result["redirects"] > 2: result["meta_score"] += 0.3
        if result["content_length"] < 500: result["meta_score"] += 0.2
        if not result["favicon_hash"]: result["meta_score"] += 0.2
        if any(x in r.url for x in ["login", "verify", "secure"]):
            result["meta_score"] += 0.3
    except Exception:
        result["meta_score"] = 0.1
    return result
