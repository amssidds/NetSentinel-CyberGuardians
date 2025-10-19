import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_API_KEY_HERE")
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"

def vt_check(domain: str):
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(VT_DOMAIN_URL.format(domain), headers=headers, timeout=6)
        if r.status_code == 200:
            data = r.json()
            analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = analysis.get("malicious", 0) + analysis.get("suspicious", 0)

            sources = []
            results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            for engine, result in results.items():
                if result["category"] in ("malicious", "suspicious"):
                    sources.append(engine)

            intel_score = min(positives * 0.1, 1.0)

            return {
                "positives": positives,
                "sources": sources[:10],
                "intel_score": intel_score
            }
        else:
            return {"positives": 0, "sources": [], "intel_score": 0.0}
    except Exception as e:
        print(f"[ThreatIntel] Error checking {domain}: {e}")
        return {"positives": 0, "sources": [], "intel_score": 0.0}
