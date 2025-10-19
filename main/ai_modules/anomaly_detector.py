# ai_modules/anomaly_detector.py
# API-based anomaly detector using VirusTotal for domain reputation
# No local database logic; results are fetched in real time.

import os
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load .env file for API key
load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3/domains/{}"

app = Flask(__name__)

def check_domain_virustotal(domain):
    """Query VirusTotal domain API and return detection stats."""
    if not VT_API_KEY:
        raise RuntimeError("VIRUSTOTAL_API_KEY not set in .env")

    headers = {"x-apikey": VT_API_KEY}
    url = VT_BASE_URL.format(domain)

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            ratio = (malicious + suspicious) / (total or 1)
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "ratio": ratio
            }
        elif r.status_code == 404:
            # Domain not found on VT (new / unseen)
            return {"error": "not_found"}
        else:
            return {"error": f"VT error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

@app.route("/", methods=["GET"])
def health():
    return jsonify({"module": "anomaly_detector_api", "status": "ok"}), 200

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(force=True) or {}
    domain = (data.get("domain") or "").strip().lower()

    if not domain:
        return jsonify({
            "module": "anomaly_detector_api",
            "ok": False,
            "flag": 0,
            "score": 0,
            "label": "error",
            "reasons": ["No domain provided"]
        }), 200

    vt_result = check_domain_virustotal(domain)
    reasons = []

    if "error" in vt_result:
        flag = 0
        score = 0
        label = "unknown"
        reasons.append(vt_result["error"])
    else:
        ratio = vt_result["ratio"]
        if ratio > 0.05:  # >5% detections → suspicious
            flag = 1
            score = round(ratio * 10, 2)
            label = "malicious" if vt_result["malicious"] > 0 else "suspicious"
            reasons.append(f"{vt_result['malicious']} engines marked as malicious")
        else:
            flag = 0
            score = 0
            label = "clean"
            reasons.append("No detections on VirusTotal")

    return jsonify({
        "module": "anomaly_detector_api",
        "ok": True,
        "flag": flag,
        "score": score,
        "label": label,
        "reasons": reasons,
        "details": vt_result
    }), 200

if __name__ == "__main__":
    print("[+] API-Based Anomaly Detector running on 0.0.0.0:6002 (/check)")
    app.run(host="0.0.0.0", port=6002)
