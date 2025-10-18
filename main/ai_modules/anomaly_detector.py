# ai_modules/anomaly_detector.py
# Simple frequency-based anomaly detector for NetSentinel.
# Flags domains rarely or never seen before in dns_logs.db.

import os, sqlite3, time
from flask import Flask, request, jsonify

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "database", "dns_logs.db")

app = Flask(__name__)

def get_recent_activity(limit_minutes=120):
    """Return a dictionary {(client_ip, domain): count} of recent queries."""
    if not os.path.exists(DB_PATH):
        return {}
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        since = time.time() - (limit_minutes * 60)
        c.execute("SELECT client_ip, domain, ts FROM logs")
        data = c.fetchall()
        conn.close()
        counts = {}
        for ip, domain, ts in data:
            key = (ip or "", domain or "")
            counts[key] = counts.get(key, 0) + 1
        return counts
    except Exception as e:
        print("[!] DB error:", e)
        return {}

@app.route("/", methods=["GET"])
def health():
    return jsonify({"module": "anomaly_detector", "status": "ok"}), 200

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(force=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    client_ip = (data.get("client_ip") or "").strip()

    if not domain:
        return jsonify({
            "module": "anomaly_detector",
            "ok": False,
            "flag": 0,
            "score": 0,
            "label": "error",
            "reasons": ["No domain provided"]
        }), 200

    # Load frequency counts
    freq_map = get_recent_activity(limit_minutes=240)
    key = (client_ip, domain)
    count = freq_map.get(key, 0)

    # --- Scoring logic ---
    if count == 0:
        score = 10
        label = "high"
        reasons = ["domain never seen before from this client"]
        flag = 1
    elif count <= 2:
        score = 5
        label = "medium"
        reasons = [f"domain queried rarely ({count} times)"]
        flag = 1
    else:
        score = 0
        label = "low"
        reasons = [f"domain seen {count} times recently"]
        flag = 0

    return jsonify({
        "module": "anomaly_detector",
        "ok": True,
        "flag": flag,
        "score": score,
        "label": label,
        "reasons": reasons,
        "details": {"recent_count": count}
    }), 200


if __name__ == "__main__":
    print("[+] Anomaly Detector microservice running on 0.0.0.0:6002 (/check)")
    app.run(host="0.0.0.0", port=6002)
