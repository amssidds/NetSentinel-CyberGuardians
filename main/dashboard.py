# dashboard.py
from flask import Flask, render_template, jsonify
import sqlite3, os
import engine_config as cfg
import requests  # used to proxy to the API handler (port 5000)

app = Flask(__name__)

API_BASE = "http://127.0.0.1:5000"

# === Utility: get logs ===
def get_logs(limit=50):
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT query_id, domain, client_ip, score, verdict, ts FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [
        {"query_id": r[0], "domain": r[1], "client_ip": r[2],
         "score": r[3], "verdict": r[4], "timestamp": r[5]}
        for r in rows
    ]

# === Utility: read allow/block lists ===
def read_list(fname):
    if not os.path.exists(fname):
        return []
    with open(fname) as f:
        return [x.strip() for x in f if x.strip()]

# === Routes ===
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/logs")
def api_logs():
    return jsonify(get_logs())

@app.route("/api/lists")
def api_lists():
    allowlist = read_list(cfg.ALLOWLIST_FILE)
    blocklist = read_list(cfg.BLOCKLIST_FILE)
    return jsonify({
        "allowlist": allowlist,
        "blocklist": blocklist,
        "allow_count": len(allowlist),
        "block_count": len(blocklist)
    })

# ---- NEW: proxy to API handler to avoid CORS / cross-port issues ----
@app.route("/api/report/<query>")
def api_report(query):
    try:
        r = requests.get(f"{API_BASE}/report/{query}", timeout=5)
        # Pass through API JSON and status code
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # Debug True only for local use
    app.run(host="0.0.0.0", port=8080, debug=True)
