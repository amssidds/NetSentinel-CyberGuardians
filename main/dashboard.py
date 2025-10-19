# dashboard.py
from flask import Flask, render_template, jsonify, request
import sqlite3, os
import requests  # proxy to the API handler (port 5000)
import engine_config as cfg

app = Flask(__name__)

API_BASE = "http://127.0.0.1:5000"  # api_handler.py runs here

# === Local helpers (read-only from the same DB) ===
def get_logs(limit=200):
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT query_id, domain, client_ip, score, verdict, ts,
               tier2_score, tier2_enrichment, tier2_intel
        FROM logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()

    data = []
    for r in rows:
        entry = {
            "query_id": r[0],
            "domain": r[1],
            "client_ip": r[2],
            "score": r[3],
            "verdict": r[4],
            "timestamp": r[5],
        }
        # Tier-2 fields (may be NULL)
        if len(r) > 6:
            entry["tier2_score"] = r[6]
            entry["tier2_enrichment"] = r[7]
            entry["tier2_intel"] = r[8]
        data.append(entry)
    return data

def read_list(fname):
    if not os.path.exists(fname):
        return []
    with open(fname) as f:
        return [x.strip() for x in f if x.strip()]

# === UI ===
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# === Local JSON (readers) ===
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

# === Proxies to API handler (writes / compute) ===
@app.route("/api/report/<query>")
def api_report(query):
    try:
        r = requests.get(f"{API_BASE}/report/{query}", timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"proxy report failed: {e}"}), 502

# Tier-2 (used by 🔍)
@app.route("/api/tier2/<query_id>")
def api_tier2(query_id):
    try:
        r = requests.get(f"{API_BASE}/api/tier2/{query_id}", timeout=20)
        ctype = r.headers.get("Content-Type", "application/json")
        return (r.text, r.status_code, {"Content-Type": ctype})
    except Exception as e:
        return jsonify({"error": f"proxy tier2 failed: {e}"}), 502

# NEW: delete one log row
@app.route("/api/logs/delete", methods=["POST"])
def api_logs_delete_proxy():
    try:
        r = requests.post(f"{API_BASE}/api/logs/delete",
                          json=request.get_json(silent=True), timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"proxy logs.delete failed: {e}"}), 502

# NEW: clear logs by scope (blocked|allowed|all)
@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear_proxy():
    try:
        r = requests.post(f"{API_BASE}/api/logs/clear",
                          json=request.get_json(silent=True), timeout=20)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"proxy logs.clear failed: {e}"}), 502

# (optional — keep list write proxies if you still use them elsewhere)
@app.route("/api/lists/add", methods=["POST"])
def api_lists_add_proxy():
    try:
        r = requests.post(f"{API_BASE}/api/lists/add",
                          json=request.get_json(silent=True), timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"proxy add failed: {e}"}), 502

@app.route("/api/lists/remove", methods=["POST"])
def api_lists_remove_proxy():
    try:
        r = requests.post(f"{API_BASE}/api/lists/remove",
                          json=request.get_json(silent=True), timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"proxy remove failed: {e}"}), 502

@app.route("/api/lists/clear", methods=["POST"])
def api_lists_clear_proxy():
    try:
        r = requests.post(f"{API_BASE}/api/lists/clear",
                          json=request.get_json(silent=True), timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"proxy clear failed: {e}"}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
