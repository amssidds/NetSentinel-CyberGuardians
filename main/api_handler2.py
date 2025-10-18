# api_handler.py
from flask import Flask, request, jsonify
import sqlite3, json, glob, os
from engine import evaluate_domain, ensure_db
import engine_config as cfg

app = Flask(__name__)
ensure_db()


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "msg": "NetSentinel API running",
        "modules": list(cfg.MODULE_ENDPOINTS.keys()),
        "endpoints": ["/evaluate", "/logs", "/lists", "/report/<query_id>"]
    })


@app.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.get_json(force=True)
    domain = data.get("domain")
    client_ip = data.get("client_ip", request.remote_addr or "unknown")
    if not domain:
        return jsonify({"error": "Missing 'domain'"}), 400
    return jsonify(evaluate_domain(domain, client_ip))


@app.route("/logs", methods=["GET"])
def logs():
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT query_id, domain, client_ip, score, verdict, ts FROM logs ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    return jsonify([{
        "query_id": r[0], "domain": r[1], "client_ip": r[2],
        "score": r[3], "verdict": r[4], "timestamp": r[5]
    } for r in rows])


@app.route("/lists", methods=["GET"])
def lists():
    with open(cfg.ALLOWLIST_FILE, "a+") as f:
        f.seek(0); allowlist = [x.strip() for x in f if x.strip()]
    with open(cfg.BLOCKLIST_FILE, "a+") as f:
        f.seek(0); blocklist = [x.strip() for x in f if x.strip()]
    return jsonify({"allowlist": allowlist, "blocklist": blocklist})


@app.route("/report/<query_id>", methods=["GET"])
def report(query_id):
    pattern = os.path.join(cfg.REPORTS_DIR, f"{query_id}_*.json")
    files = glob.glob(pattern)
    reports = {}
    for fpath in files:
        with open(fpath) as f:
            reports[os.path.basename(fpath)] = json.load(f)
    return jsonify({"query_id": query_id, "reports": reports})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
