# api_handler.py
# NetSentinel unified API backend
# Works with dashboard and AI modules

from flask import Flask, request, jsonify
import sqlite3, json, glob, os
from engine import evaluate_domain, ensure_db
import engine_config as cfg

app = Flask(__name__)
ensure_db()

# =========================================================
# === Helper Functions
# =========================================================

def _read_list(path):
    """Read domains from list file."""
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [x.strip() for x in f if x.strip()]

def _write_list(path, items):
    """Write domains safely (deduplicated + lowercase)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    items = sorted(set(x.strip().lower() for x in items if x.strip()))
    with open(path, "w") as f:
        for d in items:
            f.write(d + "\n")

# =========================================================
# === Root & Info
# =========================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "msg": "✅ NetSentinel API running",
        "modules": list(cfg.MODULE_ENDPOINTS.keys()),
        "endpoints": [
            "/evaluate",
            "/api/logs",
            "/api/lists",
            "/api/lists/add",
            "/api/lists/remove",
            "/api/lists/clear",
            "/report/<query_id>"
        ]
    })

# =========================================================
# === Evaluate Domain
# =========================================================

@app.route("/evaluate", methods=["POST"])
def evaluate():
    """Evaluate a domain via the detection engine."""
    data = request.get_json(force=True)
    domain = data.get("domain")
    client_ip = data.get("client_ip", request.remote_addr or "unknown")

    if not domain:
        return jsonify({"error": "Missing 'domain'"}), 400

    result = evaluate_domain(domain, client_ip)
    return jsonify(result)

# =========================================================
# === Logs
# =========================================================

@app.route("/api/logs", methods=["GET"])
@app.route("/logs", methods=["GET"])  # backward compatibility
def logs():
    """Return recent DNS evaluation logs from SQLite."""
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT query_id, domain, client_ip, score, verdict, ts FROM logs ORDER BY id DESC LIMIT 200")
    rows = cur.fetchall()
    conn.close()

    data = [{
        "query_id": r[0],
        "domain": r[1],
        "client_ip": r[2],
        "score": r[3],
        "verdict": r[4],
        "timestamp": r[5]
    } for r in rows]

    return jsonify(data)

# =========================================================
# === List Management
# =========================================================

@app.route("/api/lists", methods=["GET"])
def api_lists():
    """Return allowlist and blocklist contents."""
    allowlist = _read_list(cfg.ALLOWLIST_FILE)
    blocklist = _read_list(cfg.BLOCKLIST_FILE)
    return jsonify({
        "allowlist": allowlist,
        "blocklist": blocklist,
        "allow_count": len(allowlist),
        "block_count": len(blocklist)
    })


@app.route("/api/lists/add", methods=["POST"])
def api_lists_add():
    """Add domain to allowlist or blocklist."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    list_type = data.get("type", "").strip().lower()  # "allow" or "block"

    if not domain or list_type not in ("allow", "block"):
        return jsonify({"error": "Bad request"}), 400

    path = cfg.ALLOWLIST_FILE if list_type == "allow" else cfg.BLOCKLIST_FILE
    items = _read_list(path)

    if domain not in items:
        items.append(domain)
        _write_list(path, items)

    return jsonify({"ok": True, "action": "added", "domain": domain, "list": list_type})


@app.route("/api/lists/remove", methods=["POST"])
def api_lists_remove():
    """Remove domain from allowlist or blocklist."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    list_type = data.get("type", "").strip().lower()  # "allow" or "block"

    if not domain or list_type not in ("allow", "block"):
        return jsonify({"error": "Bad request"}), 400

    path = cfg.ALLOWLIST_FILE if list_type == "allow" else cfg.BLOCKLIST_FILE
    items = [x for x in _read_list(path) if x != domain]
    _write_list(path, items)

    return jsonify({"ok": True, "action": "removed", "domain": domain, "list": list_type})


@app.route("/api/lists/clear", methods=["POST"])
def api_lists_clear():
    """Clear entire allowlist or blocklist."""
    data = request.get_json(force=True)
    list_type = data.get("type", "").strip().lower()  # "allow" or "block"

    if list_type not in ("allow", "block"):
        return jsonify({"error": "Bad request"}), 400

    path = cfg.ALLOWLIST_FILE if list_type == "allow" else cfg.BLOCKLIST_FILE
    open(path, "w").close()  # empty the file safely
    return jsonify({"ok": True, "action": "cleared", "list": list_type})

# =========================================================
# === Reports
# =========================================================

@app.route("/report/<query_id>", methods=["GET"])
def report(query_id):
    """Return detailed report JSON for a specific query ID."""
    pattern = os.path.join(cfg.REPORTS_DIR, f"{query_id}_*.json")
    files = glob.glob(pattern)
    reports = {}

    for fpath in files:
        with open(fpath, "r") as f:
            reports[os.path.basename(fpath)] = json.load(f)

    return jsonify({"query_id": query_id, "reports": reports})

# =========================================================
# === Start Server
# =========================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
