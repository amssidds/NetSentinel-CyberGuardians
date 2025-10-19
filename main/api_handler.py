# api_handler.py
from flask import Flask, request, jsonify
import sqlite3, json, glob, os
from engine import evaluate_domain, ensure_db
import engine_config as cfg
from ai_modules.threat_intel import vt_check
from ai_modules.url_enricher import enrich_url

app = Flask(__name__)
ensure_db()

# ---------- Utility helpers ----------
def _read_list(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [x.strip() for x in f if x.strip()]

def _write_list(path, items):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    items = sorted(set(x.strip().lower() for x in items if x.strip()))
    with open(path, "w") as f:
        for d in items:
            f.write(d + "\n")

def _get_log_by_qid(qid):
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT query_id, domain, client_ip, score, verdict, ts,
               COALESCE(tier2_intel, ''), COALESCE(tier2_enrichment, ''), COALESCE(tier2_score, 0.0)
          FROM logs
         WHERE query_id = ?
         ORDER BY id DESC LIMIT 1
    """, (qid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "query_id": row[0],
        "domain": row[1],
        "client_ip": row[2],
        "score": row[3],
        "verdict": row[4],
        "timestamp": row[5],
        "tier2_intel": json.loads(row[6]) if row[6] else None,
        "tier2_enrichment": json.loads(row[7]) if row[7] else None,
        "tier2_score": row[8],
    }

def _update_tier2(query_id, intel_obj, enrich_obj, score):
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        UPDATE logs
           SET tier2_intel = ?,
               tier2_enrichment = ?,
               tier2_score = ?
         WHERE query_id = ?
    """, (json.dumps(intel_obj or {}), json.dumps(enrich_obj or {}), float(score or 0.0), query_id))
    conn.commit()
    conn.close()

# ---------- Routes ----------
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
            "/api/logs/delete",
            "/api/logs/clear",
            "/api/tier2/<query_id>",
            "/report/<query_or_domain>"
        ]
    })

@app.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.get_json(force=True)
    domain = data.get("domain")
    client_ip = data.get("client_ip", request.remote_addr or "unknown")
    if not domain:
        return jsonify({"error": "Missing 'domain'"}), 400

    try:
        result = evaluate_domain(domain, client_ip)
    except Exception as e:
        return jsonify({"error": f"Evaluation failed: {str(e)}"}), 503

    # --- Tier-2: enrichment + threat intel ---
    enrichment = {}
    intel = {}
    try:
        enrichment = enrich_url(domain) or {}
    except Exception as e:
        enrichment = {"meta_score": 0.0, "error": str(e)}

    try:
        intel = vt_check(domain) or {}
    except Exception as e:
        intel = {"intel_score": 0.0, "error": str(e)}

    meta_score = float(enrichment.get("meta_score", 0.0) or 0.0)
    intel_score = float(intel.get("intel_score", 0.0) or 0.0)
    tier2_score = round((meta_score + intel_score) / 2, 3)

    result["tier2_enrichment"] = enrichment
    result["tier2_intel"] = intel
    result["tier2_score"] = tier2_score

    avg_score = float(result.get("score", 0.0) or 0.0)
    result["score"] = round((avg_score * 0.9) + (tier2_score * 0.1), 2)
    result["verdict"] = (
        "MALICIOUS" if result["score"] > 0.7
        else "SUSPICIOUS" if result["score"] > 0.5
        else "LEGIT"
    )
    return jsonify(result)

@app.route("/api/logs", methods=["GET"])
@app.route("/logs", methods=["GET"])
def logs():
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

@app.route("/api/lists", methods=["GET"])
def api_lists():
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
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    list_type = data.get("type", "").strip().lower()
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
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    list_type = data.get("type", "").strip().lower()
    if not domain or list_type not in ("allow", "block"):
        return jsonify({"error": "Bad request"}), 400
    path = cfg.ALLOWLIST_FILE if list_type == "allow" else cfg.BLOCKLIST_FILE
    items = [x for x in _read_list(path) if x != domain]
    _write_list(path, items)
    return jsonify({"ok": True, "action": "removed", "domain": domain, "list": list_type})

@app.route("/api/lists/clear", methods=["POST"])
def api_lists_clear():
    data = request.get_json(force=True)
    list_type = data.get("type", "").strip().lower()
    if list_type not in ("allow", "block"):
        return jsonify({"error": "Bad request"}), 400
    path = cfg.ALLOWLIST_FILE if list_type == "allow" else cfg.BLOCKLIST_FILE
    open(path, "w").close()
    return jsonify({"ok": True, "action": "cleared", "list": list_type})

@app.route("/report/<query_or_domain>")
def get_report(query_or_domain):
    q = query_or_domain.strip()
    if q.startswith("QX-"):
        try:
            conn = sqlite3.connect(cfg.DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT query_id, domain, client_ip, score, verdict, reasons, modules_result, ts FROM logs WHERE query_id = ?", (q,))
            row = cur.fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "Query ID not found"}), 404
            qid, domain, cip, score, verdict, reasons, modules_json, ts = row
            modules = json.loads(modules_json) if modules_json else {}
            story = [f"The query **{qid}** from client **{cip}** attempted to reach **{domain}** at {ts}."]
            story.append(f"The system classified this request with a **final verdict of {verdict.upper()}**, based on analyzer consensus and weighted risk scoring.")
            if modules:
                story.append("Here is how each analyzer contributed:")
                for mod, res in modules.items():
                    flag = "⚠️ Flagged" if int(res.get("flag", 0)) else "✅ Allowed"
                    label = res.get("label", "unknown").capitalize()
                    score_mod = res.get("score", "?")
                    reason = res.get("reason", "")
                    story.append(f"- **{mod.replace('_',' ').title()}** → {flag} as *{label}* (score={score_mod}). {reason}")
            story.append(f"🧾 **Final Verdict:** {verdict.upper()} with total score {score} (threshold {cfg.DECISION_THRESHOLD}).")
            return jsonify({"query_id": qid, "domain": domain, "narrative": "\n".join(story)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        pattern = os.path.join(cfg.REPORTS_DIR, f"*_{q}.json")
        files = glob.glob(pattern)
        if not files:
            return jsonify({"error": f"No reports found for domain {q}"}), 404
        story = [f"📊 Report summary for **{q}**:"]
        for fpath in files:
            base = os.path.basename(fpath)
            with open(fpath, "r") as f:
                data = json.load(f)
            module = data.get("module", os.path.splitext(base)[0])
            flag = "⚠️ Flagged" if int(data.get("flag", 0)) else "✅ Allowed"
            label = data.get("label", "unknown").capitalize()
            score_mod = data.get("score", "?")
            reason = data.get("reason", "")
            story.append(f"- **{module.replace('_',' ').title()}** → {flag} as *{label}* (score={score_mod}). {reason}")
        story.append("🧩 Combined verdict derived from analyzer modules.")
        return jsonify({"domain": q, "narrative": "\n".join(story)})

@app.route("/api/tier2/<query_id>")
def api_tier2(query_id):
    row = _get_log_by_qid(query_id)
    if not row:
        return jsonify({"error": "query_id not found"}), 404
    if row.get("tier2_intel") or row.get("tier2_enrichment"):
        return jsonify(row)

    domain = row["domain"]
    intel  = vt_check(domain)        # {positives, sources, intel_score}
    enrich = enrich_url(domain)      # {final_url, redirects, meta_score, favicon_hash, ...}

    intel_score = float((intel or {}).get("intel_score", 0.0) or 0.0)
    meta_score  = float((enrich or {}).get("meta_score", 0.0) or 0.0)
    t2_score    = round(min(intel_score*0.7 + meta_score*0.3, 1.0), 3)

    _update_tier2(query_id, intel, enrich, t2_score)
    row = _get_log_by_qid(query_id)
    return jsonify(row)

# ---------- NEW: log delete / clear ----------
@app.route("/api/logs/delete", methods=["POST"])
def api_logs_delete():
    data = request.get_json(force=True) or {}
    qid = (data.get("query_id") or "").strip()
    if not qid:
        return jsonify({"error": "query_id required"}), 400
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM logs WHERE query_id = ?", (qid,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "deleted": int(deleted)})

@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    data = request.get_json(force=True) or {}
    scope = (data.get("scope") or "all").lower()
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    if scope == "blocked":
        cur.execute("DELETE FROM logs WHERE verdict IN ('BLOCK','MALICIOUS')")
    elif scope == "allowed":
        cur.execute("DELETE FROM logs WHERE verdict IN ('ALLOW','LEGIT')")
    else:
        cur.execute("DELETE FROM logs")
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "deleted": int(deleted), "scope": scope})

# ---------- Main ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
