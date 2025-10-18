# engine.py
import os
import json
import sqlite3
import datetime
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import engine_config as cfg


# --- Ensure DB and folders exist ---
os.makedirs(cfg.LISTS_DIR, exist_ok=True)
os.makedirs(cfg.REPORTS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(cfg.DB_PATH), exist_ok=True)


def ensure_db():
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id TEXT,
            domain TEXT,
            client_ip TEXT,
            score INTEGER,
            verdict TEXT,
            reasons TEXT,
            modules_result TEXT,
            ts TEXT
        )
    """)
    conn.commit()
    conn.close()


# --- Utils ---
def new_query_id():
    return "QX-" + str(uuid.uuid4())[:8]


def in_list(fname, domain):
    if not os.path.exists(fname):
        return False
    with open(fname) as f:
        return domain.strip() in [x.strip() for x in f]


def add_to_list(fname, domain):
    with open(fname, "a+") as f:
        f.seek(0)
        lines = [line.strip() for line in f]
        if domain not in lines:
            f.write(domain + "\n")


def call_module(name, url, payload):
    result = {"ok": False, "flag": 0, "score": 0, "reason": "no-response"}
    try:
        r = requests.post(url, json=payload, timeout=cfg.HTTP_TIMEOUT_SECONDS)
        if r.status_code == 200:
            data = r.json()
            flag = int(data.get("flag", data.get("score", 0)))
            reason = data.get("reason", "ok")
            result = {"ok": True, "flag": flag, "score": flag, "reason": reason}
    except Exception as e:
        result["reason"] = f"error:{e}"
    return result


def write_report(query_id, module, domain, data):
    path = f"{cfg.REPORTS_DIR}/{query_id}_{module}_{domain.replace('/', '_')}.json"
    data.update({
        "query_id": query_id,
        "module": module,
        "domain": domain
    })
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def aggregate_results(modules_results):
    total = 0
    reasons = []
    for name, res in modules_results.items():
        weight = cfg.MODULE_WEIGHTS.get(name, 1)
        flag = res.get("flag", 0)
        total += weight * (1 if flag else 0)
        reasons.append(f"{name}:{'FLAG' if flag else 'OK'}({res.get('reason','')})")
    verdict = "BLOCK" if total >= cfg.DECISION_THRESHOLD else "ALLOW"
    return total, verdict, "; ".join(reasons)


def log_decision(query_id, domain, client_ip, score, verdict, reasons, modules_results):
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (query_id, domain, client_ip, score, verdict, reasons, modules_result, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (query_id, domain, client_ip, score, verdict, reasons,
          json.dumps(modules_results), datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# --- Main Evaluation ---
def evaluate_domain(domain, client_ip="unknown"):
    ensure_db()
    query_id = new_query_id()

    if in_list(cfg.ALLOWLIST_FILE, domain):
        verdict, score, reasons = "ALLOW", 0, "allowlisted"
        log_decision(query_id, domain, client_ip, score, verdict, reasons, {})
        return {"query_id": query_id, "domain": domain, "verdict": verdict, "reason": reasons}

    if in_list(cfg.BLOCKLIST_FILE, domain):
        verdict, score, reasons = "BLOCK", cfg.DECISION_THRESHOLD, "blocklisted"
        log_decision(query_id, domain, client_ip, score, verdict, reasons, {})
        return {"query_id": query_id, "domain": domain, "verdict": verdict, "reason": reasons}

    # Run modules
    payload = {"query_id": query_id, "domain": domain, "client_ip": client_ip}
    modules_results = {}
    with ThreadPoolExecutor(max_workers=len(cfg.MODULE_ENDPOINTS)) as executor:
        futures = {executor.submit(call_module, name, url, payload): name
                   for name, url in cfg.MODULE_ENDPOINTS.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            result = fut.result()
            modules_results[name] = result
            write_report(query_id, name, domain, result)

    score, verdict, reasons = aggregate_results(modules_results)
    add_to_list(cfg.BLOCKLIST_FILE if verdict == "BLOCK" else cfg.ALLOWLIST_FILE, domain)
    log_decision(query_id, domain, client_ip, score, verdict, reasons, modules_results)

    return {
        "query_id": query_id,
        "domain": domain,
        "client_ip": client_ip,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "modules": modules_results
    }
