import os
import json
import sqlite3
import datetime
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import engine_config as cfg
from ai_modules.url_enricher import enrich_url  


# --- Ensure DB and folders exist ---
os.makedirs(os.path.join(os.path.dirname(cfg.DB_PATH), "lists"), exist_ok=True)
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
            score REAL,
            verdict TEXT,
            reasons TEXT,
            modules_result TEXT,
            tier2_enrichment TEXT,
            tier2_intel TEXT,
            tier2_score REAL,
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


# --- Main Evaluation ---
def evaluate_domain(domain, client_ip="unknown"):
    ensure_db()
    query_id = new_query_id()

    # --- Check Allow/Block Lists ---
    if in_list(cfg.ALLOWLIST_FILE, domain):
        verdict, score, reasons = "ALLOW", 0, "allowlisted"
        _log_simple(query_id, domain, client_ip, score, verdict, reasons)
        return {"query_id": query_id, "domain": domain, "verdict": verdict, "reason": reasons}

    if in_list(cfg.BLOCKLIST_FILE, domain):
        verdict, score, reasons = "BLOCK", cfg.DECISION_THRESHOLD, "blocklisted"
        _log_simple(query_id, domain, client_ip, score, verdict, reasons)
        return {"query_id": query_id, "domain": domain, "verdict": verdict, "reason": reasons}

    # --- Tier 1: Run core AI modules ---
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

    # --- Tier 2: URL Enrichment (Redirects, Metadata, Favicon) ---
    try:
        enrichment_data = enrich_url(domain)
        tier2_enrichment_json = json.dumps(enrichment_data)
        print(f"[Tier2] Enricher: {domain} -> "
              f"{enrichment_data.get('redirects')} hops, "
              f"final {enrichment_data.get('final_url')}, "
              f"meta {enrichment_data.get('meta_score')}")
    except Exception as e:
        print(f"[Tier2] Enricher failed for {domain}: {e}")
        enrichment_data = {}
        tier2_enrichment_json = json.dumps({})

    # --- Log final decision + enrichment ---
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (query_id, domain, client_ip, score, verdict, reasons,
                          modules_result, tier2_enrichment, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        query_id, domain, client_ip, score, verdict, reasons,
        json.dumps(modules_results), tier2_enrichment_json,
        datetime.datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

    return {
        "query_id": query_id,
        "domain": domain,
        "client_ip": client_ip,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "modules": modules_results,
        "tier2_enrichment": enrichment_data
    }


def _log_simple(query_id, domain, client_ip, score, verdict, reasons):
    conn = sqlite3.connect(cfg.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (query_id, domain, client_ip, score, verdict, reasons, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (query_id, domain, client_ip, score, verdict, reasons,
          datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
