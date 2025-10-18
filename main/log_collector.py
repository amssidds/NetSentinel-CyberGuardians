# log_collector.py
import json
import sqlite3
import time
import os
from engine_config import DB_PATH, ALLOWLIST_FILE, BLOCKLIST_FILE, DECISION_THRESHOLD

# simple ANSI colors (no extra deps)
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

def color_verdict(v):
    return (GREEN if v == "ALLOW" else RED) + v + RESET

def read_lists():
    allow = set()
    block = set()
    if os.path.exists(ALLOWLIST_FILE):
        with open(ALLOWLIST_FILE) as f:
            allow = {x.strip() for x in f if x.strip()}
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE) as f:
            block = {x.strip() for x in f if x.strip()}
    return allow, block

def follow_logs(poll_interval=2):
    last_id = 0
    print(CYAN + "🔍 Watching for new log entries..." + RESET)
    allowset, blockset = read_lists()

    while True:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, query_id, domain, client_ip, score, verdict, reasons, modules_result, ts
            FROM logs
            WHERE id > ?
            ORDER BY id
        """, (last_id,))
        rows = cur.fetchall()
        conn.close()

        for row in rows:
            (rid, qid, domain, cip, score, verdict, reasons, modules_json, ts) = row
            last_id = rid
            try:
                modules = json.loads(modules_json) if modules_json else {}
            except Exception:
                modules = {}

            # header line
            print()
            print(BOLD + f"[{ts}] {qid} | {domain} | {cip} → " + color_verdict(verdict) + RESET)
            print(DIM + f"  score={score}  threshold={DECISION_THRESHOLD}" + RESET)

            if not modules:
                # Stage 1 decision (lists)
                hit = "allowlist" if domain in allowset else ("blocklist" if domain in blockset else "lists")
                print(YELLOW + f"  Stage-1: lists → {hit} ({reasons})" + RESET)
            else:
                # Stage 2 decision (analyzers)
                print(YELLOW + "  Stage-2: analyzers" + RESET)
                for name, res in modules.items():
                    flag = int(res.get("flag", 0))
                    reason = res.get("reason", "")
                    status = (RED + "FLAG" + RESET) if flag else (GREEN + "OK" + RESET)
                    print(f"    • {name:<18} {status}  {DIM}{reason}{RESET}")

        time.sleep(poll_interval)

if __name__ == "__main__":
    follow_logs()
