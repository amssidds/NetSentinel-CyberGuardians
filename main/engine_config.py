import os
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    print("⚠️  VirusTotal API key not found — please set in .env file")
    
# === Directory Paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "dns_logs.db")
LISTS_DIR = os.path.join(BASE_DIR, "lists")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# === AI Module Endpoints ===
MODULE_ENDPOINTS = {
    "domain_classifier": "http://127.0.0.1:6001/check",
    "anomaly_detector":  "http://127.0.0.1:6002/check",
    "whois_analyzer":    "http://127.0.0.1:6003/check"
}

# === Module weights (importance) ===
MODULE_WEIGHTS = {
    "domain_classifier": 1,
    "anomaly_detector":  1,
    "whois_analyzer":    1
}

# === Decision Logic ===
DECISION_THRESHOLD = 2   # block if >= 2 modules flag suspicious

# === File paths for lists ===
ALLOWLIST_FILE = os.path.join(LISTS_DIR, "allowlist.txt")
BLOCKLIST_FILE = os.path.join(LISTS_DIR, "blocklist.txt")

# === Network ===
HTTP_TIMEOUT_SECONDS = 4
HTTP_RETRIES = 1

# === Optional Unbound Reload ===
ENABLE_UNBOUND_RELOAD = False
UNBOUND_RELOAD_CMD = ["sudo", "unbound-control", "reload"]
