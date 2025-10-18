# ai_modules/whois_analyzer.py
# Self-contained WHOIS analyzer microservice with /check endpoint.
# - No imports from whois_client.py / feature_extractor.py / rule_scorer.py
# - If rules.yaml is present next to this file, it will be used.
# - Otherwise, built-in default rules/thresholds are used.
#
# Matches engine_config.py endpoint: http://127.0.0.1:6003/check

import os
import json
from flask import Flask, request, jsonify
from datetime import datetime, timezone

# deps from requirements.txt
import yaml      # PyYAML
import whois     # python-whois

app = Flask(__name__)

# ---------------------------
# Config / rules loading
# ---------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(HERE, "rules.yaml")

DEFAULT_RULES = {
    "rules": {
        # Example rules; adjust or replace with your rules.yaml any time.
        "recent_registration": {
            "when": "features['days_since_creation'] < 90",
            "points": 6,
            "reason": "Domain is newly registered (< 90 days)"
        },
        "privacy_protection": {
            "when": "features['registrant_privacy'] == True",
            "points": 4,
            "reason": "WHOIS uses privacy/proxy/obfuscation"
        },
        "low_ns_diversity": {
            "when": "features['unique_ns_count'] <= 1",
            "points": 3,
            "reason": "Low DNS nameserver diversity"
        },
        "suspicious_tld": {
            "when": "features['tld'] in ['xyz','top','gq','ga','cf','tk','ml']",
            "points": 3,
            "reason": "TLD associated with abuse patterns"
        }
    },
    "thresholds": {
        "medium": 5,
        "high"  : 10
    }
}

def load_rules():
    # If rules.yaml exists next to this file, use it; else use defaults.
    try:
        if os.path.isfile(RULES_PATH):
            with open(RULES_PATH, "r") as f:
                data = yaml.safe_load(f) or {}
            # Basic shape validation
            if "rules" in data and "thresholds" in data:
                return data
    except Exception:
        pass
    return DEFAULT_RULES

RULESET = load_rules()

# ---------------------------
# WHOIS fetch (embedded)
# ---------------------------
def fetch_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        creation_date = getattr(w, "creation_date", None)
        if isinstance(creation_date, list) and creation_date:
            creation_date = creation_date[0]

        if creation_date:
            # normalize tz
            if getattr(creation_date, "tzinfo", None) is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_since_creation = (now - creation_date).days
        else:
            days_since_creation = 9999  # unknown treated as very old

        whois_data = {
            "domain": domain,
            "registrar": getattr(w, "registrar", None) or "Unknown",
            "creation_date": str(creation_date) if creation_date else "Unknown",
            "days_since_creation": days_since_creation,
            "nameservers": list(getattr(w, "name_servers", []) or []),
            "tld": domain.split(".")[-1].lower() if "." in domain else domain.lower(),
            "registrant_privacy": any(
                kw in str(getattr(w, "text", "")).lower()
                for kw in ["privacy", "redacted", "proxy"]
            ),
        }
        return whois_data

    except Exception as e:
        return {"error": str(e), "domain": domain}

# ---------------------------
# Feature extractor (embedded)
# ---------------------------
def extract_features(whois_data: dict) -> dict:
    ns = whois_data.get("nameservers") or []
    ns_count = len(set([str(x).strip().lower() for x in ns if str(x).strip()]))
    return {
        "days_since_creation": whois_data.get("days_since_creation", 9999),
        "registrant_privacy": bool(whois_data.get("registrant_privacy", False)),
        "tld": (whois_data.get("tld") or "").lower(),
        "unique_ns_count": ns_count,
    }

# ---------------------------
# Rule scorer (embedded)
# ---------------------------
def apply_rules(features: dict, ruleset: dict) -> tuple[int, str, list]:
    rules = ruleset.get("rules", {})
    thresholds = ruleset.get("thresholds", {"medium": 5, "high": 10})

    score = 0
    reasons = []

    for name, rule in rules.items():
        cond = str(rule.get("when", "")).strip()
        pts = int(rule.get("points", 0))
        reason = str(rule.get("reason", f"Rule matched: {name}"))

        if not cond:
            continue

        try:
            # Safe-ish eval: no builtins; give only 'features'
            if eval(cond, {"__builtins__": {}}, {"features": features}):
                score += pts
                reasons.append(reason)
        except Exception:
            # Ignore malformed/errored rule
            continue

    # Labeling
    medium = thresholds.get("medium", 5)
    high = thresholds.get("high", 10)
    if score < medium:
        label = "low"
    elif score < high:
        label = "medium"
    else:
        label = "high"
    return score, label, reasons

# ---------------------------
# Flask routes
# ---------------------------
@app.route("/", methods=["GET"])
def health():
    return jsonify({"module": "whois_analyzer", "status": "ok"}), 200

# IMPORTANT: matches engine_config.py -> /check
@app.route("/check", methods=["POST"])
def check():
    try:
        data = request.get_json(force=True) or {}
        domain = (data.get("domain") or "").strip()
        if not domain:
            return jsonify({
                "module": "whois_analyzer",
                "ok": False,
                "flag": 0,
                "score": 0,
                "label": "error",
                "reasons": ["No domain provided"],
                "details": {}
            }), 200

        whois_data = fetch_whois(domain)
        if "error" in whois_data:
            return jsonify({
                "module": "whois_analyzer",
                "ok": False,
                "flag": 0,
                "score": 0,
                "label": "error",
                "reasons": [str(whois_data["error"])],
                "details": {"domain": domain}
            }), 200

        features = extract_features(whois_data)
        raw_score, label, reasons = apply_rules(features, RULESET)
        flag = 1 if label in ("medium", "high") else 0

        return jsonify({
            "module": "whois_analyzer",
            "ok": True,
            "flag": flag,                 # 0/1 used by engine voting
            "score": float(raw_score),    # raw rule score
            "label": label,               # low/medium/high
            "reasons": reasons,
            "details": {
                "domain": domain,
                "registrar": whois_data.get("registrar"),
                "tld": whois_data.get("tld"),
                "days_since_creation": whois_data.get("days_since_creation"),
                "privacy_protected": whois_data.get("registrant_privacy"),
                "unique_ns_count": features.get("unique_ns_count", 0),
            }
        }), 200

    except Exception as e:
        return jsonify({
            "module": "whois_analyzer",
            "ok": False,
            "flag": 0,
            "score": 0,
            "label": "error",
            "reasons": [str(e)],
            "details": {}
        }), 200

if __name__ == "__main__":
    print("[+] WHOIS Analyzer microservice running on 0.0.0.0:6003 (/check)")
    app.run(host="0.0.0.0", port=6003)
