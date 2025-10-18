# main.py
from whois_client import fetch_whois
from feature_extractor import extract_features
from rule_scorer import apply_rules
import json

def analyze_domain(domain: str):
    whois_data = fetch_whois(domain)
    if "error" in whois_data:
        return whois_data

    features = extract_features(whois_data)
    score, label, reasons = apply_rules(features)

    result = {
        "domain": domain,
        "registrar": whois_data["registrar"],
        "tld": whois_data["tld"],
        "days_since_creation": whois_data["days_since_creation"],
        "score": score,
        "label": label,
        "reasons": reasons,
    }
    return result

if __name__ == "__main__":
    test_domain = input("Enter domain to analyze: ")
    print(json.dumps(analyze_domain(test_domain), indent=2))
