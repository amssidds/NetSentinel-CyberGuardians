# feature_extractor.py
def extract_features(whois_data: dict):
    ns_count = len(set(whois_data.get("nameservers", [])))
    return {
        "days_since_creation": whois_data.get("days_since_creation", 9999),
        "registrant_privacy": whois_data.get("registrant_privacy", False),
        "tld": whois_data.get("tld", ""),
        "unique_ns_count": ns_count,
    }
