import random

def vt_check(domain):
    sources = ["PhishTank", "GoogleSafeBrowsing", "AbuseIPDB", "CiscoTalos"]
    positives = random.choice([0, 1, 3, 5])
    return {
        "positives": positives,
        "sources": random.sample(sources, k=min(len(sources), positives)) if positives else [],
        "intel_score": min(positives * 0.2, 1.0)
    }
