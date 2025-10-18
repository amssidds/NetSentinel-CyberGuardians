import re
import math
import time
import joblib
import tldextract
import os
os.environ["SCAPY_DISABLE_AUTO_LOAD"] = "yes"

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from threading import Thread
from queue import Queue, Empty

from scapy.all import sniff, DNS, DNSQR


def calculate_entropy(string):
    if not string:
        return 0.0
    probabilities = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p, 2) for p in probabilities])
    return round(entropy, 3)


def extract_features(domain):
    ext = tldextract.extract(domain)
    name = ext.domain
    tld = ext.suffix
    features = {
        "domain_length": len(domain),
        "num_digits": sum(c.isdigit() for c in domain),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", domain)),
        "entropy": calculate_entropy(name),
        "has_hyphen": 1 if "-" in domain else 0,
        "tld_len": len(tld)
    }
    return features


def train_model(csv_path="domains_dataset.csv"):
    df = pd.read_csv(csv_path)
    if "domain" in df.columns:
        df = df.drop(columns=["domain"])
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    print("Accuracy:", round(accuracy_score(y_test, preds) * 100, 2), "%")
    joblib.dump(clf, "model_domain.pkl")


def classify_domain(domain, entropy_threshold=4.0, log_file="dns_log.csv"):
    feats = extract_features(domain)
    entropy = feats["entropy"]

    if entropy > entropy_threshold:
        score = 1.0
        label = "MALICIOUS (entropy)"
    else:
        model = joblib.load("model_domain.pkl")
        df = pd.DataFrame([feats])
        score = model.predict_proba(df)[0][1]
        label = "MALICIOUS" if score >= 0.5 else "LEGIT"

    print(f"Domain: {domain} | Score: {score:.2f} | {label}")

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    pd.DataFrame([{
        "timestamp": timestamp,
        "domain": domain,
        "score": round(score, 3),
        "entropy": entropy,
        "label": label
    }]).to_csv(log_file, mode="a", header=False, index=False)

    return score


def capture_dns(iface=None):
    q = Queue()

    def packet_handler(pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qdcount > 0:
            qd = pkt.getlayer(DNSQR)
            if qd and hasattr(qd, "qname"):
                domain = qd.qname.decode(errors="ignore").rstrip(".")
                q.put(domain)

    Thread(target=lambda: sniff(filter="udp port 53", prn=packet_handler, iface=iface, store=False), daemon=True).start()

    print("Listening for DNS queries... Press Ctrl+C to stop.\n")
    while True:
        try:
            domain = q.get(timeout=1)
            classify_domain(domain)
        except Empty:
            continue
        except KeyboardInterrupt:
            print("\nStopped DNS capture.")
            break


capture_dns()
