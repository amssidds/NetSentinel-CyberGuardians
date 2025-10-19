# domain_classifier.py
# Lightweight Flask microservice version
# Port: 6001

from flask import Flask, request, jsonify
import joblib
import pandas as pd
import re, math, tldextract, os

app = Flask(__name__)

#MODEL_PATH = os.path.join(os.path.dirname(__file__), "model_domain.pkl")

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "model_domain.pkl"))
print("Model path:", MODEL_PATH)


# === Load model once at startup ===
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("Domain Classifier model loaded successfully.")
    except Exception as e:
        print("Error loading model:", e)
else:
    print("model_domain.pkl not found.")

# === Helper: entropy calculation ===
def calculate_entropy(string):
    if not string:
        return 0.0
    probabilities = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p, 2) for p in probabilities])
    return round(entropy, 3)

# === Feature extraction ===
def extract_features(domain):
    ext = tldextract.extract(domain)
    name = ext.domain
    tld = ext.suffix
    return {
        "domain_length": len(domain),
        "num_digits": sum(c.isdigit() for c in domain),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", domain)),
        "entropy": calculate_entropy(name),
        "has_hyphen": 1 if "-" in domain else 0,
        "tld_len": len(tld)
    }

@app.route("/")
def index():
    return jsonify({"module": "domain_classifier", "status": "ready"})

@app.route("/check", methods=["POST"])
def check_domain():
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"flag": 0, "reason": "missing domain"}), 400

    if model is None:
        return jsonify({"flag": 0, "reason": "Model not loaded"})

    feats = extract_features(domain)
    df = pd.DataFrame([feats])

    try:
        proba = model.predict_proba(df)[0][1]
        flag = 1 if proba >= 0.5 else 0
        reason = f"ML probability={proba:.2f} → {'malicious' if flag else 'legit'}"
        print(f"[DomainClassifier] {domain} → {reason}")
        return jsonify({"flag": flag, "score": round(proba, 2), "reason": reason})
    except Exception as e:
        return jsonify({"flag": 0, "reason": f"error:{e}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6001)
