import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Load your real-world log
df = pd.read_csv("dns_log.csv", names=["timestamp", "domain", "score", "entropy", "label"])

# Clean domain names (remove any NaNs)
df = df.dropna(subset=["domain"]).reset_index(drop=True)

# Convert labels to numeric for training (1 = malicious, 0 = legit)
df["label"] = df["label"].apply(lambda x: 1 if "MALICIOUS" in x.upper() else 0)

# Whitelist: correct known safe domains
WHITELIST = ["google.com", "microsoft.com", "spotify.com", "vscode-cdn.net", "steamserver.net"]
df.loc[df["domain"].apply(lambda d: any(w in d for w in WHITELIST)), "label"] = 0

# Feature engineering (same features as before)
def calculate_entropy(s):
    import math
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = -sum([p * math.log(p, 2) for p in probs])
    return round(entropy, 3)

def extract_features(domain):
    import re, tldextract
    ext = tldextract.extract(domain)
    name, tld = ext.domain, ext.suffix
    feats = {
        "domain_length": len(domain),
        "num_digits": sum(c.isdigit() for c in domain),
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", domain)),
        "entropy": calculate_entropy(name),
        "has_hyphen": 1 if "-" in domain else 0,
        "tld_len": len(tld)
    }
    return feats

# Extract feature columns
rows = []
for d in df["domain"]:
    try:
        feats = extract_features(d)
        rows.append(feats)
    except Exception:
        rows.append({"domain_length":0,"num_digits":0,"num_special_chars":0,"entropy":0,"has_hyphen":0,"tld_len":0})

features = pd.DataFrame(rows)
features["label"] = df["label"]

# Drop duplicates and balance
features = features.drop_duplicates()
malicious = features[features["label"] == 1]
legit = features[features["label"] == 0]
balanced = pd.concat([malicious, legit.sample(n=len(malicious), replace=True, random_state=42)], ignore_index=True)

# Train a new model
X = balanced.drop(columns=["label"])
y = balanced["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42)
clf.fit(X_train, y_train)

preds = clf.predict(X_test)
acc = round(accuracy_score(y_test, preds) * 100, 2)
print("✅ New Model Accuracy:", acc, "%")

# Save the improved model
joblib.dump(clf, "model_domain.pkl")
print("New model saved as model_domain.pkl")
