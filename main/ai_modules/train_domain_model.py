# train_domain_model.py
# Rebuilds a fresh RandomForest model and saves model_domain.pkl

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

csv_path = "domains_dataset.csv"

print(f"📘 Loading dataset from {csv_path}")
df = pd.read_csv(csv_path)
print("Dataset preview:\n", df.head(), "\n")

# Split features and labels
X = df.drop(columns=["label"])
y = df["label"]

# Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train a simple RandomForest
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

preds = clf.predict(X_test)
acc = round(accuracy_score(y_test, preds) * 100, 2)
print(f"✅ Model trained successfully with accuracy: {acc}%")

# Save the model
model_path = "model_domain.pkl"
joblib.dump(clf, model_path)
print(f"💾 Model saved to {model_path}")
