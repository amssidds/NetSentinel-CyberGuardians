# NetSentinel-CyberGuardians

### Team Cyber Guardians | Innovation Hackathon UAE 2025  
**Developed by:**  
- Ameen Siddiqui — Backend & DNS Engine  
- Ahmed Hussein — WHOIS & NLP Analyzer  
- Mohamed Ibrahim Idris — Data & Behavior Response  

---

## 🚀 Overview

**NetSentinel** is an intelligent, **real-time DNS filtering and analytics system** that detects and blocks malicious domains at the network layer using multi-stage AI analysis, WHOIS metadata, and behavioral anomaly detection.  

The system integrates:
- A machine-learning **Domain Classifier**  
- A behavior-based **Anomaly Detector**  
- A metadata-driven **WHOIS Analyzer**  
- A **central API** with unified logging  
- A **real-time Flask Dashboard**  

Together, these components deliver a modern, autonomous network defense platform capable of identifying phishing, command-and-control, and zero-day domains **before** users can connect to them.

---

## 🧩 Architecture

```
+-------------------+       +--------------------+
|  Client DNS Query | --->  |  NetSentinel Core  |
| (via Unbound/Pi)  |       |  Decision Engine   |
+-------------------+       +--------------------+
                                      |
             ----------------------------------------------------
             |                       |                         |
   +--------------------+   +--------------------+   +--------------------+
   | Domain Classifier  |   | Anomaly Detector   |   | WHOIS Analyzer     |
   | (ML / Scikit-Learn)|   | (Behavior Stats)   |   | (WHOIS Metadata)   |
   +--------------------+   +--------------------+   +--------------------+
                                      |
                            +--------------------+
                            | Unified Log DB     |
                            | SQLite + JSON      |
                            +--------------------+
                                      |
                            +--------------------+
                            | Flask API Handler  |
                            +--------------------+
                                      |
                            +--------------------+
                            | Live Web Dashboard |
                            +--------------------+
```

---

## ⚙️ Key Features

✅ **AI-Driven Domain Classification** — Uses ML model (trained via scikit-learn) to detect algorithmic or phishing-like domain names.  
✅ **Anomaly Detection Engine** — Flags domains never seen before per client (frequency-based behavioral detection).  
✅ **WHOIS Intelligence Analyzer** — Evaluates registration age, registrar reputation, privacy masking.  
✅ **Multi-Module Scoring System** — Each module contributes weighted evidence; combined verdict determines ALLOW / BLOCK.  
✅ **Live Dashboard** — Real-time Flask UI showing blocked/allowed queries, risk trends, and “Ask Why” explanations.  
✅ **Full Traceability** — Every decision saved as a JSON report for transparency and forensic replay.  

---

## 🧠 Tech Stack

| Component | Technology |
|------------|-------------|
| **Backend Framework** | Python (Flask) |
| **AI Models** | scikit-learn, pandas |
| **Database** | SQLite (dns_logs.db) |
| **Dashboard** | HTML5 / CSS / JS (Flask templates) |
| **APIs** | Flask REST (port 5000) |
| **Modules** | Domain Classifier (6001), Anomaly Detector (6002), WHOIS Analyzer (6003) |
| **Visualization** | Real-Time Dashboard (port 8080) |
| **Data Format** | JSON (report exports) |

---

## 🧰 Installation

```bash
# Clone the repo
git clone https://github.com/<yourusername>/NetSentinel-CyberGuardians.git
cd NetSentinel-CyberGuardians

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

### Start the system
```bash
python3 run_all.py
```

You’ll see:
```
[*] Launching Domain Classifier (6001) ...
[*] Launching Anomaly Detector (6002) ...
[*] Launching WHOIS Analyzer (6003) ...
[*] Launching API Handler (5000) ...
[*] Launching Dashboard (8080) ...
✅ All services launched successfully!
```

### Access the Dashboard
Open your browser and navigate to:  
👉 **http://127.0.0.1:8080**

### Test from Command Line
```bash
# Evaluate a domain directly
curl -s -X POST http://127.0.0.1:5000/evaluate   -H "Content-Type: application/json"   -d '{"domain": "example.com", "client_ip": "127.0.0.1"}' | jq
```

### Check an analyzer report
```bash
curl -s http://127.0.0.1:5000/report/example.com | jq -r '.narrative'
```

---

## 📊 Dashboard Preview

_Add screenshots here:_  
- `/screenshots/dashboard_main.png`  
- `/screenshots/report_example.png`  

---

## 🧠 How It Works

Each incoming domain query flows through **three independent analyzers**, each scoring the request on a risk scale:

| Module | Checks | Output |
|--------|---------|---------|
| Domain Classifier | Lexical ML model (entropy, length, TLD, digits) | Risk score (0–1) |
| WHOIS Analyzer | Domain age, registrar reputation, privacy shield | Risk score (0–1) |
| Anomaly Detector | Domain frequency vs historical behavior | Risk score (0–1) |

Results are weighted according to `engine_config.py`:
```python
MODULE_WEIGHTS = {
    "domain_classifier": 1,
    "anomaly_detector": 1,
    "whois_analyzer": 1
}
DECISION_THRESHOLD = 1  # >=1 modules flag → BLOCK
```

If total weighted score ≥ threshold → domain is **BLOCKED** and recorded in `/reports/`.

---

## 🧠 Example Output Narrative

```
The query **QX-e9fa657a** from client **127.0.0.1**
attempted to reach **example.com** at 2025-10-18T16:33:33.

The system classified this request with a **final verdict of BLOCK**,
based on analyzer consensus and weighted risk scoring.

- Domain Classifier → ✅ Allowed (score=0.2). Legitimate lexical profile.
- Anomaly Detector → ⚠️ Flagged (score=10). Domain never seen before from this client.
- WHOIS Analyzer → ⚠️ Flagged (score=0.7). Recently registered domain.

🧾 **Final Verdict:** BLOCK with total risk score 2 (threshold 1)
```

---

## 🛠️ Future Enhancements

- 🔬 Tier-2 content analyzer (HTTP fetch + favicon hash)
- ☁️ Cloud dashboard integration with Grafana
- 🧱 RPZ feed ingestion for external blocklists
- 🕵️ Malware sandbox integration for detonation analysis
- 🤖 GPT-powered chatbot for natural-language log queries

---

## 🧑‍💻 License

MIT License © 2025 — Team Cyber Guardians  
Permission granted for academic and research use.

---

## 📞 Contact

For collaboration or bug reports:  
📧 **netsentinel@cyberguardians.tech**  
🌐 [github.com/NetSentinel-CyberGuardians](https://github.com/NetSentinel-CyberGuardians)

---

> “**Prevent. Detect. Respond.** — NetSentinel guards your network in real time.”
