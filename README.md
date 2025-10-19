# 🛡️ NetSentinel — AI-Powered DNS, WHOIS & VirusTotal Threat Advisor

### Team Cyber Guardians | Innovation Hackathon UAE 2025  
**Developed by:**  
- Ameen Siddiqui — Backend & DNS Engine  
- Ahmed Hussein — WHOIS & NLP Analyzer  
- Mohamed Ibrahim Idris — Data & Behavior Analytics  

---

## 🚀 Overview

**NetSentinel** is an intelligent, **real-time DNS filtering and analytics system** that detects and blocks malicious domains at the network layer using **multi-stage AI analysis**, **WHOIS metadata**, **VirusTotal enrichment**, and **behavioral anomaly detection**.  

The system integrates:
- 🧠 **Domain Classifier** — Machine Learning lexical risk engine  
- 📊 **Anomaly Detector** — Frequency-based behavioral analytics  
- 🔍 **WHOIS Analyzer** — Metadata inspection (age, registrar, privacy)  
- 🧬 **VirusTotal Intelligence API** — URL & domain reputation lookup  
- ⚙️ **Central API + Dashboard** — Unified visibility & decision-making  

Together, these components deliver a modern, autonomous network defense platform capable of identifying phishing, C2, and zero-day domains **before** users can connect to them.

---

## 🧩 Architecture

```
+-------------------+       +--------------------+
|  Client DNS Query | --->  |  NetSentinel Core  |
| (via Unbound/Pi)  |       |  Decision Engine   |
+-------------------+       +--------------------+
                                      |
             ----------------------------------------------------------------
             |             |                |               |               |
   +------------------+ +------------------+ +------------------+ +------------------+
   | Domain Classifier| | Anomaly Detector | | WHOIS Analyzer   | | VirusTotal API  |
   | (ML / Scikit)    | | (Behavior Stats) | | (WHOIS Metadata) | | (Reputation)    |
   +------------------+ +------------------+ +------------------+ +------------------+
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

✅ **AI Domain Classification** — Detects phishing/DGA domains using ML.  
✅ **Anomaly Detection Engine** — Flags domains never seen before per client.  
✅ **WHOIS Intelligence Analyzer** — Evaluates registration metadata.  
✅ **VirusTotal Integration** — Queries the VirusTotal API to cross-check domain or URL reputation, detect community flags, and integrate confidence scores into the unified verdict.  
✅ **Multi-Module Scoring System** — Weighted analyzer consensus model.  
✅ **Real-Time Dashboard** — Flask-based visualization with live logs.  
✅ **Explainable AI Reports** — JSON + human-readable narratives per verdict.  

---

## 🧠 Tech Stack

| Component | Technology |
|------------|-------------|
| **Backend Framework** | Python (Flask) |
| **AI Models** | scikit-learn, pandas |
| **Threat Intelligence** | VirusTotal REST API |
| **Database** | SQLite (dns_logs.db) |
| **Dashboard** | HTML5 / CSS / JS (Flask templates) |
| **APIs** | Flask REST (port 5000) |
| **Modules** | Domain Classifier (6001), Anomaly Detector (6002), WHOIS Analyzer (6003), VirusTotal (6004) |
| **Visualization** | Real-Time Dashboard (port 8080) |
| **Data Format** | JSON Reports + Markdown Summaries |

---

## 🧬 VirusTotal Integration

NetSentinel connects to the **VirusTotal Intelligence API** to verify suspicious domains or URLs against live global reputation data.  

### 🔗 API Behavior
- Each detected domain is enriched by querying VirusTotal's `/domains/{domain}` endpoint.  
- The result returns:  
  - Reputation score  
  - Number of engines marking it malicious  
  - Categories (e.g., phishing, malware, spam)  
  - Last analysis timestamp  
- A verdict score (0–100) is normalized and weighted with other modules.

### 🧰 Example Result
```json
{
  "module": "virustotal_analyzer",
  "flag": 1,
  "label": "high",
  "score": 0.95,
  "reasons": ["Listed as 'phishing' by 12/90 engines"]
}
```

You can enable or disable VirusTotal in `engine_config.py`:
```python
ENABLE_VIRUSTOTAL = True
VT_API_KEY = "your_virustotal_api_key_here"
VT_ENDPOINT = "https://www.virustotal.com/api/v3/domains/"
```

---

## ▶️ Usage

### Start the system
```bash
python3 run_all.py
```
All modules launch automatically, including VirusTotal integration (port 6004 if standalone).

### Test a domain
```bash
curl -s -X POST http://127.0.0.1:5000/evaluate   -H "Content-Type: application/json"   -d '{"domain": "example.com"}' | jq
```

---

## 📊 Dashboard

Visit **http://127.0.0.1:8080** to view:
- Blocked & allowed domains  
- Live verdicts per module  
- AI-generated explanations ("Ask Why a Domain Was Blocked")  
- VirusTotal enrichment results  

---

## 📁 Folder Structure

```
NetSentinel-CyberGuardians/
├── ai_modules/
│   ├── domain_classifier.py
│   ├── anomaly_detector.py
│   ├── whois_analyzer.py
│   ├── virustotal_analyzer.py
│   ├── model_domain.pkl
│   └── train_domain_model.py
├── engine.py
├── engine_config.py
├── api_handler.py
├── dashboard.py
├── templates/dashboard.html
├── reports/
├── lists/
├── database/
│   └── dns_logs.db
└── run_all.py
```

---

## 🧾 Example Narrative Output

```
The query QX-b238cee6 from client 127.0.0.1 attempted to reach phishing-login.xyz at 2025-10-18T16:33:33.

Final verdict: **BLOCK** (score=3, threshold=1).

- Domain Classifier → ⚠️ Flagged (score=0.73) — ML model detected phishing-like entropy.
- Anomaly Detector → ⚠️ Flagged (score=10) — Never seen before for this client.
- WHOIS Analyzer → ⚠️ Flagged — Recently registered (< 15 days old).
- VirusTotal → ⚠️ Flagged — 12 vendors detected as phishing.

🧾 **Overall Verdict:** BLOCK — Domain correlated across AI + global threat feeds.
```

---

## 🛠️ Future Enhancements

- 🧠 Machine Learning retraining pipeline (auto-update)
- 🔬 Tier-2 web-content signature hashing
- ☁️ Grafana / Loki visualization
- 🧱 RPZ ingestion for external blocklists
- 🕵️ Malware sandbox testing (air-gapped)
- 🤖 Chatbot module for interactive investigation
