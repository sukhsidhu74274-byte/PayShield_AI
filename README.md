# 🛡️ PayShield AI: Autonomous SOC Copilot & PayPal Fraud Shield

PayShield AI is a next-generation cybersecurity and automated threat-mitigation system built for the PayPal AI Hackathon. It acts as an autonomous Security Operations Center (SOC) Copilot designed to protect the PayPal payment ecosystem in real-time by inspecting transactions, detecting malicious payloads (SQLi, XSS, Phishing), and automatically communicating with PayPal Sandbox APIs to flag or block fraudulent orders.

---

## 🚀 Key Features

1. **⚡ Live PayPal Sandbox Integration:** Connects directly with PayPal Developer Sandbox (`/v2/checkout/orders`) to generate genuine Order IDs and simulate real-time automated threat mitigation.
2. **🔍 Deep Threat Analyzer:** Scans transaction IDs, URLs, IP addresses, and raw logs using advanced heuristic and regular expression (Regex) pattern matching to detect Injection attacks (SQLi/XSS) and phishing indicators.
3. **📁 Enterprise Log Batch Scanner:** Upload large-scale server or SIEM log files (`.txt` or `.csv`) for automated bulk threat mining and anomaly counting.
4. **🛡️ Autonomous SOC Guard:** Dynamically calculates risk scores (0-100%) and triggers automated security actions (Quarantine, Review Queue, or Payment Block).

---

## 🛠️ Tech Stack

* **Frontend & UI:** Streamlit (Python)
* **API & Networking:** Requests (REST API Integration with PayPal OAuth2)
* **Threat Detection:** Python Regular Expressions (`re`), Custom Cybersecurity Heuristics
* **Environment:** Python venv

---

## ⚙️ Installation & Setup Guide

Follow these steps to run the project locally on your machine:

### 1. Clone the Repository
```bash
git clone [https://github.com/APKA_GITHUB_USERNAME/PayShield-AI.git](https://github.com/sukhsidhu74274-byte/PayShield-AI.git)
cd PayShield-AI