# Web Application Attack Detector & Investigation Platform

A python-based web application threat detection, event correlation, and investigation platform. This defensive SOC tool imports web server logs (Apache/Nginx CLF or CSV), normalizes HTTP request components, detects suspicious web attack patterns using rule-based and behavioral heuristics, correlates related incidents into attack campaigns, scores risk levels, and presents findings through a Streamlit SOC dashboard with PDF report generation capabilities.

> **Note**: This application is built strictly for **defensive security monitoring, educational analysis, and controlled log investigation**. It does NOT perform offensive web scanning or exploitation.

---

## 🚀 Key Features

* **Multi-Format Log Parser**: Parses standard Apache/Nginx Combined Log Format (CLF) and custom CSV HTTP access logs.
* **Multi-Pass Request Normalizer**: Performs iterative URL decoding, HTML entity decoding, whitespace normalization, and parameter extraction while preserving original raw requests for forensic evidence.
* **Attack Detection Engine**: High-precision rule-based detection for:
  * **SQL Injection (SQLi)**: Boolean bypass, `UNION` extraction, time-based blind (`SLEEP`, `BENCHMARK`), DDL/DML, `information_schema` probing, and `xp_cmdshell`.
  * **Cross-Site Scripting (XSS)**: Reflected/stored `<script>` injection, `javascript:` protocol payloads, event handler attributes (`onerror`, `onload`), DOM manipulation functions, and `<iframe>` injection.
  * **Path Traversal**: Parent directory sequences (`../`, URL-encoded `%2e%2e%2f`), Linux sensitive files (`/etc/passwd`, `/etc/shadow`, `~/.ssh`), and Windows system files (`boot.ini`, `system32`).
  * **Command Injection (CMDI)**: Shell separators `;`, `|`, `&&`, `$()`, backticks, OS commands (`whoami`, `id`, `ls`), shell binaries (`/bin/bash`, `cmd.exe`), and network tool abuse (`wget`, `curl`, `nc`).
  * **Authentication Attacks**: Sliding time-window detection for repeated failed login attempts (e.g. 5+ failed HTTP 401/403 requests from the same IP within 5 minutes).
  * **Parameter Manipulation**: Null-byte injection (`%00`), HTTP Parameter Pollution (duplicate query params), and excessively long payload detection.
* **Contextual Risk Engine**: Computes 0–100 risk scores mapped to `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` severities with automatic risk escalation for multi-vector threat actors.
* **Campaign Correlator**: Automatically groups related alerts from the same source IP within a configurable time window into coordinated **Attack Campaigns**.
* **SQLite Persistence**: Stores parsed HTTP events, alerts, and campaigns locally with instant filtering and alert status management (`Open`, `Investigating`, `Resolved`).
* **Professional SOC Dashboard**: Interactive Streamlit interface with dark theme, metric cards, Plotly charts (attack breakdown, risk distribution, time series, top attackers, target endpoints), attack timeline, IP investigation, and endpoint vulnerability view.
* **PDF Security Report Generation**: Export executive summaries, threat matrices, campaign breakdowns, and detailed alert logs to styled PDF reports using ReportLab.
* **Controlled Test App**: Included Flask test target for generating real HTTP logs via Burp Suite, `curl`, or custom scripts.

---

## 🏗️ System Architecture

```text
       HTTP Access Logs (CLF / CSV)
                   │
                   ▼
         ┌──────────────────┐
         │   Log Parser     │  (core/parser.py)
         └─────────┬────────┘
                   │
                   ▼
         ┌──────────────────┐
         │   Normalizer     │  (core/normalizer.py)
         └─────────┬────────┘
                   │
                   ▼
         ┌──────────────────┐
         │ Detection Engine │  (core/detector.py & rules/attack_rules.py)
         └─────────┬────────┘
                   │
                   ▼
         ┌──────────────────┐
         │   Risk Engine    │  (core/risk_engine.py)
         └─────────┬────────┘
                   │
                   ▼
         ┌──────────────────┐
         │ Campaign Grouping│  (core/correlator.py)
         └─────────┬────────┘
                   │
                   ▼
         ┌──────────────────┐
         │ SQLite Database  │  (core/database.py -> data/detector.db)
         └─────────┬────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
┌──────────────────┐  ┌──────────────────┐
│Streamlit SOC Dash│  │ PDF Report Generator
└──────────────────┘  └──────────────────┘
```

---

## 💻 Installation & Setup

### Prerequisites

* Python 3.11+
* `pip` package manager

### 1. Clone or Navigate to Directory

```bash
cd "Web Application Attack Detector"
```

### 2. Create Virtual Environment

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚦 Quick Start & Usage

### Launch Dashboard

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

### Running Demo Data

1. Click **🎭 Demo** in the sidebar.
2. The platform will automatically parse synthetic HTTP logs containing normal requests alongside SQLi, XSS, Path Traversal, Command Injection, and Brute-Force attacks.
3. Explore metrics, charts, alert details, IP investigation, attack timelines, and PDF generation.

### Uploading Log Files

* Supported formats: Standard Apache/Nginx `access.log` lines or `.csv` files.
* CSV header requirement: `timestamp, source_ip, method, endpoint, status_code` (optional: `query, user_agent, referer, response_size`).

---

## 🧪 Running Unit Tests

Verify project correctness by running the test suite:

```bash
python3 -m unittest discover tests
```

---

## 🎯 Burp Suite & Controlled Test Application

The platform includes a dedicated test application under `test_app/app.py` for generating HTTP access logs during controlled security testing.

### Workflow

```text
Controlled Test Application (Flask :5000)
             ↑
      Burp Suite / Client
             │ (Generates HTTP traffic)
             ▼
     data/test_app_access.log
             │
             ▼
  Web Application Attack Detector
```

### Instructions

1. Start the test target app:
   ```bash
   python3 test_app/app.py
   ```
2. Configure Burp Suite proxy or use `curl` to send test requests to `http://127.0.0.1:5000/`.
3. The test target will log HTTP traffic to `data/test_app_access.log`.
4. Upload `data/test_app_access.log` into the Attack Detector dashboard to analyze the recorded traffic.

---

## 🛡️ Supported Attack Categories

| Category | Identifiers / Examples | Severities |
|---|---|---|
| **SQL Injection** | `' OR '1'='1`, `UNION SELECT`, `SLEEP()`, `DROP TABLE`, `information_schema`, `xp_cmdshell` | CRITICAL, HIGH |
| **Cross-Site Scripting** | `<script>`, `javascript:`, `onerror=`, `document.cookie`, `alert()`, `<iframe>` | HIGH, MEDIUM |
| **Path Traversal** | `../`, `%2e%2e%2f`, `/etc/passwd`, `/etc/shadow`, `boot.ini`, `system32` | CRITICAL, HIGH |
| **Command Injection** | `; whoami`, `\| id`, `&& cat`, `$(whoami)`, `/bin/bash`, `cmd.exe`, `curl`, `wget` | CRITICAL, HIGH |
| **Authentication Attack** | 5+ failed HTTP 401/403 requests on `/login` or `/auth` within 5 min window | HIGH, CRITICAL |
| **Parameter Manipulation** | Null bytes (`%00`), HTTP Parameter Pollution (duplicate params), long tokens | MEDIUM, LOW |

---

## 🔮 Future Improvements

* **Machine Learning Anomaly Detection**: Isolation Forests & Autoencoders for zero-day parameter anomaly scoring.
* **Real-time Log Ingestion**: Streaming ingestion via `tail`, Filebeat, or Syslog sockets.
* **SIEM Integration**: Exporting formatted alerts to Splunk HTTP Event Collector (HEC) or Elastic Stack (ELK).
* **Suricata / Snort Integration**: Correlating IDS/IPS network alerts with web application HTTP events.
* **WAF Integration**: Automatic generation of ModSecurity / AWS WAF rule sets from verified attack campaigns.
* **Threat Intelligence Feed Matching**: Enriching source IPs against AbuseIPDB and AlienVault OTX.

---

## 📜 License

Educational and Defensive Security Monitoring Project.
# ASTRA
