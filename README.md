# SIEM Lite — Threat Intelligence Dashboard

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-black?style=flat-square&logo=flask)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-Integrated-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A lightweight SIEM (Security Information and Event Management) system built from scratch in Python. Parses real Linux log files, detects attack patterns using custom rule-based detection, enriches attacker IPs with live threat intelligence from AbuseIPDB, and visualizes everything in a clean web dashboard.

> Built as a portfolio project to demonstrate defensive security engineering — log analysis, detection engineering, threat intelligence integration, and full-stack development.

---

## Dashboard

![SIEM Lite Dashboard](docs/dashboard.png)

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│   Log Sources   │────▶│   Log Parser     │────▶│ Detection Engine  │────▶│  Threat Intel    │
│                 │     │                  │     │                   │     │                  │
│  • auth.log     │     │  • Regex parsing │     │  • Brute force    │     │  • AbuseIPDB API │
│  • access.log   │     │  • Normalization │     │  • Credential     │     │  • Abuse score   │
│  • File upload  │     │  • Structured    │     │    stuffing       │     │  • Country / ISP │
│                 │     │    events        │     │  • Web recon      │     │  • Auto severity │
└─────────────────┘     └──────────────────┘     │  • Injection      │     │    boosting      │
                                                  │  • Priv escalation│     └────────┬─────────┘
                                                  └───────────────────┘              │
                                                                                     ▼
                                                                         ┌──────────────────────┐
                                                                         │   Flask Dashboard    │
                                                                         │                      │
                                                                         │  • Live alert feed   │
                                                                         │  • Stat cards        │
                                                                         │  • IP enrichment     │
                                                                         │  • File upload UI    │
                                                                         └──────────────────────┘
```

---

## Features

### Log Parsing
- Parses `/var/log/auth.log` — SSH login attempts, sudo commands, invalid users
- Parses Apache/Nginx `access.log` — HTTP requests, 404s, suspicious paths
- Normalizes all events into a consistent schema regardless of source
- Auto-detects log type by filename

### Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force | 5+ SSH failures from same IP within 60s | Critical |
| Credential Stuffing | Same IP tries 3+ different usernames | High |
| Web Recon Sweep | Same IP hits 3+ suspicious paths in 60s | High |
| SQL Injection | SQLi patterns detected in HTTP request | Critical |
| XSS Attack | XSS payload detected in HTTP request | High |
| Path Traversal | Directory traversal attempt detected | Critical |
| Privilege Escalation | sudo to shell binary (bash/sh/zsh) | Critical |

### Threat Intelligence
- Queries AbuseIPDB for every unique attacker IP
- Returns abuse confidence score (0–100%), total global reports, country, ISP
- Automatically skips private and internal IPs
- Deduplicates lookups — same IP is queried only once per analysis
- Auto-boosts alert severity if AbuseIPDB score exceeds threshold

### Dashboard
- Real-time alert feed with severity badges
- Summary stat cards — total events, alerts by severity, unique attacker IPs
- Abuse score progress bars with color coding per risk level
- Upload your own log files directly through the UI for instant analysis
- Auto-refreshes every 30 seconds

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Web framework | Flask |
| Log parsing | Regex (stdlib) |
| Threat intel | AbuseIPDB REST API |
| HTTP client | requests |
| Environment | python-dotenv |
| Frontend | HTML, CSS, JavaScript (vanilla) |
| Font | Space Grotesk + IBM Plex Mono |

---

## Project Structure

```
siem_lite/
├── app.py                      # Flask app — routes and API endpoints
├── parser/
│   └── log_parser.py           # Log parsing and normalization
├── detection/
│   ├── detection_engine.py     # Rule-based alert detection
│   └── threat_intel.py         # AbuseIPDB enrichment
├── logs/
│   └── samples/
│       ├── auth.log            # Sample SSH auth log
│       └── access.log          # Sample Apache access log
├── templates/
│   └── dashboard.html          # Frontend dashboard
├── docs/
│   └── dashboard.png           # Dashboard screenshot
├── .env.example                # Environment variable template
├── requirements.txt
└── .gitignore
```

---

## Setup and Run

### 1. Clone the repo

```bash
git clone https://github.com/Kpv12/siem-lite-.git
cd siem-lite-
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure your API key

```bash
cp .env.example .env
```

Open the `.env` file and add your AbuseIPDB key:

```
ABUSEIPDB_API_KEY=your_actual_key_here
```

Get a free API key at [abuseipdb.com](https://www.abuseipdb.com). The free tier allows 1,000 lookups per day which is more than enough for local use.

> Your `.env` file is listed in `.gitignore` and will never be pushed to GitHub. The `.env.example` file is a safe template with no real keys — it just shows others what variable they need to set.

### 4. Run the dashboard

```bash
python3 app.py
```

Open `http://localhost:5000` in your browser.

### 5. Analyze your own logs

Either upload your log files through the dashboard UI, or drop them into `logs/samples/` and restart the server. The tool accepts standard Linux `/var/log/auth.log` and Apache/Nginx `access.log` formats.

---

## Detection Logic

### Brute Force Detection
Uses a sliding window algorithm — groups SSH failures by IP, sorts by timestamp, then checks if 5 or more failures fit within a 60-second window. Avoids false positives from spread-out failures while catching automated attack tools that operate in tight bursts.

### Credential Stuffing vs Brute Force
Brute force targets one account repeatedly. Credential stuffing tries many different usernames from the same IP — a pattern seen when attackers spray leaked credential databases. Detected separately by tracking unique username attempts per IP.

### Severity Boosting
When AbuseIPDB returns a confidence score above 80%, the system automatically upgrades a HIGH alert to CRITICAL. This cross-references local detection with global threat intelligence — a core technique used in real SOC workflows.

---

## Sample Output

```
Total events loaded: 47
ALERTS FIRED: 14

[CRITICAL] BRUTE_FORCE
   IP          : 185.220.101.45
   Description : 6 failed SSH logins within 60s
   Abuse Score : 100%
   Reports     : 18,432
   Country     : DE
   ISP         : Tor Project

[CRITICAL] INJECTION_ATTACK
   IP          : 91.240.118.172
   Description : SQL Injection → /index.php?id=1 UNION SELECT null,null,null--
   Abuse Score : 87%
   Reports     : 4,201
   Country     : RU
   ISP         : Petersburg Internet Network
```

---

## What I Learned

- How real SIEM systems ingest, normalize, and correlate log data
- Writing production-grade regex for log parsing across multiple formats
- Sliding window algorithms for time-based anomaly detection
- REST API integration with rate limiting and response caching
- The difference between brute force and credential stuffing at a detection level
- How threat intelligence enrichment works in real SOC environments

---

## Future Improvements

- SQLite database for persistent event storage across sessions
- Email and Slack alerting on critical detections
- Support for Windows Event Logs and Syslog formats
- Custom detection rule builder via the UI
- Exportable PDF reports per analysis session

---

## Author

**Varun K P** — Cybersecurity Analyst

[LinkedIn](https://linkedin.com/in/varun-kp8732a4374)
