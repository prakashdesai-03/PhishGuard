# PhishGuard 🛡️

**Explainable Phishing URL and Scam Message Detection System**

IBM SkillsBuild Cyber Security 2026 · BharatCares  
**Author:** Prakash Desai  
**Version:** 1.0.0

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Problem Statement](#problem-statement)
3. [Features and Modules](#features-and-modules)
4. [Technology Stack](#technology-stack)
5. [Dataset](#dataset)
6. [Project Structure](#project-structure)
7. [Prerequisites](#prerequisites)
8. [Installation](#installation)
9. [Running the Application](#running-the-application)
10. [Training the ML Model](#training-the-ml-model)
11. [Running Tests](#running-tests)
12. [Example Inputs and Expected Behavior](#example-inputs-and-expected-behavior)
13. [Security and Privacy Notes](#security-and-privacy-notes)
14. [Known Limitations](#known-limitations)
15. [References](#references)

---

## Project Overview

PhishGuard is a cybersecurity web application built with Python and Flask. It allows users to:

- Analyse suspicious URLs for structural and lexical phishing indicators.
- Analyse SMS, email, and digital payment messages for scam patterns.
- View explainable risk scores with indicator-by-indicator explanations.
- Optionally train a Random Forest ML classifier on a phishing URL dataset.
- View session statistics on a live dashboard.
- Download plain-text analysis reports.

**This tool is for educational use only.** It is not a substitute for professional security software or threat-intelligence services.

---

## Problem Statement

Phishing websites and fraudulent messages trick millions of users into revealing credentials, clicking dangerous links, or making unsafe financial decisions. Ordinary users cannot reliably recognise suspicious URL structures or social-engineering language patterns.

PhishGuard provides an accessible, transparent, and explainable tool that identifies specific warning indicators and explains why they matter — helping users make safer decisions online.

---

## Features and Modules

| Module | Description |
|--------|-------------|
| **A — URL Scanner** | Lexical/structural URL analysis (30 features, 14 rule categories) |
| **B — Message Analyzer** | 12-category scam pattern detection with regex rules |
| **C — ML Pipeline** | Random Forest classifier, dataset loader, model persistence |
| **D — Risk Assessment** | Unified explainable risk score (rule-based + ML blend) |
| **E — Dashboard & Reports** | Session stats, Chart.js visualisations, text report export |
| **F — Security Tips** | Educational safety guidance for students and general users |

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, Flask 3.0+ |
| Machine Learning | scikit-learn 1.4+ (Random Forest) |
| Data Processing | pandas 2.0+, NumPy 1.26+ |
| Model Persistence | Joblib 1.3+ |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4.x (CDN, no install required) |
| URL Parsing | Python stdlib: urllib.parse, ipaddress, re |
| Report Generation | python-docx 1.1+ |

---

## Dataset

**LegitPhish — Mendeley Data**  
URL: https://data.mendeley.com/datasets/hx4m73v2sf/2  
Version: 2  
License: CC BY 4.0

The dataset contains labelled URLs classified as phishing or legitimate.

### Expected Schema

| Column | Description |
|--------|-------------|
| `url` | URL string |
| `label` | `0` = legitimate, `1` = phishing (or `"legitimate"` / `"phishing"` strings) |

### Setup

1. Download the CSV from the link above.
2. Rename/copy it to `data/phishing_urls.csv` inside the project folder.
3. Use the **Model Performance** page to train the classifier.

> The rule-based URL scanner works fully without the dataset.  
> Only ML prediction requires the dataset.

---

## Project Structure

```
PhishGuard/
├── PrakashDesai_PhishGuard.py      # Main Flask application (all modules)
├── requirements.txt                # Python dependencies
├── PrakashDesai_ProjectReport.docx # Project report (Word format)
├── README.md                       # This file
├── generate_report.py              # Script to regenerate the Word report
├── templates/
│   ├── base.html                   # Shared layout template
│   ├── index.html                  # Dashboard
│   ├── url_scanner.html            # URL Scanner page
│   ├── message_analyzer.html       # Message Analyzer page
│   ├── model_performance.html      # ML Model page
│   ├── security_tips.html          # Security Tips page
│   ├── about.html                  # About Project page
│   └── error.html                  # Error page
├── static/
│   ├── css/
│   │   └── style.css               # Dark navy cybersecurity theme
│   └── js/
│       ├── main.js                 # Shared JS utilities
│       ├── url_scanner.js          # URL Scanner page logic
│       └── message_analyzer.js     # Message Analyzer page logic
├── models/
│   └── phish_rf_model.joblib       # Saved ML model (created after training)
├── data/
│   └── phishing_urls.csv           # Dataset (download separately)
└── tests/
    └── test_phishguard.py          # 64 automated tests
```

---

## Prerequisites

- **Python 3.11 or later** (tested on Python 3.14.2)
- pip (comes with Python)
- Windows 10/11 or Linux/macOS
- A modern web browser (Chrome, Firefox, Edge)

Check your Python version:

```cmd
python --version
```

---

## Installation

### 1. Clone or Download the Project

```cmd
cd C:\Users\YourName\Desktop
```

If using git:
```cmd
git clone <repository-url>
cd PhishGuard
```

Or simply copy the PhishGuard folder to your desktop.

### 2. (Recommended) Create a Virtual Environment

```cmd
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```cmd
pip install -r requirements.txt
```

---

## Running the Application

```cmd
cd PhishGuard
python PrakashDesai_PhishGuard.py
```

You should see:

```
============================================================
  PhishGuard — IBM SkillsBuild Cyber Security 2026
  Author: Prakash Desai
  ML model loaded: False
  Open http://127.0.0.1:5000 in your browser
============================================================
```

Open **http://127.0.0.1:5000** in your browser.

> Press `Ctrl+C` to stop the server.

---

## Training the ML Model

1. Download the LegitPhish dataset from https://data.mendeley.com/datasets/hx4m73v2sf/2
2. Save it as `data/phishing_urls.csv` inside the PhishGuard folder.
3. Start the application (see above).
4. Navigate to **Model Performance** in the navigation bar.
5. Click **Train / Retrain Model**.
6. Wait for training to complete (typically 30–120 seconds depending on dataset size).
7. The model is saved automatically to `models/phish_rf_model.joblib`.
8. On the next startup, the model loads automatically.

Alternatively, train from the command line:

```cmd
python -c "from PrakashDesai_PhishGuard import train_model; print(train_model())"
```

---

## Running Tests

From the PhishGuard directory:

```cmd
python -m pytest tests/ -v
```

Or using unittest directly:

```cmd
python -m unittest discover -s tests -v
```

**Expected result:** 64 tests pass, 0 failures.

Test categories:
- Helper utilities (entropy, IP detection, risk scoring)
- URL feature extraction (14 tests)
- Rule-based URL analysis (11 tests)
- Scam message analysis (10 tests)
- Unified scan and ML fallback (3 tests)
- Report export (2 tests)
- Flask API and page routes (15 tests)

---

## Example Inputs and Expected Behavior

### URL Scanner

| Input URL | Expected Risk Level | Key Indicators |
|-----------|--------------------|--------------  |
| `https://www.google.com` | Low | None |
| `http://192.168.1.1/login` | High | IP_HOST, NO_HTTPS, LOGIN_NO_HTTPS |
| `http://paypal.secure-verify.tk/login@user` | High | BRAND_SUBDOMAIN, SUSPICIOUS_TLD, AT_SYMBOL, NO_HTTPS |
| `https://bit.ly/3xKm92p` | Medium | URL_SHORTENER |
| `http://example.com/%70%61%79` | Medium | NO_HTTPS, HEX_ENCODING |

### Message Analyzer

| Input Message | Expected Risk Level | Key Indicators |
|--------------|--------------------|--------------  |
| `"Your Amazon order has shipped."` | Low | None |
| `"Share your OTP to verify your account."` | High | OTP_REQUEST |
| `"Urgent! Account suspended within 24 hours."` | High | URGENT_ACTION, ACCOUNT_SUSPEND |
| `"Congratulations! You have won Rs. 50,000."` | High | PRIZE_REWARD |
| `"Complete your KYC: http://sbi-update.tk"` | High | KYC_SCAM, EMBEDDED_URL |

---

## Security and Privacy Notes

- **No URLs are visited** by the server. All analysis is purely lexical.
- **No message content is stored or logged.** Session memory holds only counts and brief summaries.
- All user input is validated and length-limited (URLs: 2048 chars, messages: 5000 chars).
- Flask request size limit: 1 MB.
- Jinja2 auto-escaping prevents XSS in HTML templates.
- No API keys or secrets are required or stored in code.
- SSRF protections are in place: the server never fetches user-supplied URLs.
- The application must be used only for legitimate educational purposes.

---

## Known Limitations

- **Lexical analysis only:** Cannot detect phishing pages with normal-looking domains.
- **No DNS or WHOIS lookups:** Domain age, registration, and IP reputation are not checked.
- **Risk scores are heuristic:** Not calibrated probabilities.
- **False positives and negatives** are possible — always verify independently.
- **URL shorteners:** Detected and flagged, but not expanded.
- **English only:** Scam message patterns are currently English-language only.
- **ML model:** Only as accurate as the training dataset. Not updated in real-time.

---

## References

1. LegitPhish Dataset — Mendeley Data v2. https://data.mendeley.com/datasets/hx4m73v2sf/2
2. scikit-learn. https://scikit-learn.org/
3. Flask. https://flask.palletsprojects.com/
4. Chart.js. https://www.chartjs.org/
5. python-docx. https://python-docx.readthedocs.io/
6. OWASP Phishing. https://owasp.org/www-community/attacks/Phishing
7. IBM SkillsBuild. https://skillsbuild.org/
8. National Cyber Crime Reporting Portal (India). https://cybercrime.gov.in/
9. PhishTank. https://phishtank.org/

---

*PhishGuard is an educational project submitted for IBM SkillsBuild Cyber Security 2026, BharatCares. It is not a commercial or professional security product.*
