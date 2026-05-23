# WebSecAudit 🔐

> Web Application Security Assessment Platform

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Category-Security-red?style=flat-square)
![Academy](https://img.shields.io/badge/Qnayds-Academy-navy?style=flat-square)

A browser-based security scanner that performs **automated header checks** and provides a **manual verification checklist** for 75+ security controls — with PDF report export.

---

## 🔍 What is WebSecAudit?

WebSecAudit is a web application security assessment tool that helps security professionals evaluate a target website against industry-standard security controls. It combines:

- **Auto-detection** of HTTP security headers, HTTPS enforcement, cookie flags, and CORS
- **Manual checklist** for server-side controls that cannot be detected externally
- **PDF report generation** suitable for audit submissions and client reporting

---

## ⚡ Quick Start

```bash
git clone https://github.com/muhammed95rafi-arch/websec-scanner.git
cd websec-scanner
pip install -r requirements.txt
python app.py
```

Open: `http://localhost:5000`

---

## 🧩 Features

| Feature | Description |
|---------|-------------|
| 🔎 Auto-Scan | Detects 13 security controls automatically |
| ✅ Manual Override | 62 items — mark PASS / FAIL / N/A with notes |
| 📊 Score Dashboard | Live security score with visual ring indicator |
| 📄 PDF Export | Professional audit report with all findings |
| 🌙 Dark UI | Terminal-style cybersecurity interface |

---

## 🛡️ Security Controls Coverage

### Auto-Detected (13 checks)

| Category | Check | Method |
|----------|-------|--------|
| Transport Security | HTTPS Enforcement | Header analysis |
| Transport Security | HSTS Header | Strict-Transport-Security |
| Transport Security | Content-Security-Policy | CSP header |
| Transport Security | X-Frame-Options | Clickjacking protection |
| Transport Security | X-Content-Type-Options | MIME sniffing |
| Transport Security | Referrer-Policy | Header check |
| Transport Security | Permissions-Policy | Header check |
| XSS Protection | X-XSS-Protection | Header check |
| Cookie Security | HttpOnly Flag | Set-Cookie analysis |
| Cookie Security | Secure Flag | Set-Cookie analysis |
| Cookie Security | SameSite Flag | Set-Cookie analysis |
| API Security | CORS Configuration | Access-Control-Allow-Origin |
| Error Handling | Server Info Disclosure | Server / X-Powered-By headers |

### Manual Verification (62 checks)

Authentication, Session Management, Token Security, Access Control, Input Validation, File Upload Security, API Security, Infrastructure, Monitoring & Alerting, Advanced Protection, Security Testing.

---

## 📊 Sample Output

```
Target  : https://example.com
Scanned : 2026-05-20 18:45:00 | HTTP 200

✅ PASS     HTTPS Enforcement        — HTTPS enabled. HSTS: max-age=31536000
✅ PASS     Content-Security-Policy  — CSP header present
❌ FAIL     X-Frame-Options          — Header not present
❌ FAIL     HttpOnly Cookie Flag     — Cookies missing HttpOnly
⚠  PARTIAL  CORS Configuration       — Restricted to specific origin
—  UNKNOWN  MFA / 2FA               — Manual verification required

Security Score : 61%  |  Moderate Risk — Improvements Needed
```

---

## 📁 Project Structure

```
websec-scanner/
├── app.py                  # Flask backend — scanning logic
├── templates/
│   └── index.html          # Frontend UI (HTML + CSS + JS)
├── requirements.txt        # Dependencies
├── Procfile                # Render.com deployment
├── runtime.txt             # Python version
└── README.md
```

---

## 📋 Requirements

```
flask==3.0.3
requests==2.32.3
gunicorn==21.2.0
```

---

## 🚀 Deploy to Render.com

1. Fork this repo
2. Go to [render.com](https://render.com) → New Web Service
3. Connect this repository
4. Set Start Command: `gunicorn app:app`
5. Deploy → Live URL ready

---

## ⚠️ Legal Disclaimer

> This tool is for **educational purposes** and **authorized security testing only**.
> Only scan websites you have **explicit permission** to test.
> The author is not responsible for any misuse or damage.

---

## 👤 Author

**Muhammed Khan**
Certified Penetration Tester (CPT) | Qnayds Academy

[![GitHub](https://img.shields.io/badge/GitHub-muhammed95rafi--arch-black?style=flat-square&logo=github)](https://github.com/muhammed95rafi-arch)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-VISIONARY-red?style=flat-square)](https://tryhackme.com)
[![HackerOne](https://img.shields.io/badge/HackerOne-High%20Severity-orange?style=flat-square)](https://hackerone.com)

