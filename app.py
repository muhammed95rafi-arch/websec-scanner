from flask import Flask, render_template, request, jsonify
import requests
import urllib.parse
import re
import json
from datetime import datetime

app = Flask(__name__)

TIMEOUT = 10

def check_https(url, headers, resp):
    result = {"id": "https", "name": "HTTPS Enforcement", "category": "Transport Security"}
    if url.startswith("https://"):
        # Check HSTS
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            result["status"] = "pass"
            result["detail"] = f"HTTPS enabled. HSTS: {hsts}"
        else:
            result["status"] = "partial"
            result["detail"] = "HTTPS enabled but HSTS header missing."
    else:
        result["status"] = "fail"
        result["detail"] = "Site not using HTTPS."
    return result

def check_security_headers(headers):
    results = []

    checks = [
        ("csp", "Content-Security-Policy", "Content-Security Policy (CSP)", "Transport Security"),
        ("xframe", "X-Frame-Options", "X-Frame-Options", "Transport Security"),
        ("xcontent", "X-Content-Type-Options", "X-Content-Type-Options", "Transport Security"),
        ("xss", "X-XSS-Protection", "X-XSS-Protection Header", "XSS Protection"),
        ("referrer", "Referrer-Policy", "Referrer-Policy", "Transport Security"),
        ("permissions", "Permissions-Policy", "Permissions-Policy", "Transport Security"),
    ]

    for id_, header, name, category in checks:
        val = headers.get(header, "")
        results.append({
            "id": id_,
            "name": name,
            "category": category,
            "status": "pass" if val else "fail",
            "detail": f"{header}: {val}" if val else f"{header} header not present."
        })
    return results

def check_cookies(resp):
    results = []
    cookies = resp.cookies
    if not cookies:
        results.append({
            "id": "cookie_httponly",
            "name": "HttpOnly Cookie Flag",
            "category": "Cookie Security",
            "status": "unknown",
            "detail": "No cookies found in response to analyze."
        })
        results.append({
            "id": "cookie_secure",
            "name": "Secure Cookie Flag",
            "category": "Cookie Security",
            "status": "unknown",
            "detail": "No cookies found in response to analyze."
        })
        results.append({
            "id": "cookie_samesite",
            "name": "SameSite Cookie Flag",
            "category": "Cookie Security",
            "status": "unknown",
            "detail": "No cookies found in response to analyze."
        })
        return results

    httponly_pass = all(c.has_nonstandard_attr("HttpOnly") for c in cookies)
    secure_pass = all(c.secure for c in cookies)

    raw = resp.headers.get("Set-Cookie", "")
    samesite_pass = "samesite" in raw.lower()

    results.append({
        "id": "cookie_httponly",
        "name": "HttpOnly Cookie Flag",
        "category": "Cookie Security",
        "status": "pass" if httponly_pass else "fail",
        "detail": "All cookies have HttpOnly flag." if httponly_pass else "Some cookies missing HttpOnly flag."
    })
    results.append({
        "id": "cookie_secure",
        "name": "Secure Cookie Flag",
        "category": "Cookie Security",
        "status": "pass" if secure_pass else "fail",
        "detail": "All cookies have Secure flag." if secure_pass else "Some cookies missing Secure flag."
    })
    results.append({
        "id": "cookie_samesite",
        "name": "SameSite Cookie Flag",
        "category": "Cookie Security",
        "status": "pass" if samesite_pass else "fail",
        "detail": "SameSite attribute present." if samesite_pass else "SameSite attribute missing on cookies."
    })
    return results

def check_cors(headers):
    acao = headers.get("Access-Control-Allow-Origin", "")
    if not acao:
        return {"id": "cors", "name": "CORS Configuration", "category": "API Security",
                "status": "unknown", "detail": "No CORS headers found. May be intentional for non-API sites."}
    if acao == "*":
        return {"id": "cors", "name": "CORS Configuration", "category": "API Security",
                "status": "fail", "detail": "CORS set to wildcard (*) — allows any origin."}
    return {"id": "cors", "name": "CORS Configuration", "category": "API Security",
            "status": "pass", "detail": f"CORS restricted to: {acao}"}

def check_server_info(headers):
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    leaking = []
    if server:
        leaking.append(f"Server: {server}")
    if powered:
        leaking.append(f"X-Powered-By: {powered}")

    if leaking:
        return {"id": "server_info", "name": "Server Info Disclosure", "category": "Error Handling",
                "status": "fail", "detail": "Sensitive headers exposed: " + ", ".join(leaking)}
    return {"id": "server_info", "name": "Server Info Disclosure", "category": "Error Handling",
            "status": "pass", "detail": "No server version info exposed in headers."}

def check_open_redirect(url, resp):
    location = resp.headers.get("Location", "")
    if location and not location.startswith(url):
        return {"id": "open_redirect", "name": "Open Redirect", "category": "Input Validation",
                "status": "fail", "detail": f"Redirect to external URL detected: {location}"}
    return {"id": "open_redirect", "name": "Open Redirect", "category": "Input Validation",
            "status": "unknown", "detail": "Basic redirect check passed. Deep validation requires manual testing."}

def manual_items():
    items = [
        # Auth
        ("manual_pwd_policy", "Strong Password Policy", "Authentication"),
        ("manual_pwd_hash", "Password Hashing (Argon2/bcrypt)", "Authentication"),
        ("manual_mfa", "MFA / 2FA Implementation", "Authentication"),
        ("manual_email_verify", "Email Verification", "Authentication"),
        ("manual_pwd_reset", "Secure Password Reset", "Authentication"),
        ("manual_session_timeout", "Session Timeout", "Session Management"),
        ("manual_device_mgmt", "Device/Session Management", "Session Management"),
        ("manual_logout_all", "Logout from All Devices", "Session Management"),
        ("manual_rate_limit", "Rate Limiting", "Brute Force Protection"),
        ("manual_captcha", "CAPTCHA Protection", "Brute Force Protection"),
        ("manual_account_lockout", "Account Lockout after Brute Force", "Brute Force Protection"),
        ("manual_otp_expiry", "OTP Expiration", "Brute Force Protection"),
        # Token
        ("manual_jwt", "JWT Validation", "Token Security"),
        ("manual_refresh_token", "Refresh Token Rotation", "Token Security"),
        ("manual_token_revoke", "Token Expiration & Revocation", "Token Security"),
        # Access Control
        ("manual_rbac", "RBAC (Role-Based Access Control)", "Access Control"),
        ("manual_backend_authz", "Backend Authorization Checks", "Access Control"),
        ("manual_idor", "IDOR Prevention (Resource Access Control)", "Access Control"),
        ("manual_admin", "Admin Panel Protection", "Access Control"),
        # Input
        ("manual_input_val", "Input Validation", "Input Security"),
        ("manual_input_san", "Input Sanitization", "Input Security"),
        ("manual_sqli", "SQL Injection Protection", "Input Security"),
        ("manual_csrf", "CSRF Protection", "Input Security"),
        ("manual_ssrf", "SSRF Protection", "Input Security"),
        ("manual_path_trav", "Path Traversal Protection", "Input Security"),
        ("manual_cmd_inject", "Command Injection Protection", "Input Security"),
        ("manual_xxe", "XXE Protection", "Input Security"),
        ("manual_graphql", "GraphQL Protection (if used)", "Input Security"),
        # File Upload
        ("manual_file_val", "File Upload Validation", "File Security"),
        ("manual_mime", "MIME Type Checking", "File Security"),
        ("manual_file_size", "File Size Limits", "File Security"),
        ("manual_malware", "Malware Scanning for Uploads", "File Security"),
        # API
        ("manual_api_auth", "API Authentication", "API Security"),
        ("manual_api_rate", "API Rate Limiting", "API Security"),
        ("manual_api_schema", "API Schema Validation", "API Security"),
        ("manual_api_headers", "Secure Headers on APIs", "API Security"),
        ("manual_websocket", "WebSocket Authentication", "API Security"),
        # Infrastructure
        ("manual_env", "Secret Management (.env Protection)", "Infrastructure"),
        ("manual_backup", "Encrypted Backups", "Infrastructure"),
        ("manual_backup_test", "Backup Recovery Testing", "Infrastructure"),
        ("manual_debug", "Debug Mode Disabled in Production", "Infrastructure"),
        ("manual_dep_scan", "Dependency Vulnerability Scanning", "Infrastructure"),
        ("manual_cloud_perm", "Cloud Permission Restrictions", "Infrastructure"),
        ("manual_db_priv", "Database Least Privilege Access", "Infrastructure"),
        ("manual_container", "Container Security Scanning", "Infrastructure"),
        ("manual_cicd", "CI/CD Secret Scanning", "Infrastructure"),
        # Monitoring
        ("manual_audit_log", "Audit Logging", "Monitoring & Alerting"),
        ("manual_suspicious", "Suspicious Activity Monitoring", "Monitoring & Alerting"),
        ("manual_central_log", "Centralized Logging", "Monitoring & Alerting"),
        ("manual_alert", "Real-Time Alerting System", "Monitoring & Alerting"),
        # Advanced
        ("manual_waf", "WAF Integration", "Advanced Protection"),
        ("manual_cdn", "CDN Protection", "Advanced Protection"),
        ("manual_bot", "Bot Detection", "Advanced Protection"),
        ("manual_ip_throttle", "IP Throttling", "Advanced Protection"),
        ("manual_cache_poison", "Cache Poisoning Protection", "Advanced Protection"),
        ("manual_subdomain", "Subdomain Takeover Monitoring", "Advanced Protection"),
        ("manual_race", "Race Condition Protection", "Advanced Protection"),
        ("manual_biz_logic", "Business Logic Validation", "Advanced Protection"),
        ("manual_open_redir", "Open Redirect Validation", "Advanced Protection"),
        # Testing
        ("manual_sast_dast", "Security Testing Pipeline (SAST/DAST)", "Security Testing"),
        ("manual_pentest", "Manual Penetration Testing Before Release", "Security Testing"),
        ("manual_dep_update", "Secure Dependency Updates", "Security Testing"),
    ]
    return [{"id": id_, "name": name, "category": cat, "status": "unknown", "detail": "Manual verification required.", "manual": True}
            for id_, name, cat in items]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                            headers={"User-Agent": "WebSecScanner/1.0 (Security Audit Tool)"})
    except requests.exceptions.SSLError:
        return jsonify({"error": "SSL/TLS error connecting to target."}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to target URL."}), 400
    except requests.exceptions.Timeout:
        return jsonify({"error": "Connection timed out."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    headers = resp.headers
    auto_results = []
    auto_results.append(check_https(url, headers, resp))
    auto_results.extend(check_security_headers(headers))
    auto_results.extend(check_cookies(resp))
    auto_results.append(check_cors(headers))
    auto_results.append(check_server_info(headers))
    auto_results.append(check_open_redirect(url, resp))

    return jsonify({
        "url": url,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status_code": resp.status_code,
        "auto_results": auto_results,
        "manual_items": manual_items()
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
