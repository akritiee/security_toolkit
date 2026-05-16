# app.py
import os
import re
import shlex
import subprocess
import logging
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv
import requests
from requests.exceptions import RequestException
import psutil
import platform
import pandas as pd
import imagehash
from sklearn.ensemble import IsolationForest
from PIL import Image
from PIL.ExifTags import TAGS,GPSTAGS
from flask_sqlalchemy import SQLAlchemy
import firebase_admin
from firebase_admin import credentials, firestore

# load .env if present
load_dotenv()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///security_toolkit.db"
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ── Firebase Setup ──────────────────────────────────────────────────────────
# Path to your Firebase service account JSON key (set in .env or environment)
FIREBASE_KEY_PATH = os.getenv("FIREBASE_KEY_PATH", "firebase-adminsdk.json")
try:
    cred = credentials.Certificate(FIREBASE_KEY_PATH)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase connected successfully.")
except Exception as _fb_err:
    db = None
    print(f"Firebase not configured: {_fb_err}")

# ── API Keys (set via .env — never hardcode secrets) ─────────────────────────
VT_API_KEY    = os.getenv("VT_API_KEY", "")       # VirusTotal
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")    # AbuseIPDB

# ── Logger ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("security_toolkit")



# Serve pages
@app.route("/")
def home():
    return render_template("first.html")


@app.route("/threat.html")
def threat_html():
    return render_template("threat.html")


@app.route("/system.html")
def system_html():
    return render_template("system.html")


@app.route("/wifi.html")
def wifi_html():
    return render_template("wifi.html")

@app.route("/Image.html")
def image_html():
    return render_template("Image.html")

@app.route("/map.html")
def map_html():
    return render_template("map.html")

# --- threat intel helper (unchanged) ---
def simple_intel_lookup(query, tpe):
    q = str(query).strip()
    result = "unknown"
    details = ""
    source = "mock"

    if tpe == "" or tpe == "domain":
        # Domain Check using VirusTotal API
        if VT_API_KEY:
            try:
                headers = {
                    "x-apikey": VT_API_KEY,
                    "User-Agent": "SecurityToolkit/1.0"
                }
                domain = q.replace("https://", "").replace("http://", "").split("/")[0]

                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                resp = requests.get(url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)

                    if malicious > 0:
                        result = "malicious"
                        source = "VirusTotal"
                        details = f"Detected by {malicious} security vendors"
                    elif suspicious > 0:
                        result = "suspicious"
                        source = "VirusTotal"
                        details = f"Flagged suspicious by {suspicious} vendors"
                    else:
                        result = "safe"
                        source = "VirusTotal"
                        details = f"Clean: {harmless} vendors marked it harmless"

                elif resp.status_code == 404:
                    result = "unknown"
                    source = "VirusTotal"
                    details = "Domain not found in VirusTotal database"

                else:
                    result = "unknown"
                    source = "VirusTotal"
                    details = f"VirusTotal status: {resp.status_code}"

            except RequestException as e:
                result = "unknown"
                details = f"VirusTotal request error: {e}"

        else:
            result = "unknown"
            details = "VirusTotal API key missing"

    elif tpe == "ip":
        if re.match(r'^(127\.0\.0\.1|localhost)$', q) \
           or q.startswith("10.") \
           or q.startswith("192.168.") \
           or re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', q):
            result = "safe"
            details = "Local/private IP"
            source = "local-check"

        elif ABUSEIPDB_KEY:
            try:
                headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
                resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                                    headers=headers,
                                    params={"ipAddress": q, "maxAgeInDays": 90},
                                    timeout=10)

                if resp.status_code == 200:
                    j = resp.json()
                    data = j.get("data", {})
                    abuse_confidence = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)

                    if abuse_confidence >= 50 or total_reports > 0:
                        result = "malicious"
                    elif abuse_confidence > 0:
                        result = "suspicious"
                    else:
                        result = "safe"

                    source = "AbuseIPDB"
                    details = f"abuseConfidence={abuse_confidence}, reports={total_reports}"

                else:
                    result = "unknown"
                    details = f"AbuseIPDB status {resp.status_code}"

            except RequestException as e:
                result = "unknown"
                details = f"AbuseIPDB request error: {e}"

        else:
            if re.search(r'mal|bad|evil|suspicious', q, re.I):
                result = "malicious"
                details = "Demo: pattern matched"
            else:
                result = "suspicious"
                details = "Demo: no external API key"

    else:
        result = "unknown"
        details = "Unsupported type"

    ts = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "query": q,
        "type": tpe,
        "result": result,
        "source": source,
        "details": details,
        "timestamp": ts
    }
# -----------------------
# Wi-Fi scanning helpers + classification
# -----------------------
def scan_wifi_nmcli():
    try:
        out = subprocess.check_output(shlex.split("nmcli -f SSID,SECURITY,SIGNAL device wifi list"), stderr=subprocess.STDOUT, text=True, timeout=8)
        lines = [l.rstrip() for l in out.splitlines() if l.strip()]
        if len(lines) <= 1:
            return []
        devices = []
        for ln in lines[1:]:
            parts = re.split(r'\s{2,}', ln.strip())
            if len(parts) >= 3:
                ssid = parts[0].strip()
                security = parts[1].strip()
                signal = parts[2].strip()
            else:
                sp = ln.split()
                ssid = sp[0]
                security = sp[-2] if len(sp) >= 2 else ''
                signal = sp[-1] if len(sp) >= 1 else ''
            open_net = (not security) or security.upper() in ("--", "NONE", "OPEN")
            devices.append({"ssid": ssid or "(hidden)", "security": security or "OPEN", "signal": signal, "open": open_net})
        return devices
    except Exception as e:
        logger.debug("scan_wifi_nmcli error: %s", e)
        return []


def scan_wifi_netsh():
    try:
        out = subprocess.check_output(shlex.split("netsh wlan show networks mode=bssid"), stderr=subprocess.STDOUT, text=True, timeout=8)
        blocks = out.split("SSID ")
        devices = []
        for b in blocks[1:]:
            m = re.search(r':\s*(.+)', b)
            ssid = m.group(1).strip() if m else "(hidden)"
            sec = "OPEN"
            ms = re.search(r'Authentication\s*:\s*(.+)', b)
            if ms:
                sec = ms.group(1).strip()
            devices.append({"ssid": ssid, "security": sec, "signal": "", "open": sec.lower().startswith("open")})
        return devices
    except Exception as e:
        logger.debug("scan_wifi_netsh error: %s", e)
        return []


def classify_network(security_str, signal_str):
    """
    Return classification dict: { verdict: 'safe'|'unsafe'|'unknown', reason: str, signal: int|None }
    Rules (simple):
      - open/none/--/OPEN  => unsafe
      - contains 'wep'     => unsafe
      - contains 'wpa3'/'wpa2'/'wpa' => safe
      - otherwise => unknown
      Also parse signal (numeric) to give weak/strong hint.
    """
    verdict = "unknown"
    reason = ""
    sec = (security_str or "").lower()
    if not security_str or sec in ("", "--", "none", "open"):
        verdict = "unsafe"
        reason = "Open/unencrypted network"
    elif "wep" in sec:
        verdict = "unsafe"
        reason = "WEP (insecure)"
    elif "wpa3" in sec or "wpa2" in sec or "wpa " in sec or re.search(r'\bwpa\b', sec):
        verdict = "safe"
        reason = "Protected (WPA family)"
    elif "wpa" in sec:
        verdict = "safe"
        reason = "Protected (WPA family)"
    else:
        verdict = "unknown"
        reason = "Security unknown"

    # parse signal
    sig = None
    try:
        if signal_str is not None and str(signal_str).strip() != "":
            # nmcli often returns integer percent, netsh may not give a number
            sig = int(re.sub(r'\D', '', str(signal_str))) if re.search(r'\d', str(signal_str)) else None
    except Exception:
        sig = None

    # signal hint
    if sig is not None:
        if sig < 30:
            reason += " — weak signal"
        elif sig >= 70:
            reason += " — strong signal"

    return {"verdict": verdict, "reason": reason, "signal": sig}


def get_wifi_networks():
    sysname = platform.system().lower()
    if 'linux' in sysname:
        devs = scan_wifi_nmcli()
        if devs:
            return devs
    if 'windows' in sysname:
        devs = scan_wifi_netsh()
        if devs:
            return devs
    # fallback sample data
    return [
        {"ssid":"HomeWiFi","security":"WPA2","signal":"78","open":False},
        {"ssid":"Cafe_Free_WiFi","security":"","signal":"40","open":True},
        {"ssid":"OfficeNet","security":"WPA2","signal":"60","open":False}
    ]


# API endpoint to return Wi-Fi scan results (with classification)
@app.route("/api/wifi/scan", methods=["GET"])
def api_wifi_scan():
    try:
        devs = get_wifi_networks()
        enriched = []
        for d in devs:
            sec = d.get("security", "")
            sig = d.get("signal", "")
            cls = classify_network(sec, sig)
            enriched.append({
                "ssid": d.get("ssid"),
                "security": sec,
                "signal": sig,
                "open": d.get("open", False),
                "verdict": cls["verdict"],
                "reason": cls["reason"],
                "signal_value": cls["signal"]
            })
        open_count = sum(1 for d in enriched if d.get("open"))
        return jsonify({"devices": enriched, "open_count": open_count})
    except Exception as e:
        logger.exception("api_wifi_scan error")
        return jsonify({"error": str(e)}), 500

# -----------------------
# System audit helpers
# -----------------------
def check_firewall():
    """
    Best-effort detection of firewall state.
    Returns: "enabled", "disabled", or "unknown"
    """
    sysname = platform.system().lower()
    try:
        if 'linux' in sysname:
            # try ufw
            try:
                out = subprocess.check_output(shlex.split("ufw status"), stderr=subprocess.STDOUT, text=True, timeout=3)
                if "inactive" in out.lower():
                    return "disabled"
                return "enabled"
            except Exception:
                # try firewall-cmd
                try:
                    out = subprocess.check_output(shlex.split("firewall-cmd --state"), stderr=subprocess.STDOUT, text=True, timeout=3)
                    if "running" in out.lower():
                        return "enabled"
                    return "unknown"
                except Exception:
                    return "unknown"
        elif 'windows' in sysname:
            try:
                out = subprocess.check_output(shlex.split("netsh advfirewall show allprofiles"), stderr=subprocess.STDOUT, text=True, timeout=3)
                lo = out.lower()
                if "state on" in lo:
                    return "enabled"
                if "state off" in lo:
                    return "disabled"
                return "unknown"
            except Exception:
                return "unknown"
        else:
            return "unknown"
    except Exception:
        return "unknown"

def check_password_strength(password):
    """
    Check password strength and return {status, details}
    Rules:
      - length < 8   => fail
      - missing uppercase, lowercase, number, special char => warning
      - all good => ok
    """

    if not password:
        return {"status": "fail", "details": "No password provided"}

    score = 0
    details = []

    if len(password) >= 12:
        score += 1
    else:
        details.append("Use 12+ characters")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        details.append("Add at least one uppercase letter")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        details.append("Add at least one lowercase letter")

    if re.search(r'\d', password):
        score += 1
    else:
        details.append("Add at least one number")

    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        score += 1
    else:
        details.append("Add at least one special character")

    if len(password) < 8:
        return {"status": "fail", "details": "Too short (minimum 8 characters)"}

    if score >= 4:
        return {"status": "ok", "details": "Strong password"}

    return {"status": "warning", "details": ", ".join(details)}


def list_listening_ports():
    """
    Return a sorted list of listening TCP ports (uses psutil).
    """
    try:
        conns = psutil.net_connections(kind='inet')
        ports = set()
        for c in conns:
            if c.status == psutil.CONN_LISTEN and c.laddr:
                ports.add(c.laddr.port)
        return sorted(list(ports))
    except Exception as e:
        logger.debug("list_listening_ports error: %s", e)
        return []
# -----------------------
# Browser
# -----------------------

def check_browser_security(browser):
    score = 0
    issues = []

    ua = (browser or {}).get("userAgent", "")
    https = (browser or {}).get("https", False)
    cookies = (browser or {}).get("cookiesEnabled", False)
    js = (browser or {}).get("jsEnabled", False)

    # Browser detection
    if ua and any(b in ua.lower() for b in ["chrome", "firefox", "edge", "safari"]):
        score += 20
    else:
        issues.append("Unknown browser detected")

    # HTTPS
    if https:
        score += 30
    else:
        issues.append("Website not accessed over HTTPS")

    # Cookies
    if cookies:
        score += 20
    else:
        issues.append("Cookies are disabled")

    # JavaScript
    if js:
        score += 20
    else:
        issues.append("JavaScript is disabled")

    # Bonus
    if not issues:
        score += 10

    status = "ok it's look safe" if score >= 80 else "warning" if score >= 50 else "fail"

    return {
        "name": "Browser Security",
        "status": status,
        "details": ", ".join(issues) if issues else "Browser security looks good",
        "score": score
    }

    
def perform_system_audit(requested=None):
    """
    Perform a selective local security audit.
    """
    all_keys = [ "firewall", "ports", "antivirus", "password" , "browser" ]
    if requested:
      to_run = set(k.lower() for k in requested )
    else:
        to_run = set(all_keys)
    checks = []
    score = 100

    # Firewall
    if "firewall" in to_run:
        fw = check_firewall()
        if fw == "enabled":
            checks.append({"name": "Firewall", "status": "ok", "details": "Firewall appears enabled"})
        elif fw == "disabled":
            checks.append({"name": "Firewall", "status": "fail", "details": "Firewall appears disabled"})
            score -= 30
        else:
            checks.append({"name": "Firewall", "status": "unknown", "details": "Could not detect firewall status"})

    # Listening ports
    if "ports" in to_run:
        ports = list_listening_ports()
        if ports:
            risky = [p for p in ports if p in (21, 23, 3389)]
            details = f"Listening ports: {', '.join(map(str, ports))}"
            if risky:
                checks.append({"name": "Open Ports", "status": "fail", "details": details})
                score -= 25
            else:
                checks.append({"name": "Open Ports", "status": "ok", "details": details})
        else:
            checks.append({"name": "Open Ports", "status": "ok", "details": "No listening TCP ports found or no permission"})

    # Antivirus detection
    if "antivirus" in to_run:
        av_ok = False
        try:
            procs = [p.name().lower() for p in psutil.process_iter()]
            if 'windows' in platform.system().lower():
                if any('msmpeng.exe' in p for p in procs):
                    av_ok = True
            else:
                if any('clamd' in p or 'clamav' in p for p in procs):
                    av_ok = True
        except Exception:
            av_ok = False

        if av_ok:
            checks.append({"name": "Antivirus", "status": "ok", "details": "Antivirus process detected"})
        else:
            checks.append({"name": "Antivirus", "status": "warning", "details": "No known antivirus process detected"})
# Browser Security
   
    if "browser" in to_run:
       
       browser_data = {}
    if request.is_json:
        browser_data = request.json.get("browser", {})

    result = check_browser_security(browser_data)
    checks.append(result)

    if result["status"] == "fail":
        score -= 25
    elif result["status"] == "warning":
        score -= 10


    # Password Policy
    if "password" in to_run:
        pwd = None
        try:
            if request.is_json:
                pwd = request.json.get("password")
        except Exception:
            pwd = None

        result = check_password_strength(pwd)
        checks.append({"name": "Password Policy", "status": result["status"], "details": result["details"]})

        if result["status"] == "fail":
            score -= 30
        elif result["status"] == "warning":
            score -= 10

    # FINAL S
    final_score = max(0, min(100, score))
    issues_count = sum(1 for c in checks if c["status"] in ["fail", "warning"])
    return {
    "score": final_score,
    "summary": f"{issues_count} issues found",
    "checks": checks
}

def analyze_logs_for_bruteforce(log_data):
    # Simulating log parsing (IP, Status)
    # In a real scenario, you'd parse /var/log/auth.log
    df = pd.DataFrame(log_data)
    
    # Feature Engineering
    stats = df.groupby('ip').agg(
        total=('status', 'count'),
        failed=('status', lambda x: (x == 'failed').sum())
    ).reset_index()
    stats['fail_ratio'] = stats['failed'] / stats['total']
    
    # ML Model (Isolation Forest)
    model = IsolationForest(contamination=0.2, random_state=42)
    X = stats[['total', 'failed', 'fail_ratio']]
    stats['anomaly_score'] = model.fit_predict(X)
    
    # -1 is an anomaly (potential brute force)
    attacks = stats[stats['anomaly_score'] == -1]
    return attacks.to_dict(orient='records')

# --- 2. IMAGE ANALYZER & GEO-OSINT LOGIC ---
def get_image_metadata(img_path):
    img = Image.open(img_path)
    
    # TinEye-style Hashing
    p_hash = str(imagehash.phash(img))
    d_hash = str(imagehash.dhash(img))
    
    # EXIF & GPS Extraction
    exif_data = {}
    gps_info = None
    info = img._getexif()
    if info:
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)
            if decoded == "GPSInfo":
                gps_info = {}
                for t in value:
                    sub_tag = GPSTAGS.get(t, t)
                    gps_info[sub_tag] = value[t]
            else:
                exif_data[decoded] = str(value)

    return p_hash, d_hash, exif_data, gps_info

def convert_to_degrees(value):
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)
# --- API endpoint for intel (unchanged) ---
@app.route("/api/intel/check", methods=["POST"])
def api_intel_check():
    try:
        data = request.get_json() or {}
        tpe = data.get("type", "ip")
        q = data.get("query", "").strip()
        if not q:
            return jsonify({"error": "query required"}), 400
        if len(q) > 2000:
            return jsonify({"error": "query too long"}), 400
        res = simple_intel_lookup(q, tpe)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": "internal error", "details": str(e)}), 500
     
# lightweight audit summary for dashboards
@app.route("/api/audit/summary", methods=["GET"])
def api_audit_summary():
    result = perform_system_audit()
    return jsonify({
        "score": result["score"],
        "summary": result["summary"]
    })
@app.route("/api/audit", methods=["POST"])
def api_audit():
    try:
        data = request.get_json() or {}
        checks = data.get("checks", [])
        # perform_system_audit will handle the password from request.json internally
        result = perform_system_audit(requested=checks)
        return jsonify(result)
    except Exception as e:
        logger.exception("api_audit error")
        return jsonify({"error": str(e)}), 500
@app.route('/api/analyze-bruteforce', methods=['POST'])
def api_bruteforce():
    # Mock data - in production, read from your server logs
    raw_logs = [
        {'ip': '192.168.1.1', 'status': 'failed'},
        {'ip': '192.168.1.1', 'status': 'failed'},
        {'ip': '192.168.1.1', 'status': 'failed'},
        {'ip': '10.0.0.5', 'status': 'success'},
        {'ip': '172.16.0.2', 'status': 'failed'}
    ]
    results = analyze_logs_for_bruteforce(raw_logs)
    return jsonify({"status": "complete", "detected_attacks": results})

# New Feature: Image Analysis & OSINT
@app.route('/api/upload-image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return "No file", 400
    
    file = request.files['file']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    
    phash, dhash, exif, gps = get_image_metadata(filepath)
    
    # Prepare Google Maps Link if GPS exists
    maps_url = None
    if gps:
        try:
            lat = convert_to_degrees(gps['GPSLatitude'])
            if gps['GPSLatitudeRef'] != 'N': lat = -lat
            lon = convert_to_degrees(gps['GPSLongitude'])
            if gps['GPSLongitudeRef'] != 'E': lon = -lon
            maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        except KeyError:
            maps_url = "No valid GPS coordinates found in metadata"

    return jsonify({
        "fingerprints": {"phash": phash, "dhash": dhash},
        "osint_metadata": exif,
        "google_maps_location": maps_url
    })

@app.route('/save-intel', methods=['POST'])
def save_intel():
    # Grab data from the HTML input fields
    query_val = request.form.get('query')
    type_val = request.form.get('type')
    result_val = "Pending Analysis" # You can replace this with your actual logic later
    
    # Send it to Firebase
    db.collection("IntelResults").add({
        "query": query_val,
        "type": type_val,
        "result": result_val,
        "timestamp": datetime.datetime.now().isoformat()
    })
    
    return "Data captured and secured in Firebase!"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True) 