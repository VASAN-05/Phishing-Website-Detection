"""
ATL Python ML Engine  —  JSON REST API  (v2, correct build)
Source: phish detector / app.py  (Apr-19-2026 revision)

Fill in your API keys below before running.
Run:  python api.py
Port: http://localhost:5001
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
import os
import requests
import base64
import hashlib
from features import extract_features

import sys
import io
# Fix Windows terminal encoding — prevents UnicodeEncodeError on any platform
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

app = Flask(__name__)
CORS(app)

# ── Allow up to 15 GB uploads ────────────────────────────────
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024 * 1024  # 15 GB

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
model_data = joblib.load(os.path.join(BASE_DIR, "phishing_model_v3.pkl"))
gb         = model_data["gb"]
rf         = model_data["rf"]
spam_model = joblib.load(os.path.join(BASE_DIR, "spam_model.pkl"))

# ── API Keys  ────────────────────────────────────────────────
# Paste your keys here — see README_SETUP.md for how to get each one
VT_API_KEY    = "bac6d6978f04db8ee1c827114379039a961092bfb432ce8d4edf8309a9352484"
GOOGLE_SB_KEY = "AIzaSyDfNtIKBSPSo3ThnT8ClOHnt7-R3Lq75Fk"
URLSCAN_KEY   = "019d88a9-af65-730e-8a16-06023b08aad3"
ABUSEIPDB_KEY = "9095d3e2fb429b6e1c0d5faea3eaada719a06d80c119082bd9c7ba82981aae8525835b41ad9ae343"
IPQS_KEY      = "DFUT3bxUvujltOjTNq7pid3cvCHfhjUx"

# ── Helpers ──────────────────────────────────────────────────
def is_valid_url(url):
    return bool(re.match(
        r"^(https?://)[\w\-]+(\.[\w\-]+)+([\w\-\._~:/?#\[\]@!\$&'\(\)\*\+,;=%]*)?$",
        url
    ))

def extract_domain(url):
    m = re.search(r"(?:https?://)?(?:www\.)?([^/?\s]+)", url)
    return m.group(1) if m else url

def extract_ip(url):
    m = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", url)
    return m.group(0) if m else None

# ── ML models ────────────────────────────────────────────────
def predict_url(url):
    f    = extract_features(url)
    df   = pd.DataFrame([f])
    gb_p = gb.predict_proba(df)[0]
    rf_p = rf.predict_proba(df)[0]
    risk = ((2 * gb_p + rf_p) / 3)[1] * 100
    return ("Phishing" if risk >= 50 else "Legitimate"), round(risk, 1)

def predict_spam(text):
    try:
        pred  = spam_model.predict([text])[0]
        proba = spam_model.predict_proba([text])[0]
        return bool(pred), round(float(max(proba)) * 100, 1)
    except:
        return False, 0.0

# ── VirusTotal URL ───────────────────────────────────────────
def vt_scan_url(url):
    try:
        if not VT_API_KEY:
            return {"success": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total": 0}
        url_id   = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "success":    True,
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values())
            }
        return {"success": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0}
    except:
        return {"success": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0}

# ── VirusTotal FILE — streams from disk, never loads full file into RAM ──
def vt_scan_file_path(filepath, filename):
    """
    Accepts a file PATH (from disk) instead of bytes.
    Streams to VirusTotal so 15 GB files don't crash memory.
    """
    try:
        if not VT_API_KEY:
            sha256 = _sha256_file(filepath)
            return {"success": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total": 0,
                    "file_type": "Unknown", "sha256": sha256}

        headers = {"x-apikey": VT_API_KEY}
        sha256  = _sha256_file(filepath)

        # 1 — Check cache first (no upload needed if VT already knows it)
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            attr  = response.json()["data"]["attributes"]
            stats = attr["last_analysis_stats"]
            return {
                "success":    True,
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values()),
                "file_type":  attr.get("type_description", "Unknown"),
                "sha256":     sha256
            }

        # 2 — Files > 32 MB need a special large-file upload URL
        file_size = os.path.getsize(filepath)
        if file_size > 32 * 1024 * 1024:
            url_resp = requests.get(
                "https://www.virustotal.com/api/v3/files/upload_url",
                headers=headers, timeout=10
            )
            if url_resp.status_code != 200:
                return {"success": False, "malicious": 0, "suspicious": 0,
                        "harmless": 0, "undetected": 0, "total": 0,
                        "file_type": "Unknown", "sha256": sha256}
            upload_url = url_resp.json().get("data", "")
        else:
            upload_url = "https://www.virustotal.com/api/v3/files"

        # 3 — Stream file to VT (no full-file read into RAM)
        with open(filepath, "rb") as fh:
            upload = requests.post(
                upload_url,
                headers=headers,
                files={"file": (filename, fh)},
                timeout=1800   # 30 min for very large files
            )

        if upload.status_code == 200:
            analysis_id = upload.json()["data"]["id"]
            # Poll for result (VT queues large files)
            for _ in range(12):          # wait up to 2 min
                import time
                time.sleep(10)
                result = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers, timeout=15
                )
                if result.status_code == 200:
                    attrs = result.json()["data"]["attributes"]
                    if attrs.get("status") == "completed":
                        stats = attrs["stats"]
                        return {
                            "success":    True,
                            "malicious":  stats.get("malicious",  0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless":   stats.get("harmless",   0),
                            "undetected": stats.get("undetected", 0),
                            "total":      sum(stats.values()),
                            "file_type":  "Uploaded File",
                            "sha256":     sha256
                        }
            # Timed out waiting — return partial
            return {"success": True, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total": 0,
                    "file_type": "Queued (large file)", "sha256": sha256}

        return {"success": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0,
                "file_type": "Unknown", "sha256": sha256}
    except Exception as e:
        print(f"VT file scan error: {e}")
        return {"success": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0,
                "file_type": "Unknown", "sha256": "N/A"}


def _sha256_file(filepath):
    """Compute SHA256 by reading in 64 MB chunks — works on any file size."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Keep legacy bytes version for URL scans (small) ──────────
def vt_scan_file(file_bytes, filename):
    """Legacy: used only when file is already in memory (small files)."""
    try:
        if not VT_API_KEY:
            return {"success": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total": 0,
                    "file_type": "Unknown",
                    "sha256": hashlib.sha256(file_bytes).hexdigest()}
        headers = {"x-apikey": VT_API_KEY}
        sha256  = hashlib.sha256(file_bytes).hexdigest()
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers, timeout=10
        )
        if response.status_code == 200:
            attr  = response.json()["data"]["attributes"]
            stats = attr["last_analysis_stats"]
            return {
                "success":    True,
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless",   0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values()),
                "file_type":  attr.get("type_description", "Unknown"),
                "sha256":     sha256
            }
        upload = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (filename, file_bytes)},
            timeout=30
        )
        if upload.status_code == 200:
            analysis_id = upload.json()["data"]["id"]
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=15
            )
            if result.status_code == 200:
                stats = result.json()["data"]["attributes"]["stats"]
                return {
                    "success":    True,
                    "malicious":  stats.get("malicious",  0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless",   0),
                    "undetected": stats.get("undetected", 0),
                    "total":      sum(stats.values()),
                    "file_type":  "Uploaded File",
                    "sha256":     sha256
                }
        return {"success": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0,
                "file_type": "Unknown", "sha256": "N/A"}
    except:
        return {"success": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0,
                "file_type": "Unknown", "sha256": "N/A"}

# ── Google Safe Browsing ─────────────────────────────────────
def google_safebrowsing(url):
    try:
        if not GOOGLE_SB_KEY:
            return {"flagged": False, "threat": "Unavailable"}
        payload = {
            "client": {"clientId": "threatdetector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE","SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE",
                                     "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={GOOGLE_SB_KEY}",
            json=payload, timeout=10
        )
        if response.status_code == 200:
            matches = response.json().get("matches", [])
            if matches:
                return {"flagged": True,
                        "threat": matches[0].get("threatType", "MALWARE")}
            return {"flagged": False, "threat": "Clean"}
        return {"flagged": False, "threat": "Unavailable"}
    except:
        return {"flagged": False, "threat": "Unavailable"}

# ── URLScan.io ───────────────────────────────────────────────
def urlscan_lookup(url):
    try:
        if not URLSCAN_KEY:
            return {"success": False, "verdict": "Unavailable", "result": "", "scan_id": ""}
        headers  = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=10
        )
        if response.status_code in [200, 201]:
            data = response.json()
            return {
                "success": True,
                "scan_id": data.get("uuid",   ""),
                "result":  data.get("result", ""),
                "verdict": "Submitted"
            }
        return {"success": False, "verdict": "Unavailable", "result": "", "scan_id": ""}
    except:
        return {"success": False, "verdict": "Unavailable", "result": "", "scan_id": ""}

# ── AbuseIPDB ────────────────────────────────────────────────
def abuseipdb_check(url):
    try:
        if not ABUSEIPDB_KEY:
            return {"success": False, "score": 0, "reports": 0, "ip": "", "country": ""}
        ip = extract_ip(url)
        if not ip:
            domain = extract_domain(url)
            try:
                import socket
                ip = socket.gethostbyname(domain)
            except:
                return {"success": False, "score": 0, "reports": 0, "ip": "", "country": ""}
        headers  = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "success":  True,
                "ip":       ip,
                "score":    data.get("abuseConfidenceScore", 0),
                "reports":  data.get("totalReports",        0),
                "country":  data.get("countryCode",         "??")
            }
        return {"success": False, "score": 0, "reports": 0, "ip": ip, "country": ""}
    except:
        return {"success": False, "score": 0, "reports": 0, "ip": "", "country": ""}

# ── IPQualityScore ───────────────────────────────────────────
def ipqs_check(url):
    try:
        if not IPQS_KEY:
            return {"success": False, "risk_score": 0}
        encoded  = requests.utils.quote(url, safe="")
        response = requests.get(
            f"https://www.ipqualityscore.com/api/json/url/{IPQS_KEY}/{encoded}",
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "success":    True,
                "phishing":   data.get("phishing",   False),
                "malware":    data.get("malware",    False),
                "suspicious": data.get("suspicious", False),
                "spam":       data.get("spamming",   False),
                "risk_score": data.get("risk_score", 0),
                "domain_age": data.get("domain_age", {}).get("human", "Unknown")
            }
        return {"success": False, "risk_score": 0}
    except:
        return {"success": False, "risk_score": 0}


# ── Composite danger score ────────────────────────────────────
def compute_composite_score(ml_risk, vt, gsb, abuse, ipqs, mode="url"):
    """
    Compute a 0-100 weighted composite danger score from all sources.
    Weights (URL mode):
      ML model      30%
      VirusTotal    35%
      AbuseIPDB     15%
      IPQualityScore 15%
      Google SB      5%
    File mode (no ML / IPQS / GSB):
      VirusTotal   100%  (only VT is meaningful for files)
    """
    breakdown = {
        "ml":        None,
        "vt":        None,
        "abuseipdb": None,
        "ipqs":      None,
        "gsb":       None,
    }

    if mode == "file":
        # For files: VT malicious ratio → 0-100
        vt_total = vt.get("total", 0)
        vt_mal   = vt.get("malicious", 0) + vt.get("suspicious", 0) * 0.5
        vt_score = round((vt_mal / vt_total) * 100, 1) if vt_total > 0 else 0.0
        breakdown["vt"] = vt_score
        return {"overall": vt_score, "breakdown": breakdown}

    scores  = []
    weights = []

    # ML model (30%)
    if ml_risk is not None:
        breakdown["ml"] = round(ml_risk, 1)
        scores.append(ml_risk);  weights.append(30)

    # VirusTotal (35%) — malicious ratio capped at 100
    vt_total = vt.get("total", 0)
    if vt.get("success") and vt_total > 0:
        raw = (vt.get("malicious", 0) + vt.get("suspicious", 0) * 0.5) / vt_total * 100
        vt_score = min(round(raw, 1), 100.0)
        breakdown["vt"] = vt_score
        scores.append(vt_score); weights.append(35)

    # AbuseIPDB (15%) — already 0-100
    if abuse.get("success"):
        a_score = float(abuse.get("score", 0))
        breakdown["abuseipdb"] = a_score
        scores.append(a_score); weights.append(15)

    # IPQualityScore (15%) — already 0-100
    if ipqs.get("success"):
        q_score = float(ipqs.get("risk_score", 0))
        breakdown["ipqs"] = q_score
        scores.append(q_score); weights.append(15)

    # Google Safe Browsing (5%) — binary 0 or 100
    gsb_score = 100.0 if gsb.get("flagged") else 0.0
    breakdown["gsb"] = gsb_score
    scores.append(gsb_score); weights.append(5)

    if not scores:
        return {"overall": 0.0, "breakdown": breakdown}

    overall = round(sum(s * w for s, w in zip(scores, weights)) / sum(weights), 1)
    return {"overall": overall, "breakdown": breakdown}

# ── Master threat classifier ─────────────────────────────────
def classify_threat(ml_label, ml_risk, vt, gsb, ipqs,
                    is_spam=False, mode="url", filename=""):
    malicious  = vt.get("malicious",  0)
    suspicious = vt.get("suspicious", 0)
    vt_flags   = malicious + suspicious
    gsb_flag   = gsb.get("flagged",   False)
    ipqs_risk  = ipqs.get("risk_score", 0)
    ext        = os.path.splitext(filename)[1].lower() if filename else ""
    name_lower = filename.lower()                       if filename else ""

    if mode == "file":
        if malicious >= 15 or any(k in name_lower
                for k in ["ransom","crypt","lock","wanna"]):
            category, risk_level = "Ransomware",       "critical"
        elif malicious >= 10:
            category, risk_level = "Virus",            "critical"
        elif malicious >= 5:
            category, risk_level = "Malware",          "high"
        elif malicious >= 3 and ext in [".apk", ".ipa"]:
            category, risk_level = "Spyware",          "high"
        elif malicious >= 1 and any(k in name_lower
                for k in ["bot","rat","c2","cmd","agent"]):
            category, risk_level = "Botnet / C2",      "critical"
        elif malicious >= 1:
            category, risk_level = "Malware",          "high"
        elif suspicious >= 5:
            category, risk_level = "Exploit Critical", "critical"
        elif suspicious >= 2:
            category, risk_level = "Suspicious",       "medium"
        else:
            category, risk_level = "Benign",           "safe"
    else:
        if malicious >= 15:
            category, risk_level = "Exploit Critical", "critical"
        elif malicious >= 10:
            category, risk_level = "Botnet / C2",      "critical"
        elif malicious >= 7:
            category, risk_level = "Ransomware",       "critical"
        elif malicious >= 5 or (gsb_flag and malicious >= 2):
            category, risk_level = "Malware",          "high"
        elif malicious >= 3:
            category, risk_level = "Virus",            "high"
        elif malicious >= 2 and ml_label == "Phishing":
            category, risk_level = "Phishing",         "high"
        elif malicious >= 1 and ml_risk >= 50:
            category, risk_level = "Phishing",         "high"
        elif gsb_flag:
            category, risk_level = "Phishing",         "high"
        elif ipqs.get("phishing") or ipqs.get("malware"):
            category, risk_level = "Phishing",         "high"
        elif is_spam or ipqs.get("spam"):
            category, risk_level = "Spam / Scam",      "medium"
        elif malicious >= 1:
            category, risk_level = "Spam / Scam",      "medium"
        elif suspicious >= 5:
            category, risk_level = "Defacement",       "medium"
        elif suspicious >= 2 or ipqs_risk >= 75:
            category, risk_level = "Spam / Scam",      "medium"
        elif ml_label == "Phishing" and ml_risk >= 70:
            category, risk_level = "Phishing",         "high"
        elif ml_label == "Phishing" and ml_risk >= 50:
            category, risk_level = "Suspicious",       "medium"
        elif ml_risk >= 30 or ipqs_risk >= 50:
            category, risk_level = "Suspicious",       "medium"
        elif ml_risk < 15 and vt_flags == 0 and not gsb_flag:
            category, risk_level = "Legitimate",       "safe"
        else:
            category, risk_level = "Benign",           "safe"

    level_map = {
        "safe":     "SAFE",
        "medium":   "WARNING",
        "high":     "DANGER",
        "critical": "CRITICAL",
    }
    return level_map[risk_level], risk_level, category

# ── REST endpoints ───────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "engine": "ATL Python ML v2",
        "apis_configured": {
            "virustotal":        bool(VT_API_KEY),
            "google_safebrowse": bool(GOOGLE_SB_KEY),
            "urlscan":           bool(URLSCAN_KEY),
            "abuseipdb":         bool(ABUSEIPDB_KEY),
            "ipqualityscore":    bool(IPQS_KEY),
        }
    })

@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()

    # Auto-add https:// if missing
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not url or not is_valid_url(url):
        return jsonify({"error": "invalid_url"}), 400

    ml_label, ml_risk  = predict_url(url)
    is_spam, spam_conf = predict_spam(url)
    vt                 = vt_scan_url(url)
    gsb                = google_safebrowsing(url)
    abuse              = abuseipdb_check(url)
    ipqs               = ipqs_check(url)
    urlscan            = urlscan_lookup(url)

    threat_label, risk_level, category = classify_threat(
        ml_label, ml_risk, vt, gsb, ipqs,
        is_spam=is_spam, mode="url"
    )

    composite = compute_composite_score(ml_risk, vt, gsb, abuse, ipqs, mode="url")

    return jsonify({
        "mode":         "url",
        "composite":    composite,
        "threat_label": threat_label,
        "risk_level":   risk_level,
        "category":     category,
        "ml": {
            "label":     ml_label,
            "risk":      ml_risk,
            "is_spam":   is_spam,
            "spam_conf": spam_conf,
        },
        "virustotal": {
            "success":    vt.get("success",    False),
            "malicious":  vt.get("malicious",  0),
            "suspicious": vt.get("suspicious", 0),
            "harmless":   vt.get("harmless",   0),
            "undetected": vt.get("undetected", 0),
            "total":      vt.get("total",      0),
        },
        "google_safebrowsing": {
            "flagged": gsb.get("flagged", False),
            "threat":  gsb.get("threat",  ""),
        },
        "abuseipdb": {
            "success":  abuse.get("success",  False),
            "ip":       abuse.get("ip",       ""),
            "score":    abuse.get("score",    0),
            "reports":  abuse.get("reports",  0),
            "country":  abuse.get("country",  ""),
        },
        "ipqualityscore": {
            "success":    ipqs.get("success",    False),
            "risk_score": ipqs.get("risk_score", 0),
            "phishing":   ipqs.get("phishing",   False),
            "malware":    ipqs.get("malware",    False),
            "spam":       ipqs.get("spam",       False),
            "domain_age": ipqs.get("domain_age", "Unknown"),
        },
        "urlscan": {
            "success": urlscan.get("success", False),
            "result":  urlscan.get("result",  ""),
            "scan_id": urlscan.get("scan_id", ""),
        },
    })


@app.route("/analyze/url/stream", methods=["POST"])
def analyze_url_stream():
    """
    Server-Sent Events version of /analyze/url.
    Emits a JSON event after each processing step so the frontend
    can display live progress in the terminal.

    Event format:  data: <json>\n\n
    Final event:   data: {"type":"result", ...full ScanResponse...}\n\n
    """
    import json as _json

    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()

    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not url or not is_valid_url(url):
        def err_stream():
            yield 'data: ' + _json.dumps({"type": "error", "message": "Invalid URL"}) + '\n\n'
        return app.response_class(err_stream(), mimetype="text/event-stream")

    def generate():
        # Step 1 — URL validation
        yield f'data: {_json.dumps({"type":"step","step":"validate","status":"done","message":"URL validated and sanitised"})}\n\n'

        # Step 2 — ML feature extraction
        yield f'data: {_json.dumps({"type":"step","step":"ml_features","status":"running","message":"Extracting 50 URL features (entropy, keyword density, TLD, subdomain depth...)"})}\n\n'
        ml_label, ml_risk = predict_url(url)
        is_spam, spam_conf = predict_spam(url)
        yield f'data: {_json.dumps({"type":"step","step":"ml_features","status":"done","message":f"ML ensemble complete — {ml_label} ({ml_risk}% risk), spam={is_spam}"})}\n\n'

        # Step 3 — VirusTotal
        yield f'data: {_json.dumps({"type":"step","step":"virustotal","status":"running","message":"Querying VirusTotal — checking against 70+ antivirus engines..."})}\n\n'
        vt = vt_scan_url(url)
        vt_msg = f"VirusTotal: {vt.get('malicious',0)} malicious, {vt.get('suspicious',0)} suspicious / {vt.get('total',0)} engines" if vt.get("success") else "VirusTotal: unavailable (check API key)"
        yield f'data: {_json.dumps({"type":"step","step":"virustotal","status":"done","message":vt_msg})}\n\n'

        # Step 4 — Google Safe Browsing
        yield f'data: {_json.dumps({"type":"step","step":"gsb","status":"running","message":"Querying Google Safe Browsing — checking MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE..."})}\n\n'
        gsb = google_safebrowsing(url)
        gsb_msg = f"Google SB: FLAGGED as {gsb['threat']}" if gsb.get("flagged") else "Google SB: Clean"
        yield f'data: {_json.dumps({"type":"step","step":"gsb","status":"done","message":gsb_msg})}\n\n'

        # Step 5 — AbuseIPDB
        yield f'data: {_json.dumps({"type":"step","step":"abuseipdb","status":"running","message":"Resolving domain to IP, checking AbuseIPDB reputation database..."})}\n\n'
        abuse = abuseipdb_check(url)
        abuse_msg = f"AbuseIPDB: IP {abuse.get('ip','??')} — confidence score {abuse.get('score',0)}/100 ({abuse.get('reports',0)} reports)" if abuse.get("success") else "AbuseIPDB: unavailable"
        yield f'data: {_json.dumps({"type":"step","step":"abuseipdb","status":"done","message":abuse_msg})}\n\n'

        # Step 6 — IPQualityScore
        yield f'data: {_json.dumps({"type":"step","step":"ipqs","status":"running","message":"Running IPQualityScore — phishing/malware/spam/domain-age analysis..."})}\n\n'
        ipqs = ipqs_check(url)
        ipqs_msg = f"IPQS: risk={ipqs.get('risk_score',0)}/100, phishing={ipqs.get('phishing',False)}, malware={ipqs.get('malware',False)}, domain age={ipqs.get('domain_age','unknown')}" if ipqs.get("success") else "IPQS: unavailable"
        yield f'data: {_json.dumps({"type":"step","step":"ipqs","status":"done","message":ipqs_msg})}\n\n'

        # Step 7 — URLScan.io
        yield f'data: {_json.dumps({"type":"step","step":"urlscan","status":"running","message":"Submitting to URLScan.io for screenshot and behaviour analysis..."})}\n\n'
        urlscan = urlscan_lookup(url)
        urlscan_msg = f"URLScan.io: submitted (scan_id={urlscan.get('scan_id','??')})" if urlscan.get("success") else "URLScan.io: unavailable"
        yield f'data: {_json.dumps({"type":"step","step":"urlscan","status":"done","message":urlscan_msg})}\n\n'

        # Step 8 — Classify + composite
        yield f'data: {_json.dumps({"type":"step","step":"classify","status":"running","message":"Running threat classifier — weighing all signals..."})}\n\n'
        threat_label, risk_level, category = classify_threat(
            ml_label, ml_risk, vt, gsb, ipqs, is_spam=is_spam, mode="url"
        )
        composite = compute_composite_score(ml_risk, vt, gsb, abuse, ipqs, mode="url")
        yield 'data: ' + _json.dumps({"type":"step","step":"classify","status":"done","message":f"Classification: {threat_label} — {category} (composite={composite['overall']}%)"}) + '\n\n'

        # Final result
        result = {
            "type":         "result",
            "mode":         "url",
            "composite":    composite,
            "threat_label": threat_label,
            "risk_level":   risk_level,
            "category":     category,
            "ml": {
                "label": ml_label, "risk": ml_risk,
                "is_spam": is_spam, "spam_conf": spam_conf,
            },
            "virustotal": {
                "success":    vt.get("success",    False),
                "malicious":  vt.get("malicious",  0),
                "suspicious": vt.get("suspicious", 0),
                "harmless":   vt.get("harmless",   0),
                "undetected": vt.get("undetected", 0),
                "total":      vt.get("total",      0),
            },
            "google_safebrowsing": {
                "flagged": gsb.get("flagged", False),
                "threat":  gsb.get("threat",  ""),
            },
            "abuseipdb": {
                "success": abuse.get("success", False),
                "ip":      abuse.get("ip",      ""),
                "score":   abuse.get("score",   0),
                "reports": abuse.get("reports", 0),
                "country": abuse.get("country", ""),
            },
            "ipqualityscore": {
                "success":    ipqs.get("success",    False),
                "risk_score": ipqs.get("risk_score", 0),
                "phishing":   ipqs.get("phishing",   False),
                "malware":    ipqs.get("malware",    False),
                "spam":       ipqs.get("spam",       False),
                "domain_age": ipqs.get("domain_age", "Unknown"),
            },
            "urlscan": {
                "success": urlscan.get("success", False),
                "result":  urlscan.get("result",  ""),
                "scan_id": urlscan.get("scan_id", ""),
            },
        }
        yield f"data: {_json.dumps(result)}\n\n"

    return app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":       "keep-alive",
        }
    )

@app.route("/analyze/file", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "no_file"}), 400

    f        = request.files["file"]
    filename = f.filename or "unknown"

    # ── Save to a temp file on disk — never read whole file into RAM ──
    import tempfile
    tmp_path = None
    try:
        suffix = os.path.splitext(filename)[1] or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp_path = tmp.name
            # Stream from Flask request to disk in 64 MB chunks
            chunk_size = 64 * 1024 * 1024
            while True:
                chunk = f.stream.read(chunk_size)
                if not chunk:
                    break
                tmp.write(chunk)

        # Scan using the disk-based path function
        vt = vt_scan_file_path(tmp_path, filename)

        threat_label, risk_level, category = classify_threat(
            "Legitimate", 0, vt,
            {"flagged": False}, {"risk_score": 0},
            is_spam=False, mode="file", filename=filename
        )

        composite = compute_composite_score(0, vt, {"flagged": False}, {"success": False}, {"success": False}, mode="file")

        return jsonify({
            "mode":         "file",
            "composite":    composite,
            "filename":     filename,
            "threat_label": threat_label,
            "risk_level":   risk_level,
            "category":     category,
            "virustotal": {
                "success":    vt.get("success",    False),
                "malicious":  vt.get("malicious",  0),
                "suspicious": vt.get("suspicious", 0),
                "harmless":   vt.get("harmless",   0),
                "undetected": vt.get("undetected", 0),
                "total":      vt.get("total",      0),
                "file_type":  vt.get("file_type",  "Unknown"),
                "sha256":     vt.get("sha256",     "N/A"),
            },
        })
    except Exception as e:
        print(f"File analysis error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # Always clean up the temp file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

if __name__ == "__main__":
    print("\n[ATL] ML Engine starting on http://localhost:5001")
    missing = [name for name, val in [
        ("VT_API_KEY", VT_API_KEY), ("GOOGLE_SB_KEY", GOOGLE_SB_KEY),
        ("URLSCAN_KEY", URLSCAN_KEY), ("ABUSEIPDB_KEY", ABUSEIPDB_KEY),
        ("IPQS_KEY", IPQS_KEY)
    ] if not val]
    if missing:
        missing_str = ", ".join(missing)
        print(f"[WARN] Missing API keys: {missing_str}")
        print("   ML model will still run — external APIs will return 'Unavailable'")
        print("   See README_SETUP.md for instructions\n")
    else:
        print("[OK] All 5 API keys configured\n")
    app.run(host="0.0.0.0", port=5001, debug=False)