# ATL — API Key Setup Guide

The ML engine uses 5 external threat intelligence APIs.
All are **free tier** — no credit card needed.
Follow the steps below, then paste each key into `api.py`.

---

## Where to paste your keys

Open `python_engine/api.py` and find these lines near the top:

```python
VT_API_KEY    = ""   # ← paste VirusTotal key here
GOOGLE_SB_KEY = ""   # ← paste Google Safe Browsing key here
URLSCAN_KEY   = ""   # ← paste URLScan.io key here
ABUSEIPDB_KEY = ""   # ← paste AbuseIPDB key here
IPQS_KEY      = ""   # ← paste IPQualityScore key here
```

The engine will work without keys — the ML model always runs,
but external APIs will show "Unavailable" until keys are added.

---

## API 1 — VirusTotal  (most important)

**What it does:** Scans URLs and files against 70+ antivirus engines.

1. Go to → https://www.virustotal.com/gui/join-us
2. Sign up with email (free)
3. After login: click your **profile icon** (top-right) → **API Key**
4. Copy the long key (64 hex characters)
5. Paste into: `VT_API_KEY = "your_key_here"`

**Free limits:** 4 lookups/minute, 500/day

---

## API 2 — Google Safe Browsing

**What it does:** Checks if a URL is flagged by Google for malware/phishing.

1. Go to → https://console.cloud.google.com/
2. Sign in with your Google account
3. Create a new project (top bar → "Select a project" → "New Project")
4. In the search bar type **"Safe Browsing API"** → click it → **Enable**
5. Go to **APIs & Services → Credentials** → **+ Create Credentials → API Key**
6. Copy the key (starts with `AIza...`)
7. Paste into: `GOOGLE_SB_KEY = "your_key_here"`

**Free limits:** 10,000 requests/day

---

## API 3 — URLScan.io

**What it does:** Submits URLs for screenshot + behaviour analysis.

1. Go to → https://urlscan.io/user/signup
2. Sign up (free)
3. After login: click your **username** (top-right) → **Settings & API**
4. Under "API Keys" click **+ Create new API key**
5. Give it a name (e.g. "ATL"), click **Create**
6. Copy the UUID key shown once
7. Paste into: `URLSCAN_KEY = "your_key_here"`

**Free limits:** 60 scans/minute public visibility

---

## API 4 — AbuseIPDB

**What it does:** Checks the IP reputation of a domain/URL host.

1. Go to → https://www.abuseipdb.com/register
2. Sign up (free)
3. After login: go to → https://www.abuseipdb.com/account/api
4. Click **Create Key**, give it a name
5. Copy the key shown
6. Paste into: `ABUSEIPDB_KEY = "your_key_here"`

**Free limits:** 1,000 checks/day

---

## API 5 — IPQualityScore

**What it does:** Detects phishing, malware, spam, and checks domain age.

1. Go to → https://www.ipqualityscore.com/create-account
2. Sign up (free — no credit card)
3. After login: go to → https://www.ipqualityscore.com/documentation/overview
4. Your **private key** is shown on your dashboard under **"API Key"**
   Or go to: https://www.ipqualityscore.com/user/settings
5. Copy the key
6. Paste into: `IPQS_KEY = "your_key_here"`

**Free limits:** 200 lookups/day

---

## Verify setup

After adding keys, start the engine:

```bash
cd python_engine
python api.py
```

You should see:
```
🛡  ATL ML Engine starting on http://localhost:5001
✅  All 5 API keys configured
```

Test it:
```bash
curl http://localhost:5001/health
```

Expected response:
```json
{
  "status": "ok",
  "engine": "ATL Python ML v2",
  "apis_configured": {
    "virustotal": true,
    "google_safebrowse": true,
    "urlscan": true,
    "abuseipdb": true,
    "ipqualityscore": true
  }
}
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: flask_cors` | Run `pip install flask-cors` |
| `ModuleNotFoundError: joblib` | Run `pip install -r requirements.txt` |
| API returns 401 | Your key is wrong or hasn't activated yet (wait 1 min) |
| Google SB returns 400 | Make sure the Safe Browsing API is **enabled** in your project |
| VT returns 204 | URL not in VT cache yet; it will be submitted on next scan |

