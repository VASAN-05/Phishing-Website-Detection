# ATL – AI Threat Lens

Full-stack threat analysis platform combining React/TypeScript frontend, Node/Express backend, and a Python ML engine.

---

## Architecture

```
┌─────────────────────────────┐
│   React Frontend (Vite)     │  :5173 (dev) / :8080 (prod)
│   client/pages/Index.tsx    │
└────────────┬────────────────┘
             │ /api/scan/url
             │ /api/scan/file
┌────────────▼────────────────┐
│   Node/Express Backend      │  :8080
│   server/routes/scan.ts     │
└────────────┬────────────────┘
             │ HTTP proxy
             │ /analyze/url
             │ /analyze/file
┌────────────▼────────────────┐
│   Python ML Engine (Flask)  │  :5001
│   python_engine/api.py      │
│   ├── ML models (.pkl)      │
│   ├── features.py           │
│   ├── VirusTotal API        │
│   ├── Google Safe Browsing  │
│   ├── AbuseIPDB             │
│   ├── IPQualityScore        │
│   └── URLScan.io            │
└─────────────────────────────┘
```

---

## Quick Start

### Step 1 — Start the Python ML Engine

```bash
cd python_engine

# Install dependencies (first time only)
pip install -r requirements.txt

# Start the engine
python api.py
# Runs on http://localhost:5001
```

**Windows:** Double-click `python_engine/start.bat`
**Mac/Linux:** Run `./python_engine/start.sh`

### Step 2 — Start the Node/React app

```bash
# Install JS dependencies (first time only)
npm install   # or: pnpm install

# Start in development mode
npm run dev   # or: pnpm dev
# Runs on http://localhost:5173
```

### Step 3 — Open in browser

Go to **http://localhost:5173**

---

## Environment Variables

Create a `.env` file in the project root:

```env
ML_ENGINE_URL=http://localhost:5001
PING_MESSAGE=pong
```

The Python ML engine URL can be changed if you host it separately (e.g., on a different server or port).

---

## Features

- **URL Scan** — ML model (GradientBoosting + RandomForest ensemble) + 6 external threat APIs
- **File / APK Scan** — VirusTotal multi-engine scan with SHA256 verification
- **Live Terminal** — Real-time scan progress in the UI
- **Threat Result Panel** — Colour-coded results (Safe / Warning / Danger / Critical)
- **ML Risk Score Bar** — Visual threat probability from the ensemble model
- **Engine Breakdown** — Individual results from each intelligence source
- **Dynamic Profile** — Avatar upload, live name preview, completion progress bar

---

## ML Model Details

- **Training data:** 48,729 real URLs
- **Features:** 50 URL-based features (entropy, keyword counts, domain structure, etc.)
- **Models:** GradientBoosting + RandomForest ensemble
- **Accuracy:** ~95%
- **Spam detection:** Separate NLP-based spam/scam classifier

---

## Python Requirements

- Python 3.9+
- flask, flask-cors, joblib, pandas, scikit-learn, requests, numpy

## Node Requirements

- Node.js 18+
- pnpm or npm
