# ShadowTrace — Backend Intelligence Engine

**Phase 2: Real-Time Phishing Risk Analysis API**

FastAPI + MongoDB backend that receives page metadata from the Chrome extension, runs multi-layer threat detection, and returns structured risk assessments.

---

## Quick Start

### Prerequisites
- Python 3.11+
- MongoDB 6.0+ running locally (or accessible via `MONGO_URI`)

### Setup

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env   # Windows
# cp .env.example .env   # Linux/macOS

# Start the server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The server starts at `http://127.0.0.1:8000`. API docs at `http://127.0.0.1:8000/docs`.

On first boot, the `trusted_domains` collection is seeded with 20 high-value targets (Google, PayPal, Chase, etc.).

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/analyze` | API Key | Analyze page signals → risk score |
| `POST` | `/report` | API Key | Report suspicious domain |
| `GET`  | `/stats` | API Key | Scan statistics & analytics |
| `GET`  | `/health` | None | Health check |
| `GET`  | `/docs` | None | Interactive API docs (Swagger) |

### Authentication

All endpoints except `/health` and `/docs` require an `X-API-Key` header:

```
X-API-Key: shadowtrace-dev-key
```

---

## Detection Engines

| Engine | Weight | Score Range | Techniques |
|--------|--------|-------------|------------|
| Domain Similarity | 30% | 0–30 | Levenshtein distance, punycode, Unicode confusables, brand substring |
| Behavioral | 30% | 0–30 | Cross-domain actions, external fetch/XHR, hidden inputs, credential-bearing requests |
| SSL/Protocol | 10% | 0–10 | HTTP penalty, IP-based URL, compound HTTP+login |
| Threat Intelligence | 30% | 0–30 | Malicious DB lookup, suspicious TLD, user report count |

### Final Score Mapping

| Score | Level |
|-------|-------|
| 0–30 | Safe |
| 31–60 | Suspicious |
| 61–100 | Dangerous |

---

## Testing

```bash
# Test /analyze (typosquat domain)
curl -X POST http://localhost:8000/analyze ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: shadowtrace-dev-key" ^
  -d "{\"domain\":{\"hostname\":\"g00gle.com\",\"protocol\":\"http\",\"isHTTPS\":false,\"isIPBased\":false,\"isPunycode\":false,\"tld\":\"com\",\"isSuspiciousTLD\":false},\"forms\":{\"hasLoginForm\":true,\"formCount\":1},\"behavior\":{\"externalFetchDetected\":true}}"

# Test /report
curl -X POST http://localhost:8000/report ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: shadowtrace-dev-key" ^
  -d "{\"domain\":\"evil-phish.tk\",\"reason\":\"Looks like Google login clone\"}"

# Test /stats
curl http://localhost:8000/stats -H "X-API-Key: shadowtrace-dev-key"

# Health check (no auth)
curl http://localhost:8000/health
```

---

## Docker

```bash
docker build -t shadowtrace-backend .
docker run -p 8000:8000 --env-file .env shadowtrace-backend
```

Requires a reachable MongoDB instance. Set `MONGO_URI` accordingly.

---

## Project Structure

```
backend/
├── app/
│   ├── main.py            # FastAPI entry point, lifespan, middleware
│   ├── config.py          # Pydantic Settings (env-driven)
│   ├── database.py        # Motor async MongoDB, indexes
│   ├── dependencies.py    # DI providers (db, auth)
│   ├── routers/
│   │   ├── analyze.py     # POST /analyze
│   │   ├── report.py      # POST /report
│   │   └── stats.py       # GET /stats
│   ├── engines/
│   │   ├── base.py        # EngineResult interface
│   │   ├── domain_similarity.py
│   │   ├── ssl_protocol.py
│   │   ├── behavioral.py
│   │   └── threat_intel.py
│   ├── services/
│   │   └── risk_scorer.py # Weighted orchestrator
│   ├── models/
│   │   ├── schemas.py     # Pydantic I/O models
│   │   └── db_models.py   # MongoDB TypedDicts
│   ├── middleware/
│   │   ├── auth.py        # API key validation
│   │   └── rate_limit.py  # Sliding window limiter
│   └── utils/
│       └── logging.py     # JSON structured logging
├── requirements.txt
├── Dockerfile
├── .env.example
└── README.md
```
