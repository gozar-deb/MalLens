# Setup Guide

This guide covers the fastest path (Docker Compose), a manual local-dev setup without
Docker, the full environment variable reference, and how to connect a real dynamic
sandbox.

## Prerequisites

- **Docker + Docker Compose** (recommended path), *or*
- **Python 3.11+**, **Node.js 20+**, **PostgreSQL 15**, and **Redis 7** for a manual
  setup.

---

## Option A: Docker Compose (recommended)

```bash
git clone <this-repo>
cd MalLens

# 1. Configure the backend
cp backend/.env.example backend/.env
# Edit backend/.env if you want to add TI/OpenAI/Cuckoo keys — optional for a first run.

# 2. Configure the frontend (optional — defaults to http://localhost:8000)
cp frontend/.env.example frontend/.env

# 3. Build and start everything
docker compose up --build
```

This starts five containers:

| Service | Port | Purpose |
|---|---|---|
| `db` | 5432 (internal) | PostgreSQL |
| `redis` | 6379 (internal) | Celery broker/result backend |
| `api` | 8000 | FastAPI backend |
| `worker` | — | Celery worker running the analysis pipeline |
| `frontend` | 3000 | React app served by nginx |

Once it's up:

- App: **http://localhost:3000**
- API docs (Swagger): **http://localhost:8000/docs**
- Health check: **http://localhost:8000/api/health**

Upload any small test file (or the EICAR test string saved as a `.com`/`.txt`) from
the Upload page and watch it move through the queue.

To stop: `docker compose down`. To also wipe the database volume: `docker compose down -v`.

---

## Option B: Manual local development (no Docker)

**1. Start Postgres and Redis** (via your package manager, or quick throwaway
containers if you have Docker just for these two):

```bash
docker run -d --name mallens-db -e POSTGRES_USER=mallens -e POSTGRES_PASSWORD=mallens_pass -e POSTGRES_DB=mallens_db -p 5432:5432 postgres:15-alpine
docker run -d --name mallens-redis -p 6379:6379 redis:7-alpine
```

**2. Backend**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# .env defaults already point at localhost for DATABASE_URL/REDIS_URL if you edit
# the host from `db`/`redis` to `localhost`.
```

Edit `.env` and change:
```
DATABASE_URL=postgresql+asyncpg://mallens:mallens_pass@localhost:5432/mallens_db
REDIS_URL=redis://localhost:6379/0
UPLOAD_DIR=./uploads
```

Then, in two separate terminals:

```bash
# Terminal 1: API
uvicorn app.main:app --reload --port 8000

# Terminal 2: Celery worker
celery -A app.celery_app worker --loglevel=info
```

**3. Frontend**

```bash
cd frontend
cp .env.example .env    # VITE_API_BASE_URL=http://localhost:8000
npm install
npm run dev
```

Open **http://localhost:3000**.

---

## Environment variable reference (`backend/.env`)

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *(placeholder)* | **Change this** for any non-local deployment |
| `DEBUG` | `false` | SQL echo + verbose errors |
| `DATABASE_URL` | `postgresql+asyncpg://...@db:5432/mallens_db` | Async SQLAlchemy URL |
| `REDIS_URL` | `redis://redis:6379/0` | Celery broker + result backend |
| `UPLOAD_DIR` | `/app/uploads` | Where raw samples are stored |
| `MAX_UPLOAD_SIZE_MB` | `100` | Upload size limit |
| `RETENTION_DAYS` | `30` | Defined for future retention pruning (not yet enforced) |
| `REQUIRE_AUTH` | `false` | `true` enforces JWT auth on write/queue endpoints |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | JWT lifetime |
| `DYNAMIC_SANDBOX_PROVIDER` | `stub` | `stub` or `cuckoo` — see below |
| `CUCKOO_API_URL` | *(empty)* | Required if provider is `cuckoo` |
| `CUCKOO_API_TOKEN` | *(empty)* | Optional Cuckoo API auth token |
| `DYNAMIC_ANALYSIS_TIMEOUT_SECONDS` | `180` | Max wait for a dynamic report |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional hash-reputation enrichment |
| `ABUSEIPDB_API_KEY` | *(empty)* | Optional IP-reputation enrichment |
| `OTX_API_KEY` | *(empty)* | Optional AlienVault OTX pulse enrichment |
| `OPENAI_API_KEY` | *(empty)* | Optional AI-generated executive summaries |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model used for summaries |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |

---

## Adding YARA rules

Drop `.yar`/`.yara` files into `backend/yara_rules/`. They're compiled and matched
automatically on every analysis — no restart needed for new uploads (the worker
recompiles the ruleset per job). A small starter set is included in
`example_rules.yar`; replace or extend it with real rulesets for production use
(e.g. from public YARA-Rules repositories or your own research).

## Connecting a real dynamic sandbox (Cuckoo)

1. Deploy [Cuckoo Sandbox](https://cuckoosandbox.org/) (or a fork like CAPEv2) on
   **isolated hardware or an isolated hypervisor network** — this is a separate,
   non-trivial infrastructure project outside the scope of this repo. Follow
   Cuckoo's own installation and network-isolation guides carefully; this is what
   actually keeps a live malware execution safe.
2. Confirm Cuckoo's REST API is reachable from wherever your `worker` container
   runs, and note the base URL (and API token, if you've enabled auth on Cuckoo).
3. In `backend/.env`:
   ```
   DYNAMIC_SANDBOX_PROVIDER=cuckoo
   CUCKOO_API_URL=http://your-cuckoo-host:8090
   CUCKOO_API_TOKEN=your-token-if-any
   ```
4. Restart the `worker` service: `docker compose restart worker`.

Until you do this, `DYNAMIC_SANDBOX_PROVIDER=stub` (the default) means uploaded
samples are **never executed** — dynamic analysis results will be a clearly-labeled
placeholder, and only static analysis + IOC extraction will reflect real findings.

## Running tests

```bash
cd backend
pip install -r requirements.txt

# Unit tests only (no services needed): static analysis, IOC extraction, scoring, validation
pytest tests/test_static_analysis.py tests/test_ioc_extractor.py tests/test_risk_scoring.py tests/test_file_validation.py -v

# Full suite including API integration tests (needs Postgres + Redis reachable,
# see conftest.py / .github/workflows/ci.yml for the exact env vars used in CI)
pytest -v
```

Frontend build check:
```bash
cd frontend
npm install
npm run build
```

## Troubleshooting

- **"Analysis stuck on `pending`"** — the `worker` container isn't running or can't
  reach Redis. Check `docker compose logs worker`.
- **`yara-python` or `pefile` fails to build** — make sure you're using the provided
  Dockerfile (it installs `build-essential`/`libmagic1`) rather than a bare `pip
  install` on an unsupported platform.
- **CORS errors in the browser console** — make sure `CORS_ORIGINS` in `backend/.env`
  includes the exact origin the frontend is served from.
- **PDF export looks empty** — this happens if the `report` row hasn't been generated
  yet; wait for `status` to reach `completed` before exporting.
